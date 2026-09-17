// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// oauthClientColumns is the canonical SELECT column list for iam_oauth_clients.
// All query functions must use this constant to avoid column-order drift between
// the SELECT and the Scan call.
//
// IMPORTANT: leading and trailing whitespace are LOAD-BEARING. Every call site
// concatenates this constant between the literal `SELECT` and the literal
// `FROM iam_oauth_clients ...`, with no whitespace added at the boundary. The
// previous last column was the COALESCE(...) wrapper whose closing `)` is a
// hard PG token boundary, so the missing trailing whitespace was masked.
// Commit 710b282 added the bare identifier `client_uri` as the new last
// column, which mashed against `FROM` to form a single identifier
// `client_uriFROM`. PG then parsed the statement with no FROM clause and
// rejected `id` as undefined (SQLSTATE 42703), and every /oauth/authorize,
// /oauth/token, and /oauth/introspect call returned `invalid_client` in
// ~200µs without ever touching iam_oauth_clients (the bug masqueraded as a
// flat seq_scan/idx_scan counter on the table).
//
// The leading newline/tab and the trailing newline below restore PG-token
// separation regardless of which identifier is added at the head or tail.
// Do not remove them. New columns appended at the end MUST land on their own
// indented line above the closing backtick — never on the same line as the
// closing delimiter.
const oauthClientColumns = `
	id, tenant_id, client_id, COALESCE(client_secret_hash, ''), client_name, client_description,
	grant_types, response_types, redirect_uris, scopes,
	access_token_lifetime, refresh_token_lifetime, id_token_lifetime,
	is_public, is_confidential, is_first_party, require_pkce, is_active,
	revoked_at, revoked_by, logo_url, tos_url, policy_url, contact_email,
	contacts, token_endpoint_auth_method, id_token_signed_response_alg,
	post_logout_redirect_uris, allowed_cors_origins,
	backchannel_logout_uri, COALESCE(backchannel_logout_session_required, false),
	frontchannel_logout_uri, COALESCE(frontchannel_logout_session_required, false),
	created_at, updated_at, created_by, updated_by,
	COALESCE(app_category, 'general'), COALESCE(require_assignment, false),
	COALESCE(require_pushed_authorization_requests, false),
	jwks::text, COALESCE(request_object_signing_alg, 'RS256'),
	client_uri,
	COALESCE(allow_external_jwt_exchange, false),
	COALESCE(refresh_token_rotation_policy, 'rotate')
`

// scanOAuthClient scans a single row into an OAuthClient.
// The column order must match oauthClientColumns exactly.
func scanOAuthClient(row interface {
	Scan(dest ...any) error
}, client *models.OAuthClient,
) error {
	return row.Scan(
		&client.ID, &client.TenantID, &client.ClientID, &client.ClientSecret,
		&client.Name, &client.Description, &client.GrantTypes, &client.ResponseTypes,
		&client.RedirectURIs, &client.Scopes, &client.AccessTokenLifetime, &client.RefreshTokenLifetime,
		&client.IDTokenLifetime, &client.IsPublic, &client.IsConfidential,
		&client.IsFirstParty, &client.RequirePKCE, &client.IsActive,
		&client.RevokedAt, &client.RevokedBy, &client.LogoURL, &client.TosURL,
		&client.PolicyURL, &client.ContactEmail, &client.Contacts,
		&client.TokenEndpointAuthMethod, &client.IDTokenSignedResponseAlg,
		&client.PostLogoutRedirectURIs, &client.AllowedCORSOrigins,
		&client.BackchannelLogoutURI, &client.BackchannelLogoutSessionRequired,
		&client.FrontchannelLogoutURI, &client.FrontchannelLogoutSessionRequired,
		&client.CreatedAt, &client.UpdatedAt, &client.CreatedBy, &client.UpdatedBy,
		&client.AppCategory, &client.RequireAssignment,
		&client.RequirePushedAuthorizationRequests,
		// RFC 9101 JAR — jwks is selected as ::text so a NULL JSONB
		// scans cleanly into *string. RequestObjectSigningAlg is
		// COALESCE'd to 'RS256' so pre-migration rows keep the
		// platform default.
		&client.Jwks, &client.RequestObjectSigningAlg,
		// RFC 7591 §2 client homepage URL (migration 227).
		&client.ClientURI,
		// RFC 8693 :jwt subject_token_type permission (migration
		// 237). COALESCE in oauthClientColumns means pre-migration
		// rows scan as false (the safe default).
		&client.AllowExternalJWTExchange,
		// Refresh-token rotation policy (migration 242). COALESCE
		// guards pre-migration rows so they scan as the canonical
		// "rotate" default.
		&client.RefreshTokenRotationPolicy,
	)
}

const msgOAuthClientNotFound = "OAuth client not found"

// ErrOAuthClientNotFound is the sentinel returned by GetByID and GetByClientID
// when no row matches. Service-layer callers should use errors.Is to
// distinguish a genuine "not found" (legitimate `invalid_client` per
// RFC 6749 §5.2) from a transient DB / pool / pgx failure that needs to be
// diagnosed rather than silently mapped to the same wire message.
var ErrOAuthClientNotFound = errors.New(msgOAuthClientNotFound)

// OAuthClientRepository handles OAuth client database operations
type OAuthClientRepository struct {
	pool DBTX
}

// NewOAuthClientRepository creates a new OAuthClientRepository
func NewOAuthClientRepository(pool *pgxpool.Pool) *OAuthClientRepository {
	return &OAuthClientRepository{pool: pool}
}

// OAuthClientTx is a transaction-scoped handle over the OAuth client repository.
// It bundles the two writes that an authorization_code token exchange MUST
// perform atomically — the compare-and-swap that marks the authorization code
// used, and the persistence of the issued refresh/access-token row — together
// with Commit/Rollback. Returned by BeginTx.
//
// Rationale (2026-07-21 OAuth migration-gap outage): the pre-fix exchange
// marked the code used with an independent, already-committed UPDATE and only
// THEN persisted the token. When the token write failed (migration 0009 had not
// been applied fleet-wide, so token_family_id did not yet exist) the code was
// already burned, turning a recoverable transient write failure into a
// permanent "authorization code already used" for that login. Wrapping both
// writes in one transaction makes any downstream failure roll the mark-used
// back so the client can simply retry the same code.
type OAuthClientTx interface {
	// MarkAuthorizationCodeUsedCAS marks the code used via a compare-and-swap
	// and reports whether THIS caller won the swap (single-use under
	// concurrency; see the method for the row-locking argument).
	MarkAuthorizationCodeUsedCAS(ctx context.Context, id uuid.UUID) (bool, error)
	// CreateOAuthToken persists the issued token row inside the transaction.
	CreateOAuthToken(ctx context.Context, token *models.OAuthToken) error
	// Commit finalises both writes; call it only after token generation has
	// fully succeeded.
	Commit(ctx context.Context) error
	// Rollback discards both writes (the code stays unused, the client can
	// retry). A Rollback after a successful Commit is a no-op.
	Rollback(ctx context.Context) error
}

// oauthClientTx binds an OAuthClientRepository to a live pgx.Tx so every
// embedded repository method runs on the transaction instead of the pool.
type oauthClientTx struct {
	*OAuthClientRepository
	tx pgx.Tx
}

func (t *oauthClientTx) Commit(ctx context.Context) error   { return t.tx.Commit(ctx) }
func (t *oauthClientTx) Rollback(ctx context.Context) error { return t.tx.Rollback(ctx) }

// BeginTx opens a transaction on the repository's pool and returns a
// transaction-scoped handle. Callers thread the handle through the writes that
// must be atomic, then Commit on success or Rollback on any failure. Because a
// Rollback after Commit is a no-op, callers may always defer the Rollback.
func (r *OAuthClientRepository) BeginTx(ctx context.Context) (OAuthClientTx, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin oauth client transaction: %w", err)
	}
	txRepo := *r
	txRepo.pool = tx
	return &oauthClientTx{OAuthClientRepository: &txRepo, tx: tx}, nil
}

// ==================== OAuth Client Operations ====================

// GetByID retrieves an OAuth client by its UUID
func (r *OAuthClientRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.OAuthClient, error) {
	query := `SELECT` + oauthClientColumns + `FROM iam_oauth_clients WHERE id = $1`
	client := &models.OAuthClient{}
	if err := scanOAuthClient(r.pool.QueryRow(ctx, query, id), client); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrOAuthClientNotFound
		}
		return nil, fmt.Errorf("failed to get OAuth client: %w", err)
	}
	return client, nil
}

// GetByClientID retrieves an OAuth client by its client_id string
func (r *OAuthClientRepository) GetByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error) {
	query := `SELECT` + oauthClientColumns + `FROM iam_oauth_clients WHERE client_id = $1`
	client := &models.OAuthClient{}
	err := scanOAuthClient(r.pool.QueryRow(ctx, query, clientID), client)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrOAuthClientNotFound
		}
		return nil, fmt.Errorf("failed to get OAuth client: %w", err)
	}

	return client, nil
}

// GetByTenantID retrieves all OAuth clients for a tenant
func (r *OAuthClientRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.OAuthClient, int64, error) {
	offset := (page - 1) * pageSize

	// Count total
	countQuery := `SELECT COUNT(*) FROM iam_oauth_clients WHERE tenant_id = $1`
	var total int64
	err := r.pool.QueryRow(ctx, countQuery, tenantID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count OAuth clients: %w", err)
	}

	// Get clients
	query := `SELECT` + oauthClientColumns + `FROM iam_oauth_clients WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	rows, err := r.pool.Query(ctx, query, tenantID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list OAuth clients: %w", err)
	}
	defer rows.Close()

	var clients []*models.OAuthClient
	for rows.Next() {
		client := &models.OAuthClient{}
		if err := scanOAuthClient(rows, client); err != nil {
			return nil, 0, fmt.Errorf("failed to scan OAuth client: %w", err)
		}
		clients = append(clients, client)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("GetByTenantID: rows iteration: %w", err)
	}

	return clients, total, nil
}

// Create creates a new OAuth client
func (r *OAuthClientRepository) Create(ctx context.Context, client *models.OAuthClient) error {
	// Default the rotation policy when the caller didn't set it (every
	// existing call site predates the field; this preserves their
	// behaviour without a churn of handler-layer edits).
	if client.RefreshTokenRotationPolicy == "" {
		client.RefreshTokenRotationPolicy = "rotate"
	}
	query := `
		INSERT INTO iam_oauth_clients (
			id, tenant_id, client_id, client_secret_hash, client_name, client_description,
			grant_types, response_types, redirect_uris, scopes,
			access_token_lifetime, refresh_token_lifetime, id_token_lifetime,
			is_public, is_confidential, is_first_party, require_pkce, is_active,
			logo_url, tos_url, policy_url, contact_email,
			contacts, token_endpoint_auth_method, id_token_signed_response_alg,
			post_logout_redirect_uris, allowed_cors_origins,
			backchannel_logout_uri, backchannel_logout_session_required,
			frontchannel_logout_uri, frontchannel_logout_session_required,
			require_pushed_authorization_requests,
			client_uri,
			allow_external_jwt_exchange,
			refresh_token_rotation_policy,
			created_at, updated_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13,
			$14, $15, $16, $17, $18,
			$19, $20, $21, $22,
			$23, $24, $25,
			$26, $27,
			$28, $29,
			$30, $31,
			$32,
			$33,
			$34,
			$35,
			$36, $37, $38
		)`

	_, err := r.pool.Exec(ctx, query,
		client.ID, client.TenantID, client.ClientID, client.ClientSecret,
		client.Name, client.Description,
		client.GrantTypes, client.ResponseTypes,
		client.RedirectURIs, client.Scopes,
		client.AccessTokenLifetime, client.RefreshTokenLifetime, client.IDTokenLifetime,
		client.IsPublic, client.IsConfidential, client.IsFirstParty,
		client.RequirePKCE, client.IsActive,
		client.LogoURL, client.TosURL, client.PolicyURL, client.ContactEmail,
		client.Contacts, client.TokenEndpointAuthMethod,
		client.IDTokenSignedResponseAlg,
		client.PostLogoutRedirectURIs,
		client.AllowedCORSOrigins,
		client.BackchannelLogoutURI, client.BackchannelLogoutSessionRequired,
		client.FrontchannelLogoutURI, client.FrontchannelLogoutSessionRequired,
		client.RequirePushedAuthorizationRequests,
		client.ClientURI,
		client.AllowExternalJWTExchange,
		client.RefreshTokenRotationPolicy,
		client.CreatedAt, client.UpdatedAt, client.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create OAuth client: %w", err)
	}

	return nil
}

// Update updates an OAuth client.
//
// IMPORTANT: this is a write-all-columns UPDATE — every field on the
// inbound struct is written unconditionally. Callers MUST load the
// full row via GetByID first; passing a partial struct will wipe
// other columns. See user_repository.go:Update for the durable
// repository-layer guard and history of this class of bug.
func (r *OAuthClientRepository) Update(ctx context.Context, client *models.OAuthClient) error {
	// Default the rotation policy when the caller didn't set it. Same
	// rationale as Create — old admin/internal handler paths predate
	// the field and would otherwise persist an empty string that the
	// CHECK constraint rejects.
	if client.RefreshTokenRotationPolicy == "" {
		client.RefreshTokenRotationPolicy = "rotate"
	}
	query := `
		UPDATE iam_oauth_clients SET
			client_name = $1, client_description = $2,
			grant_types = $3, response_types = $4, redirect_uris = $5, scopes = $6,
			access_token_lifetime = $7, refresh_token_lifetime = $8, id_token_lifetime = $9,
			is_public = $10, is_confidential = $11, is_first_party = $12,
			require_pkce = $13, is_active = $14,
			logo_url = $15, tos_url = $16, policy_url = $17, contact_email = $18,
			contacts = $19, token_endpoint_auth_method = $20, id_token_signed_response_alg = $21,
			post_logout_redirect_uris = $22, allowed_cors_origins = $23,
			backchannel_logout_uri = $24, backchannel_logout_session_required = $25,
			frontchannel_logout_uri = $26, frontchannel_logout_session_required = $27,
			require_pushed_authorization_requests = $28,
			client_uri = $29,
			allow_external_jwt_exchange = $30,
			refresh_token_rotation_policy = $31,
			updated_at = $32, updated_by = $33
		WHERE id = $34`

	result, err := r.pool.Exec(ctx, query,
		client.Name, client.Description,
		client.GrantTypes, client.ResponseTypes,
		client.RedirectURIs, client.Scopes,
		client.AccessTokenLifetime, client.RefreshTokenLifetime, client.IDTokenLifetime,
		client.IsPublic, client.IsConfidential, client.IsFirstParty,
		client.RequirePKCE, client.IsActive,
		client.LogoURL, client.TosURL, client.PolicyURL, client.ContactEmail,
		client.Contacts, client.TokenEndpointAuthMethod,
		client.IDTokenSignedResponseAlg,
		client.PostLogoutRedirectURIs,
		client.AllowedCORSOrigins,
		client.BackchannelLogoutURI, client.BackchannelLogoutSessionRequired,
		client.FrontchannelLogoutURI, client.FrontchannelLogoutSessionRequired,
		client.RequirePushedAuthorizationRequests,
		client.ClientURI,
		client.AllowExternalJWTExchange,
		client.RefreshTokenRotationPolicy,
		client.UpdatedAt, client.UpdatedBy,
		client.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update OAuth client: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgOAuthClientNotFound)
	}

	return nil
}

// Delete deletes an OAuth client
func (r *OAuthClientRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM iam_oauth_clients WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete OAuth client: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgOAuthClientNotFound)
	}

	return nil
}

// GetClientsWithFrontchannelLogout returns all active OAuth clients that have a
// frontchannel_logout_uri configured. An optional tenantID filters to a single
// tenant; pass uuid.Nil to query across all tenants.
//
// The OIDC RP-initiated logout page renders one <iframe> per row this returns
// (Front-Channel Logout 1.0 §3). RPs that opt out of FCL leave the column
// NULL and are skipped here.
func (r *OAuthClientRepository) GetClientsWithFrontchannelLogout(ctx context.Context, tenantID uuid.UUID) ([]models.OAuthClient, error) {
	baseQuery := `SELECT` + oauthClientColumns + `FROM iam_oauth_clients WHERE frontchannel_logout_uri IS NOT NULL AND is_active = true`

	var (
		rows pgx.Rows
		err  error
	)
	if tenantID == uuid.Nil {
		rows, err = r.pool.Query(ctx, baseQuery)
	} else {
		rows, err = r.pool.Query(ctx, baseQuery+" AND tenant_id = $1", tenantID)
	}
	if err != nil {
		return nil, fmt.Errorf("GetClientsWithFrontchannelLogout: query: %w", err)
	}
	defer rows.Close()

	var clients []models.OAuthClient
	for rows.Next() {
		var client models.OAuthClient
		if err := scanOAuthClient(rows, &client); err != nil {
			return nil, fmt.Errorf("GetClientsWithFrontchannelLogout: scan: %w", err)
		}
		clients = append(clients, client)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetClientsWithFrontchannelLogout: rows iteration: %w", err)
	}

	return clients, nil
}

// GetClientsWithBackchannelLogout returns all active OAuth clients that have a
// backchannel_logout_uri configured. An optional tenantID filters to a single
// tenant; pass uuid.Nil to query across all tenants (e.g. platform-wide logout).
func (r *OAuthClientRepository) GetClientsWithBackchannelLogout(ctx context.Context, tenantID uuid.UUID) ([]models.OAuthClient, error) {
	baseQuery := `SELECT` + oauthClientColumns + `FROM iam_oauth_clients WHERE backchannel_logout_uri IS NOT NULL AND is_active = true`

	var (
		rows pgx.Rows
		err  error
	)
	if tenantID == uuid.Nil {
		rows, err = r.pool.Query(ctx, baseQuery)
	} else {
		rows, err = r.pool.Query(ctx, baseQuery+" AND tenant_id = $1", tenantID)
	}
	if err != nil {
		return nil, fmt.Errorf("GetClientsWithBackchannelLogout: query: %w", err)
	}
	defer rows.Close()

	var clients []models.OAuthClient
	for rows.Next() {
		var client models.OAuthClient
		if err := scanOAuthClient(rows, &client); err != nil {
			return nil, fmt.Errorf("GetClientsWithBackchannelLogout: scan: %w", err)
		}
		clients = append(clients, client)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetClientsWithBackchannelLogout: rows iteration: %w", err)
	}

	return clients, nil
}

// UpdateSecret updates the client secret
func (r *OAuthClientRepository) UpdateSecret(ctx context.Context, id uuid.UUID, secretHash string) error {
	query := `UPDATE iam_oauth_clients SET client_secret_hash = $1, updated_at = $2 WHERE id = $3`
	result, err := r.pool.Exec(ctx, query, secretHash, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update client secret: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgOAuthClientNotFound)
	}

	return nil
}

// ==================== Authorization Code Operations ====================

// CreateAuthorizationCode creates a new authorization code
func (r *OAuthClientRepository) CreateAuthorizationCode(ctx context.Context, code *models.OAuthAuthorizationCode) error {
	query := `
		INSERT INTO iam_oauth_authorization_codes (
			id, tenant_id, client_id, user_id, code, redirect_uri, scopes,
			state, nonce, code_challenge, code_challenge_method,
			is_used, expires_at, created_at,
			auth_methods_used, idp_session_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

	if code.AuthMethodsUsed == nil {
		code.AuthMethodsUsed = []string{}
	}

	_, err := r.pool.Exec(ctx, query,
		code.ID, code.TenantID, code.ClientID, code.UserID,
		code.Code, code.RedirectURI, code.Scopes,
		code.State, code.Nonce, code.CodeChallenge, code.CodeChallengeMethod,
		code.IsUsed, code.ExpiresAt, code.CreatedAt,
		code.AuthMethodsUsed, code.IdpSessionID,
	)
	if err != nil {
		return fmt.Errorf("failed to create authorization code: %w", err)
	}

	return nil
}

// GetAuthorizationCode retrieves an authorization code
func (r *OAuthClientRepository) GetAuthorizationCode(ctx context.Context, code string) (*models.OAuthAuthorizationCode, error) {
	query := `
		SELECT id, tenant_id, client_id, user_id, code, redirect_uri, scopes,
		       state, nonce, code_challenge, code_challenge_method,
		       is_used, used_at, expires_at, created_at,
		       auth_methods_used, idp_session_id
		FROM iam_oauth_authorization_codes
		WHERE code = $1`

	authCode := &models.OAuthAuthorizationCode{}
	err := r.pool.QueryRow(ctx, query, code).Scan(
		&authCode.ID, &authCode.TenantID, &authCode.ClientID, &authCode.UserID,
		&authCode.Code, &authCode.RedirectURI, &authCode.Scopes,
		&authCode.State, &authCode.Nonce, &authCode.CodeChallenge, &authCode.CodeChallengeMethod,
		&authCode.IsUsed, &authCode.UsedAt, &authCode.ExpiresAt, &authCode.CreatedAt,
		&authCode.AuthMethodsUsed, &authCode.IdpSessionID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("authorization code not found")
		}
		return nil, fmt.Errorf("failed to get authorization code: %w", err)
	}

	return authCode, nil
}

// MarkAuthorizationCodeUsed marks an authorization code as used
func (r *OAuthClientRepository) MarkAuthorizationCodeUsed(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	query := `UPDATE iam_oauth_authorization_codes SET is_used = true, used_at = $1 WHERE id = $2`
	_, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("failed to mark authorization code as used: %w", err)
	}
	return nil
}

// MarkAuthorizationCodeUsedCAS atomically marks an authorization code used via a
// compare-and-swap (UPDATE ... WHERE id = $2 AND is_used = false) and reports
// whether THIS caller won the swap. Under Postgres row-level locking exactly one
// concurrent redemption of the same live code matches the predicate and flips
// it (RowsAffected == 1); every other redemption blocks until the winner's
// transaction resolves and then sees RowsAffected == 0.
//
// This is the single-use guard for the transactional token exchange. Because
// the flip lives INSIDE the exchange transaction, a rollback (on a downstream
// token-generation failure) restores is_used = false so the code can be
// redeemed again, while a committed win permanently consumes it — and a
// concurrent exchange that raced the winner sees the committed flip and is told
// it lost. Contrast MarkAuthorizationCodeUsed, whose independent UPDATE always
// reports success and cannot be rolled back into a retryable state.
func (r *OAuthClientRepository) MarkAuthorizationCodeUsedCAS(ctx context.Context, id uuid.UUID) (bool, error) {
	now := time.Now()
	query := `UPDATE iam_oauth_authorization_codes SET is_used = true, used_at = $1 WHERE id = $2 AND is_used = false`
	tag, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return false, fmt.Errorf("failed to mark authorization code as used: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ==================== OAuth Token Operations ====================

// CreateOAuthToken creates a new OAuth token
func (r *OAuthClientRepository) CreateOAuthToken(ctx context.Context, token *models.OAuthToken) error {
	query := `
		INSERT INTO iam_oauth_tokens (
			id, tenant_id, client_id, user_id, token_type, token, scopes,
			refresh_token, ip_address, user_agent, is_revoked, expires_at,
			created_at, updated_at,
			auth_methods_used, idp_session_id, token_family_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`

	if token.AuthMethodsUsed == nil {
		token.AuthMethodsUsed = []string{}
	}

	// RFC 9700 §4.14 — a token must never be family-less. If the caller did
	// not stamp a lineage (root issuance), the token roots its own family.
	if token.TokenFamilyID == nil {
		id := token.ID
		token.TokenFamilyID = &id
	}

	_, err := r.pool.Exec(ctx, query,
		token.ID, token.TenantID, token.ClientID, token.UserID,
		token.TokenType, token.Token, token.Scopes,
		token.RefreshToken, token.IPAddress, token.UserAgent,
		token.IsRevoked, token.ExpiresAt, token.CreatedAt, token.UpdatedAt,
		token.AuthMethodsUsed, token.IdpSessionID, token.TokenFamilyID,
	)
	if err != nil {
		return fmt.Errorf("failed to create OAuth token: %w", err)
	}

	return nil
}

// GetOAuthTokenByHash retrieves an OAuth token by its hash
func (r *OAuthClientRepository) GetOAuthTokenByHash(ctx context.Context, tokenHash string) (*models.OAuthToken, error) {
	query := `
		SELECT id, tenant_id, client_id, user_id, token_type, token, scopes,
		       refresh_token, ip_address, user_agent, is_revoked, revoked_at,
		       expires_at, created_at, updated_at,
		       auth_methods_used, idp_session_id, token_family_id
		FROM iam_oauth_tokens
		WHERE token = $1 OR refresh_token = $1`

	token := &models.OAuthToken{}
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID, &token.TenantID, &token.ClientID, &token.UserID,
		&token.TokenType, &token.Token, &token.Scopes,
		&token.RefreshToken, &token.IPAddress, &token.UserAgent,
		&token.IsRevoked, &token.RevokedAt, &token.ExpiresAt,
		&token.CreatedAt, &token.UpdatedAt,
		&token.AuthMethodsUsed, &token.IdpSessionID, &token.TokenFamilyID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("token not found")
		}
		return nil, fmt.Errorf("failed to get OAuth token: %w", err)
	}

	return token, nil
}

// RevokeOAuthToken revokes an OAuth token
func (r *OAuthClientRepository) RevokeOAuthToken(ctx context.Context, tokenHash string) error {
	now := time.Now()
	query := `UPDATE iam_oauth_tokens SET is_revoked = true, revoked_at = $1 WHERE token = $2 OR refresh_token = $2`
	_, err := r.pool.Exec(ctx, query, now, tokenHash)
	if err != nil {
		return fmt.Errorf("failed to revoke OAuth token: %w", err)
	}
	return nil
}

// ConsumeRefreshToken atomically consumes (revokes) a refresh token by id
// using a compare-and-swap: it flips is_revoked true → but ONLY for a row that
// is currently un-revoked. It reports whether THIS caller won the swap.
//
// RFC 9700 §4.14.2 atomicity requirement: the revoked-check and the revocation
// MUST be a single atomic operation, otherwise two concurrent redemptions of
// the same live refresh token can both read is_revoked=false, both proceed,
// and FORK the token family (the better-auth GHSA-392p-2q2v-4372 class of bug).
// A single `UPDATE ... WHERE id=$1 AND is_revoked = false` is atomic under
// Postgres row-level locking — exactly one concurrent statement matches the
// row and flips it; every other sees 0 rows affected. The winner (rowcount 1)
// proceeds to mint the rotated pair; every loser (rowcount 0) fails closed and
// the caller returns invalid_grant WITHOUT revoking the family (a lost race is
// not theft — the token was live, it merely arrived second).
func (r *OAuthClientRepository) ConsumeRefreshToken(ctx context.Context, tokenID uuid.UUID) (bool, error) {
	now := time.Now()
	query := `UPDATE iam_oauth_tokens
	          SET is_revoked = true, revoked_at = $1, updated_at = $1
	          WHERE id = $2 AND is_revoked = false`
	tag, err := r.pool.Exec(ctx, query, now, tokenID)
	if err != nil {
		return false, fmt.Errorf("failed to consume refresh token: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RevokeRefreshTokenFamily revokes every still-live token sharing the given
// RFC 9700 §4.14 family (lineage) id and returns how many rows it revoked.
// Called on detected refresh-token reuse: a replayed rotated token means the
// whole grant is compromised, so the entire lineage — every access/refresh
// row descended from the original authorization grant — is killed in one
// atomic statement. Already-revoked rows are skipped (is_revoked = false
// guard) so the count reflects only the tokens this call actually terminated.
func (r *OAuthClientRepository) RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) (int64, error) {
	now := time.Now()
	query := `UPDATE iam_oauth_tokens
	          SET is_revoked = true, revoked_at = $1, updated_at = $1
	          WHERE token_family_id = $2 AND is_revoked = false`
	tag, err := r.pool.Exec(ctx, query, now, familyID)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke refresh token family: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RevokeAllClientTokens revokes all tokens for a client
func (r *OAuthClientRepository) RevokeAllClientTokens(ctx context.Context, clientID uuid.UUID) error {
	now := time.Now()
	query := `UPDATE iam_oauth_tokens SET is_revoked = true, revoked_at = $1 WHERE client_id = $2`
	_, err := r.pool.Exec(ctx, query, now, clientID)
	if err != nil {
		return fmt.Errorf("failed to revoke client tokens: %w", err)
	}
	return nil
}

// RevokeUserClientTokens revokes all tokens for a specific user and client combination.
func (r *OAuthClientRepository) RevokeUserClientTokens(ctx context.Context, userID, clientID uuid.UUID) error {
	now := time.Now()
	query := `UPDATE iam_oauth_tokens SET is_revoked = true, revoked_at = $1 WHERE user_id = $2 AND client_id = $3`
	_, err := r.pool.Exec(ctx, query, now, userID, clientID)
	if err != nil {
		return fmt.Errorf("failed to revoke user client tokens: %w", err)
	}
	return nil
}

// RevokeAllUserOAuthTokens revokes every OAuth token (across every client)
// belonging to a user. Used by password-change, user-deletion, and admin-
// driven session-kill flows that previously relied on
// tokenRepo.RevokeAllUserRefreshTokens against the now-dropped
// iam_refresh_tokens table (Phase 3 — migration 233).
//
// The OAuth token store carries both access and refresh tokens for every
// OIDC RP a user has signed in to (svc-talon, svc-accounts, gitlab,
// harbor, argocd, etc.) — so a single sweep here is the equivalent of the
// pre-Phase-3 dual revoke against iam_refresh_tokens (auth-service path,
// now removed) AND the per-RP revoke that already shipped via
// tokenBlacklist + BCL fan-out.
//
// is_revoked=true causes IntrospectToken to return active=false on next
// call (RFC 7662 §2.2 conformance per memory
// internal engineering notes), and ConsumeRefreshToken on
// the OAuth side classifies the token as ConsumeRefreshTokenReuseDetected
// → triggers the full family revoke + OIDC Back-Channel Logout fan-out
// to every relying party.
func (r *OAuthClientRepository) RevokeAllUserOAuthTokens(ctx context.Context, userID uuid.UUID, reason string) error {
	now := time.Now()
	// reason is captured in audit / CAEP emission paths; the column itself
	// is is_revoked + revoked_at (no reason column on iam_oauth_tokens).
	_ = reason
	query := `UPDATE iam_oauth_tokens SET is_revoked = true, revoked_at = $1 WHERE user_id = $2 AND is_revoked = false`
	_, err := r.pool.Exec(ctx, query, now, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke all user OAuth tokens: %w", err)
	}
	return nil
}

// ==================== User Consent Operations ====================

// GetConsent retrieves a user's consent for a client
func (r *OAuthClientRepository) GetConsent(ctx context.Context, userID, clientID uuid.UUID) (*models.OAuthConsent, error) {
	query := `
		SELECT id, user_id, client_id, scopes, granted_at, expires_at, revoked_at
		FROM iam_oauth_consents
		WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL`

	consent := &models.OAuthConsent{}
	err := r.pool.QueryRow(ctx, query, userID, clientID).Scan(
		&consent.ID, &consent.UserID, &consent.ClientID, &consent.Scopes,
		&consent.GrantedAt, &consent.ExpiresAt, &consent.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // No consent found
		}
		return nil, fmt.Errorf("failed to get consent: %w", err)
	}

	return consent, nil
}

// CreateOrUpdateConsent creates or updates a user's consent
func (r *OAuthClientRepository) CreateOrUpdateConsent(ctx context.Context, consent *models.OAuthConsent) error {
	query := `
		INSERT INTO iam_oauth_consents (id, user_id, client_id, scopes, granted_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, client_id) DO UPDATE SET
			scopes = $4,
			granted_at = $5,
			expires_at = $6,
			revoked_at = NULL`

	_, err := r.pool.Exec(ctx, query,
		consent.ID, consent.UserID, consent.ClientID,
		consent.Scopes, consent.GrantedAt, consent.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create/update consent: %w", err)
	}

	return nil
}

// RevokeConsent revokes a user's consent for a client
func (r *OAuthClientRepository) RevokeConsent(ctx context.Context, userID, clientID uuid.UUID) error {
	now := time.Now()
	query := `UPDATE iam_oauth_consents SET revoked_at = $1 WHERE user_id = $2 AND client_id = $3`
	_, err := r.pool.Exec(ctx, query, now, userID, clientID)
	if err != nil {
		return fmt.Errorf("failed to revoke consent: %w", err)
	}
	return nil
}

// GetUserConsentsEnriched returns the user's active consents with the
// OAuth client's display fields (name, logo, category) and the
// most-recent token-usage timestamp pre-joined. Replaces the prior
// `GetUserConsents` for the user-facing "Connected Apps" page —
// previously the BFF had to either return the raw consent UUIDs (no
// names / logos) or maintain a hard-coded display table. Source of
// truth lives in iam_oauth_clients; one query, no N+1.
//
// last_used_at uses the GREATEST of iam_oauth_tokens.updated_at over
// the non-revoked tokens for this (user, client). NULL when the
// consent exists but no token has ever been issued (rare — usually
// implies a half-finished authorization code grant) OR when every
// token has been revoked. Frontend renders the column as "—" in
// that case.
//
// Filtered to c.revoked_at IS NULL (the page only lists ACTIVE
// consents — revoked rows are surfaced via the security audit log,
// not here).
func (r *OAuthClientRepository) GetUserConsentsEnriched(ctx context.Context, userID uuid.UUID) ([]*models.OAuthConsentEnriched, error) {
	query := `
		SELECT
		    c.id,
		    c.client_id,
		    cl.client_id,
		    cl.client_name,
		    cl.logo_url,
		    COALESCE(cl.is_first_party, false),
		    c.scopes,
		    c.granted_at,
		    c.expires_at,
		    (
		        SELECT MAX(t.updated_at)
		        FROM iam_oauth_tokens t
		        WHERE t.user_id = c.user_id
		          AND t.client_id = c.client_id
		          AND t.is_revoked = false
		    ) AS last_used_at
		FROM iam_oauth_consents c
		JOIN iam_oauth_clients cl ON cl.id = c.client_id
		WHERE c.user_id = $1 AND c.revoked_at IS NULL
		ORDER BY c.granted_at DESC`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("GetUserConsentsEnriched: %w", err)
	}
	defer rows.Close()

	out := make([]*models.OAuthConsentEnriched, 0)
	for rows.Next() {
		consent := &models.OAuthConsentEnriched{}
		var isFirstParty bool
		if err := rows.Scan(
			&consent.ID,
			&consent.ClientUUID,
			&consent.ClientID,
			&consent.Name,
			&consent.IconURL,
			&isFirstParty,
			&consent.Scopes,
			&consent.GrantedAt,
			&consent.ExpiresAt,
			&consent.LastUsedAt,
		); err != nil {
			return nil, fmt.Errorf("GetUserConsentsEnriched: scan: %w", err)
		}
		if isFirstParty {
			consent.Category = "official"
		} else {
			consent.Category = "third_party"
		}
		out = append(out, consent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserConsentsEnriched: rows: %w", err)
	}
	return out, nil
}

// GetUserConsents retrieves all consents for a user
func (r *OAuthClientRepository) GetUserConsents(ctx context.Context, userID uuid.UUID) ([]*models.OAuthConsent, error) {
	query := `
		SELECT c.id, c.user_id, c.client_id, c.scopes, c.granted_at, c.expires_at, c.revoked_at
		FROM iam_oauth_consents c
		WHERE c.user_id = $1 AND c.revoked_at IS NULL
		ORDER BY c.granted_at DESC`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list consents: %w", err)
	}
	defer rows.Close()

	var consents []*models.OAuthConsent
	for rows.Next() {
		consent := &models.OAuthConsent{}
		err := rows.Scan(
			&consent.ID, &consent.UserID, &consent.ClientID, &consent.Scopes,
			&consent.GrantedAt, &consent.ExpiresAt, &consent.RevokedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan consent: %w", err)
		}

		consents = append(consents, consent)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserConsents: rows iteration: %w", err)
	}

	return consents, nil
}

// ==================== OAuth State Operations ====================

// CreateOAuthState creates a new OAuth state for CSRF protection
func (r *OAuthClientRepository) CreateOAuthState(ctx context.Context, state *models.OAuthState) error {
	query := `
		INSERT INTO iam_oauth_states (
			id, tenant_id, client_id, user_id, state, redirect_uri, nonce,
			code_challenge, code_challenge_method, is_used, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err := r.pool.Exec(ctx, query,
		state.ID, state.TenantID, state.ClientID, state.UserID,
		state.State, state.RedirectURI, state.Nonce,
		state.CodeChallenge, state.CodeChallengeMethod,
		state.IsUsed, state.ExpiresAt, state.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create OAuth state: %w", err)
	}

	return nil
}

// GetOAuthState retrieves an OAuth state
func (r *OAuthClientRepository) GetOAuthState(ctx context.Context, state string) (*models.OAuthState, error) {
	query := `
		SELECT id, tenant_id, client_id, user_id, state, redirect_uri, nonce,
		       code_challenge, code_challenge_method, is_used, used_at, expires_at, created_at
		FROM iam_oauth_states
		WHERE state = $1`

	oauthState := &models.OAuthState{}
	err := r.pool.QueryRow(ctx, query, state).Scan(
		&oauthState.ID, &oauthState.TenantID, &oauthState.ClientID, &oauthState.UserID,
		&oauthState.State, &oauthState.RedirectURI, &oauthState.Nonce,
		&oauthState.CodeChallenge, &oauthState.CodeChallengeMethod,
		&oauthState.IsUsed, &oauthState.UsedAt, &oauthState.ExpiresAt, &oauthState.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("state not found")
		}
		return nil, fmt.Errorf("failed to get OAuth state: %w", err)
	}

	return oauthState, nil
}

// MarkOAuthStateUsed marks an OAuth state as used
func (r *OAuthClientRepository) MarkOAuthStateUsed(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	query := `UPDATE iam_oauth_states SET is_used = true, used_at = $1 WHERE id = $2`
	_, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("failed to mark OAuth state as used: %w", err)
	}
	return nil
}

// UpsertServiceClientResult is returned by UpsertServiceClient.
type UpsertServiceClientResult struct {
	// ID is the UUID primary key of the iam_oauth_clients row.
	ID uuid.UUID
	// Created is true when the row was inserted, false when it already existed
	// and was updated.
	Created bool
}

// UpsertServiceClient inserts or updates a service OAuth client record.
// On first insert the secretHash is stored; on subsequent calls the row is
// updated (scopes / name) but the secret is left unchanged so existing tokens
// remain valid.
func (r *OAuthClientRepository) UpsertServiceClient(
	ctx context.Context,
	clientID string,
	clientName string,
	_ string,
	scopes []string,
	secretHash string,
) (UpsertServiceClientResult, error) {
	var result UpsertServiceClientResult

	query := `
		INSERT INTO iam_oauth_clients (
			id, client_id, client_name, client_secret_hash, scopes,
			grant_types, response_types, is_active, is_public, is_confidential,
			is_first_party, require_pkce, access_token_lifetime, refresh_token_lifetime,
			id_token_lifetime, created_at, updated_at
		) VALUES (
			gen_random_uuid(), $1, $2, $3, $4,
			ARRAY['client_credentials'], ARRAY[]::text[], true, false, true,
			true, false, 300, 0,
			300, now(), now()
		)
		ON CONFLICT (client_id) DO UPDATE
			SET client_name  = EXCLUDED.client_name,
			    scopes        = EXCLUDED.scopes,
			    updated_at    = now()
		RETURNING id, (xmax = 0) AS inserted`
	// response_types is intentionally empty (was 'token' through 2026-04-29):
	// client_credentials grant never reaches /oauth/authorize, so
	// response_types is structurally irrelevant. The previous 'token'
	// value was vestigial implicit-flow cruft cleaned up by migration 222
	// (IAM-04). Emitting it here would silently re-create the OAuth-2.1
	// non-conformant rows on the next ServiceClient provisioning event.
	// validateOAuth21GrantsAndResponses in oauth_provider_service.go
	// rejects 'token' at the public CreateClient/UpdateClient API; this
	// upsert path is internal but we keep the contract consistent.

	row := r.pool.QueryRow(ctx, query, clientID, clientName, secretHash, scopes)
	var inserted bool
	if err := row.Scan(&result.ID, &inserted); err != nil {
		return result, fmt.Errorf("UpsertServiceClient: %w", err)
	}
	result.Created = inserted
	return result, nil
}

// CleanupExpiredStates removes expired OAuth states
func (r *OAuthClientRepository) CleanupExpiredStates(ctx context.Context) error {
	query := `DELETE FROM iam_oauth_states WHERE expires_at < $1`
	_, err := r.pool.Exec(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired states: %w", err)
	}
	return nil
}

// CleanupExpiredCodes removes expired authorization codes
func (r *OAuthClientRepository) CleanupExpiredCodes(ctx context.Context) error {
	query := `DELETE FROM iam_oauth_authorization_codes WHERE expires_at < $1`
	_, err := r.pool.Exec(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired codes: %w", err)
	}
	return nil
}

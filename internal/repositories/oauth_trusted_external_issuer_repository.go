// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// OAuthTrustedExternalIssuerRepository persists the per-tenant
// registry of external JWT issuers Falcon-ID accepts as
// subject_tokens during RFC 8693 token exchange (subject_token_type
// = `urn:ietf:params:oauth:token-type:jwt`). Backs the storage
// introduced by Migration 237.
//
// Mirrors WorkloadIdentityRepository's shape on purpose — that
// repo's pattern is the canonical "external IdP federation" shape
// in this codebase. Distinct concerns (workload vs human
// delegation) but identical persistence ergonomics.
type OAuthTrustedExternalIssuerRepository struct {
	pool DBPool
}

// NewOAuthTrustedExternalIssuerRepository constructs the repository.
func NewOAuthTrustedExternalIssuerRepository(pool DBPool) *OAuthTrustedExternalIssuerRepository {
	return &OAuthTrustedExternalIssuerRepository{pool: pool}
}

// ----------------------------------------------------------------
// CRUD for iam_oauth_trusted_external_issuers
// ----------------------------------------------------------------

// Create inserts a new issuer row. Caller is responsible for
// validation of issuer_url / jwks_url (absolute https URIs); the
// DB-layer CHECK constraint only bounds max_token_age_seconds.
func (r *OAuthTrustedExternalIssuerRepository) Create(ctx context.Context, issuer *models.OAuthTrustedExternalIssuer) error {
	now := time.Now().UTC()
	issuer.ID = uuid.New()
	issuer.CreatedAt = now
	issuer.UpdatedAt = now

	const query = `
		INSERT INTO iam_oauth_trusted_external_issuers (
			id, tenant_id, name, issuer_url, jwks_url,
			audiences, max_token_age_seconds, is_active, description,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`

	_, err := r.pool.Exec(ctx, query,
		issuer.ID, issuer.TenantID, issuer.Name, issuer.IssuerURL, issuer.JWKSURL,
		issuer.Audiences, issuer.MaxTokenAgeSeconds, issuer.IsActive, issuer.Description,
		issuer.CreatedAt, issuer.UpdatedAt, issuer.CreatedBy, issuer.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("oauth_trusted_external_issuer_repository.Create: %w", err)
	}
	return nil
}

// GetByID returns an issuer by primary key, or nil if not found.
func (r *OAuthTrustedExternalIssuerRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.OAuthTrustedExternalIssuer, error) {
	const query = `
		SELECT
			id, tenant_id, name, issuer_url, jwks_url,
			audiences, max_token_age_seconds, is_active, description,
			created_at, updated_at, created_by, updated_by
		FROM iam_oauth_trusted_external_issuers
		WHERE id = $1`

	row := r.pool.QueryRow(ctx, query, id)
	issuer, err := scanOAuthTrustedExternalIssuer(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oauth_trusted_external_issuer_repository.GetByID: %w", err)
	}
	return issuer, nil
}

// GetByIssuer is the hot-path lookup the token-exchange service
// calls on every external-JWT exchange — resolves a JWT `iss`
// claim to its registered Falcon-ID trust config. Returns nil when
// no row exists for (tenant, issuer_url); the returned row's
// `IsActive` field tells the caller whether the issuer is currently
// trusted or was revoked.
//
// The query intentionally does NOT filter on `is_active`. Pre-2026-
// 05-21 the repo applied the filter directly, collapsing "issuer was
// never registered" with "issuer was registered but revoked" — the
// caller couldn't distinguish a typo'd `iss` claim from a known
// attacker replaying a previously-trusted issuer's tokens after the
// revocation cut, losing the `revoked_issuer_replay_attempt` audit
// signal entirely. See
// docs/audits/2026-05-21-repo-state-filter-audit.md.
func (r *OAuthTrustedExternalIssuerRepository) GetByIssuer(ctx context.Context, tenantID uuid.UUID, issuerURL string) (*models.OAuthTrustedExternalIssuer, error) {
	const query = `
		SELECT
			id, tenant_id, name, issuer_url, jwks_url,
			audiences, max_token_age_seconds, is_active, description,
			created_at, updated_at, created_by, updated_by
		FROM iam_oauth_trusted_external_issuers
		WHERE tenant_id = $1
		  AND issuer_url = $2
		LIMIT 1`

	row := r.pool.QueryRow(ctx, query, tenantID, issuerURL)
	issuer, err := scanOAuthTrustedExternalIssuer(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oauth_trusted_external_issuer_repository.GetByIssuer: %w", err)
	}
	return issuer, nil
}

// List enumerates issuers for a tenant with simple pagination.
func (r *OAuthTrustedExternalIssuerRepository) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.OAuthTrustedExternalIssuer, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	const countQuery = `SELECT COUNT(*) FROM iam_oauth_trusted_external_issuers WHERE tenant_id = $1`
	var total int64
	if err := r.pool.QueryRow(ctx, countQuery, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("oauth_trusted_external_issuer_repository.List count: %w", err)
	}

	const listQuery = `
		SELECT
			id, tenant_id, name, issuer_url, jwks_url,
			audiences, max_token_age_seconds, is_active, description,
			created_at, updated_at, created_by, updated_by
		FROM iam_oauth_trusted_external_issuers
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.pool.Query(ctx, listQuery, tenantID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("oauth_trusted_external_issuer_repository.List query: %w", err)
	}
	defer rows.Close()

	var issuers []*models.OAuthTrustedExternalIssuer
	for rows.Next() {
		issuer, scanErr := scanOAuthTrustedExternalIssuerFromRows(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf("oauth_trusted_external_issuer_repository.List scan: %w", scanErr)
		}
		issuers = append(issuers, issuer)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("oauth_trusted_external_issuer_repository.List rows: %w", err)
	}
	return issuers, total, nil
}

// Update replaces the mutable fields. issuer_url is intentionally
// also writable — operators may need to retarget a name (e.g.
// staging→prod hostname change) without churning the row UUID.
func (r *OAuthTrustedExternalIssuerRepository) Update(ctx context.Context, issuer *models.OAuthTrustedExternalIssuer) error {
	issuer.UpdatedAt = time.Now().UTC()

	const query = `
		UPDATE iam_oauth_trusted_external_issuers SET
			name                  = $2,
			issuer_url            = $3,
			jwks_url              = $4,
			audiences             = $5,
			max_token_age_seconds = $6,
			is_active             = $7,
			description           = $8,
			updated_at            = $9,
			updated_by            = $10
		WHERE id = $1`

	tag, err := r.pool.Exec(ctx, query,
		issuer.ID, issuer.Name, issuer.IssuerURL, issuer.JWKSURL,
		issuer.Audiences, issuer.MaxTokenAgeSeconds, issuer.IsActive, issuer.Description,
		issuer.UpdatedAt, issuer.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("oauth_trusted_external_issuer_repository.Update: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("oauth_trusted_external_issuer_repository.Update: issuer not found")
	}
	return nil
}

// Delete hard-deletes a row. ON DELETE CASCADE on the join table
// drops associated client grants automatically.
func (r *OAuthTrustedExternalIssuerRepository) Delete(ctx context.Context, id uuid.UUID) error {
	const query = `DELETE FROM iam_oauth_trusted_external_issuers WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("oauth_trusted_external_issuer_repository.Delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("oauth_trusted_external_issuer_repository.Delete: issuer not found")
	}
	return nil
}

// ----------------------------------------------------------------
// Per-client trust grants (iam_oauth_client_trusted_external_issuers)
// ----------------------------------------------------------------

// GetClientGrant resolves the (client × issuer) trust grant row.
// Returns nil + nil error when no row exists — caller treats absence
// as "not authorised to exchange JWTs from this issuer" (the
// deny-by-default model).
func (r *OAuthTrustedExternalIssuerRepository) GetClientGrant(ctx context.Context, clientID, issuerID uuid.UUID) (*models.OAuthClientTrustedExternalIssuer, error) {
	const query = `
		SELECT client_id, issuer_id, audiences, created_at, created_by
		FROM iam_oauth_client_trusted_external_issuers
		WHERE client_id = $1 AND issuer_id = $2`

	row := r.pool.QueryRow(ctx, query, clientID, issuerID)
	var grant models.OAuthClientTrustedExternalIssuer
	err := row.Scan(
		&grant.ClientID, &grant.IssuerID, &grant.Audiences,
		&grant.CreatedAt, &grant.CreatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oauth_trusted_external_issuer_repository.GetClientGrant: %w", err)
	}
	return &grant, nil
}

// GrantClient creates a (client × issuer) trust grant. Upsert on
// the composite primary key — if the grant already exists the row
// is left alone (idempotent).
func (r *OAuthTrustedExternalIssuerRepository) GrantClient(ctx context.Context, grant *models.OAuthClientTrustedExternalIssuer) error {
	if grant.CreatedAt.IsZero() {
		grant.CreatedAt = time.Now().UTC()
	}
	const query = `
		INSERT INTO iam_oauth_client_trusted_external_issuers (
			client_id, issuer_id, audiences, created_at, created_by
		) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (client_id, issuer_id) DO NOTHING`
	_, err := r.pool.Exec(ctx, query,
		grant.ClientID, grant.IssuerID, grant.Audiences,
		grant.CreatedAt, grant.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("oauth_trusted_external_issuer_repository.GrantClient: %w", err)
	}
	return nil
}

// ListClientGrants returns every (client × issuer) trust grant row
// for the supplied client. Used by reconcile-style provisioners (the
// Crossplane serviceclient-provisioner trust-grant reconcile loop)
// to compute the set of orphan grants — rows present in the DB but
// no longer declared on the ServiceClientClaim's
// `externalJWTExchange.trustedIssuers` — so they can be DELETE'd.
//
// Ordered by created_at ASC for deterministic iteration; callers
// typically just diff against a desired-set and don't rely on order.
func (r *OAuthTrustedExternalIssuerRepository) ListClientGrants(ctx context.Context, clientID uuid.UUID) ([]*models.OAuthClientTrustedExternalIssuer, error) {
	const query = `
		SELECT client_id, issuer_id, audiences, created_at, created_by
		FROM iam_oauth_client_trusted_external_issuers
		WHERE client_id = $1
		ORDER BY created_at ASC`

	rows, err := r.pool.Query(ctx, query, clientID)
	if err != nil {
		return nil, fmt.Errorf("oauth_trusted_external_issuer_repository.ListClientGrants: %w", err)
	}
	defer rows.Close()

	var grants []*models.OAuthClientTrustedExternalIssuer
	for rows.Next() {
		var g models.OAuthClientTrustedExternalIssuer
		if err := rows.Scan(
			&g.ClientID, &g.IssuerID, &g.Audiences,
			&g.CreatedAt, &g.CreatedBy,
		); err != nil {
			return nil, fmt.Errorf("oauth_trusted_external_issuer_repository.ListClientGrants: scan: %w", err)
		}
		grants = append(grants, &g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("oauth_trusted_external_issuer_repository.ListClientGrants: rows: %w", err)
	}
	return grants, nil
}

// RevokeClient removes a (client × issuer) trust grant. Idempotent
// — no error if the row doesn't exist (matches deny-by-default).
func (r *OAuthTrustedExternalIssuerRepository) RevokeClient(ctx context.Context, clientID, issuerID uuid.UUID) error {
	const query = `
		DELETE FROM iam_oauth_client_trusted_external_issuers
		WHERE client_id = $1 AND issuer_id = $2`
	if _, err := r.pool.Exec(ctx, query, clientID, issuerID); err != nil {
		return fmt.Errorf("oauth_trusted_external_issuer_repository.RevokeClient: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------
// Scan helpers
// ----------------------------------------------------------------

// rowScanner abstracts pgx.Row vs pgx.Rows for shared scan code.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanOAuthTrustedExternalIssuer(r rowScanner) (*models.OAuthTrustedExternalIssuer, error) {
	var issuer models.OAuthTrustedExternalIssuer
	if err := r.Scan(
		&issuer.ID, &issuer.TenantID, &issuer.Name, &issuer.IssuerURL, &issuer.JWKSURL,
		&issuer.Audiences, &issuer.MaxTokenAgeSeconds, &issuer.IsActive, &issuer.Description,
		&issuer.CreatedAt, &issuer.UpdatedAt, &issuer.CreatedBy, &issuer.UpdatedBy,
	); err != nil {
		return nil, err
	}
	return &issuer, nil
}

func scanOAuthTrustedExternalIssuerFromRows(rows pgx.Rows) (*models.OAuthTrustedExternalIssuer, error) {
	return scanOAuthTrustedExternalIssuer(rows)
}

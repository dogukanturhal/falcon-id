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

const msgGetLoginHistory = "GetLoginHistory: %w"

// sessionColumns is the canonical column list for iam_sessions queries.
// All methods that read sessions MUST use this constant to avoid column drift.
//
// asn / asn_org / city / region / is_vpn_hint added in platform migration
// v0.232.246; nullable for pre-migration rows.
const sessionColumns = `id, user_id, session_token_hash, device_info, ip_address, user_agent, location, country_code,
	asn, asn_org, city, region, is_vpn_hint,
	is_active, created_at, last_activity_at, expires_at, ended_at, end_reason,
	saml_provider_id, saml_name_id, saml_session_index,
	authenticated_at, previous_session_id, session_regenerated,
	auth_methods_used`

// scanSession scans a single row into a models.Session.
func scanSession(row pgx.Row) (*models.Session, error) {
	s := &models.Session{}
	err := row.Scan(
		&s.ID, &s.UserID, &s.SessionTokenHash,
		&s.DeviceInfo, &s.IPAddress, &s.UserAgent, &s.Location, &s.CountryCode,
		&s.ASN, &s.ASNOrg, &s.City, &s.Region, &s.IsVPNHint,
		&s.IsActive, &s.CreatedAt, &s.LastActivityAt, &s.ExpiresAt,
		&s.EndedAt, &s.EndReason,
		&s.SAMLProviderID, &s.SAMLNameID, &s.SAMLSessionIndex,
		&s.AuthenticatedAt, &s.PreviousSessionID, &s.SessionRegenerated,
		&s.AuthMethodsUsed,
	)
	return s, err
}

// scanSessionFromRows scans the current row from pgx.Rows into a models.Session.
func scanSessionFromRows(rows pgx.Rows) (models.Session, error) {
	var s models.Session
	err := rows.Scan(
		&s.ID, &s.UserID, &s.SessionTokenHash,
		&s.DeviceInfo, &s.IPAddress, &s.UserAgent, &s.Location, &s.CountryCode,
		&s.ASN, &s.ASNOrg, &s.City, &s.Region, &s.IsVPNHint,
		&s.IsActive, &s.CreatedAt, &s.LastActivityAt, &s.ExpiresAt,
		&s.EndedAt, &s.EndReason,
		&s.SAMLProviderID, &s.SAMLNameID, &s.SAMLSessionIndex,
		&s.AuthenticatedAt, &s.PreviousSessionID, &s.SessionRegenerated,
		&s.AuthMethodsUsed,
	)
	return s, err
}

// SessionRepository is an exported type.
type SessionRepository struct {
	db *pgxpool.Pool
}

// NewSessionRepository is an exported function.
func NewSessionRepository(db *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{db: db}
}

// Create is an exported function.
//
// Persists asn / asn_org / city / region / is_vpn_hint added in
// platform migration v0.232.246; callers populate via
// clientctx.GeoFromContext in createSession (auth_credentials_service.go).
// Pre-migration / Worker-not-deployed flow leaves them nil → NULL.
func (r *SessionRepository) Create(ctx context.Context, session *models.Session) error {
	query := `
		INSERT INTO iam_sessions (
			id, user_id, session_token_hash, device_info, ip_address, user_agent,
			location, country_code, asn, asn_org, city, region, is_vpn_hint,
			expires_at, saml_provider_id, saml_name_id, saml_session_index,
			authenticated_at, previous_session_id, session_regenerated,
			auth_methods_used
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
		RETURNING created_at, last_activity_at`

	if session.ID == uuid.Nil {
		session.ID = uuid.New()
	}
	if session.AuthMethodsUsed == nil {
		session.AuthMethodsUsed = []string{}
	}

	return r.db.QueryRow(ctx, query,
		session.ID, session.UserID, session.SessionTokenHash,
		session.DeviceInfo, session.IPAddress, session.UserAgent, session.Location, session.CountryCode,
		session.ASN, session.ASNOrg, session.City, session.Region, session.IsVPNHint,
		session.ExpiresAt,
		session.SAMLProviderID, session.SAMLNameID, session.SAMLSessionIndex,
		session.AuthenticatedAt, session.PreviousSessionID, session.SessionRegenerated,
		session.AuthMethodsUsed,
	).Scan(&session.CreatedAt, &session.LastActivityAt)
}

// RevokeTenantSessions ends all active sessions for a user within a specific tenant.
// SECURITY: Used for cross-tenant session revocation propagation when a session fixation
// or cross-tenant replay attack is detected.
func (r *SessionRepository) RevokeTenantSessions(ctx context.Context, userID, tenantID uuid.UUID, reason string) (int64, error) {
	query := `
		UPDATE iam_sessions s
		SET is_active = false, ended_at = NOW(), end_reason = $3
		FROM iam_users u
		WHERE s.user_id = u.id
		  AND s.user_id = $1
		  AND u.tenant_id = $2
		  AND s.is_active = true`

	result, err := r.db.Exec(ctx, query, userID, tenantID, reason)
	if err != nil {
		return 0, fmt.Errorf("RevokeTenantSessions: %w", err)
	}
	return result.RowsAffected(), nil
}

// RegenerateSession atomically ends an old session and creates a new one with
// a reference to the previous session. Returns the new session.
// SECURITY: Prevents session fixation by ensuring the old session is invalidated
// before the new session is created.
func (r *SessionRepository) RegenerateSession(ctx context.Context, oldSessionID uuid.UUID, newSession *models.Session) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("RegenerateSession: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// 1. End the old session
	endResult, err := tx.Exec(ctx,
		`UPDATE iam_sessions SET is_active = false, ended_at = NOW(), end_reason = 'session_regenerated'
		 WHERE id = $1 AND is_active = true`,
		oldSessionID,
	)
	if err != nil {
		return fmt.Errorf("RegenerateSession: end old session: %w", err)
	}
	_ = endResult // old session may already be ended; that is acceptable

	// 2. Create the new session with reference to old
	if newSession.ID == uuid.Nil {
		newSession.ID = uuid.New()
	}
	newSession.PreviousSessionID = &oldSessionID
	newSession.SessionRegenerated = true

	createQuery := `
		INSERT INTO iam_sessions (
			id, user_id, session_token_hash, device_info, ip_address, user_agent,
			location, country_code, asn, asn_org, city, region, is_vpn_hint,
			expires_at, saml_provider_id, saml_name_id, saml_session_index,
			authenticated_at, previous_session_id, session_regenerated,
			auth_methods_used
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
		RETURNING created_at, last_activity_at`

	if newSession.AuthMethodsUsed == nil {
		newSession.AuthMethodsUsed = []string{}
	}

	err = tx.QueryRow(ctx, createQuery,
		newSession.ID, newSession.UserID, newSession.SessionTokenHash,
		newSession.DeviceInfo, newSession.IPAddress, newSession.UserAgent, newSession.Location, newSession.CountryCode,
		newSession.ASN, newSession.ASNOrg, newSession.City, newSession.Region, newSession.IsVPNHint,
		newSession.ExpiresAt,
		newSession.SAMLProviderID, newSession.SAMLNameID, newSession.SAMLSessionIndex,
		newSession.AuthenticatedAt, newSession.PreviousSessionID, newSession.SessionRegenerated,
		newSession.AuthMethodsUsed,
	).Scan(&newSession.CreatedAt, &newSession.LastActivityAt)
	if err != nil {
		return fmt.Errorf("RegenerateSession: create new session: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("RegenerateSession: commit: %w", err)
	}

	return nil
}

// GetByID is an exported function.
func (r *SessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	query := `SELECT ` + sessionColumns + ` FROM iam_sessions WHERE id = $1`
	session, err := scanSession(r.db.QueryRow(ctx, query, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	return session, nil
}

// GetByTokenHash is an exported function.
func (r *SessionRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	query := `SELECT ` + sessionColumns + ` FROM iam_sessions WHERE session_token_hash = $1`
	session, err := scanSession(r.db.QueryRow(ctx, query, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByTokenHash: %w", err)
	}
	return session, nil
}

// GetActiveSessions is an exported function.
func (r *SessionRepository) GetActiveSessions(ctx context.Context, userID uuid.UUID) ([]models.Session, error) {
	query := `SELECT ` + sessionColumns + `
		FROM iam_sessions
		WHERE user_id = $1 AND is_active = true AND expires_at > NOW()
		ORDER BY last_activity_at DESC
		LIMIT 100`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("GetActiveSessions: %w", err)
	}
	defer rows.Close()

	var sessions []models.Session
	for rows.Next() {
		session, err := scanSessionFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("GetActiveSessions: %w", err)
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetActiveSessions: rows iteration: %w", err)
	}
	return sessions, nil
}

// UpdateLastActivity is an exported function.
func (r *SessionRepository) UpdateLastActivity(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_sessions SET last_activity_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("UpdateLastActivity: %w", err)
	}
	return nil
}

// RefreshAuthenticatedAt stamps authenticated_at to NOW() on the given
// session. Called immediately after a successful step-up MFA verification
// so RequireFreshAuth (RFC 9470 max_age check) on the retried sensitive
// endpoint sees a fresh auth_time and lets the request through.
//
// Why this is necessary: VerifyStepUp records a per-action verification
// row AND elevates AuthMethodsUsed, but neither updates authenticated_at —
// so RequireFreshAuth (which only knows about AuthTime) keeps rejecting
// the retry with "authentication time unknown / too old" even though the
// user just proved factor possession. Without this, every freshAuth-
// gated endpoint loops between 401 step-up challenge and 401 step-up
// challenge after a successful TOTP code, which surfaces to the user as
// "the OTP did nothing".
//
// Idempotent: re-running on the same session within the freshness
// window just bumps the timestamp; later RequireFreshAuth checks pass
// for the configured max_age (5 min today).
func (r *SessionRepository) RefreshAuthenticatedAt(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_sessions SET authenticated_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("RefreshAuthenticatedAt: %w", err)
	}
	return nil
}

// AppendAuthMethod atomically appends an RFC 8176 authentication-method
// reference (e.g. "mfa", "otp", "webauthn") to the session's auth_methods_used
// array if-and-only-if it isn't already present. Used by the step-up path
// (RFC 9470 §3): after the user completes a fresh MFA factor on an already-
// active session, the session's recorded AMR is elevated so that the next
// /oauth/authorize evaluation against `acr_values=mfa` passes (Tier-1 IdP
// pattern — Entra/Auth0/Okta all atomically update session-state on
// factor verification rather than relying on a separate "verification token"
// the OAuth handler would have to consult).
//
// idempotent — calling twice with the same method is a no-op (the WHERE
// clause filters with NOT(auth_methods_used @> jsonb_build_array($2))).
// Returns (false, nil) when the method was already present; (true, nil)
// when newly appended; non-nil error on DB failure.
//
// SECURITY NOTE: callers MUST have already verified the user actually
// performed the named auth method in the same request. This method ONLY
// records the AMR — it does NOT itself prove anything. Wiring it into
// /mfa/setup/totp/verify, /mfa/step-up/verify etc. is the contract.
func (r *SessionRepository) AppendAuthMethod(ctx context.Context, id uuid.UUID, method string) (bool, error) {
	// Column type is TEXT[] (PostgreSQL native array — verified live
	// against information_schema 2026-05-11; `data_type=ARRAY,
	// udt_name=_text`). Use array_append + ANY for idempotent append,
	// NOT jsonb operators.
	result, err := r.db.Exec(ctx,
		`UPDATE iam_sessions
		   SET auth_methods_used = array_append(COALESCE(auth_methods_used, ARRAY[]::text[]), $2::text)
		 WHERE id = $1
		   AND is_active = true
		   AND NOT ($2::text = ANY(COALESCE(auth_methods_used, ARRAY[]::text[])))`,
		id, method,
	)
	if err != nil {
		return false, fmt.Errorf("AppendAuthMethod: %w", err)
	}
	return result.RowsAffected() == 1, nil
}

// EndSession is an exported function.
func (r *SessionRepository) EndSession(ctx context.Context, id uuid.UUID, reason string) error {
	result, err := r.db.Exec(ctx,
		`UPDATE iam_sessions SET is_active = false, ended_at = NOW(), end_reason = $2 WHERE id = $1 AND is_active = true`,
		id, reason,
	)
	if err != nil {
		return fmt.Errorf("EndSession: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("EndSession: session %s not found or already ended", id)
	}
	return nil
}

// EndAllUserSessions is an exported function.
func (r *SessionRepository) EndAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_sessions SET is_active = false, ended_at = NOW(), end_reason = $2
		 WHERE user_id = $1 AND is_active = true`,
		userID, reason,
	)
	if err != nil {
		return fmt.Errorf("EndAllUserSessions: %w", err)
	}
	return nil
}

// EndAllUserSessionsExcept is an exported function.
func (r *SessionRepository) EndAllUserSessionsExcept(ctx context.Context, userID uuid.UUID, exceptID uuid.UUID, reason string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_sessions SET is_active = false, ended_at = NOW(), end_reason = $3
		 WHERE user_id = $1 AND id != $2 AND is_active = true`,
		userID, exceptID, reason,
	)
	if err != nil {
		return fmt.Errorf("EndAllUserSessionsExcept: %w", err)
	}
	return nil
}

// CleanupExpiredSessions is an exported function.
func (r *SessionRepository) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	result, err := r.db.Exec(ctx,
		`UPDATE iam_sessions SET is_active = false, ended_at = NOW(), end_reason = 'expired'
		 WHERE is_active = true AND expires_at < NOW()`,
	)
	if err != nil {
		return 0, fmt.Errorf("CleanupExpiredSessions: %w", err)
	}
	return result.RowsAffected(), nil
}

// CountActiveSessions is an exported function.
func (r *SessionRepository) CountActiveSessions(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_sessions WHERE user_id = $1 AND is_active = true AND expires_at > NOW()`,
		userID,
	).Scan(&count)
	if err != nil {
		return count, fmt.Errorf("CountActiveSessions: %w", err)
	}
	return count, nil
}

// DeleteOldSessions is an exported function.
func (r *SessionRepository) DeleteOldSessions(ctx context.Context, before time.Time) (int64, error) {
	result, err := r.db.Exec(ctx,
		`DELETE FROM iam_sessions WHERE is_active = false AND ended_at < $1`,
		before,
	)
	if err != nil {
		return 0, fmt.Errorf("DeleteOldSessions: %w", err)
	}
	return result.RowsAffected(), nil
}

// CleanupStaleSessions marks sessions as inactive if they haven't had activity for the specified duration
// This handles cases where users close their browser without logging out
func (r *SessionRepository) CleanupStaleSessions(ctx context.Context, inactivityTimeout time.Duration) (int64, error) {
	threshold := time.Now().Add(-inactivityTimeout)
	result, err := r.db.Exec(ctx,
		`UPDATE iam_sessions
		 SET is_active = false, ended_at = NOW(), end_reason = 'inactivity_timeout'
		 WHERE is_active = true AND last_activity_at < $1`,
		threshold,
	)
	if err != nil {
		return 0, fmt.Errorf("CleanupStaleSessions: %w", err)
	}
	return result.RowsAffected(), nil
}

// GetLoginHistory returns all sessions (including ended) for a user with pagination
func (r *SessionRepository) GetLoginHistory(ctx context.Context, userID uuid.UUID, page, pageSize int) ([]models.Session, int64, error) {
	// Count total
	var total int64
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_sessions WHERE user_id = $1`,
		userID,
	).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf(msgGetLoginHistory, err)
	}

	// Get paginated results
	offset := (page - 1) * pageSize
	query := `SELECT ` + sessionColumns + `
		FROM iam_sessions
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.Query(ctx, query, userID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf(msgGetLoginHistory, err)
	}
	defer rows.Close()

	var sessions []models.Session
	for rows.Next() {
		session, err := scanSessionFromRows(rows)
		if err != nil {
			return nil, 0, fmt.Errorf(msgGetLoginHistory, err)
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("GetLoginHistory: rows iteration: %w", err)
	}
	return sessions, total, nil
}

// GetAllActiveSessionsForTenant returns all active sessions for users belonging to the given tenant
// SECURITY: Limited to 100 sessions to prevent memory exhaustion
func (r *SessionRepository) GetAllActiveSessionsForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.SessionWithUser, error) {
	query := `
		SELECT s.id, s.user_id, s.session_token_hash, s.device_info, s.ip_address, s.user_agent, s.location, s.country_code,
			   s.is_active, s.created_at, s.last_activity_at, s.expires_at, s.ended_at, s.end_reason,
			   s.saml_provider_id, s.saml_name_id, s.saml_session_index,
			   s.authenticated_at, s.previous_session_id, s.session_regenerated,
			   u.username
		FROM iam_sessions s
		INNER JOIN iam_users u ON s.user_id = u.id
		WHERE u.tenant_id = $1 AND s.is_active = true AND s.expires_at > NOW()
		ORDER BY s.last_activity_at DESC
		LIMIT 100`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetAllActiveSessionsForTenant: %w", err)
	}
	defer rows.Close()

	var sessions []models.SessionWithUser
	for rows.Next() {
		var session models.SessionWithUser
		err := rows.Scan(
			&session.ID, &session.UserID, &session.SessionTokenHash,
			&session.DeviceInfo, &session.IPAddress, &session.UserAgent, &session.Location, &session.CountryCode,
			&session.IsActive, &session.CreatedAt, &session.LastActivityAt, &session.ExpiresAt,
			&session.EndedAt, &session.EndReason,
			&session.SAMLProviderID, &session.SAMLNameID, &session.SAMLSessionIndex,
			&session.AuthenticatedAt, &session.PreviousSessionID, &session.SessionRegenerated,
			&session.Username,
		)
		if err != nil {
			return nil, fmt.Errorf("GetAllActiveSessionsForTenant: %w", err)
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetAllActiveSessionsForTenant: rows iteration: %w", err)
	}
	return sessions, nil
}

// GetBySAMLMetadata finds active sessions matching the given SAML provider, NameID,
// and optionally SessionIndex. Used for IDP-initiated Single Logout.
// SECURITY: Includes tenant isolation via JOIN to prevent cross-tenant session termination.
func (r *SessionRepository) GetBySAMLMetadata(ctx context.Context, providerID uuid.UUID, nameID string, sessionIndex *string) ([]models.Session, error) {
	var rows pgx.Rows
	var err error

	if sessionIndex != nil && *sessionIndex != "" {
		query := `
			SELECT ` + sessionColumns + `
			FROM iam_sessions s
			INNER JOIN iam_users u ON s.user_id = u.id
			INNER JOIN iam_identity_providers p ON s.saml_provider_id = p.id
			WHERE s.saml_provider_id = $1 AND s.saml_name_id = $2 AND s.saml_session_index = $3
			  AND s.is_active = true AND s.expires_at > NOW()
			  AND u.tenant_id = p.tenant_id
			ORDER BY s.created_at DESC
			LIMIT 100`
		rows, err = r.db.Query(ctx, query, providerID, nameID, *sessionIndex)
	} else {
		query := `
			SELECT ` + sessionColumns + `
			FROM iam_sessions s
			INNER JOIN iam_users u ON s.user_id = u.id
			INNER JOIN iam_identity_providers p ON s.saml_provider_id = p.id
			WHERE s.saml_provider_id = $1 AND s.saml_name_id = $2
			  AND s.is_active = true AND s.expires_at > NOW()
			  AND u.tenant_id = p.tenant_id
			ORDER BY s.created_at DESC
			LIMIT 100`
		rows, err = r.db.Query(ctx, query, providerID, nameID)
	}
	if err != nil {
		return nil, fmt.Errorf("GetBySAMLMetadata: %w", err)
	}
	defer rows.Close()

	var sessions []models.Session
	for rows.Next() {
		session, err := scanSessionFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("GetBySAMLMetadata: %w", err)
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetBySAMLMetadata: rows iteration: %w", err)
	}
	return sessions, nil
}

// GetSAMLSessionForUser returns the most recent active SAML session for a user
// at a given provider. Used for SP-initiated Single Logout to extract NameID
// and SessionIndex for the outbound LogoutRequest.
func (r *SessionRepository) GetSAMLSessionForUser(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) (*models.Session, error) {
	query := `SELECT ` + sessionColumns + `
		FROM iam_sessions
		WHERE user_id = $1 AND saml_provider_id = $2 AND is_active = true AND expires_at > NOW()
		ORDER BY created_at DESC
		LIMIT 1`

	session, err := scanSession(r.db.QueryRow(ctx, query, userID, providerID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetSAMLSessionForUser: %w", err)
	}
	return session, nil
}

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

// WebAuthnRepository manages persistence of WebAuthn passkey credentials in the
// iam_webauthn_credentials table (created by migration 081, extended by migration 153).
type WebAuthnRepository struct {
	db      DBPool
	realmID *uuid.UUID
}

// WithRealmID returns a shallow clone of WebAuthnRepository scoped to the given realm.
func (r *WebAuthnRepository) WithRealmID(realmID uuid.UUID) *WebAuthnRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewWebAuthnRepository creates a new WebAuthnRepository backed by the given pool.
func NewWebAuthnRepository(db *pgxpool.Pool) *WebAuthnRepository {
	return &WebAuthnRepository{db: db}
}

// columnList is the canonical SELECT column list for all credential queries.
// It must stay in sync with scanCredential().
//
//nolint:gosec // not a real credential, this is a SQL column list constant
const credentialColumns = `
	id, user_id, tenant_id, credential_id, public_key,
	attestation_type, transport, sign_count, aaguid,
	clone_warning, friendly_name, last_used_at, created_at,
	is_discoverable, backup_eligible, backup_state,
	expires_at, revoked_at, revoked_by`

// scanCredential reads a single WebAuthnCredential row into cred.
// Column order must match credentialColumns.
func scanCredential(row interface {
	Scan(...any) error
}, cred *models.WebAuthnCredential,
) error {
	return row.Scan(
		&cred.ID, &cred.UserID, &cred.TenantID, &cred.CredentialID, &cred.PublicKey,
		&cred.AttestationType, &cred.Transport, &cred.SignCount, &cred.AAGUID,
		&cred.CloneWarning, &cred.FriendlyName, &cred.LastUsedAt, &cred.CreatedAt,
		&cred.IsDiscoverable, &cred.BackupEligible, &cred.BackupState,
		&cred.ExpiresAt, &cred.RevokedAt, &cred.RevokedBy,
	)
}

// Create persists a new credential record. The ID is generated if zero-valued;
// CreatedAt is stamped by the database and read back via RETURNING.
func (r *WebAuthnRepository) Create(ctx context.Context, cred *models.WebAuthnCredential) error {
	if cred.ID == uuid.Nil {
		cred.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_webauthn_credentials (
			id, user_id, tenant_id, credential_id, public_key,
			attestation_type, transport, sign_count, aaguid,
			clone_warning, friendly_name, last_used_at,
			is_discoverable, backup_eligible, backup_state, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING created_at`

	return r.db.QueryRow(ctx, query,
		cred.ID, cred.UserID, cred.TenantID, cred.CredentialID, cred.PublicKey,
		cred.AttestationType, cred.Transport, cred.SignCount, cred.AAGUID,
		cred.CloneWarning, cred.FriendlyName, cred.LastUsedAt,
		cred.IsDiscoverable, cred.BackupEligible, cred.BackupState, cred.ExpiresAt,
	).Scan(&cred.CreatedAt)
}

// GetByID retrieves a credential by its primary-key UUID.
// Returns (nil, nil) when no matching row is found.
//
// Surfaced for the admin-revoke + CAEP-emit flow, which only has the
// credential's PK (not its raw byte ID nor the owning user_id) at the
// REST entry-point. Cheap O(1) PK lookup; no behaviour change to
// existing call sites.
func (r *WebAuthnRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.WebAuthnCredential, error) {
	cred := &models.WebAuthnCredential{}
	query := `SELECT ` + credentialColumns + `
		FROM iam_webauthn_credentials
		WHERE id = $1`

	err := scanCredential(r.db.QueryRow(ctx, query, id), cred)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	return cred, nil
}

// GetByCredentialID retrieves a credential by its raw WebAuthn credential ID bytes.
// Returns nil, nil when no matching row is found.
func (r *WebAuthnRepository) GetByCredentialID(ctx context.Context, credentialID []byte) (*models.WebAuthnCredential, error) {
	cred := &models.WebAuthnCredential{}
	query := `SELECT ` + credentialColumns + `
		FROM iam_webauthn_credentials
		WHERE credential_id = $1`

	err := scanCredential(r.db.QueryRow(ctx, query, credentialID), cred)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByCredentialID: %w", err)
	}
	return cred, nil
}

// ListByUser returns all credentials registered to the given user within the given tenant,
// ordered by creation time descending (newest first). Revoked and expired credentials
// are included; callers may filter via WebAuthnCredential.IsActive().
func (r *WebAuthnRepository) ListByUser(ctx context.Context, userID, tenantID uuid.UUID) ([]models.WebAuthnCredential, error) {
	query := `SELECT ` + credentialColumns + `
		FROM iam_webauthn_credentials
		WHERE user_id = $1 AND tenant_id = $2
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListByUser: %w", err)
	}
	defer rows.Close()

	var creds []models.WebAuthnCredential
	for rows.Next() {
		var cred models.WebAuthnCredential
		if err := scanCredential(rows, &cred); err != nil {
			return nil, fmt.Errorf("ListByUser: scan: %w", err)
		}
		creds = append(creds, cred)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListByUser: rows iteration: %w", err)
	}

	return creds, nil
}

// CountActiveByUser returns the number of non-revoked, non-expired credentials for
// the given user. Used to enforce MaxCredentialsPerUser attestation policy.
func (r *WebAuthnRepository) CountActiveByUser(ctx context.Context, userID, tenantID uuid.UUID) (int, error) {
	var count int
	query := `
		SELECT COUNT(*) FROM iam_webauthn_credentials
		WHERE user_id = $1
		  AND tenant_id = $2
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())`
	err := r.db.QueryRow(ctx, query, userID, tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("CountActiveByUser: %w", err)
	}
	return count, nil
}

// ListDiscoverableByTenant returns all active discoverable credentials within a
// tenant. This is used by the conditional UI (passwordless autofill) flow where
// the user has not yet provided a username.
func (r *WebAuthnRepository) ListDiscoverableByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.WebAuthnCredential, error) {
	query := `SELECT ` + credentialColumns + `
		FROM iam_webauthn_credentials
		WHERE tenant_id = $1
		  AND is_discoverable = true
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY last_used_at DESC NULLS LAST`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListDiscoverableByTenant: %w", err)
	}
	defer rows.Close()

	var creds []models.WebAuthnCredential
	for rows.Next() {
		var cred models.WebAuthnCredential
		if err := scanCredential(rows, &cred); err != nil {
			return nil, fmt.Errorf("ListDiscoverableByTenant: scan: %w", err)
		}
		creds = append(creds, cred)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListDiscoverableByTenant: rows iteration: %w", err)
	}

	return creds, nil
}

// UpdateSignCount sets a new sign_count and stamps last_used_at to the current
// time for the credential identified by id.
func (r *WebAuthnRepository) UpdateSignCount(ctx context.Context, id uuid.UUID, signCount uint32) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_webauthn_credentials
		 SET sign_count = $2, last_used_at = $3
		 WHERE id = $1`,
		id, signCount, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("UpdateSignCount: %w", err)
	}
	return nil
}

// UpdateLastUsedAt stamps last_used_at without changing the sign count. Used by
// the conditional-UI authentication path where the client does not always report
// an updated counter.
func (r *WebAuthnRepository) UpdateLastUsedAt(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_webauthn_credentials
		 SET last_used_at = $2
		 WHERE id = $1`,
		id, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("UpdateLastUsedAt: %w", err)
	}
	return nil
}

// Delete permanently removes a credential by its primary key.
func (r *WebAuthnRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM iam_webauthn_credentials WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	return nil
}

// Revoke marks a credential as revoked by an administrator without deleting the
// row. The audit trail (who revoked it and when) is preserved in the row itself.
// Subsequent authentications will fail because the service checks IsActive().
func (r *WebAuthnRepository) Revoke(ctx context.Context, id uuid.UUID, revokedBy uuid.UUID) error {
	now := time.Now().UTC()
	_, err := r.db.Exec(ctx,
		`UPDATE iam_webauthn_credentials
		 SET revoked_at = $2, revoked_by = $3
		 WHERE id = $1 AND revoked_at IS NULL`,
		id, now, revokedBy,
	)
	if err != nil {
		return fmt.Errorf("Revoke: %w", err)
	}
	return nil
}

// SetCloneWarning marks the credential as having exhibited a sign-count anomaly
// that indicates it may have been cloned. Once set, this flag is not cleared
// automatically — a security review is required.
func (r *WebAuthnRepository) SetCloneWarning(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_webauthn_credentials SET clone_warning = true WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("SetCloneWarning: %w", err)
	}
	return nil
}

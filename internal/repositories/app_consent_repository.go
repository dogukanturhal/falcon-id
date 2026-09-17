// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// AppConsentRepository handles app consent database operations.
type AppConsentRepository struct {
	pool *pgxpool.Pool
}

// NewAppConsentRepository creates a new AppConsentRepository.
func NewAppConsentRepository(pool *pgxpool.Pool) *AppConsentRepository {
	return &AppConsentRepository{pool: pool}
}

const appConsentColumns = `id, application_id, tenant_id, consented_by, consent_type, scopes, status, granted_at, revoked_at`

func scanAppConsent(scanner interface {
	Scan(dest ...interface{}) error
},
) (*models.AppConsent, error) {
	var c models.AppConsent
	err := scanner.Scan(
		&c.ID, &c.ApplicationID, &c.TenantID, &c.ConsentedBy,
		&c.ConsentType, &c.Scopes, &c.Status, &c.GrantedAt, &c.RevokedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Upsert creates or updates a consent record (idempotent grant).
func (r *AppConsentRepository) Upsert(ctx context.Context, consent *models.AppConsent) error {
	if consent.ID == uuid.Nil {
		consent.ID = uuid.New()
	}
	if consent.Scopes == nil {
		consent.Scopes = []string{}
	}

	query := `
		INSERT INTO iam_app_consents (id, application_id, tenant_id, consented_by, consent_type, scopes, status, granted_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (application_id, tenant_id, consented_by, consent_type)
		DO UPDATE SET scopes = EXCLUDED.scopes, status = 'granted', granted_at = NOW(), revoked_at = NULL
		RETURNING id, granted_at`

	err := r.pool.QueryRow(ctx, query,
		consent.ID, consent.ApplicationID, consent.TenantID, consent.ConsentedBy,
		consent.ConsentType, consent.Scopes, consent.Status, consent.GrantedAt,
	).Scan(&consent.ID, &consent.GrantedAt)
	if err != nil {
		return fmt.Errorf("AppConsentRepository.Upsert: %w", err)
	}
	return nil
}

// Revoke soft-revokes a consent.
func (r *AppConsentRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_app_consents SET status = 'revoked', revoked_at = $1 WHERE id = $2`,
		now, id,
	)
	if err != nil {
		return fmt.Errorf("AppConsentRepository.Revoke: %w", err)
	}
	return nil
}

// RevokeByAppAndTenant revokes all consents for an app in a tenant.
func (r *AppConsentRepository) RevokeByAppAndTenant(ctx context.Context, appID, tenantID uuid.UUID) error {
	now := time.Now()
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_app_consents SET status = 'revoked', revoked_at = $1 WHERE application_id = $2 AND tenant_id = $3 AND status = 'granted'`,
		now, appID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("AppConsentRepository.RevokeByAppAndTenant: %w", err)
	}
	return nil
}

// HasConsent checks if there is an active (granted) admin consent for an app in a tenant.
func (r *AppConsentRepository) HasConsent(ctx context.Context, appID, tenantID uuid.UUID) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM iam_app_consents WHERE application_id = $1 AND tenant_id = $2 AND status = 'granted' AND consent_type = 'admin')`,
		appID, tenantID,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("AppConsentRepository.HasConsent: %w", err)
	}
	return exists, nil
}

// ListByApp returns all consents for an application.
func (r *AppConsentRepository) ListByApp(ctx context.Context, appID uuid.UUID) ([]models.AppConsent, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_app_consents WHERE application_id = $1 ORDER BY granted_at DESC`, appConsentColumns)

	rows, err := r.pool.Query(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("AppConsentRepository.ListByApp: %w", err)
	}
	defer rows.Close()

	var consents []models.AppConsent
	for rows.Next() {
		consent, err := scanAppConsent(rows)
		if err != nil {
			return nil, fmt.Errorf("AppConsentRepository.ListByApp scan: %w", err)
		}
		consents = append(consents, *consent)
	}
	return consents, rows.Err()
}

// ListByTenant returns all consents for a tenant.
func (r *AppConsentRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.AppConsent, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_app_consents WHERE tenant_id = $1 ORDER BY granted_at DESC`, appConsentColumns)

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("AppConsentRepository.ListByTenant: %w", err)
	}
	defer rows.Close()

	var consents []models.AppConsent
	for rows.Next() {
		consent, err := scanAppConsent(rows)
		if err != nil {
			return nil, fmt.Errorf("AppConsentRepository.ListByTenant scan: %w", err)
		}
		consents = append(consents, *consent)
	}
	return consents, rows.Err()
}

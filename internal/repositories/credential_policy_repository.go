// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// CredentialPolicyRepository handles credential policy database operations.
type CredentialPolicyRepository struct {
	pool *pgxpool.Pool
}

// NewCredentialPolicyRepository creates a new CredentialPolicyRepository.
func NewCredentialPolicyRepository(pool *pgxpool.Pool) *CredentialPolicyRepository {
	return &CredentialPolicyRepository{pool: pool}
}

const credPolicyColumns = `id, scope_type, scope_id, max_secret_lifetime_days, max_cert_lifetime_days, require_expiry, created_at, updated_at` //nolint:gosec // not a credential, this is a column name constant

func scanCredentialPolicy(scanner interface {
	Scan(dest ...interface{}) error
},
) (*models.CredentialPolicy, error) {
	var p models.CredentialPolicy
	err := scanner.Scan(
		&p.ID, &p.ScopeType, &p.ScopeID,
		&p.MaxSecretLifetimeDays, &p.MaxCertLifetimeDays,
		&p.RequireExpiry, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// GetByScope retrieves the credential policy for a given scope.
func (r *CredentialPolicyRepository) GetByScope(ctx context.Context, scopeType models.CredentialPolicyScopeType, scopeID *uuid.UUID) (*models.CredentialPolicy, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_credential_policies WHERE scope_type = $1`, credPolicyColumns)
	var row pgx.Row
	if scopeID == nil {
		query += ` AND scope_id IS NULL`
		row = r.pool.QueryRow(ctx, query, scopeType)
	} else {
		query += ` AND scope_id = $2`
		row = r.pool.QueryRow(ctx, query, scopeType, *scopeID)
	}

	p, err := scanCredentialPolicy(row)
	if err != nil {
		return nil, fmt.Errorf("CredentialPolicyRepository.GetByScope: %w", err)
	}
	return p, nil
}

// GetEffective retrieves the most specific policy for a tenant — tenant-level if exists, otherwise platform-level.
func (r *CredentialPolicyRepository) GetEffective(ctx context.Context, tenantID uuid.UUID) (*models.CredentialPolicy, error) {
	// Try tenant-level first
	p, err := r.GetByScope(ctx, models.CredentialPolicyScopeTenant, &tenantID)
	if err == nil {
		return p, nil
	}

	// Fall back to platform-level
	return r.GetByScope(ctx, models.CredentialPolicyScopePlatform, nil)
}

// Upsert creates or updates a credential policy for a scope.
func (r *CredentialPolicyRepository) Upsert(ctx context.Context, policy *models.CredentialPolicy) error {
	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_credential_policies (id, scope_type, scope_id, max_secret_lifetime_days, max_cert_lifetime_days, require_expiry, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, now(), now())
		ON CONFLICT (scope_type, scope_id) DO UPDATE SET
			max_secret_lifetime_days = EXCLUDED.max_secret_lifetime_days,
			max_cert_lifetime_days = EXCLUDED.max_cert_lifetime_days,
			require_expiry = EXCLUDED.require_expiry,
			updated_at = now()
		RETURNING id, created_at, updated_at`

	err := r.pool.QueryRow(ctx, query,
		policy.ID, policy.ScopeType, policy.ScopeID,
		policy.MaxSecretLifetimeDays, policy.MaxCertLifetimeDays,
		policy.RequireExpiry,
	).Scan(&policy.ID, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("CredentialPolicyRepository.Upsert: %w", err)
	}
	return nil
}

// Delete removes a credential policy by ID.
func (r *CredentialPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM iam_credential_policies WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("CredentialPolicyRepository.Delete: %w", err)
	}
	return nil
}

// List returns all credential policies.
func (r *CredentialPolicyRepository) List(ctx context.Context) ([]models.CredentialPolicy, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_credential_policies ORDER BY scope_type, created_at`, credPolicyColumns)
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("CredentialPolicyRepository.List: %w", err)
	}
	defer rows.Close()

	var policies []models.CredentialPolicy
	for rows.Next() {
		p, err := scanCredentialPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("CredentialPolicyRepository.List scan: %w", err)
		}
		policies = append(policies, *p)
	}
	return policies, nil
}

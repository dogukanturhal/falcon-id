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

// DelegationRepository handles delegation database operations
type DelegationRepository struct {
	db      DBPool
	realmID *uuid.UUID
}

// WithRealmID returns a shallow clone of DelegationRepository scoped to the given realm.
func (r *DelegationRepository) WithRealmID(realmID uuid.UUID) *DelegationRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewDelegationRepository creates a new DelegationRepository
func NewDelegationRepository(db *pgxpool.Pool) *DelegationRepository {
	return &DelegationRepository{db: db}
}

// Create creates a new delegation record
func (r *DelegationRepository) Create(ctx context.Context, delegation *models.Delegation) error {
	// Generate ID if not set
	if delegation.ID == uuid.Nil {
		delegation.ID = uuid.New()
	}

	// Set timestamps
	now := time.Now()
	delegation.CreatedAt = now
	delegation.UpdatedAt = now

	query := `
		INSERT INTO iam_delegations (
			id, tenant_id, delegator_id, delegatee_id, permissions,
			resource_type, resource_id, expires_at, reason, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := r.db.Exec(ctx, query,
		delegation.ID,
		delegation.TenantID,
		delegation.DelegatorID,
		delegation.DelegateeID,
		delegation.Permissions,
		delegation.ResourceType,
		delegation.ResourceID,
		delegation.ExpiresAt,
		delegation.Reason,
		delegation.CreatedAt,
		delegation.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create delegation: %w", err)
	}

	return nil
}

// GetByID retrieves a delegation by ID
func (r *DelegationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Delegation, error) {
	query := `
		SELECT id, tenant_id, delegator_id, delegatee_id, permissions,
			resource_type, resource_id, expires_at, reason,
			revoked_at, revoked_by, created_at, updated_at
		FROM iam_delegations
		WHERE id = $1
	`

	delegation := &models.Delegation{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&delegation.ID,
		&delegation.TenantID,
		&delegation.DelegatorID,
		&delegation.DelegateeID,
		&delegation.Permissions,
		&delegation.ResourceType,
		&delegation.ResourceID,
		&delegation.ExpiresAt,
		&delegation.Reason,
		&delegation.RevokedAt,
		&delegation.RevokedBy,
		&delegation.CreatedAt,
		&delegation.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("delegation not found: %w", err)
	}

	return delegation, nil
}

// Revoke marks a delegation as revoked
func (r *DelegationRepository) Revoke(ctx context.Context, delegationID, revokerID uuid.UUID) error {
	query := `
		UPDATE iam_delegations
		SET revoked_at = $1, revoked_by = $2, updated_at = $1
		WHERE id = $3 AND revoked_at IS NULL
	`

	now := time.Now()
	result, err := r.db.Exec(ctx, query, now, revokerID, delegationID)
	if err != nil {
		return fmt.Errorf("failed to revoke delegation: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("delegation not found or already revoked")
	}

	return nil
}

// ListByDelegator lists all delegations created by a user
func (r *DelegationRepository) ListByDelegator(ctx context.Context, userID uuid.UUID, includeRevoked bool) ([]*models.Delegation, error) {
	var query string
	if includeRevoked {
		query = `
			SELECT id, tenant_id, delegator_id, delegatee_id, permissions,
				resource_type, resource_id, expires_at, reason,
				revoked_at, revoked_by, created_at, updated_at
			FROM iam_delegations
			WHERE delegator_id = $1
			ORDER BY created_at DESC
		`
	} else {
		query = `
			SELECT id, tenant_id, delegator_id, delegatee_id, permissions,
				resource_type, resource_id, expires_at, reason,
				revoked_at, revoked_by, created_at, updated_at
			FROM iam_delegations
			WHERE delegator_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
			ORDER BY created_at DESC
		`
	}

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list delegations: %w", err)
	}
	defer rows.Close()

	return scanDelegations(rows)
}

// ListByDelegatee lists all delegations received by a user
func (r *DelegationRepository) ListByDelegatee(ctx context.Context, userID uuid.UUID, includeRevoked bool) ([]*models.Delegation, error) {
	var query string
	if includeRevoked {
		query = `
			SELECT id, tenant_id, delegator_id, delegatee_id, permissions,
				resource_type, resource_id, expires_at, reason,
				revoked_at, revoked_by, created_at, updated_at
			FROM iam_delegations
			WHERE delegatee_id = $1
			ORDER BY created_at DESC
		`
	} else {
		query = `
			SELECT id, tenant_id, delegator_id, delegatee_id, permissions,
				resource_type, resource_id, expires_at, reason,
				revoked_at, revoked_by, created_at, updated_at
			FROM iam_delegations
			WHERE delegatee_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
			ORDER BY created_at DESC
		`
	}

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list delegations: %w", err)
	}
	defer rows.Close()

	return scanDelegations(rows)
}

// GetActiveDelegationsForUser returns all active delegations for a user (as delegatee)
func (r *DelegationRepository) GetActiveDelegationsForUser(ctx context.Context, delegateeID uuid.UUID) ([]*models.Delegation, error) {
	query := `
		SELECT id, tenant_id, delegator_id, delegatee_id, permissions,
			resource_type, resource_id, expires_at, reason,
			revoked_at, revoked_by, created_at, updated_at
		FROM iam_delegations
		WHERE delegatee_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		ORDER BY expires_at ASC
	`

	rows, err := r.db.Query(ctx, query, delegateeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active delegations: %w", err)
	}
	defer rows.Close()

	return scanDelegations(rows)
}

// CleanupExpired removes delegations that have been expired for longer than retentionDays
func (r *DelegationRepository) CleanupExpired(ctx context.Context, retentionDays int) (int64, error) {
	query := `
		DELETE FROM iam_delegations
		WHERE expires_at < NOW() - INTERVAL '1 day' * $1
	`

	result, err := r.db.Exec(ctx, query, retentionDays)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired delegations: %w", err)
	}

	return result.RowsAffected(), nil
}

// scanDelegations is a helper to scan delegation rows
func scanDelegations(rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Err() error
},
) ([]*models.Delegation, error) {
	var delegations []*models.Delegation

	for rows.Next() {
		d := &models.Delegation{}
		err := rows.Scan(
			&d.ID,
			&d.TenantID,
			&d.DelegatorID,
			&d.DelegateeID,
			&d.Permissions,
			&d.ResourceType,
			&d.ResourceID,
			&d.ExpiresAt,
			&d.Reason,
			&d.RevokedAt,
			&d.RevokedBy,
			&d.CreatedAt,
			&d.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan delegation: %w", err)
		}
		delegations = append(delegations, d)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scanDelegations: rows iteration: %w", err)
	}

	return delegations, nil
}

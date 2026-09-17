// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// SCPRepository handles persistence for service control policies.
// It satisfies the scpServiceRepo interface defined in the services package.
type SCPRepository struct {
	pool DBPool
}

// NewSCPRepository creates a new SCPRepository backed by the given pool.
func NewSCPRepository(pool DBPool) *SCPRepository {
	return &SCPRepository{pool: pool}
}

// Create persists a new service control policy.
// It populates scp.ID, scp.CreatedAt, and scp.UpdatedAt before the insert.
func (r *SCPRepository) Create(ctx context.Context, scp *models.ServiceControlPolicy) error {
	now := time.Now().UTC()
	scp.ID = uuid.New()
	scp.CreatedAt = now
	scp.UpdatedAt = now

	policyJSON, err := json.Marshal(scp.PolicyDocument)
	if err != nil {
		return fmt.Errorf("scp_repository.Create: marshal policy document: %w", err)
	}

	_, err = r.pool.Exec(ctx,
		`INSERT INTO iam_service_control_policies
		 (id, name, description, scope, scope_id, policy_document, priority, is_enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		scp.ID, scp.Name, scp.Description, string(scp.Scope), scp.ScopeID,
		policyJSON, scp.Priority, scp.IsEnabled, scp.CreatedAt, scp.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("scp_repository.Create: exec: %w", err)
	}

	return nil
}

// GetByID retrieves a single service control policy by its UUID.
// Returns (nil, nil) when no row is found.
func (r *SCPRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ServiceControlPolicy, error) {
	var scp models.ServiceControlPolicy
	var policyJSON []byte
	var scope string

	err := r.pool.QueryRow(ctx,
		`SELECT id, name, description, scope, scope_id, policy_document,
		        priority, is_enabled, created_at, updated_at
		 FROM iam_service_control_policies
		 WHERE id = $1`, id,
	).Scan(
		&scp.ID, &scp.Name, &scp.Description, &scope, &scp.ScopeID,
		&policyJSON, &scp.Priority, &scp.IsEnabled, &scp.CreatedAt, &scp.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scp_repository.GetByID: scan: %w", err)
	}

	scp.Scope = models.SCPScope(scope)
	if err := json.Unmarshal(policyJSON, &scp.PolicyDocument); err != nil {
		return nil, fmt.Errorf("scp_repository.GetByID: unmarshal policy document: %w", err)
	}

	return &scp, nil
}

// List returns a paginated slice of service control policies and the total
// count matching the optional scope filter. Pass an empty string for scope to
// return all scopes. Results are ordered by priority DESC, then created_at DESC.
func (r *SCPRepository) List(ctx context.Context, scope string, page, pageSize int) ([]*models.ServiceControlPolicy, int64, error) {
	offset := (page - 1) * pageSize

	var (
		total    int64
		countErr error
	)

	if scope != "" {
		countErr = r.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM iam_service_control_policies WHERE scope = $1`, scope,
		).Scan(&total)
	} else {
		countErr = r.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM iam_service_control_policies`,
		).Scan(&total)
	}
	if countErr != nil {
		return nil, 0, fmt.Errorf("scp_repository.List: count: %w", countErr)
	}

	var (
		rows pgx.Rows
		err  error
	)

	if scope != "" {
		rows, err = r.pool.Query(ctx,
			`SELECT id, name, description, scope, scope_id, policy_document,
			        priority, is_enabled, created_at, updated_at
			 FROM iam_service_control_policies
			 WHERE scope = $1
			 ORDER BY priority DESC, created_at DESC
			 LIMIT $2 OFFSET $3`,
			scope, pageSize, offset,
		)
	} else {
		rows, err = r.pool.Query(ctx,
			`SELECT id, name, description, scope, scope_id, policy_document,
			        priority, is_enabled, created_at, updated_at
			 FROM iam_service_control_policies
			 ORDER BY priority DESC, created_at DESC
			 LIMIT $1 OFFSET $2`,
			pageSize, offset,
		)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("scp_repository.List: query: %w", err)
	}
	defer rows.Close()

	policies, err := collectSCPPointers(rows)
	if err != nil {
		return nil, 0, err
	}

	return policies, total, nil
}

// Update applies a partial update to an existing service control policy using
// only the non-nil fields from req. It returns the fully updated record.
func (r *SCPRepository) Update(ctx context.Context, id uuid.UUID, req *models.UpdateSCPRequest) (*models.ServiceControlPolicy, error) {
	// Load current record so we can apply the sparse patch.
	current, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("scp_repository.Update: load current: %w", err)
	}
	if current == nil {
		return nil, fmt.Errorf("scp_repository.Update: SCP not found")
	}

	if req.Name != nil {
		current.Name = *req.Name
	}
	if req.Description != nil {
		current.Description = *req.Description
	}
	if req.PolicyDocument != nil {
		current.PolicyDocument = *req.PolicyDocument
	}
	if req.Priority != nil {
		current.Priority = *req.Priority
	}
	current.UpdatedAt = time.Now().UTC()

	policyJSON, err := json.Marshal(current.PolicyDocument)
	if err != nil {
		return nil, fmt.Errorf("scp_repository.Update: marshal policy document: %w", err)
	}

	result, err := r.pool.Exec(ctx,
		`UPDATE iam_service_control_policies
		 SET name = $1, description = $2, policy_document = $3,
		     priority = $4, updated_at = $5
		 WHERE id = $6`,
		current.Name, current.Description, policyJSON,
		current.Priority, current.UpdatedAt, id,
	)
	if err != nil {
		return nil, fmt.Errorf("scp_repository.Update: exec: %w", err)
	}
	if result.RowsAffected() == 0 {
		return nil, fmt.Errorf("scp_repository.Update: SCP not found")
	}

	return current, nil
}

// Delete removes a service control policy by ID.
// Returns an error if the policy does not exist.
func (r *SCPRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := r.pool.Exec(ctx,
		`DELETE FROM iam_service_control_policies WHERE id = $1`, id,
	)
	if err != nil {
		return fmt.Errorf("scp_repository.Delete: exec: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("scp_repository.Delete: SCP not found")
	}

	return nil
}

// SetEnabled toggles the is_enabled flag on the identified policy.
func (r *SCPRepository) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	result, err := r.pool.Exec(ctx,
		`UPDATE iam_service_control_policies
		 SET is_enabled = $1, updated_at = $2
		 WHERE id = $3`,
		enabled, time.Now().UTC(), id,
	)
	if err != nil {
		return fmt.Errorf("scp_repository.SetEnabled: exec: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("scp_repository.SetEnabled: SCP not found")
	}

	return nil
}

// ListApplicable returns all enabled SCPs that apply to the given scope chain
// (platform-wide, realm-scoped, tenant-scoped), ordered by priority DESC.
func (r *SCPRepository) ListApplicable(ctx context.Context, tenantID, realmID uuid.UUID) ([]*models.ServiceControlPolicy, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name, description, scope, scope_id, policy_document,
		        priority, is_enabled, created_at, updated_at
		 FROM iam_service_control_policies
		 WHERE is_enabled = true
		   AND (
		       scope = 'platform'
		       OR (scope = 'realm'   AND scope_id = $1)
		       OR (scope = 'tenant'  AND scope_id = $2)
		   )
		 ORDER BY priority DESC`,
		realmID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("scp_repository.ListApplicable: query: %w", err)
	}
	defer rows.Close()

	policies, err := collectSCPPointers(rows)
	if err != nil {
		return nil, fmt.Errorf("scp_repository.ListApplicable: %w", err)
	}

	return policies, nil
}

// collectSCPPointers scans all rows from a query result into a slice of
// *models.ServiceControlPolicy. It is a package-level helper shared by
// List and ListApplicable to avoid code duplication.
func collectSCPPointers(rows pgx.Rows) ([]*models.ServiceControlPolicy, error) {
	var result []*models.ServiceControlPolicy

	for rows.Next() {
		var scp models.ServiceControlPolicy
		var policyJSON []byte
		var scope string

		if err := rows.Scan(
			&scp.ID, &scp.Name, &scp.Description, &scope, &scp.ScopeID,
			&policyJSON, &scp.Priority, &scp.IsEnabled, &scp.CreatedAt, &scp.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("collectSCPPointers: scan: %w", err)
		}

		scp.Scope = models.SCPScope(scope)
		if err := json.Unmarshal(policyJSON, &scp.PolicyDocument); err != nil {
			return nil, fmt.Errorf("collectSCPPointers: unmarshal policy document: %w", err)
		}

		result = append(result, &scp)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("collectSCPPointers: rows iteration: %w", err)
	}

	return result, nil
}

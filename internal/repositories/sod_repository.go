// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// SoDRepository persists iam_sod_rules and iam_sod_violations.
//
// Tenant scoping follows falcon-id convention (RLS via
// app.current_tenant_id, applied by the connection middleware — see
// internal/repositories/withdb.go); queries additionally filter by
// tenant_id in application code for the tenant-scoped BFF surface,
// belt-and-suspenders with RLS per this repo's existing pattern in
// role_repository.go/permission_repository.go.
type SoDRepository struct {
	db DBPool
}

// NewSoDRepository is an exported function.
func NewSoDRepository(db *pgxpool.Pool) *SoDRepository {
	return &SoDRepository{db: db}
}

// ListActiveRulesForTenant returns every active (not disabled) rule
// visible to a tenant: the tenant's own rules plus every platform default
// rule (tenant_id IS NULL).
func (r *SoDRepository) ListActiveRulesForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.SoDRule, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, module, permission_a, permission_b, mode,
		       description, is_default, created_by, disabled_at, created_at, updated_at
		FROM iam_sod_rules
		WHERE disabled_at IS NULL
		  AND (tenant_id = $1 OR tenant_id IS NULL)
		  -- A tenant "disables" a platform default by owning a pre-disabled
		  -- override for the same pair (CreateDisablingOverride); the default
		  -- must not stay active for that tenant.
		  AND NOT (
		      tenant_id IS NULL AND EXISTS (
		          SELECT 1 FROM iam_sod_rules o
		          WHERE o.tenant_id = $1
		            AND o.permission_a = iam_sod_rules.permission_a
		            AND o.permission_b = iam_sod_rules.permission_b
		            AND o.disabled_at IS NOT NULL
		            AND NOT EXISTS (
		                SELECT 1 FROM iam_sod_rules o2
		                WHERE o2.tenant_id = $1
		                  AND o2.permission_a = o.permission_a
		                  AND o2.permission_b = o.permission_b
		                  AND o2.disabled_at IS NULL
		            )
		      )
		  )
		ORDER BY module, permission_a, permission_b`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListActiveRulesForTenant: %w", err)
	}
	defer rows.Close()

	return scanSoDRules(rows)
}

// ListRulesForTenant returns every rule (active or disabled) that belongs
// to the tenant itself, i.e. excludes platform defaults — used by the
// tenant-facing SoD Rules screen's "your rules" listing. Combine with the
// platform-defaults listing (ListDefaultRules) for the full editor view.
func (r *SoDRepository) ListRulesForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.SoDRule, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, module, permission_a, permission_b, mode,
		       description, is_default, created_by, disabled_at, created_at, updated_at
		FROM iam_sod_rules
		WHERE tenant_id = $1
		ORDER BY module, permission_a, permission_b`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListRulesForTenant: %w", err)
	}
	defer rows.Close()

	return scanSoDRules(rows)
}

// ListDefaultRules returns every platform-default rule (tenant_id IS
// NULL), active or disabled.
func (r *SoDRepository) ListDefaultRules(ctx context.Context) ([]models.SoDRule, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, module, permission_a, permission_b, mode,
		       description, is_default, created_by, disabled_at, created_at, updated_at
		FROM iam_sod_rules
		WHERE tenant_id IS NULL
		ORDER BY module, permission_a, permission_b`)
	if err != nil {
		return nil, fmt.Errorf("ListDefaultRules: %w", err)
	}
	defer rows.Close()

	return scanSoDRules(rows)
}

// GetRuleByIDAndTenant fetches a tenant-owned rule (never a platform
// default — those are edited only via a tenant-scoped disabling override,
// never mutated in place by a tenant).
func (r *SoDRepository) GetRuleByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.SoDRule, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, module, permission_a, permission_b, mode,
		       description, is_default, created_by, disabled_at, created_at, updated_at
		FROM iam_sod_rules
		WHERE id = $1 AND tenant_id = $2`, id, tenantID)

	rule, err := scanSoDRule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetRuleByIDAndTenant: %w", err)
	}
	return rule, nil
}

// CreateRule inserts a tenant-owned SoD rule (a net-new addition, or a
// disabling override of a default pair).
func (r *SoDRepository) CreateRule(ctx context.Context, rule *models.SoDRule) error {
	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	err := r.db.QueryRow(ctx, `
		INSERT INTO iam_sod_rules
			(id, tenant_id, module, permission_a, permission_b, mode, description, is_default, created_by, disabled_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING created_at, updated_at`,
		rule.ID, rule.TenantID, rule.Module, rule.PermissionA, rule.PermissionB,
		rule.Mode, rule.Description, rule.IsDefault, rule.CreatedBy, rule.DisabledAt,
	).Scan(&rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		return fmt.Errorf("CreateRule: %w", err)
	}
	return nil
}

// UpdateRule applies a partial update to a tenant-owned rule. Only
// non-nil fields on req are changed.
func (r *SoDRepository) UpdateRule(ctx context.Context, id, tenantID uuid.UUID, req *models.UpdateSoDRuleRequest) (*models.SoDRule, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE iam_sod_rules
		SET mode        = COALESCE($3, mode),
		    description = COALESCE($4, description),
		    disabled_at = CASE
		                      WHEN $5::boolean IS NULL THEN disabled_at
		                      WHEN $5::boolean = true THEN COALESCE(disabled_at, now())
		                      ELSE NULL
		                  END,
		    updated_at  = now()
		WHERE id = $1 AND tenant_id = $2
		RETURNING id, tenant_id, module, permission_a, permission_b, mode,
		          description, is_default, created_by, disabled_at, created_at, updated_at`,
		id, tenantID, req.Mode, req.Description, req.Disabled)

	rule, err := scanSoDRule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("UpdateRule: %w", err)
	}
	return rule, nil
}

// UpsertViolation records (or refreshes) a SoD violation for
// (tenantID, userID, ruleID). If an open or previously-resolved violation
// already exists for that triple, its snapshot fields and detected_at are
// refreshed and resolved_at is cleared (re-detection reopens it).
func (r *SoDRepository) UpsertViolation(ctx context.Context, v *models.SoDViolation) error {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	err := r.db.QueryRow(ctx, `
		INSERT INTO iam_sod_violations
			(id, tenant_id, user_id, rule_id, permission_a, permission_b, mode, role_ids)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, user_id, rule_id) DO UPDATE
		SET permission_a = EXCLUDED.permission_a,
		    permission_b = EXCLUDED.permission_b,
		    mode         = EXCLUDED.mode,
		    role_ids     = EXCLUDED.role_ids,
		    detected_at  = now(),
		    resolved_at  = NULL,
		    resolved_by  = NULL
		RETURNING id, detected_at`,
		v.ID, v.TenantID, v.UserID, v.RuleID, v.PermissionA, v.PermissionB, v.Mode, v.RoleIDs,
	).Scan(&v.ID, &v.DetectedAt)
	if err != nil {
		return fmt.Errorf("UpsertViolation: %w", err)
	}
	return nil
}

// ListViolationsForTenant returns violations for a tenant. When
// openOnly is true, only unresolved violations are returned (the
// default view for the SoD violation report screen, §8.3).
func (r *SoDRepository) ListViolationsForTenant(ctx context.Context, tenantID uuid.UUID, openOnly bool) ([]models.SoDViolation, error) {
	query := `
		SELECT id, tenant_id, user_id, rule_id, permission_a, permission_b, mode, role_ids,
		       detected_at, resolved_at, resolved_by
		FROM iam_sod_violations
		WHERE tenant_id = $1`
	if openOnly {
		query += " AND resolved_at IS NULL"
	}
	query += " ORDER BY detected_at DESC"

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListViolationsForTenant: %w", err)
	}
	defer rows.Close()

	var out []models.SoDViolation
	for rows.Next() {
		var v models.SoDViolation
		if err := rows.Scan(&v.ID, &v.TenantID, &v.UserID, &v.RuleID, &v.PermissionA, &v.PermissionB,
			&v.Mode, &v.RoleIDs, &v.DetectedAt, &v.ResolvedAt, &v.ResolvedBy); err != nil {
			return nil, fmt.Errorf("ListViolationsForTenant: scan: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListViolationsForTenant: %w", err)
	}
	return out, nil
}

// scanSoDRule uses the shared rowScanner interface (declared in
// oauth_trusted_external_issuer_repository.go) that abstracts pgx.Row vs
// pgx.Rows for scan code.
func scanSoDRule(row rowScanner) (*models.SoDRule, error) {
	var rule models.SoDRule
	err := row.Scan(&rule.ID, &rule.TenantID, &rule.Module, &rule.PermissionA, &rule.PermissionB,
		&rule.Mode, &rule.Description, &rule.IsDefault, &rule.CreatedBy, &rule.DisabledAt,
		&rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

func scanSoDRules(rows pgx.Rows) ([]models.SoDRule, error) {
	var out []models.SoDRule
	for rows.Next() {
		rule, err := scanSoDRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scanSoDRules: %w", err)
		}
		out = append(out, *rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scanSoDRules: %w", err)
	}
	return out, nil
}

// ReportViolation records a violation found by the continuous re-evaluation
// job. Unlike UpsertViolation it keeps detected_at of a violation that is
// already open, and reports newlyOpen=true only when the violation did not
// exist or was resolved before (so audit/metrics fire once per occurrence,
// not once per daily run).
func (r *SoDRepository) ReportViolation(ctx context.Context, v *models.SoDViolation) (newlyOpen bool, err error) {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	err = r.db.QueryRow(ctx, `
		WITH prev AS (
			SELECT resolved_at FROM iam_sod_violations
			WHERE tenant_id = $2 AND user_id = $3 AND rule_id = $4
		)
		INSERT INTO iam_sod_violations
			(id, tenant_id, user_id, rule_id, permission_a, permission_b, mode, role_ids)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, user_id, rule_id) DO UPDATE SET
			permission_a = EXCLUDED.permission_a,
			permission_b = EXCLUDED.permission_b,
			mode         = EXCLUDED.mode,
			role_ids     = EXCLUDED.role_ids,
			detected_at  = CASE WHEN iam_sod_violations.resolved_at IS NULL
			                    THEN iam_sod_violations.detected_at ELSE now() END,
			resolved_at  = NULL,
			resolved_by  = NULL
		RETURNING id, detected_at,
			NOT EXISTS (SELECT 1 FROM prev)
			OR (SELECT resolved_at IS NOT NULL FROM prev)`,
		v.ID, v.TenantID, v.UserID, v.RuleID, v.PermissionA, v.PermissionB, v.Mode, v.RoleIDs,
	).Scan(&v.ID, &v.DetectedAt, &newlyOpen)
	if err != nil {
		return false, fmt.Errorf("ReportViolation: %w", err)
	}
	return newlyOpen, nil
}

// ResolveViolationsNotIn marks the user's open violations whose rule is not in
// keepRuleIDs as resolved (system-resolved: resolved_by stays NULL). Used when
// a re-evaluation finds the conflict no longer holds (role removed, rule
// disabled or deleted). Returns how many rows it resolved.
func (r *SoDRepository) ResolveViolationsNotIn(ctx context.Context, tenantID, userID uuid.UUID, keepRuleIDs []uuid.UUID) (int, error) {
	if keepRuleIDs == nil {
		keepRuleIDs = []uuid.UUID{}
	}
	tag, err := r.db.Exec(ctx, `
		UPDATE iam_sod_violations
		SET resolved_at = now()
		WHERE tenant_id = $1 AND user_id = $2 AND resolved_at IS NULL
		  AND NOT (rule_id = ANY($3))`, tenantID, userID, keepRuleIDs)
	if err != nil {
		return 0, fmt.Errorf("ResolveViolationsNotIn: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ListTenantsForSoDReevaluation returns every tenant that has a user with an
// unexpired role assignment or an open violation.
func (r *SoDRepository) ListTenantsForSoDReevaluation(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := r.db.Query(ctx, `
		SELECT r.tenant_id
		FROM iam_user_roles ur JOIN iam_roles r ON r.id = ur.role_id
		WHERE ur.expires_at IS NULL OR ur.expires_at > now()
		UNION
		SELECT tenant_id FROM iam_sod_violations WHERE resolved_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("ListTenantsForSoDReevaluation: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("ListTenantsForSoDReevaluation scan: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ListUsersForSoDReevaluation returns, for one tenant, every user with an
// unexpired role assignment (and the role ids held) plus users that only have
// open violations (empty role list), so stale violations get resolved.
func (r *SoDRepository) ListUsersForSoDReevaluation(ctx context.Context, tenantID uuid.UUID) (map[uuid.UUID][]uuid.UUID, error) {
	rows, err := r.db.Query(ctx, `
		SELECT ur.user_id, ur.role_id
		FROM iam_user_roles ur JOIN iam_roles r ON r.id = ur.role_id
		WHERE r.tenant_id = $1 AND (ur.expires_at IS NULL OR ur.expires_at > now())
		UNION ALL
		SELECT user_id, NULL::uuid FROM iam_sod_violations
		WHERE tenant_id = $1 AND resolved_at IS NULL`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListUsersForSoDReevaluation: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID][]uuid.UUID{}
	for rows.Next() {
		var userID uuid.UUID
		var roleID *uuid.UUID
		if err := rows.Scan(&userID, &roleID); err != nil {
			return nil, fmt.Errorf("ListUsersForSoDReevaluation scan: %w", err)
		}
		if roleID != nil {
			out[userID] = append(out[userID], *roleID)
		} else if _, ok := out[userID]; !ok {
			out[userID] = nil
		}
	}
	return out, rows.Err()
}

// CountOpenViolations returns the number of unresolved violations.
func (r *SoDRepository) CountOpenViolations(ctx context.Context) (int, error) {
	var n int
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM iam_sod_violations WHERE resolved_at IS NULL`).Scan(&n); err != nil {
		return 0, fmt.Errorf("CountOpenViolations: %w", err)
	}
	return n, nil
}

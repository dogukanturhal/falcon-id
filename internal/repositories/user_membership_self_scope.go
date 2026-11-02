// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// WithUserMembershipScope runs fn in a transaction where app.current_user_id
// is userID. iam_user_memberships has FORCE RLS with a tenant-only policy and
// falcon_id_app is NOBYPASSRLS, so a lookup by user across tenants (tenant
// switcher, tenant token exchange) sees nothing on the raw pool. Migration
// 0019 adds a SELECT-only policy matching user_id = app.current_user_id; the
// GUC is transaction-local (set_config(..., true)) so it never leaks onto a
// pooled connection. Callers MUST pass the authenticated user's own ID.
func WithUserMembershipScope(ctx context.Context, db DBTX, userID uuid.UUID, fn func(pgx.Tx) error) error {
	if userID == uuid.Nil {
		return errors.New("WithUserMembershipScope: nil user id")
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("WithUserMembershipScope: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit makes rollback a no-op
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_user_id', $1, true)", userID.String()); err != nil {
		return fmt.Errorf("WithUserMembershipScope: set app.current_user_id: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("WithUserMembershipScope: commit: %w", err)
	}
	return nil
}

// ResolveTenantExchange returns userID's membership in tenantID together with
// the tenant's status and the user's role names scoped to tenantID, or nil
// when no membership row exists. It does not judge the result: the caller
// rejects inactive memberships, unsupported seat classes and suspended
// tenants.
func (r *UserMembershipRepository) ResolveTenantExchange(ctx context.Context, userID, tenantID uuid.UUID) (*models.TenantExchangeMembership, error) {
	var out *models.TenantExchangeMembership
	err := WithUserMembershipScope(ctx, r.db, userID, func(tx pgx.Tx) error {
		var m models.TenantExchangeMembership
		err := tx.QueryRow(ctx, `
			SELECT m.tenant_id, t.slug, t.status, m.seat_class, m.status
			FROM iam_user_memberships m
			INNER JOIN iam_tenants t ON t.id = m.tenant_id
			WHERE m.user_id = $1 AND m.tenant_id = $2`,
			userID, tenantID,
		).Scan(&m.TenantID, &m.TenantSlug, &m.TenantStatus, &m.SeatClass, &m.Status)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("ResolveTenantExchange: membership: %w", err)
		}

		// Role names in the target tenant only: an accountant who is an
		// administrator in their own partner tenant must not carry that
		// role name into a client-tenant token.
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT r.name
			FROM iam_user_roles ur
			INNER JOIN iam_roles r ON r.id = ur.role_id
			WHERE ur.user_id = $1
				AND r.tenant_id = $2
				AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
			ORDER BY r.name`,
			userID, tenantID,
		)
		if err != nil {
			return fmt.Errorf("ResolveTenantExchange: roles: %w", err)
		}
		defer rows.Close()
		m.RoleNames = make([]string, 0)
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return fmt.Errorf("ResolveTenantExchange: scan role: %w", err)
			}
			m.RoleNames = append(m.RoleNames, name)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("ResolveTenantExchange: roles: %w", err)
		}
		out = &m
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

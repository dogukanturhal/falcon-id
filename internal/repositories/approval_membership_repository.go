// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ListApprovalMembers is a complete authoritative non-guest membership snapshot,
// not a billable-seat count. Only external guests are excluded; every other
// active seat class is included. Lifecycle filtering is immediate,
// even before the access-expiry/deletion workers have run.
func (r *UserMembershipRepository) ListApprovalMembers(ctx context.Context, tenantID uuid.UUID) ([]uuid.UUID, error) {
	members := make([]uuid.UUID, 0)
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT m.user_id
			FROM iam_user_memberships m JOIN iam_users u ON u.id = m.user_id
			WHERE m.tenant_id = $1 AND m.status = 'active'
			  AND m.seat_class <> 'external'
			  AND (m.access_expires_at IS NULL OR m.access_expires_at > now())
			  AND u.is_active = true AND u.deletion_scheduled_at IS NULL
			  AND (u.activation_status IS NULL OR u.activation_status NOT IN ('pending_deletion', 'admin_deleted'))
			ORDER BY m.user_id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			members = append(members, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("approval membership snapshot: %w", err)
	}
	return members, nil
}

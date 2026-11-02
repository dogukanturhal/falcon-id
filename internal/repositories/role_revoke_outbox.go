// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RoleRevokeEventType reserves these rows for the unbounded security-revoke
// drainer, rather than the generic outbox's finite retry/dead-letter policy.
const RoleRevokeEventType = "role.revoked"

// deleteRolesWithOutbox records the exact SpiceDB tuple for each removed role
// in the same statement/transaction. Roles being reinserted are not revokes.
func deleteRolesWithOutbox(ctx context.Context, tx pgx.Tx, deleteSQL string, args []interface{}, kept []uuid.UUID) error {
	if kept == nil {
		kept = []uuid.UUID{}
	}
	query := fmt.Sprintf(`WITH removed AS (%s RETURNING ur.user_id, ur.role_id)
		INSERT INTO iam_permission_outbox
		(id, tenant_id, event_type, resource_type, resource_id, relation,
		 subject_type, subject_id, operation, status, retry_count, max_retries, created_at)
		SELECT gen_random_uuid(), r.tenant_id, 'role.revoked', 'role',
		 r.tenant_id::text || '/' || r.id::text, 'member', 'user',
		 r.tenant_id::text || '/' || removed.user_id::text, 'delete', 'pending', 0, 2147483647, NOW()
		FROM removed JOIN iam_roles r ON r.id = removed.role_id
		WHERE NOT (removed.role_id = ANY($%d::uuid[]))`, deleteSQL, len(args)+1)
	_, err := tx.Exec(ctx, query, append(args, kept)...)
	return err
}

// EnqueueRoleRevokeTx also covers JIT grants whose UI projection never landed.
func EnqueueRoleRevokeTx(ctx context.Context, tx pgx.Tx, tenantID, userID, roleID uuid.UUID) error {
	_, err := tx.Exec(ctx, `INSERT INTO iam_permission_outbox
		(id, tenant_id, event_type, resource_type, resource_id, relation,
		 subject_type, subject_id, operation, status, retry_count, max_retries, created_at)
		VALUES ($1, $2, 'role.revoked', 'role', $3, 'member', 'user', $4,
		 'delete', 'pending', 0, 2147483647, NOW())`,
		uuid.New(), tenantID, tenantID.String()+"/"+roleID.String(), tenantID.String()+"/"+userID.String())
	return err
}

// RoleRevokeRetryDelay is overflow-safe even after a prolonged outage.
func RoleRevokeRetryDelay(attempt int) time.Duration {
	if attempt >= 6 {
		return 60 * time.Second
	}
	if attempt < 1 {
		attempt = 1
	}
	return time.Second * time.Duration(1<<uint(attempt))
}

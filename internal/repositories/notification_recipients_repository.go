// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// NotificationRecipientRow is one candidate notification recipient in a
// tenant. Active uses the same predicates as ListApprovalMembers except that
// seat_class is reported (MembershipKind) rather than filtered. Email is
// empty unless the user is active, so inactive/deleted accounts never leak an
// address. A requested user with no membership or no iam_users row comes back
// with Active=false.
type NotificationRecipientRow struct {
	UserID         uuid.UUID
	Email          string
	Active         bool
	MembershipKind string // "internal", "external", or "" when the user has no membership
	SystemRoles    []string
}

// NotificationRecipientRepository resolves notification recipients from
// iam_user_memberships, iam_users and iam_user_roles/iam_roles.
type NotificationRecipientRepository struct {
	db  DBTX
	enc *crypto.EncryptionService
}

// NewNotificationRecipientRepository creates the repository. enc decrypts the
// per-tenant encrypted iam_users.email; it is required to return addresses.
func NewNotificationRecipientRepository(db *pgxpool.Pool, enc *crypto.EncryptionService) *NotificationRecipientRepository {
	return &NotificationRecipientRepository{db: db, enc: enc}
}

// ListNotificationRecipients returns, in one tenant-scoped query, the
// requested users plus every active holder of one of systemRoles (matched by
// iam_roles.name within the tenant, non-expired iam_user_roles only).
// Requested users are always returned; role holders are returned only when
// active. SystemRoles lists which of the requested role names the user holds.
func (r *NotificationRecipientRepository) ListNotificationRecipients(ctx context.Context, tenantID uuid.UUID, userIDs []uuid.UUID, systemRoles []string) ([]NotificationRecipientRow, error) {
	if userIDs == nil {
		userIDs = []uuid.UUID{}
	}
	if systemRoles == nil {
		systemRoles = []string{}
	}
	type rawRow struct {
		NotificationRecipientRow
		homeTenant *uuid.UUID
	}
	var raw []rawRow
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH held AS (
				SELECT ur.user_id, array_agg(DISTINCT r.name ORDER BY r.name) AS names
				FROM iam_user_roles ur
				JOIN iam_roles r ON r.id = ur.role_id
				WHERE r.tenant_id = $1
				  AND r.name = ANY($3::text[])
				  AND (ur.expires_at IS NULL OR ur.expires_at > now())
				GROUP BY ur.user_id
			), cand AS (
				SELECT id, true AS requested FROM unnest($2::uuid[]) AS id
				UNION
				SELECT user_id, false FROM held
			), resolved AS (
				SELECT c.id AS user_id,
				       bool_or(c.requested) AS requested,
				       u.tenant_id AS home_tenant,
				       u.email,
				       COALESCE(m.status = 'active'
				                AND (m.access_expires_at IS NULL OR m.access_expires_at > now())
				                AND u.is_active = true
				                AND u.deletion_scheduled_at IS NULL
				                AND (u.activation_status IS NULL OR u.activation_status NOT IN ('pending_deletion', 'admin_deleted')),
				                false) AS active,
				       m.seat_class,
				       COALESCE(h.names, '{}'::text[]) AS names
				FROM cand c
				LEFT JOIN iam_user_memberships m ON m.tenant_id = $1 AND m.user_id = c.id
				LEFT JOIN iam_users u ON u.id = c.id
				LEFT JOIN held h ON h.user_id = c.id
				GROUP BY c.id, u.tenant_id, u.email, u.is_active, u.deletion_scheduled_at, u.activation_status,
				         m.status, m.access_expires_at, m.seat_class, h.names
			)
			SELECT user_id, home_tenant, email, active, seat_class, names
			FROM resolved
			WHERE requested OR active
			ORDER BY user_id`, tenantID, userIDs, systemRoles)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				row       rawRow
				email     *string
				seatClass *string
			)
			if err := rows.Scan(&row.UserID, &row.homeTenant, &email, &row.Active, &seatClass, &row.SystemRoles); err != nil {
				return err
			}
			if row.Active && email != nil {
				row.Email = *email
			}
			switch {
			case seatClass == nil:
			case *seatClass == "external":
				row.MembershipKind = "external"
			default:
				row.MembershipKind = "internal"
			}
			raw = append(raw, row)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("notification recipients snapshot: %w", err)
	}

	out := make([]NotificationRecipientRow, 0, len(raw))
	for _, row := range raw {
		if row.Email != "" {
			if r.enc == nil || row.homeTenant == nil {
				return nil, fmt.Errorf("notification recipients: cannot decrypt email for user %s", row.UserID)
			}
			dec, err := r.enc.DecryptForTenant(*row.homeTenant, row.Email)
			if err != nil {
				return nil, fmt.Errorf("notification recipients: decrypt email: %w", err)
			}
			row.Email = dec
		}
		out = append(out, row.NotificationRecipientRow)
	}
	return out, nil
}

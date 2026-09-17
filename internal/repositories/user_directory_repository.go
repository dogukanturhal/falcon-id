// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ListTenantMemberCards returns ONE PAGE of active members in a tenant (the
// viewer excluded) plus the total count, for the peer member directory. It is
// purpose-built and lean: it selects ONLY the columns a directory card needs
// (identity + the visibility-gated fields + the prefs that gate them),
// decrypts just this page's PII in place, and runs NO per-user roles query —
// unlike the admin UserRepository.List. The total drives pagination on top.
//
// PII (email/first_name/last_name/display_name/phone) is decrypted via the same
// r.decryptPII path List uses; title/avatar_url/preferences are plaintext.
// preferences is returned inline (no separate fetch), so the whole page costs
// exactly two queries: COUNT + the page SELECT.
func (r *UserRepository) ListTenantMemberCards(
	ctx context.Context,
	tenantID, viewerID uuid.UUID,
	limit, offset int,
) ([]models.User, int, error) {
	var total int
	if err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_users WHERE tenant_id = $1 AND is_active = true AND id <> $2`,
		tenantID, viewerID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("ListTenantMemberCards: count: %w", err)
	}
	if total == 0 {
		return nil, 0, nil
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, display_name, first_name, last_name, username,
		       avatar_url, title, email, phone, COALESCE(preferences, '{}'::jsonb)
		  FROM iam_users
		 WHERE tenant_id = $1 AND is_active = true AND id <> $2
		 ORDER BY created_at
		 LIMIT $3 OFFSET $4`, tenantID, viewerID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("ListTenantMemberCards: query: %w", err)
	}
	defer rows.Close()

	var out []models.User
	for rows.Next() {
		var u models.User
		var prefs []byte
		if err := rows.Scan(
			&u.ID, &u.TenantID, &u.DisplayName, &u.FirstName, &u.LastName, &u.Username,
			&u.AvatarURL, &u.Title, &u.Email, &u.Phone, &prefs,
		); err != nil {
			return nil, 0, fmt.Errorf("ListTenantMemberCards: scan: %w", err)
		}
		u.Preferences = prefs
		// Decrypt this row's PII only (no fetch of the full column set).
		if err := r.decryptPII(&u); err != nil {
			return nil, 0, fmt.Errorf("ListTenantMemberCards: decrypt user %s: %w", u.ID, err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ListTenantMemberCards: rows: %w", err)
	}
	return out, total, nil
}

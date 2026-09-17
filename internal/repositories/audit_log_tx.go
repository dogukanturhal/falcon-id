// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/jackc/pgx/v5"
)

// CreateAuditLogTx is the transaction-scoped form of TokenRepository.CreateAuditLog.
func CreateAuditLogTx(ctx context.Context, tx pgx.Tx, log *models.AuditLog) error {
	return tx.QueryRow(ctx, `INSERT INTO iam_audit_log (tenant_id, user_id, target_user_id, action, resource_type, resource_id, details, ip_address, country_code, user_agent, success, error_message)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id, created_at`,
		log.TenantID, log.UserID, log.TargetUserID, log.Action, log.ResourceType, log.ResourceID, log.Details, log.IPAddress, log.CountryCode, log.UserAgent, log.Success, log.ErrorMessage,
	).Scan(&log.ID, &log.CreatedAt)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const auditResourceTypeAPIKey = "api_key"

// Audit actions for tenant API keys. Secrets and key hashes are never part of
// the details.
const (
	AuditActionAPIKeyCreated    = "api_key.created"
	AuditActionAPIKeyRotated    = "api_key.rotated"
	AuditActionAPIKeyRevoked    = "api_key.revoked"
	AuditActionAPIKeyDeleted    = "api_key.deleted"
	AuditActionAPIKeyAuthDenied = "api_key.auth_denied"

	AuditActionAPIKeyCompanySyncFailed = "api_key.company_sync_failed"
)

// LogTenantAPIKeyEvent records a tenant API key lifecycle or authentication
// event. actorID is the human who acted (nil for key-driven events).
func (s *AuditService) LogTenantAPIKeyEvent(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, keyID uuid.UUID, action string, success bool, details map[string]interface{}) {
	if s == nil || s.tokenRepo == nil {
		return
	}
	resourceType := auditResourceTypeAPIKey
	log := &models.AuditLog{
		TenantID:     tenantID,
		UserID:       actorID,
		Action:       action,
		ResourceType: &resourceType,
		ResourceID:   &keyID,
		Details:      details,
		Success:      success,
	}
	if err := s.tokenRepo.CreateAuditLog(ctx, log); err != nil {
		logger.Error("Failed to create API key audit log", zap.String("action", action), zap.Error(err))
	}
}

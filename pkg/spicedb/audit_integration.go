// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/audit"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	contextKeyClientIP      contextKey = "client_ip"
	contextKeyUserAgent     contextKey = "user_agent"
	contextKeyRequestID     contextKey = "request_id"
	contextKeyCorrelationID contextKey = "correlation_id"
)

// AuditedClient wraps the SpiceDB client with audit logging
type AuditedClient struct {
	*Client
	auditLogger audit.Logger
}

// NewAuditedClient creates a new audited SpiceDB client
func NewAuditedClient(client *Client, auditLogger audit.Logger) *AuditedClient {
	return &AuditedClient{
		Client:      client,
		auditLogger: auditLogger,
	}
}

// WriteUserRole writes a user-role relationship with audit logging
func (c *AuditedClient) WriteUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error) {
	// Execute the write
	token, err := c.Client.WriteUserRole(ctx, tenantID, userID, roleID)

	// Extract context information
	actorID := GetAuthenticatedUser(ctx)
	if actorID == uuid.Nil {
		actorID = userID // Fallback to user if no authenticated user
	}

	ipAddress, userAgent, requestID := extractContextInfo(ctx)

	// Log the relationship change
	if c.auditLogger != nil {
		auditEntry := audit.RelationshipAuditEntry{
			TenantID:     tenantID,
			ActorID:      actorID,
			ActorType:    audit.ActorTypeUser,
			Action:       audit.ActionRelationshipCreated,
			ResourceType: "role",
			ResourceID:   roleID.String(),
			Relation:     "member",
			SubjectType:  spicedbObjectTypeUser,
			SubjectID:    userID.String(),
			Metadata: map[string]interface{}{
				"operation": "assign_user_role",
			},
			IPAddress: ipAddress,
			UserAgent: userAgent,
			RequestID: requestID,
		}

		if err != nil {
			auditEntry.Metadata["error"] = err.Error()
		}

		if auditErr := c.auditLogger.LogRelationshipChange(ctx, auditEntry); auditErr != nil {
			logger.Log.Warn("Failed to log relationship change audit",
				zap.Error(auditErr),
				zap.String("tenant_id", tenantID.String()),
			)
		}
	}

	if err != nil {
		return "", fmt.Errorf("WriteUserRole: %w", err)
	}
	return token, nil
}

// DeleteUserRole removes a user-role relationship with audit logging
func (c *AuditedClient) DeleteUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error) {
	// Execute the delete
	token, err := c.Client.DeleteUserRole(ctx, tenantID, userID, roleID)

	// Extract context information
	actorID := GetAuthenticatedUser(ctx)
	if actorID == uuid.Nil {
		actorID = userID
	}

	ipAddress, userAgent, requestID := extractContextInfo(ctx)

	// Log the relationship deletion
	if c.auditLogger != nil {
		auditEntry := audit.RelationshipAuditEntry{
			TenantID:     tenantID,
			ActorID:      actorID,
			ActorType:    audit.ActorTypeUser,
			Action:       audit.ActionRelationshipDeleted,
			ResourceType: "role",
			ResourceID:   roleID.String(),
			Relation:     "member",
			SubjectType:  spicedbObjectTypeUser,
			SubjectID:    userID.String(),
			Metadata: map[string]interface{}{
				"operation": "remove_user_role",
			},
			IPAddress: ipAddress,
			UserAgent: userAgent,
			RequestID: requestID,
		}

		if err != nil {
			auditEntry.Metadata["error"] = err.Error()
		}

		if auditErr := c.auditLogger.LogRelationshipChange(ctx, auditEntry); auditErr != nil {
			logger.Log.Warn("Failed to log relationship deletion audit",
				zap.Error(auditErr),
				zap.String("tenant_id", tenantID.String()),
			)
		}
	}

	if err != nil {
		return "", fmt.Errorf("DeleteUserRole: %w", err)
	}
	return token, nil
}

// WriteRolePermission writes a role-permission relationship with audit logging
func (c *AuditedClient) WriteRolePermission(ctx context.Context, tenantID, roleID uuid.UUID, objectType, objectID, relation string) (string, error) {
	// Execute the write
	token, err := c.Client.WriteRolePermission(ctx, tenantID, roleID, objectType, objectID, relation)

	// Extract context information
	actorID := GetAuthenticatedUser(ctx)
	if actorID == uuid.Nil {
		actorID = roleID // Fallback
	}

	ipAddress, userAgent, requestID := extractContextInfo(ctx)

	// Log the relationship change
	if c.auditLogger != nil {
		auditEntry := audit.RelationshipAuditEntry{
			TenantID:     tenantID,
			ActorID:      actorID,
			ActorType:    audit.ActorTypeUser,
			Action:       audit.ActionRelationshipCreated,
			ResourceType: objectType,
			ResourceID:   objectID,
			Relation:     relation,
			SubjectType:  "role",
			SubjectID:    roleID.String(),
			Metadata: map[string]interface{}{
				"operation": "assign_role_permission",
			},
			IPAddress: ipAddress,
			UserAgent: userAgent,
			RequestID: requestID,
		}

		if err != nil {
			auditEntry.Metadata["error"] = err.Error()
		}

		if auditErr := c.auditLogger.LogRelationshipChange(ctx, auditEntry); auditErr != nil {
			logger.Log.Warn("Failed to log role permission audit",
				zap.Error(auditErr),
				zap.String("tenant_id", tenantID.String()),
			)
		}
	}

	if err != nil {
		return "", fmt.Errorf("WriteRolePermission: %w", err)
	}
	return token, nil
}

// CheckPermission checks a permission with optional audit logging for denials
func (c *AuditedClient) CheckPermission(ctx context.Context, tenantID, userID uuid.UUID, objectType, objectID, permission string) (bool, error) {
	startTime := time.Now()

	// Execute the permission check
	allowed, err := c.Client.CheckPermission(ctx, tenantID, userID, objectType, objectID, permission)

	latency := time.Since(startTime)

	// Only log denials and errors for security monitoring
	// Don't log successful checks to avoid excessive audit log volume
	if c.auditLogger != nil && (!allowed || err != nil) {
		ipAddress, userAgent, requestID := extractContextInfo(ctx)

		errorMsg := ""
		if err != nil {
			errorMsg = err.Error()
		}

		auditEntry := audit.PermissionCheckAuditEntry{
			TenantID:     tenantID,
			ActorID:      userID,
			ResourceType: objectType,
			ResourceID:   objectID,
			Permission:   permission,
			Result:       allowed,
			Latency:      latency,
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			RequestID:    requestID,
			ErrorMessage: errorMsg,
		}

		if auditErr := c.auditLogger.LogPermissionCheck(ctx, auditEntry); auditErr != nil {
			logger.Log.Warn("Failed to log permission check audit",
				zap.Error(auditErr),
				zap.String("tenant_id", tenantID.String()),
			)
		}
	}

	if err != nil {
		return allowed, fmt.Errorf("CheckPermission: %w", err)
	}
	return allowed, nil
}

// LogSecurityEvent logs a security-related event
func (c *AuditedClient) LogSecurityEvent(ctx context.Context, entry audit.SecurityAuditEntry) error {
	if c.auditLogger == nil {
		return nil
	}

	return c.auditLogger.LogSecurityEvent(ctx, entry)
}

// extractContextInfo extracts IP address, user agent, and request ID from context
func extractContextInfo(ctx context.Context) (ipAddress, userAgent, requestID string) {
	// Try to extract from context values using type-safe keys
	if ip := ctx.Value(contextKeyClientIP); ip != nil {
		if ipStr, ok := ip.(string); ok {
			ipAddress = ipStr
		}
	}

	if ua := ctx.Value(contextKeyUserAgent); ua != nil {
		if uaStr, ok := ua.(string); ok {
			userAgent = uaStr
		}
	}

	if rid := ctx.Value(contextKeyRequestID); rid != nil {
		if ridStr, ok := rid.(string); ok {
			requestID = ridStr
		}
	}

	// Try correlation ID as fallback for request ID
	if requestID == "" {
		if cid := ctx.Value(contextKeyCorrelationID); cid != nil {
			if cidStr, ok := cid.(string); ok {
				requestID = cidStr
			}
		}
	}

	return
}

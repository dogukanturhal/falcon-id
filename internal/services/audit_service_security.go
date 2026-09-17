// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ============================================================================
// SECURITY AUDIT LOGGING METHODS
// These methods log security-specific events for threat detection and compliance
// ============================================================================

// SecurityEventSeverity represents the severity level of a security event
type SecurityEventSeverity string

const (
	// SecuritySeverityLow is an exported identifier.
	SecuritySeverityLow SecurityEventSeverity = "low"
	// SecuritySeverityMedium is an exported identifier.
	SecuritySeverityMedium SecurityEventSeverity = "medium"
	// SecuritySeverityHigh is an exported identifier.
	SecuritySeverityHigh SecurityEventSeverity = "high"
	// SecuritySeverityCritical is an exported identifier.
	SecuritySeverityCritical SecurityEventSeverity = "critical"
)

// SecurityEventCategory represents the category of security event
type SecurityEventCategory string

const (
	// SecurityCategoryRateLimit is an exported identifier.
	SecurityCategoryRateLimit SecurityEventCategory = "rate_limit"
	// SecurityCategoryCSRF is an exported identifier.
	SecurityCategoryCSRF SecurityEventCategory = "csrf"
	// SecurityCategoryAuthorization is an exported identifier.
	SecurityCategoryAuthorization SecurityEventCategory = "authorization"
	// SecurityCategoryFileUpload is an exported identifier.
	SecurityCategoryFileUpload SecurityEventCategory = "file_upload"
	// SecurityCategoryTenantIsolation is an exported identifier.
	SecurityCategoryTenantIsolation SecurityEventCategory = "tenant_isolation"
	// SecurityCategoryAuthentication is an exported identifier.
	SecurityCategoryAuthentication SecurityEventCategory = "authentication"
	// SecurityCategoryInjection is an exported identifier.
	SecurityCategoryInjection SecurityEventCategory = "injection"
	// SecurityCategorySuspicious is an exported identifier.
	SecurityCategorySuspicious SecurityEventCategory = "suspicious_activity"
)

// SecurityAuditEvent represents a security-related audit event
type SecurityAuditEvent struct {
	TenantID    uuid.UUID
	UserID      *uuid.UUID
	IPAddress   string
	UserAgent   string
	RequestPath string
	RequestID   string
	Category    SecurityEventCategory
	Severity    SecurityEventSeverity
	Action      string
	Description string
	Details     map[string]interface{}
	Blocked     bool
	ThreatScore int // 0-100, used for risk assessment
}

// LogSecurityEvent logs a general security event
func (s *AuditService) LogSecurityEvent(ctx context.Context, event *SecurityAuditEvent) {
	if s.tokenRepo == nil {
		return
	}
	if event.Details == nil {
		event.Details = make(map[string]interface{})
	}

	// Add security-specific metadata
	event.Details["security_category"] = string(event.Category)
	event.Details["security_severity"] = string(event.Severity)
	event.Details["request_path"] = event.RequestPath
	event.Details["request_id"] = event.RequestID
	event.Details["blocked"] = event.Blocked
	event.Details["threat_score"] = event.ThreatScore

	resourceType := "security_event"
	log := &models.AuditLog{
		TenantID:     event.TenantID,
		UserID:       event.UserID,
		Action:       event.Action,
		ResourceType: &resourceType,
		IPAddress:    &event.IPAddress,
		UserAgent:    &event.UserAgent,
		Details:      event.Details,
		Success:      !event.Blocked, // Success means the request was allowed
	}

	if event.Blocked {
		log.ErrorMessage = &event.Description
	}

	if err := s.tokenRepo.CreateAuditLog(ctx, log); err != nil {
		logger.Error("Failed to create security audit log",
			zap.Error(err),
			zap.String("action", event.Action),
			zap.String("category", string(event.Category)),
		)
	}

	// Log high severity events to structured logger for real-time alerting
	if event.Severity == SecuritySeverityHigh || event.Severity == SecuritySeverityCritical {
		logger.Log.Warn("High severity security event",
			zap.String("category", string(event.Category)),
			zap.String("severity", string(event.Severity)),
			zap.String("action", event.Action),
			zap.String("description", event.Description),
			zap.String("ip_address", event.IPAddress),
			zap.String("request_path", event.RequestPath),
			zap.Bool("blocked", event.Blocked),
			zap.Int("threat_score", event.ThreatScore),
		)
	}
}

// LogRateLimitViolation logs when a rate limit is exceeded
func (s *AuditService) LogRateLimitViolation(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, ipAddress, userAgent, endpoint string, limiterType string, currentCount, limit int) {
	severity := SecuritySeverityMedium
	threatScore := 30

	// Escalate severity based on how much the limit was exceeded
	if currentCount > limit*2 {
		severity = SecuritySeverityHigh
		threatScore = 60
	}
	if currentCount > limit*5 {
		severity = SecuritySeverityCritical
		threatScore = 90
	}

	event := &SecurityAuditEvent{
		TenantID:    tenantID,
		UserID:      userID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		RequestPath: endpoint,
		Category:    SecurityCategoryRateLimit,
		Severity:    severity,
		Action:      "rate_limit_exceeded",
		Description: fmt.Sprintf("Rate limit exceeded on %s: %d requests (limit: %d)", endpoint, currentCount, limit),
		Details: map[string]interface{}{
			"limiter_type":  limiterType,
			"current_count": currentCount,
			"limit":         limit,
			"exceeded_by":   currentCount - limit,
		},
		Blocked:     true,
		ThreatScore: threatScore,
	}

	s.LogSecurityEvent(ctx, event)
}

// LogCSRFValidationFailure logs CSRF token or origin validation failures
func (s *AuditService) LogCSRFValidationFailure(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, ipAddress, userAgent, endpoint, failureReason string, requestOrigin, expectedOrigin string) {
	event := &SecurityAuditEvent{
		TenantID:    tenantID,
		UserID:      userID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		RequestPath: endpoint,
		Category:    SecurityCategoryCSRF,
		Severity:    SecuritySeverityHigh,
		Action:      "csrf_validation_failed",
		Description: fmt.Sprintf("CSRF validation failed: %s", failureReason),
		Details: map[string]interface{}{
			"failure_reason":  failureReason,
			"request_origin":  requestOrigin,
			"expected_origin": expectedOrigin,
		},
		Blocked:     true,
		ThreatScore: 70,
	}

	s.LogSecurityEvent(ctx, event)
}

// LogAuthorizationDenied logs when authorization/permission check fails
func (s *AuditService) LogAuthorizationDenied(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, ipAddress, endpoint, requiredPermission, resource string) {
	event := &SecurityAuditEvent{
		TenantID:    tenantID,
		UserID:      &userID,
		IPAddress:   ipAddress,
		RequestPath: endpoint,
		Category:    SecurityCategoryAuthorization,
		Severity:    SecuritySeverityMedium,
		Action:      "authorization_denied",
		Description: fmt.Sprintf("Access denied: missing permission '%s' for resource '%s'", requiredPermission, resource),
		Details: map[string]interface{}{
			"required_permission": requiredPermission,
			"resource":            resource,
		},
		Blocked:     true,
		ThreatScore: 40,
	}

	s.LogSecurityEvent(ctx, event)
}

// LogTenantIsolationViolation logs when a user attempts to access another tenant's resources
func (s *AuditService) LogTenantIsolationViolation(ctx context.Context, userTenantID, targetTenantID uuid.UUID, userID uuid.UUID, ipAddress, userAgent, endpoint, resourceType string, resourceID *uuid.UUID) {
	event := &SecurityAuditEvent{
		TenantID:    userTenantID,
		UserID:      &userID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		RequestPath: endpoint,
		Category:    SecurityCategoryTenantIsolation,
		Severity:    SecuritySeverityCritical,
		Action:      "tenant_isolation_violation",
		Description: fmt.Sprintf("Attempted cross-tenant access from tenant %s to tenant %s", userTenantID, targetTenantID),
		Details: map[string]interface{}{
			"user_tenant_id":   userTenantID.String(),
			"target_tenant_id": targetTenantID.String(),
			"resource_type":    resourceType,
		},
		Blocked:     true,
		ThreatScore: 95,
	}

	if resourceID != nil {
		event.Details["resource_id"] = resourceID.String()
	}

	s.LogSecurityEvent(ctx, event)
}

// LogFileUploadRejection logs when a file upload is rejected for security reasons
func (s *AuditService) LogFileUploadRejection(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, ipAddress, userAgent, endpoint, filename, rejectionReason string, fileSize int64, mimeType string) {
	severity := SecuritySeverityMedium
	threatScore := 40

	// Escalate for certain rejection reasons
	if rejectionReason == "polyglot_detected" || rejectionReason == "script_detected" {
		severity = SecuritySeverityHigh
		threatScore = 75
	}
	if rejectionReason == "path_traversal" || rejectionReason == "null_byte" {
		severity = SecuritySeverityCritical
		threatScore = 90
	}

	event := &SecurityAuditEvent{
		TenantID:    tenantID,
		UserID:      userID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		RequestPath: endpoint,
		Category:    SecurityCategoryFileUpload,
		Severity:    severity,
		Action:      "file_upload_rejected",
		Description: fmt.Sprintf("File upload rejected: %s", rejectionReason),
		Details: map[string]interface{}{
			"filename":         filename,
			"rejection_reason": rejectionReason,
			"file_size":        fileSize,
			"mime_type":        mimeType,
		},
		Blocked:     true,
		ThreatScore: threatScore,
	}

	s.LogSecurityEvent(ctx, event)
}

// LogSuspiciousActivity logs suspicious patterns that may indicate an attack
func (s *AuditService) LogSuspiciousActivity(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, ipAddress, userAgent, endpoint, activityType, description string, indicators map[string]interface{}) {
	event := &SecurityAuditEvent{
		TenantID:    tenantID,
		UserID:      userID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		RequestPath: endpoint,
		Category:    SecurityCategorySuspicious,
		Severity:    SecuritySeverityHigh,
		Action:      "suspicious_activity_detected",
		Description: description,
		Details: map[string]interface{}{
			"activity_type": activityType,
			"indicators":    indicators,
		},
		Blocked:     false, // Suspicious activity is logged but not necessarily blocked
		ThreatScore: 65,
	}

	s.LogSecurityEvent(ctx, event)
}

// LogInjectionAttempt logs potential SQL/XSS/command injection attempts
func (s *AuditService) LogInjectionAttempt(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, ipAddress, userAgent, endpoint, injectionType string, payload string, fieldName string) {
	// Truncate payload for storage (avoid storing huge payloads)
	truncatedPayload := payload
	if len(truncatedPayload) > 500 {
		truncatedPayload = truncatedPayload[:500] + "...[truncated]"
	}

	event := &SecurityAuditEvent{
		TenantID:    tenantID,
		UserID:      userID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		RequestPath: endpoint,
		Category:    SecurityCategoryInjection,
		Severity:    SecuritySeverityCritical,
		Action:      "injection_attempt_detected",
		Description: fmt.Sprintf("Potential %s injection attempt in field '%s'", injectionType, fieldName),
		Details: map[string]interface{}{
			"injection_type": injectionType,
			"field_name":     fieldName,
			"payload_sample": truncatedPayload,
		},
		Blocked:     true,
		ThreatScore: 95,
	}

	s.LogSecurityEvent(ctx, event)
}

// LogBruteForceAttempt logs brute force attack patterns
func (s *AuditService) LogBruteForceAttempt(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, ipAddress, userAgent, endpoint string, attemptCount int, timeWindowMinutes int, targetType string, targetIdentifier string) {
	severity := SecuritySeverityMedium
	threatScore := 50

	if attemptCount > 10 {
		severity = SecuritySeverityHigh
		threatScore = 75
	}
	if attemptCount > 25 {
		severity = SecuritySeverityCritical
		threatScore = 95
	}

	event := &SecurityAuditEvent{
		TenantID:    tenantID,
		UserID:      userID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		RequestPath: endpoint,
		Category:    SecurityCategoryAuthentication,
		Severity:    severity,
		Action:      "brute_force_detected",
		Description: fmt.Sprintf("Possible brute force attack: %d attempts in %d minutes", attemptCount, timeWindowMinutes),
		Details: map[string]interface{}{
			"attempt_count":       attemptCount,
			"time_window_minutes": timeWindowMinutes,
			"target_type":         targetType,
			"target_identifier":   targetIdentifier,
		},
		Blocked:     true,
		ThreatScore: threatScore,
	}

	s.LogSecurityEvent(ctx, event)
}

// LogAccountLockout logs when an account is locked due to failed attempts
func (s *AuditService) LogAccountLockout(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, ipAddress string, reason string, lockDurationMinutes int, failedAttempts int) {
	event := &SecurityAuditEvent{
		TenantID:    tenantID,
		UserID:      &userID,
		IPAddress:   ipAddress,
		Category:    SecurityCategoryAuthentication,
		Severity:    SecuritySeverityHigh,
		Action:      "account_locked",
		Description: fmt.Sprintf("Account locked: %s", reason),
		Details: map[string]interface{}{
			"lock_reason":           reason,
			"lock_duration_minutes": lockDurationMinutes,
			"failed_attempts":       failedAttempts,
		},
		Blocked:     true,
		ThreatScore: 60,
	}

	s.LogSecurityEvent(ctx, event)
}

// LogPrivilegeEscalationAttempt logs when a user attempts to gain unauthorized privileges
func (s *AuditService) LogPrivilegeEscalationAttempt(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, ipAddress, endpoint string, attemptedRole string, currentRoles []string) {
	event := &SecurityAuditEvent{
		TenantID:    tenantID,
		UserID:      &userID,
		IPAddress:   ipAddress,
		RequestPath: endpoint,
		Category:    SecurityCategoryAuthorization,
		Severity:    SecuritySeverityCritical,
		Action:      "privilege_escalation_attempt",
		Description: fmt.Sprintf("Attempted to gain unauthorized role: %s", attemptedRole),
		Details: map[string]interface{}{
			"attempted_role": attemptedRole,
			"current_roles":  currentRoles,
		},
		Blocked:     true,
		ThreatScore: 95,
	}

	s.LogSecurityEvent(ctx, event)
}

// LogTokenMisuse logs suspicious token usage patterns
func (s *AuditService) LogTokenMisuse(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, ipAddress, userAgent string, tokenType, misuseType, description string) {
	event := &SecurityAuditEvent{
		TenantID:    tenantID,
		UserID:      userID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Category:    SecurityCategoryAuthentication,
		Severity:    SecuritySeverityHigh,
		Action:      "token_misuse_detected",
		Description: description,
		Details: map[string]interface{}{
			"token_type":  tokenType,
			"misuse_type": misuseType,
		},
		Blocked:     true,
		ThreatScore: 80,
	}

	s.LogSecurityEvent(ctx, event)
}

// GetSecurityEventsForAnalysis retrieves security events for threat analysis
func (s *AuditService) GetSecurityEventsForAnalysis(ctx context.Context, tenantID uuid.UUID, ipAddress string, hoursBack int) ([]models.AuditLog, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not configured")
	}

	query := `
		SELECT id, tenant_id, user_id, action, resource_type, resource_id,
		       details, ip_address, user_agent, success, error_message,
		       correlation_id, target_user_id, created_at
		FROM iam_audit_log
		WHERE tenant_id = $1
		  AND ($2 = '' OR ip_address = $2)
		  AND resource_type = 'security_event'
		  AND created_at > NOW() - ($3 || ' hours')::INTERVAL
		ORDER BY created_at DESC
		LIMIT 1000`

	rows, err := s.db.Query(ctx, query, tenantID, ipAddress, hoursBack)
	if err != nil {
		logger.Error("Failed to query security events", zap.Error(err))
		return nil, fmt.Errorf("GetSecurityEventsForAnalysis: %w", err)
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var log models.AuditLog
		var detailsJSON []byte

		err := rows.Scan(
			&log.ID, &log.TenantID, &log.UserID, &log.Action, &log.ResourceType, &log.ResourceID,
			&detailsJSON, &log.IPAddress, &log.UserAgent, &log.Success, &log.ErrorMessage,
			&log.CorrelationID, &log.TargetUserID, &log.CreatedAt,
		)
		if err != nil {
			logger.Error("Failed to scan security event", zap.Error(err))
			continue
		}

		if len(detailsJSON) > 0 {
			if err := json.Unmarshal(detailsJSON, &log.Details); err != nil {
				logger.Warn("Failed to unmarshal security event details", zap.Error(err))
			}
		}

		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetSecurityEventsForAnalysis: row iteration error: %w", err)
	}

	return logs, nil
}

// CalculateThreatScoreForIP calculates an aggregate threat score for an IP address
func (s *AuditService) CalculateThreatScoreForIP(ctx context.Context, tenantID uuid.UUID, ipAddress string, hoursBack int) (int, map[string]int, error) {
	events, err := s.GetSecurityEventsForAnalysis(ctx, tenantID, ipAddress, hoursBack)
	if err != nil {
		return 0, nil, fmt.Errorf("CalculateThreatScoreForIP: GetSecurityEventsForAnalysis failed: %w", err)
	}

	totalScore := 0
	categoryCounts := make(map[string]int)

	for _, event := range events {
		if event.Details != nil {
			if score, ok := event.Details["threat_score"].(float64); ok {
				totalScore += int(score)
			}
			if category, ok := event.Details["security_category"].(string); ok {
				categoryCounts[category]++
			}
		}
	}

	// Normalize score (cap at 100)
	normalizedScore := totalScore
	if len(events) > 0 {
		normalizedScore = totalScore / len(events)
	}
	if normalizedScore > 100 {
		normalizedScore = 100
	}

	return normalizedScore, categoryCounts, nil
}

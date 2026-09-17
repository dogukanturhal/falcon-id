// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// AdminAuditEvent represents a comprehensive admin action audit event
type AdminAuditEvent struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	ActorID     uuid.UUID              // Who performed the action
	ActorEmail  string                 // Email of the actor
	ActorIP     string                 // IP address of the actor
	Action      string                 // e.g., "user.create", "role.update", "session.revoke"
	Resource    string                 // Resource type (user, role, permission, session, etc.)
	ResourceID  *uuid.UUID             // Resource ID if applicable
	OldValue    map[string]interface{} // JSON of previous state (for updates)
	NewValue    map[string]interface{} // JSON of new state
	Details     map[string]interface{} // Additional context
	IPAddress   string                 // Real client public IP (CF-Connecting-IP via APISIX X-Real-IP)
	CountryCode string                 // ISO 3166-1 alpha-2 (CF-IPCountry), "" if absent
	UserAgent   string                 // Request User-Agent
	RequestID   string                 // Correlation/request ID
	Timestamp   time.Time
	Success     bool
	ErrorMsg    *string
	Duration    int64 // Action duration in milliseconds
}

// AuditQueryFilters for querying admin audit events
type AuditQueryFilters struct {
	TenantID   *uuid.UUID
	ActorID    *uuid.UUID
	Action     string
	Resource   string
	ResourceID *uuid.UUID
	Success    *bool
	FromDate   *time.Time
	ToDate     *time.Time
	Page       int
	PageSize   int
}

// AdminAuditService handles admin action audit logging
type AdminAuditService struct {
	db           *pgxpool.Pool
	auditService *AuditService // Reuse existing audit service for some operations
}

// NewAdminAuditService creates a new admin audit service
func NewAdminAuditService(db *pgxpool.Pool, auditService *AuditService) *AdminAuditService {
	return &AdminAuditService{
		db:           db,
		auditService: auditService,
	}
}

// LogEvent logs an admin audit event
func (s *AdminAuditService) LogEvent(ctx context.Context, event *AdminAuditEvent) error {
	if s.db == nil {
		logger.Warn("Database not configured for admin audit logging")
		return nil
	}

	// Ensure event has an ID
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}

	// Ensure timestamp is set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Serialize old and new values to JSON
	var oldValueJSON, newValueJSON []byte
	var err error

	if event.OldValue != nil {
		oldValueJSON, err = json.Marshal(sanitizeForLog(event.OldValue))
		if err != nil {
			logger.Error("Failed to marshal old value", zap.Error(err))
			oldValueJSON = []byte("{}")
		}
	}

	if event.NewValue != nil {
		newValueJSON, err = json.Marshal(sanitizeForLog(event.NewValue))
		if err != nil {
			logger.Error("Failed to marshal new value", zap.Error(err))
			newValueJSON = []byte("{}")
		}
	}

	// Serialize details
	var detailsJSON []byte
	if event.Details != nil {
		detailsJSON, err = json.Marshal(sanitizeForLog(event.Details))
		if err != nil {
			logger.Error("Failed to marshal details", zap.Error(err))
			detailsJSON = []byte("{}")
		}
	}

	// CountryCode is nullable in the DB; pass nil for the empty case so
	// PG inserts NULL rather than the empty-string literal (which would
	// fail the varchar(2) CHECK length-constraint applied in migration
	// v0.232.245).
	var countryCodeArg interface{}
	if event.CountryCode != "" {
		countryCodeArg = event.CountryCode
	}

	query := `
		INSERT INTO iam_admin_audit_log (
			id, tenant_id, actor_id, actor_email, action, resource,
			resource_id, old_value, new_value, details, ip_address,
			country_code, user_agent, request_id, success, error_message,
			duration, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`

	_, err = s.db.Exec(ctx, query,
		event.ID,
		event.TenantID,
		event.ActorID,
		event.ActorEmail,
		event.Action,
		event.Resource,
		event.ResourceID,
		oldValueJSON,
		newValueJSON,
		detailsJSON,
		event.IPAddress,
		countryCodeArg,
		event.UserAgent,
		event.RequestID,
		event.Success,
		event.ErrorMsg,
		event.Duration,
		event.Timestamp,
	)
	if err != nil {
		logger.Error("Failed to log admin audit event", zap.Error(err))
		return fmt.Errorf("LogEvent: %w", err)
	}

	// Also log high-severity actions to structured logger for real-time alerting
	if isHighSeverityAction(event.Action) {
		logger.Log.Warn("High-severity admin action",
			zap.String("action", event.Action),
			zap.String("actor_id", event.ActorID.String()),
			zap.String("actor_email", event.ActorEmail),
			zap.String("resource", event.Resource),
			zap.String("ip_address", event.IPAddress),
			zap.Bool("success", event.Success),
		)
	}

	return nil
}

// LogUserAction logs a user-related admin action
func (s *AdminAuditService) LogUserAction(ctx context.Context, action string, userID uuid.UUID, details map[string]interface{}) error {
	// Extract actor and request context from context
	actorID, _ := ctx.Value("actor_id").(uuid.UUID)
	actorEmail, _ := ctx.Value("actor_email").(string)
	tenantID, _ := ctx.Value("tenant_id").(uuid.UUID)
	ipAddress, _ := ctx.Value("ip_address").(string)
	countryCode, _ := ctx.Value("country_code").(string)
	userAgent, _ := ctx.Value("user_agent").(string)
	requestID, _ := ctx.Value("request_id").(string)

	event := &AdminAuditEvent{
		TenantID:    tenantID,
		ActorID:     actorID,
		ActorEmail:  actorEmail,
		Action:      action,
		Resource:    "user",
		ResourceID:  &userID,
		Details:     details,
		IPAddress:   ipAddress,
		CountryCode: countryCode,
		UserAgent:   userAgent,
		RequestID:   requestID,
		Success:     true,
	}

	return s.LogEvent(ctx, event)
}

// LogRoleAction logs a role-related admin action
func (s *AdminAuditService) LogRoleAction(ctx context.Context, action string, roleID uuid.UUID, details map[string]interface{}) error {
	actorID, _ := ctx.Value("actor_id").(uuid.UUID)
	actorEmail, _ := ctx.Value("actor_email").(string)
	tenantID, _ := ctx.Value("tenant_id").(uuid.UUID)
	ipAddress, _ := ctx.Value("ip_address").(string)
	countryCode, _ := ctx.Value("country_code").(string)
	userAgent, _ := ctx.Value("user_agent").(string)
	requestID, _ := ctx.Value("request_id").(string)

	event := &AdminAuditEvent{
		TenantID:    tenantID,
		ActorID:     actorID,
		ActorEmail:  actorEmail,
		Action:      action,
		Resource:    "role",
		ResourceID:  &roleID,
		Details:     details,
		IPAddress:   ipAddress,
		CountryCode: countryCode,
		UserAgent:   userAgent,
		RequestID:   requestID,
		Success:     true,
	}

	return s.LogEvent(ctx, event)
}

// LogSecurityEvent logs a security-related admin action
func (s *AdminAuditService) LogSecurityEvent(ctx context.Context, eventType string, details map[string]interface{}) error {
	actorID, _ := ctx.Value("actor_id").(uuid.UUID)
	actorEmail, _ := ctx.Value("actor_email").(string)
	tenantID, _ := ctx.Value("tenant_id").(uuid.UUID)
	ipAddress, _ := ctx.Value("ip_address").(string)
	countryCode, _ := ctx.Value("country_code").(string)
	userAgent, _ := ctx.Value("user_agent").(string)
	requestID, _ := ctx.Value("request_id").(string)

	event := &AdminAuditEvent{
		TenantID:    tenantID,
		ActorID:     actorID,
		ActorEmail:  actorEmail,
		Action:      eventType,
		Resource:    "security",
		Details:     details,
		IPAddress:   ipAddress,
		CountryCode: countryCode,
		UserAgent:   userAgent,
		RequestID:   requestID,
		Success:     true,
	}

	return s.LogEvent(ctx, event)
}

// QueryEvents retrieves admin audit events with filtering
func (s *AdminAuditService) QueryEvents(ctx context.Context, filters AuditQueryFilters) ([]AdminAuditEvent, int64, error) {
	if s.db == nil {
		return nil, 0, fmt.Errorf("database not configured")
	}

	normalizePagination(&filters)
	offset := (filters.Page - 1) * filters.PageSize

	baseQuery, args, argIndex := buildAuditQueryWhere(filters)

	total, err := countAuditEvents(ctx, s.db, baseQuery, args)
	if err != nil {
		return nil, 0, err
	}

	events, err := fetchAuditEvents(ctx, s.db, baseQuery, args, argIndex, filters.PageSize, offset)
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

// normalizePagination applies default bounds to Page and PageSize.
func normalizePagination(filters *AuditQueryFilters) {
	if filters.Page < 1 {
		filters.Page = 1
	}
	if filters.PageSize < 1 || filters.PageSize > 100 {
		filters.PageSize = 50
	}
}

// buildAuditQueryWhere builds the WHERE clause and argument list for audit event queries.
func buildAuditQueryWhere(filters AuditQueryFilters) (string, []interface{}, int) {
	baseQuery := "FROM iam_admin_audit_log WHERE 1=1"
	args := []interface{}{}
	argIndex := 1

	if filters.TenantID != nil {
		baseQuery += fmt.Sprintf(" AND tenant_id = $%d", argIndex)
		args = append(args, *filters.TenantID)
		argIndex++
	}
	if filters.ActorID != nil {
		baseQuery += fmt.Sprintf(" AND actor_id = $%d", argIndex)
		args = append(args, *filters.ActorID)
		argIndex++
	}
	if filters.Action != "" {
		baseQuery += fmt.Sprintf(" AND action = $%d", argIndex)
		args = append(args, filters.Action)
		argIndex++
	}
	if filters.Resource != "" {
		baseQuery += fmt.Sprintf(" AND resource = $%d", argIndex)
		args = append(args, filters.Resource)
		argIndex++
	}
	if filters.ResourceID != nil {
		baseQuery += fmt.Sprintf(" AND resource_id = $%d", argIndex)
		args = append(args, *filters.ResourceID)
		argIndex++
	}
	if filters.Success != nil {
		baseQuery += fmt.Sprintf(" AND success = $%d", argIndex)
		args = append(args, *filters.Success)
		argIndex++
	}
	if filters.FromDate != nil {
		baseQuery += fmt.Sprintf(" AND created_at >= $%d", argIndex)
		args = append(args, *filters.FromDate)
		argIndex++
	}
	if filters.ToDate != nil {
		baseQuery += fmt.Sprintf(" AND created_at <= $%d", argIndex)
		args = append(args, *filters.ToDate)
		argIndex++
	}
	return baseQuery, args, argIndex
}

// countAuditEvents returns the total number of matching audit events.
func countAuditEvents(ctx context.Context, db *pgxpool.Pool, baseQuery string, args []interface{}) (int64, error) {
	var total int64
	err := db.QueryRow(ctx, "SELECT COUNT(*) "+baseQuery, args...).Scan(&total)
	if err != nil {
		logger.Error("Failed to count admin audit events", zap.Error(err))
		return 0, fmt.Errorf("QueryEvents: %w", err)
	}
	return total, nil
}

// fetchAuditEvents queries and scans paginated audit events.
func fetchAuditEvents(ctx context.Context, db *pgxpool.Pool, baseQuery string, args []interface{}, argIndex, pageSize, offset int) ([]AdminAuditEvent, error) {
	selectQuery := fmt.Sprintf(`
		SELECT id, tenant_id, actor_id, actor_email, action, resource,
		       resource_id, old_value, new_value, details, ip_address,
		       country_code, user_agent, request_id, success, error_message,
		       duration, created_at
		%s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		baseQuery, argIndex, argIndex+1)
	args = append(args, pageSize, offset)
	queryArgs := args

	rows, err := db.Query(ctx, selectQuery, queryArgs...)
	if err != nil {
		logger.Error("Failed to query admin audit events", zap.Error(err))
		return nil, fmt.Errorf("QueryEvents: %w", err)
	}
	defer rows.Close()

	var events []AdminAuditEvent
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			logger.Error("Failed to scan admin audit event", zap.Error(err))
			continue
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("QueryEvents: row iteration error: %w", err)
	}
	return events, nil
}

// scanAuditEvent scans one audit event row and unmarshals its JSON fields.
func scanAuditEvent(rows interface {
	Scan(...interface{}) error
},
) (AdminAuditEvent, error) {
	var event AdminAuditEvent
	var oldValueJSON, newValueJSON, detailsJSON []byte
	var countryCode *string

	err := rows.Scan(
		&event.ID,
		&event.TenantID,
		&event.ActorID,
		&event.ActorEmail,
		&event.Action,
		&event.Resource,
		&event.ResourceID,
		&oldValueJSON,
		&newValueJSON,
		&detailsJSON,
		&event.IPAddress,
		&countryCode,
		&event.UserAgent,
		&event.RequestID,
		&event.Success,
		&event.ErrorMsg,
		&event.Duration,
		&event.Timestamp,
	)
	if err != nil {
		return event, err
	}
	if countryCode != nil {
		event.CountryCode = *countryCode
	}
	unmarshalJSONField(oldValueJSON, &event.OldValue, "old value")
	unmarshalJSONField(newValueJSON, &event.NewValue, "new value")
	unmarshalJSONField(detailsJSON, &event.Details, "details")
	return event, nil
}

// unmarshalJSONField unmarshals a JSON byte slice into dest, logging a warning on failure.
func unmarshalJSONField(data []byte, dest interface{}, fieldName string) {
	if len(data) == 0 {
		return
	}
	if err := json.Unmarshal(data, dest); err != nil {
		logger.Warn("Failed to unmarshal "+fieldName, zap.Error(err))
	}
}

// GetEventByID retrieves a single admin audit event by ID
func (s *AdminAuditService) GetEventByID(ctx context.Context, id uuid.UUID) (*AdminAuditEvent, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not configured")
	}

	query := `
		SELECT id, tenant_id, actor_id, actor_email, action, resource,
		       resource_id, old_value, new_value, details, ip_address,
		       country_code, user_agent, request_id, success, error_message,
		       duration, created_at
		FROM iam_admin_audit_log
		WHERE id = $1
	`

	var event AdminAuditEvent
	var oldValueJSON, newValueJSON, detailsJSON []byte
	var countryCode *string

	err := s.db.QueryRow(ctx, query, id).Scan(
		&event.ID,
		&event.TenantID,
		&event.ActorID,
		&event.ActorEmail,
		&event.Action,
		&event.Resource,
		&event.ResourceID,
		&oldValueJSON,
		&newValueJSON,
		&detailsJSON,
		&event.IPAddress,
		&countryCode,
		&event.UserAgent,
		&event.RequestID,
		&event.Success,
		&event.ErrorMsg,
		&event.Duration,
		&event.Timestamp,
	)
	if err != nil {
		return nil, fmt.Errorf("GetEventByID: %w", err)
	}
	if countryCode != nil {
		event.CountryCode = *countryCode
	}

	// Unmarshal JSON fields
	if len(oldValueJSON) > 0 {
		if err := json.Unmarshal(oldValueJSON, &event.OldValue); err != nil {
			logger.Warn("Failed to unmarshal old value", zap.Error(err))
		}
	}
	if len(newValueJSON) > 0 {
		if err := json.Unmarshal(newValueJSON, &event.NewValue); err != nil {
			logger.Warn("Failed to unmarshal new value", zap.Error(err))
		}
	}
	if len(detailsJSON) > 0 {
		if err := json.Unmarshal(detailsJSON, &event.Details); err != nil {
			logger.Warn("Failed to unmarshal details", zap.Error(err))
		}
	}

	return &event, nil
}

// sanitizeForLog removes sensitive fields from data before logging
// SECURITY: Never log passwords, tokens, secrets, or other sensitive data
func sanitizeForLog(data map[string]interface{}) map[string]interface{} {
	if data == nil {
		return nil
	}

	sanitized := make(map[string]interface{})
	sensitiveFields := map[string]bool{
		"password":           true,
		"new_password":       true,
		"current_password":   true,
		"old_password":       true,
		"password_hash":      true,
		"token":              true,
		"access_token":       true,
		"refresh_token":      true,
		"api_key":            true,
		"secret":             true,
		"client_secret":      true,
		"private_key":        true,
		"mfa_secret":         true,
		"totp_secret":        true,
		"recovery_codes":     true,
		"backup_codes":       true,
		"encryption_key":     true,
		"oauth_token":        true,
		"authorization_code": true,
		"session_token":      true,
		"csrf_token":         true,
	}

	for key, value := range data {
		// Check if field is sensitive
		if sensitiveFields[key] {
			sanitized[key] = "***REDACTED***"
			continue
		}

		// Recursively sanitize nested maps
		if nestedMap, ok := value.(map[string]interface{}); ok {
			sanitized[key] = sanitizeForLog(nestedMap)
			continue
		}

		// Copy non-sensitive values
		sanitized[key] = value
	}

	return sanitized
}

// isHighSeverityAction determines if an action requires immediate alerting
func isHighSeverityAction(action string) bool {
	highSeverityActions := map[string]bool{
		"user.delete":                     true,
		"user.password_reset":             true,
		"user.disable":                    true,
		"role.delete":                     true,
		"role.permission_grant":           true,
		"role.permission_revoke":          true,
		"permission.delete":               true,
		"session.revoke_all":              true,
		"security.mfa_disable":            true,
		"security.password_policy_change": true,
		"security.ip_rule_delete":         true,
		"security.rate_limit_disable":     true,
		"identity_provider.delete":        true,
		"tenant.suspend":                  true,
		"admin.impersonate":               true,
	}

	return highSeverityActions[action]
}

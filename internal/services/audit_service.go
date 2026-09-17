// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

const (
	auditResourceTypeUser       = "user"
	auditResourceTypeRole       = "role"
	auditResourceTypePermission = "permission"
)

// auditServiceTokenRepo defines the token repository methods needed by AuditService.
type auditServiceTokenRepo interface {
	CreateAuditLog(ctx context.Context, log *models.AuditLog) error
	GetAuditLogByID(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) (*models.AuditLog, error)
	ListAuditLogs(ctx context.Context, tenantID uuid.UUID, page, pageSize int, filters map[string]interface{}) ([]models.AuditLog, int64, error)
}

// AuditService is an exported type.
type AuditService struct {
	tokenRepo auditServiceTokenRepo
	db        *pgxpool.Pool
}

// NewAuditService is an exported function.
func NewAuditService(tokenRepo auditServiceTokenRepo, db *pgxpool.Pool) *AuditService {
	return &AuditService{
		tokenRepo: tokenRepo,
		db:        db,
	}
}

// LogLogin logs a login attempt
func (s *AuditService) LogLogin(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, ipAddress, userAgent string, success bool, errorMsg string) {
	if s.tokenRepo == nil {
		return
	}
	log := &models.AuditLog{
		TenantID:  tenantID,
		UserID:    userID,
		Action:    "login",
		IPAddress: &ipAddress,
		UserAgent: &userAgent,
		Success:   success,
	}

	if !success && errorMsg != "" {
		log.ErrorMessage = &errorMsg
	}

	if err := s.tokenRepo.CreateAuditLog(ctx, log); err != nil {
		logger.Error("Failed to create audit log", zap.Error(err))
	}
}

// LogLoginRememberMe stamps the rememberMe flag on iam_audit_log so a
// security review can identify long-lived sessions. Separate from
// LogLogin so the boolean lands in `details` (the canonical column
// for non-fixed action metadata) without changing the LogLogin shape
// that downstream SIEM dashboards depend on.
//
// Action is `login.remember_me` regardless of value — the boolean is
// the meaningful bit. Queries like `details->>'remember_me' = 'true'`
// produce the list of long-lived sessions; pairing with
// `LogSessionAction` keyed on the same session_id yields the full
// audit trail for an iam_sessions row.
//
// Best-effort: audit write failures are logged but never propagated
// back to the caller (matches LogLogin / LogSessionAction semantics).
func (s *AuditService) LogLoginRememberMe(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, sessionID uuid.UUID, rememberMe bool, ipAddress, userAgent string) {
	if s.tokenRepo == nil {
		return
	}
	resourceType := "session"
	log := &models.AuditLog{
		TenantID:     tenantID,
		UserID:       &userID,
		Action:       "login.remember_me",
		ResourceType: &resourceType,
		ResourceID:   &sessionID,
		IPAddress:    &ipAddress,
		UserAgent:    &userAgent,
		Success:      true,
		Details: map[string]interface{}{
			"remember_me": rememberMe,
		},
	}

	if err := s.tokenRepo.CreateAuditLog(ctx, log); err != nil {
		logger.Error("Failed to create remember-me audit log", zap.Error(err))
	}
}

// LogLogout logs a logout action
func (s *AuditService) LogLogout(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, ipAddress, userAgent string) {
	if s.tokenRepo == nil {
		return
	}
	log := &models.AuditLog{
		TenantID:  tenantID,
		UserID:    &userID,
		Action:    "logout",
		IPAddress: &ipAddress,
		UserAgent: &userAgent,
		Success:   true,
	}

	if err := s.tokenRepo.CreateAuditLog(ctx, log); err != nil {
		logger.Error("Failed to create audit log", zap.Error(err))
	}
}

// LogUserAction logs a user-related action
func (s *AuditService) LogUserAction(ctx context.Context, tenantID uuid.UUID, actorID, targetUserID *uuid.UUID, action string, success bool, details map[string]interface{}) {
	if s.tokenRepo == nil {
		return
	}
	resourceType := auditResourceTypeUser
	log := &models.AuditLog{
		TenantID:     tenantID,
		UserID:       actorID,
		TargetUserID: targetUserID,
		Action:       action,
		ResourceType: &resourceType,
		ResourceID:   targetUserID,
		Details:      details,
		Success:      success,
	}

	if err := s.tokenRepo.CreateAuditLog(ctx, log); err != nil {
		logger.Error("Failed to create audit log", zap.Error(err))
	}
}

// LogRoleAction logs a role-related action
func (s *AuditService) LogRoleAction(ctx context.Context, tenantID uuid.UUID, actorID, roleID *uuid.UUID, action string, success bool, details map[string]interface{}) {
	if s.tokenRepo == nil {
		return
	}
	resourceType := auditResourceTypeRole
	log := &models.AuditLog{
		TenantID:     tenantID,
		UserID:       actorID,
		Action:       action,
		ResourceType: &resourceType,
		ResourceID:   roleID,
		Details:      details,
		Success:      success,
	}

	if err := s.tokenRepo.CreateAuditLog(ctx, log); err != nil {
		logger.Error("Failed to create audit log", zap.Error(err))
	}
}

// LogSessionAction logs a session-related action
func (s *AuditService) LogSessionAction(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, sessionID *uuid.UUID, action string, ipAddress string) {
	if s.tokenRepo == nil {
		return
	}
	resourceType := "session"
	log := &models.AuditLog{
		TenantID:     tenantID,
		UserID:       &userID,
		Action:       action,
		ResourceType: &resourceType,
		ResourceID:   sessionID,
		IPAddress:    &ipAddress,
		Success:      true,
	}

	if err := s.tokenRepo.CreateAuditLog(ctx, log); err != nil {
		logger.Error("Failed to create audit log", zap.Error(err))
	}
}

// LogPasswordAction logs a password-related action
func (s *AuditService) LogPasswordAction(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, action string, success bool, ipAddress string) {
	if s.tokenRepo == nil {
		return
	}
	log := &models.AuditLog{
		TenantID:  tenantID,
		UserID:    &userID,
		Action:    action,
		IPAddress: &ipAddress,
		Success:   success,
	}

	if err := s.tokenRepo.CreateAuditLog(ctx, log); err != nil {
		logger.Error("Failed to create audit log", zap.Error(err))
	}
}

// LogPasswordResetRequest logs a password reset request
func (s *AuditService) LogPasswordResetRequest(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, ipAddress string, success bool, errorMsg string) {
	if s.tokenRepo == nil {
		return
	}
	log := &models.AuditLog{
		TenantID:  tenantID,
		UserID:    &userID,
		Action:    "password_reset_request",
		IPAddress: &ipAddress,
		Success:   success,
	}

	if !success && errorMsg != "" {
		log.ErrorMessage = &errorMsg
	}

	if err := s.tokenRepo.CreateAuditLog(ctx, log); err != nil {
		logger.Error("Failed to create audit log", zap.Error(err))
	}
}

// LogPasswordReset logs a completed password reset
func (s *AuditService) LogPasswordReset(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, ipAddress string, success bool, errorMsg string) {
	if s.tokenRepo == nil {
		return
	}
	log := &models.AuditLog{
		TenantID:  tenantID,
		UserID:    &userID,
		Action:    "password_reset",
		IPAddress: &ipAddress,
		Success:   success,
	}

	if !success && errorMsg != "" {
		log.ErrorMessage = &errorMsg
	}

	if err := s.tokenRepo.CreateAuditLog(ctx, log); err != nil {
		logger.Error("Failed to create audit log", zap.Error(err))
	}
}

// GetAuditLogByID retrieves a single audit log entry by ID
func (s *AuditService) GetAuditLogByID(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) (*models.AuditLogResponse, error) {
	if s.tokenRepo == nil {
		return nil, fmt.Errorf("audit repository not configured")
	}
	log, err := s.tokenRepo.GetAuditLogByID(ctx, id, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetAuditLogByID: %w", err)
	}
	if log == nil {
		return nil, nil
	}

	return &models.AuditLogResponse{
		ID:           log.ID,
		TenantID:     log.TenantID,
		UserID:       log.UserID,
		Username:     log.Username,
		Action:       log.Action,
		ResourceType: log.ResourceType,
		ResourceID:   log.ResourceID,
		Details:      log.Details,
		IPAddress:    log.IPAddress,
		Success:      log.Success,
		CreatedAt:    log.CreatedAt,
	}, nil
}

// GetAuditLogs retrieves audit logs for a tenant
func (s *AuditService) GetAuditLogs(ctx context.Context, tenantID uuid.UUID, page, pageSize int, filters map[string]interface{}) (*models.AuditLogListResponse, error) {
	if s.tokenRepo == nil {
		return nil, fmt.Errorf("audit repository not configured")
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	logs, total, err := s.tokenRepo.ListAuditLogs(ctx, tenantID, page, pageSize, filters)
	if err != nil {
		return nil, fmt.Errorf("GetAuditLogs: %w", err)
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	responses := make([]models.AuditLogResponse, len(logs))
	for i, log := range logs {
		responses[i] = models.AuditLogResponse{
			ID:           log.ID,
			TenantID:     log.TenantID,
			UserID:       log.UserID,
			Username:     log.Username,
			Action:       log.Action,
			ResourceType: log.ResourceType,
			ResourceID:   log.ResourceID,
			Details:      log.Details,
			IPAddress:    log.IPAddress,
			Success:      log.Success,
			CreatedAt:    log.CreatedAt,
		}
	}

	return &models.AuditLogListResponse{
		Logs:       responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// LogPlatformAction logs a platform admin action to the platform_admin_audit_log table
func (s *AuditService) LogPlatformAction(ctx context.Context, log *models.PlatformAuditLog) error {
	if s.db == nil {
		logger.Warn("Database not configured for platform audit logging")
		return nil
	}

	var detailsJSON []byte
	var err error
	if log.Details != nil {
		detailsJSON, err = json.Marshal(log.Details)
		if err != nil {
			logger.Error("Failed to marshal audit log details", zap.Error(err))
			detailsJSON = []byte("{}")
		}
	}

	query := `
		INSERT INTO platform_admin_audit_log (
			admin_user_id, admin_username, target_tenant_id, target_tenant_name,
			target_user_id, target_resource_type, target_resource_id,
			action, action_category, details, ip_address, user_agent,
			request_id, success, error_message
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	_, err = s.db.Exec(ctx, query,
		log.AdminUserID, log.AdminUsername, log.TargetTenantID, log.TargetTenantName,
		log.TargetUserID, log.TargetResourceType, log.TargetResourceID,
		log.Action, log.ActionCategory, detailsJSON, log.IPAddress, log.UserAgent,
		log.RequestID, log.Success, log.ErrorMessage,
	)
	if err != nil {
		logger.Error("Failed to log platform action", zap.Error(err))
		return fmt.Errorf("LogPlatformAction: %w", err)
	}

	return nil
}

// GetPlatformAuditLog retrieves audit logs from the main iam_audit_log table
// with filtering and pagination. Returns data in AuditLogResponse format matching
// the SDK's AuditLog type.
func (s *AuditService) GetPlatformAuditLog(ctx context.Context, page, pageSize int, filters models.PlatformAuditFilters) ([]models.AuditLogResponse, int64, error) {
	if s.db == nil {
		return nil, 0, fmt.Errorf("database not configured")
	}

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	// Build dynamic query against the main audit log table
	baseQuery := "FROM iam_audit_log a LEFT JOIN iam_users u ON a.user_id = u.id WHERE 1=1"
	args := []interface{}{}
	argIndex := 1

	if filters.Action != "" {
		baseQuery += fmt.Sprintf(" AND a.action = $%d", argIndex)
		args = append(args, filters.Action)
		argIndex++
	}

	if filters.TargetTenantID != nil {
		baseQuery += fmt.Sprintf(" AND a.tenant_id = $%d", argIndex)
		args = append(args, *filters.TargetTenantID)
		argIndex++
	}

	if filters.AdminUserID != nil {
		baseQuery += fmt.Sprintf(" AND a.user_id = $%d", argIndex)
		args = append(args, *filters.AdminUserID)
		argIndex++
	}

	if filters.From != nil {
		baseQuery += fmt.Sprintf(" AND a.created_at >= $%d", argIndex)
		args = append(args, *filters.From)
		argIndex++
	}

	if filters.To != nil {
		baseQuery += fmt.Sprintf(" AND a.created_at <= $%d", argIndex)
		args = append(args, *filters.To)
		argIndex++
	}

	// Get total count
	var total int64
	countQuery := "SELECT COUNT(*) " + baseQuery
	err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		logger.Error("Failed to count audit logs", zap.Error(err))
		return nil, 0, fmt.Errorf("GetPlatformAuditLog: %w", err)
	}

	// Get logs with pagination
	selectQuery := fmt.Sprintf(`
		SELECT a.id, a.tenant_id, a.user_id, u.username,
		       a.action, a.resource_type, a.resource_id,
		       a.details,
		       a.ip_address, a.user_agent,
		       a.success, a.error_message, a.created_at
		%s ORDER BY a.created_at DESC LIMIT $%d OFFSET $%d`,
		baseQuery, argIndex, argIndex+1)
	args = append(args, pageSize, offset)

	rows, err := s.db.Query(ctx, selectQuery, args...)
	if err != nil {
		logger.Error("Failed to query audit logs", zap.Error(err))
		return nil, 0, fmt.Errorf("GetPlatformAuditLog: %w", err)
	}
	defer rows.Close()

	var logs []models.AuditLogResponse
	for rows.Next() {
		var log models.AuditLogResponse
		var detailsJSON []byte

		err := rows.Scan(
			&log.ID, &log.TenantID, &log.UserID, &log.Username,
			&log.Action, &log.ResourceType, &log.ResourceID,
			&detailsJSON,
			&log.IPAddress, &log.UserAgent,
			&log.Success, &log.ErrorMessage, &log.CreatedAt,
		)
		if err != nil {
			logger.Error("Failed to scan audit log", zap.Error(err))
			continue
		}

		if len(detailsJSON) > 0 {
			if err := json.Unmarshal(detailsJSON, &log.Details); err != nil {
				logger.Warn("Failed to unmarshal audit log details", zap.Error(err))
			}
		}

		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("GetPlatformAuditLog: row iteration error: %w", err)
	}

	return logs, total, nil
}

// LogPermissionChange logs permission or role assignments/revocations with correlation ID
func (s *AuditService) LogPermissionChange(ctx context.Context, event *models.PermissionChangeEvent) error {
	if s.tokenRepo == nil {
		return nil
	}
	// Copy the details map to avoid mutating the caller's data
	details := make(map[string]interface{})
	for k, v := range event.Details {
		details[k] = v
	}

	log := &models.AuditLog{
		TenantID:      uuid.Nil, // Will be set from context or event
		UserID:        &event.UserID,
		TargetUserID:  &event.TargetUserID,
		Action:        event.ChangeType,
		IPAddress:     &event.IPAddress,
		Success:       true,
		CorrelationID: event.CorrelationID,
		Details:       details,
	}

	if event.RoleID != nil && event.RoleName != nil {
		log.Details["role_id"] = event.RoleID.String()
		log.Details["role_name"] = *event.RoleName
		resourceType := auditResourceTypeRole
		log.ResourceType = &resourceType
		log.ResourceID = event.RoleID
	}

	if event.PermissionID != nil && event.PermissionName != nil {
		log.Details["permission_id"] = event.PermissionID.String()
		log.Details["permission_name"] = *event.PermissionName
		resourceType := auditResourceTypePermission
		log.ResourceType = &resourceType
		log.ResourceID = event.PermissionID
	}

	if err := s.tokenRepo.CreateAuditLog(ctx, log); err != nil {
		logger.Error("Failed to log permission change", zap.Error(err))
		return fmt.Errorf("LogPermissionChange: %w", err)
	}

	return nil
}

// GetAuditLogsForArchive retrieves audit logs older than retention period for archiving
func (s *AuditService) GetAuditLogsForArchive(ctx context.Context, tenantID uuid.UUID, retentionDays int) ([]models.AuditLog, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not configured")
	}

	if retentionDays <= 0 {
		retentionDays = 365 // Default 1 year retention
	}

	query := `
		SELECT id, tenant_id, user_id, action, resource_type, resource_id,
		       details, ip_address, user_agent, success, error_message,
		       archived, archive_date, archive_location, correlation_id, target_user_id, created_at
		FROM iam_audit_log
		WHERE tenant_id = $1
		  AND archived = false
		  AND created_at < NOW() - ($2 || ' days')::INTERVAL
		ORDER BY created_at`

	rows, err := s.db.Query(ctx, query, tenantID, retentionDays)
	if err != nil {
		logger.Error("Failed to query audit logs for archive", zap.Error(err))
		return nil, fmt.Errorf("GetAuditLogsForArchive: %w", err)
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var log models.AuditLog
		var detailsJSON []byte

		err := rows.Scan(
			&log.ID, &log.TenantID, &log.UserID, &log.Action, &log.ResourceType, &log.ResourceID,
			&detailsJSON, &log.IPAddress, &log.UserAgent, &log.Success, &log.ErrorMessage,
			&log.Archived, &log.ArchiveDate, &log.ArchiveLocation, &log.CorrelationID, &log.TargetUserID, &log.CreatedAt,
		)
		if err != nil {
			logger.Error("Failed to scan audit log for archive", zap.Error(err))
			continue
		}

		if len(detailsJSON) > 0 {
			if err := json.Unmarshal(detailsJSON, &log.Details); err != nil {
				logger.Warn("Failed to unmarshal audit log details", zap.Error(err))
			}
		}

		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetAuditLogsForArchive: row iteration error: %w", err)
	}

	return logs, nil
}

// MarkAuditLogsAsArchived marks audit logs as archived with S3 location
func (s *AuditService) MarkAuditLogsAsArchived(ctx context.Context, logIDs []uuid.UUID, archiveLocation string) error {
	if s.db == nil {
		return fmt.Errorf("database not configured")
	}

	if len(logIDs) == 0 {
		return nil
	}

	query := `
		UPDATE iam_audit_log
		SET archived = true,
		    archive_date = NOW(),
		    archive_location = $1
		WHERE id = ANY($2)`

	_, err := s.db.Exec(ctx, query, archiveLocation, logIDs)
	if err != nil {
		logger.Error("Failed to mark audit logs as archived", zap.Error(err))
		return fmt.Errorf("MarkAuditLogsAsArchived: %w", err)
	}

	logger.Info("Marked audit logs as archived",
		zap.Int("count", len(logIDs)),
		zap.String("location", archiveLocation),
	)

	return nil
}

// CreateArchiveMetadata creates metadata record for archived audit log batch
func (s *AuditService) CreateArchiveMetadata(ctx context.Context, metadata *models.AuditArchiveMetadata) error {
	if s.db == nil {
		return fmt.Errorf("database not configured")
	}

	query := `
		INSERT INTO iam_audit_archive_metadata (
			id, tenant_id, archive_batch_id, start_date, end_date, record_count,
			s3_bucket, s3_key, s3_etag, file_size_bytes, compression_type,
			encrypted, object_lock_enabled, object_lock_until, checksum_sha256, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING created_at`

	if metadata.ID == uuid.Nil {
		metadata.ID = uuid.New()
	}
	if metadata.ArchiveBatchID == uuid.Nil {
		metadata.ArchiveBatchID = uuid.New()
	}

	err := s.db.QueryRow(ctx, query,
		metadata.ID, metadata.TenantID, metadata.ArchiveBatchID,
		metadata.StartDate, metadata.EndDate, metadata.RecordCount,
		metadata.S3Bucket, metadata.S3Key, metadata.S3ETag, metadata.FileSizeBytes,
		metadata.CompressionType, metadata.Encrypted, metadata.ObjectLockEnabled,
		metadata.ObjectLockUntil, metadata.ChecksumSHA256, metadata.CreatedBy,
	).Scan(&metadata.CreatedAt)
	if err != nil {
		logger.Error("Failed to create archive metadata", zap.Error(err))
		return fmt.Errorf("CreateArchiveMetadata: %w", err)
	}

	logger.Info("Created archive metadata",
		zap.String("batch_id", metadata.ArchiveBatchID.String()),
		zap.Int64("record_count", metadata.RecordCount),
	)

	return nil
}

// GetArchiveMetadata retrieves archive metadata for a tenant
func (s *AuditService) GetArchiveMetadata(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]models.AuditArchiveMetadata, int64, error) {
	if s.db == nil {
		return nil, 0, fmt.Errorf("database not configured")
	}

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	// Get total count
	var total int64
	countQuery := `SELECT COUNT(*) FROM iam_audit_archive_metadata WHERE tenant_id = $1`
	err := s.db.QueryRow(ctx, countQuery, tenantID).Scan(&total)
	if err != nil {
		logger.Error("Failed to count archive metadata", zap.Error(err))
		return nil, 0, fmt.Errorf("GetArchiveMetadata: %w", err)
	}

	// Get records
	query := `
		SELECT id, tenant_id, archive_batch_id, start_date, end_date, record_count,
		       s3_bucket, s3_key, s3_etag, file_size_bytes, compression_type,
		       encrypted, object_lock_enabled, object_lock_until, checksum_sha256,
		       created_at, created_by
		FROM iam_audit_archive_metadata
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := s.db.Query(ctx, query, tenantID, pageSize, offset)
	if err != nil {
		logger.Error("Failed to query archive metadata", zap.Error(err))
		return nil, 0, fmt.Errorf("GetArchiveMetadata: %w", err)
	}
	defer rows.Close()

	var metadata []models.AuditArchiveMetadata
	for rows.Next() {
		var m models.AuditArchiveMetadata
		err := rows.Scan(
			&m.ID, &m.TenantID, &m.ArchiveBatchID, &m.StartDate, &m.EndDate, &m.RecordCount,
			&m.S3Bucket, &m.S3Key, &m.S3ETag, &m.FileSizeBytes, &m.CompressionType,
			&m.Encrypted, &m.ObjectLockEnabled, &m.ObjectLockUntil, &m.ChecksumSHA256,
			&m.CreatedAt, &m.CreatedBy,
		)
		if err != nil {
			logger.Error("Failed to scan archive metadata", zap.Error(err))
			continue
		}
		metadata = append(metadata, m)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("GetArchiveMetadata: row iteration error: %w", err)
	}

	return metadata, total, nil
}

// Security audit logging methods are in audit_service_security.go

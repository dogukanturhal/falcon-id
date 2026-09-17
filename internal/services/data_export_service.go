// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// dataExportUserRepo defines the user repository methods needed by DataExportService.
type dataExportUserRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error)
}

// dataExportSessionRepo defines the session repository methods needed by DataExportService.
type dataExportSessionRepo interface {
	GetActiveSessions(ctx context.Context, userID uuid.UUID) ([]models.Session, error)
}

// dataExportDeviceRepo defines the device repository methods needed by DataExportService.
type dataExportDeviceRepo interface {
	GetByUserID(ctx context.Context, userID uuid.UUID, page, pageSize int) ([]models.Device, int64, error)
}

// dataExportDBQuerier is the minimal DB interface required by DataExportService.
// Both *pgxpool.Pool and pgxmock.PgxPoolIface satisfy this interface.
type dataExportDBQuerier interface {
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
}

// DataExportService handles GDPR data export requests
type DataExportService struct {
	userRepo    dataExportUserRepo
	sessionRepo dataExportSessionRepo
	mfaRepo     interface{} // not currently used directly
	deviceRepo  dataExportDeviceRepo
	db          dataExportDBQuerier
}

// NewDataExportService creates a new data export service
func NewDataExportService(
	userRepo dataExportUserRepo,
	sessionRepo dataExportSessionRepo,
	mfaRepo interface{},
	deviceRepo dataExportDeviceRepo,
	db *pgxpool.Pool,
) *DataExportService {
	return &DataExportService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		mfaRepo:     mfaRepo,
		deviceRepo:  deviceRepo,
		db:          db,
	}
}

// UserExportData represents all user data for GDPR export
type UserExportData struct {
	User     *UserData      `json:"user"`
	Sessions []SessionData  `json:"sessions"`
	MFA      *MFAData       `json:"mfa,omitempty"`
	Devices  []DeviceData   `json:"devices"`
	Audit    []AuditLogData `json:"audit_logs"`
}

// UserData represents exported user data
type UserData struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	RealmID           string     `json:"realm_id"`
	Username          string     `json:"username"`
	Email             string     `json:"email"`
	FirstName         *string    `json:"first_name,omitempty"`
	LastName          *string    `json:"last_name,omitempty"`
	DisplayName       *string    `json:"display_name,omitempty"`
	Phone             *string    `json:"phone,omitempty"`
	Department        *string    `json:"department,omitempty"`
	Title             *string    `json:"title,omitempty"`
	AvatarURL         *string    `json:"avatar_url,omitempty"`
	FederationType    *string    `json:"federation_type,omitempty"`
	FederationID      *string    `json:"federation_id,omitempty"`
	FederationSource  *string    `json:"federation_source,omitempty"`
	IsActive          bool       `json:"is_active"`
	IsEmailVerified   bool       `json:"is_email_verified"`
	MFAEnabled        bool       `json:"mfa_enabled"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP       *string    `json:"last_login_ip,omitempty"`
	PasswordChangedAt *time.Time `json:"password_changed_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	Roles             []string   `json:"roles"`
	Permissions       []string   `json:"permissions"`
}

// SessionData represents exported session data
type SessionData struct {
	ID         string     `json:"id"`
	DeviceInfo *string    `json:"device_info,omitempty"`
	IPAddress  *string    `json:"ip_address,omitempty"`
	UserAgent  *string    `json:"user_agent,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
}

// MFAData represents exported MFA data
type MFAData struct {
	Enabled         bool    `json:"enabled"`
	TOTPEnabled     bool    `json:"totp_enabled"`
	EmailEnabled    bool    `json:"email_enabled"`
	PreferredMethod *string `json:"preferred_method,omitempty"`
}

// DeviceData represents exported device data
type DeviceData struct {
	ID             string     `json:"id"`
	Fingerprint    string     `json:"fingerprint"`
	DeviceType     *string    `json:"device_type,omitempty"`
	UserAgent      *string    `json:"user_agent,omitempty"`
	IPAddress      *string    `json:"ip_address,omitempty"`
	IsTrusted      bool       `json:"is_trusted"`
	TrustExpiresAt *time.Time `json:"trust_expires_at,omitempty"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
}

// AuditLogData represents exported audit log data
type AuditLogData struct {
	ID        string                 `json:"id"`
	Action    string                 `json:"action"`
	IPAddress *string                `json:"ip_address,omitempty"`
	UserAgent *string                `json:"user_agent,omitempty"`
	Success   bool                   `json:"success"`
	ErrorMsg  *string                `json:"error_message,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// CollectUserData aggregates all user data from IAM and related modules
func (s *DataExportService) CollectUserData(ctx context.Context, userID uuid.UUID) (*UserExportData, error) {
	logger.Info("Collecting user data for GDPR export",
		zap.String("user_id", userID.String()),
	)

	// Get user data
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Get roles and permissions
	roles, err := s.userRepo.GetUserRoles(ctx, userID)
	if err != nil {
		logger.Warn("Failed to get user roles", zap.Error(err))
		roles = []models.Role{}
	}

	permissions, err := s.userRepo.GetUserPermissions(ctx, userID)
	if err != nil {
		logger.Warn("Failed to get user permissions", zap.Error(err))
		permissions = []models.Permission{}
	}

	// Convert user data
	userData := &UserData{
		ID:                user.ID.String(),
		TenantID:          user.TenantID.String(),
		RealmID:           user.RealmID.String(),
		Username:          user.Username,
		Email:             user.Email,
		FirstName:         user.FirstName,
		LastName:          user.LastName,
		DisplayName:       user.DisplayName,
		Phone:             user.Phone,
		Department:        user.Department,
		Title:             user.Title,
		AvatarURL:         user.AvatarURL,
		FederationType:    user.FederationType,
		FederationID:      user.FederationID,
		FederationSource:  user.FederationSource,
		IsActive:          user.IsActive,
		IsEmailVerified:   user.IsEmailVerified,
		MFAEnabled:        user.MFAEnabled,
		LastLoginAt:       user.LastLoginAt,
		LastLoginIP:       user.LastLoginIP,
		PasswordChangedAt: user.PasswordChangedAt,
		CreatedAt:         user.CreatedAt,
		UpdatedAt:         user.UpdatedAt,
	}

	// Add roles
	userData.Roles = make([]string, len(roles))
	for i, role := range roles {
		userData.Roles[i] = role.Name
	}

	// Add permissions
	userData.Permissions = make([]string, len(permissions))
	for i, perm := range permissions {
		userData.Permissions[i] = perm.Name
	}

	// Get sessions
	sessions, err := s.sessionRepo.GetActiveSessions(ctx, userID)
	if err != nil {
		logger.Warn("Failed to get sessions", zap.Error(err))
		sessions = []models.Session{}
	}

	sessionData := make([]SessionData, len(sessions))
	for i, session := range sessions {
		lastUsedAt := session.LastActivityAt // Copy to take address
		sessionData[i] = SessionData{
			ID:         session.ID.String(),
			DeviceInfo: session.DeviceInfo,
			IPAddress:  session.IPAddress,
			UserAgent:  session.UserAgent,
			CreatedAt:  session.CreatedAt,
			LastUsedAt: &lastUsedAt,
			ExpiresAt:  session.ExpiresAt,
			EndedAt:    session.EndedAt,
		}
	}

	// Get MFA data
	var mfaData *MFAData
	if user.MFAEnabled {
		mfaData = &MFAData{
			Enabled:         user.MFAEnabled,
			TOTPEnabled:     user.MFATOTPEnabled,
			EmailEnabled:    user.MFAEmailEnabled,
			PreferredMethod: user.MFAPreferredMethod,
		}
	}

	// Get devices
	devicesList, _, err := s.deviceRepo.GetByUserID(ctx, userID, 1, 1000) // Get up to 1000 devices
	if err != nil {
		logger.Warn("Failed to get devices", zap.Error(err))
		devicesList = []models.Device{}
	}

	deviceData := make([]DeviceData, len(devicesList))
	for i, device := range devicesList {
		// Create a fingerprint string from hash for display (first 16 chars)
		fingerprint := device.FingerprintHash
		if len(fingerprint) > 16 {
			fingerprint = fingerprint[:16] + "..."
		}

		deviceData[i] = DeviceData{
			ID:             device.ID.String(),
			Fingerprint:    fingerprint,
			DeviceType:     device.DeviceType,
			UserAgent:      nil, // Not stored in device model
			IPAddress:      device.LastIP,
			IsTrusted:      device.IsTrusted,
			TrustExpiresAt: device.TrustExpiresAt,
			FirstSeenAt:    device.FirstSeenAt,
			LastSeenAt:     device.LastSeenAt,
		}
	}

	// Get audit logs
	auditLogs := s.getAuditLogs(ctx, userID, user.TenantID)

	exportData := &UserExportData{
		User:     userData,
		Sessions: sessionData,
		MFA:      mfaData,
		Devices:  deviceData,
		Audit:    auditLogs,
	}

	logger.Info("Successfully collected user data for export",
		zap.String("user_id", userID.String()),
		zap.Int("sessions", len(sessionData)),
		zap.Int("devices", len(deviceData)),
		zap.Int("audit_logs", len(auditLogs)),
	)

	return exportData, nil
}

// getAuditLogs retrieves audit logs for a user from Cassandra
func (s *DataExportService) getAuditLogs(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) []AuditLogData {
	// In a real implementation, this would query Cassandra
	// For now, we'll query PostgreSQL audit logs if available
	if s.db == nil {
		return []AuditLogData{}
	}

	query := `
		SELECT id, action, ip_address, user_agent, success, error_message, metadata, created_at
		FROM iam_audit_logs
		WHERE tenant_id = $1 AND user_id = $2
		ORDER BY created_at DESC
		LIMIT 1000
	`

	rows, err := s.db.Query(ctx, query, tenantID, userID)
	if err != nil {
		logger.Warn("Failed to get audit logs", zap.Error(err))
		return []AuditLogData{}
	}
	defer rows.Close()

	var auditLogs []AuditLogData
	for rows.Next() {
		var log AuditLogData
		var metadataJSON []byte

		err := rows.Scan(
			&log.ID,
			&log.Action,
			&log.IPAddress,
			&log.UserAgent,
			&log.Success,
			&log.ErrorMsg,
			&metadataJSON,
			&log.CreatedAt,
		)
		if err != nil {
			logger.Warn("Failed to scan audit log", zap.Error(err))
			continue
		}

		// Parse metadata JSON
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &log.Metadata); err != nil {
				logger.Warn("Failed to parse audit log metadata", zap.Error(err))
			}
		}

		auditLogs = append(auditLogs, log)
	}

	if err := rows.Err(); err != nil {
		logger.Warn("Audit log row iteration error", zap.Error(err))
	}

	return auditLogs
}

// ExportToJSON exports user data to JSON format
func (s *DataExportService) ExportToJSON(data *UserExportData) ([]byte, error) {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return jsonData, nil
}

// ExportToCSV exports user data to CSV format
func (s *DataExportService) ExportToCSV(data *UserExportData) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write user data section
	_ = writer.Write([]string{"=== USER DATA ==="})
	_ = writer.Write([]string{"Field", "Value"})
	_ = writer.Write([]string{"ID", data.User.ID})
	_ = writer.Write([]string{"Username", data.User.Username})
	_ = writer.Write([]string{"Email", data.User.Email})
	if data.User.FirstName != nil {
		_ = writer.Write([]string{"First Name", *data.User.FirstName})
	}
	if data.User.LastName != nil {
		_ = writer.Write([]string{"Last Name", *data.User.LastName})
	}
	_ = writer.Write([]string{"Created At", data.User.CreatedAt.Format(time.RFC3339)})
	_ = writer.Write([]string{})

	// Write sessions section
	_ = writer.Write([]string{"=== SESSIONS ==="})
	_ = writer.Write([]string{"ID", "Device Info", "IP Address", "Created At", "Expires At"})
	for _, session := range data.Sessions {
		deviceInfo := ""
		if session.DeviceInfo != nil {
			deviceInfo = *session.DeviceInfo
		}
		ipAddr := ""
		if session.IPAddress != nil {
			ipAddr = *session.IPAddress
		}
		_ = writer.Write([]string{
			session.ID,
			deviceInfo,
			ipAddr,
			session.CreatedAt.Format(time.RFC3339),
			session.ExpiresAt.Format(time.RFC3339),
		})
	}
	_ = writer.Write([]string{})

	// Write devices section
	_ = writer.Write([]string{"=== DEVICES ==="})
	_ = writer.Write([]string{"ID", "Fingerprint", "Device Type", "Is Trusted", "First Seen", "Last Seen"})
	for _, device := range data.Devices {
		deviceType := ""
		if device.DeviceType != nil {
			deviceType = *device.DeviceType
		}
		_ = writer.Write([]string{
			device.ID,
			device.Fingerprint,
			deviceType,
			fmt.Sprintf("%v", device.IsTrusted),
			device.FirstSeenAt.Format(time.RFC3339),
			device.LastSeenAt.Format(time.RFC3339),
		})
	}
	_ = writer.Write([]string{})

	// Write audit logs section
	_ = writer.Write([]string{"=== AUDIT LOGS ==="})
	_ = writer.Write([]string{"Action", "Success", "IP Address", "Created At"})
	for _, log := range data.Audit {
		ipAddr := ""
		if log.IPAddress != nil {
			ipAddr = *log.IPAddress
		}
		_ = writer.Write([]string{
			log.Action,
			fmt.Sprintf("%v", log.Success),
			ipAddr,
			log.CreatedAt.Format(time.RFC3339),
		})
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("failed to write CSV: %w", err)
	}

	return buf.Bytes(), nil
}

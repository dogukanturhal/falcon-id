// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// impersonationServiceImpersonationRepo defines the impersonation repository methods needed by ImpersonationService.
type impersonationServiceImpersonationRepo interface {
	GetActiveByAdminID(ctx context.Context, adminUserID uuid.UUID) (*models.ImpersonationSession, error)
	Create(ctx context.Context, session *models.ImpersonationSession) error
	EndSession(ctx context.Context, id uuid.UUID) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ImpersonationSession, error)
	GetWithUsers(ctx context.Context, id uuid.UUID) (*models.ImpersonationSession, error)
	List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, adminUserID, targetUserID *uuid.UUID, activeOnly bool) ([]*models.ImpersonationSession, int, error)
}

// impersonationServiceUserRepo defines the user repository methods needed by ImpersonationService.
type impersonationServiceUserRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error)
}

// ImpersonationService handles impersonation business logic
type ImpersonationService struct {
	impersonationRepo impersonationServiceImpersonationRepo
	userRepo          impersonationServiceUserRepo
	sessionRepo       *repositories.SessionRepository
	auditService      *AuditService
	authService       *AuthService
}

// NewImpersonationService creates a new ImpersonationService
func NewImpersonationService(
	impersonationRepo impersonationServiceImpersonationRepo,
	userRepo impersonationServiceUserRepo,
	sessionRepo *repositories.SessionRepository,
	auditService *AuditService,
	authService *AuthService,
) *ImpersonationService {
	return &ImpersonationService{
		impersonationRepo: impersonationRepo,
		userRepo:          userRepo,
		sessionRepo:       sessionRepo,
		auditService:      auditService,
		authService:       authService,
	}
}

// StartImpersonation starts an impersonation session
func (s *ImpersonationService) StartImpersonation(
	ctx context.Context,
	adminUserID uuid.UUID,
	targetUserID uuid.UUID,
	reason string,
	ipAddress string,
	userAgent string,
	originalSessionID *uuid.UUID,
) (*models.ImpersonationResponse, error) {
	// Get admin user
	adminUser, err := s.userRepo.GetByID(ctx, adminUserID)
	if err != nil {
		return nil, fmt.Errorf("admin user not found")
	}

	// Get target user
	targetUser, err := s.userRepo.GetByID(ctx, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("target user not found")
	}

	// Verify same tenant
	if adminUser.TenantID != targetUser.TenantID {
		return nil, fmt.Errorf("cannot impersonate user from different tenant")
	}

	// Cannot impersonate self
	if adminUserID == targetUserID {
		return nil, fmt.Errorf("cannot impersonate yourself")
	}

	// Check if admin already has an active impersonation
	existing, _ := s.impersonationRepo.GetActiveByAdminID(ctx, adminUserID)
	if existing != nil {
		return nil, fmt.Errorf("you already have an active impersonation session")
	}

	// Validate reason length
	if len(reason) < 10 {
		return nil, fmt.Errorf("reason must be at least 10 characters")
	}

	// Create impersonation session record
	now := time.Now()
	impersonationSession := &models.ImpersonationSession{
		ID:                uuid.New(),
		TenantID:          adminUser.TenantID,
		AdminUserID:       adminUserID,
		TargetUserID:      targetUserID,
		Reason:            reason,
		IPAddress:         &ipAddress,
		UserAgent:         &userAgent,
		StartedAt:         now,
		OriginalSessionID: originalSessionID,
		CreatedAt:         now,
	}

	if err := s.impersonationRepo.Create(ctx, impersonationSession); err != nil {
		return nil, fmt.Errorf("failed to create impersonation session: %w", err)
	}

	// Get target user's roles and permissions for the token
	roleObjs, err := s.userRepo.GetUserRoles(ctx, targetUserID)
	if err != nil {
		roleObjs = []models.Role{}
	}
	roles := make([]string, len(roleObjs))
	for i, r := range roleObjs {
		roles[i] = r.Name
	}

	permObjs, err := s.userRepo.GetUserPermissions(ctx, targetUserID)
	if err != nil {
		permObjs = []models.Permission{}
	}
	permissions := make([]string, len(permObjs))
	for i, p := range permObjs {
		permissions[i] = p.Name
	}

	// Generate tokens for target user with impersonator claim
	accessToken, expiresIn, err := s.authService.GenerateImpersonationTokens(
		ctx,
		targetUser,
		roles,
		permissions,
		adminUserID,
		impersonationSession.ID,
	)
	if err != nil {
		// Rollback impersonation session
		_ = s.impersonationRepo.EndSession(ctx, impersonationSession.ID)
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Log audit event
	s.logAuditEvent(ctx, adminUser.TenantID, adminUserID, "impersonation.started", map[string]interface{}{
		"target_user_id":        targetUserID.String(),
		"target_username":       targetUser.Username,
		"reason":                reason,
		"impersonation_session": impersonationSession.ID.String(),
	}, ipAddress, userAgent)

	return &models.ImpersonationResponse{
		ImpersonationSessionID: impersonationSession.ID.String(),
		AccessToken:            accessToken,
		ExpiresIn:              expiresIn,
		TokenType:              "Bearer",
		TargetUser:             targetUser,
		Message:                fmt.Sprintf("Now impersonating %s", targetUser.Username),
	}, nil
}

// EndImpersonation ends an active impersonation session
func (s *ImpersonationService) EndImpersonation(
	ctx context.Context,
	impersonationSessionID uuid.UUID,
	adminUserID uuid.UUID,
	ipAddress string,
	userAgent string,
) error {
	// Get impersonation session
	session, err := s.impersonationRepo.GetByID(ctx, impersonationSessionID)
	if err != nil {
		return fmt.Errorf("impersonation session not found")
	}

	// Verify the admin is the one who started the impersonation
	if session.AdminUserID != adminUserID {
		return fmt.Errorf("you did not start this impersonation session")
	}

	// Check if already ended
	if session.EndedAt != nil {
		return fmt.Errorf("impersonation session already ended")
	}

	// End the impersonation session
	if err := s.impersonationRepo.EndSession(ctx, impersonationSessionID); err != nil {
		return fmt.Errorf("failed to end impersonation session: %w", err)
	}

	// Log audit event
	s.logAuditEvent(ctx, session.TenantID, adminUserID, "impersonation.ended", map[string]interface{}{
		"target_user_id":        session.TargetUserID.String(),
		"impersonation_session": impersonationSessionID.String(),
	}, ipAddress, userAgent)

	return nil
}

// GetImpersonationStatus gets the current impersonation status
func (s *ImpersonationService) GetImpersonationStatus(
	ctx context.Context,
	impersonatorID *uuid.UUID,
	impersonationSessionID *uuid.UUID,
) (*models.ImpersonationStatus, error) {
	status := &models.ImpersonationStatus{
		IsImpersonating: false,
	}

	if impersonatorID == nil || impersonationSessionID == nil {
		return status, nil
	}

	// Get impersonation session details
	session, err := s.impersonationRepo.GetWithUsers(ctx, *impersonationSessionID)
	if err != nil {
		return status, nil //nolint:nilerr // intentional: if no session found, return empty status without error
	}

	// Only return status if session is still active
	if session.EndedAt != nil {
		return status, nil
	}

	impSessionID := impersonationSessionID.String()
	adminID := session.AdminUserID.String()
	targetID := session.TargetUserID.String()

	status.IsImpersonating = true
	status.ImpersonationSessionID = &impSessionID
	status.AdminUserID = &adminID
	status.TargetUserID = &targetID
	status.StartedAt = &session.StartedAt
	status.Reason = &session.Reason

	if session.AdminUser != nil {
		status.AdminUsername = &session.AdminUser.Username
		status.AdminEmail = &session.AdminUser.Email
	}

	if session.TargetUser != nil {
		status.TargetUsername = &session.TargetUser.Username
	}

	return status, nil
}

// ListImpersonationSessions lists impersonation sessions
func (s *ImpersonationService) ListImpersonationSessions(
	ctx context.Context,
	tenantID uuid.UUID,
	page, pageSize int,
	adminUserID, targetUserID *uuid.UUID,
	activeOnly bool,
) (*models.ImpersonationSessionListResponse, error) {
	sessions, total, err := s.impersonationRepo.List(ctx, tenantID, page, pageSize, adminUserID, targetUserID, activeOnly)
	if err != nil {
		return nil, fmt.Errorf("ListImpersonationSessions: %w", err)
	}

	// Load user details for each session
	for _, session := range sessions {
		if adminUser, err := s.userRepo.GetByID(ctx, session.AdminUserID); err == nil {
			session.AdminUser = adminUser
		}
		if targetUser, err := s.userRepo.GetByID(ctx, session.TargetUserID); err == nil {
			session.TargetUser = targetUser
		}
	}

	totalPages := (total + pageSize - 1) / pageSize

	return &models.ImpersonationSessionListResponse{
		Sessions:   sessions,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// GetImpersonationSession gets a single impersonation session
func (s *ImpersonationService) GetImpersonationSession(ctx context.Context, id uuid.UUID) (*models.ImpersonationSession, error) {
	return s.impersonationRepo.GetWithUsers(ctx, id)
}

// GetActiveImpersonation gets the active impersonation for an admin
func (s *ImpersonationService) GetActiveImpersonation(ctx context.Context, adminUserID uuid.UUID) (*models.ImpersonationSession, error) {
	session, err := s.impersonationRepo.GetActiveByAdminID(ctx, adminUserID)
	if err != nil {
		return nil, fmt.Errorf("GetActiveImpersonation: %w", err)
	}
	if session == nil {
		return nil, nil
	}

	// Load user details
	if adminUser, err := s.userRepo.GetByID(ctx, session.AdminUserID); err == nil {
		session.AdminUser = adminUser
	}
	if targetUser, err := s.userRepo.GetByID(ctx, session.TargetUserID); err == nil {
		session.TargetUser = targetUser
	}

	return session, nil
}

// logAuditEvent logs an audit event
func (s *ImpersonationService) logAuditEvent(
	ctx context.Context,
	tenantID uuid.UUID,
	userID uuid.UUID,
	action string,
	details map[string]interface{},
	_ string,
	_ string,
) {
	if s.auditService == nil {
		return
	}

	// Use LogUserAction for impersonation events
	s.auditService.LogUserAction(ctx, tenantID, &userID, nil, action, true, details)
}

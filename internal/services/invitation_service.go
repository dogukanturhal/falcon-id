// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

const (
	// DefaultInvitationExpiry is the default expiry time for invitations (72 hours)
	DefaultInvitationExpiry = 72 * time.Hour
	// MaxInvitationEmailsPerDay is the max number of invitation emails per user per day
	MaxInvitationEmailsPerDay = 5
)

// invitationServiceInvitationRepo defines the invitation repository methods needed by InvitationService.
type invitationServiceInvitationRepo interface {
	RevokePendingByUserID(ctx context.Context, userID uuid.UUID) error
	Create(ctx context.Context, inv *models.UserInvitation) error
	UpdateEmailSent(ctx context.Context, id uuid.UUID) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*models.UserInvitation, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) (*models.UserInvitation, error)
	UpdateTokenHash(ctx context.Context, id uuid.UUID, tokenHash string, expiresAt time.Time) error
	MarkAsAccepted(ctx context.Context, id uuid.UUID, ipAddress string) error
	ExpireOldInvitations(ctx context.Context) (int64, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.UserInvitation, error)
}

// invitationServiceUserRepo defines the user repository methods needed by InvitationService.
type invitationServiceUserRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	UpdateActivationStatus(ctx context.Context, userID uuid.UUID, status string) error
	Update(ctx context.Context, user *models.User) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error)
}

// invitationServiceSessionRepo defines the session repository methods needed by InvitationService.
type invitationServiceSessionRepo interface {
	Create(ctx context.Context, session *models.Session) error
}

// InvitationService is an exported type.
type InvitationService struct {
	config         *config.Config
	invitationRepo invitationServiceInvitationRepo
	userRepo       invitationServiceUserRepo
	roleRepo       *repositories.RoleRepository
	sessionRepo    invitationServiceSessionRepo
	tokenService   *TokenService
	emailService   *EmailService
	auditService   *AuditService
	tenantRepo     *repositories.TenantRepository
}

// SetTenantRepository injects the tenant repository for tenant slug resolution.
func (s *InvitationService) SetTenantRepository(tenantRepo *repositories.TenantRepository) {
	s.tenantRepo = tenantRepo
}

// NewInvitationService is an exported function.
func NewInvitationService(
	cfg *config.Config,
	invitationRepo invitationServiceInvitationRepo,
	userRepo invitationServiceUserRepo,
	roleRepo *repositories.RoleRepository,
	sessionRepo invitationServiceSessionRepo,
	tokenService *TokenService,
	emailService *EmailService,
	auditService *AuditService,
) *InvitationService {
	return &InvitationService{
		config:         cfg,
		invitationRepo: invitationRepo,
		userRepo:       userRepo,
		roleRepo:       roleRepo,
		sessionRepo:    sessionRepo,
		tokenService:   tokenService,
		emailService:   emailService,
		auditService:   auditService,
	}
}

// CreateInvitation creates a new invitation for a user
func (s *InvitationService) CreateInvitation(ctx context.Context, req *models.CreateInvitationRequest) (*models.InvitationResponse, string, error) {
	// Check if user exists
	user, err := s.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		logger.Error("Failed to get user", zap.Error(err))
		return nil, "", fmt.Errorf("failed to get user")
	}
	if user == nil {
		return nil, "", fmt.Errorf("user not found")
	}

	// Check if user already has a valid password (shouldn't send invitation)
	if user.PasswordHash != nil && *user.PasswordHash != "" && user.ActivationStatus == string(models.UserActivationActive) {
		return nil, "", fmt.Errorf("user already has an active account")
	}

	// Revoke any existing pending invitations
	if err := s.invitationRepo.RevokePendingByUserID(ctx, req.UserID); err != nil {
		logger.Error("Failed to revoke existing invitations", zap.Error(err))
	}

	// Generate secure token
	rawToken, err := crypto.GenerateSecureToken()
	if err != nil {
		logger.Error("Failed to generate invitation token", zap.Error(err))
		return nil, "", fmt.Errorf("failed to generate token")
	}

	// Calculate expiry
	expiryHours := req.ExpiryHours
	if expiryHours <= 0 {
		expiryHours = 72 // Default 72 hours
	}

	// Hash the token
	tokenHash, err := crypto.HashToken(rawToken)
	if err != nil {
		logger.Error("Failed to hash invitation token", zap.Error(err))
		return nil, "", fmt.Errorf("failed to hash token")
	}

	// Create invitation
	invitation := &models.UserInvitation{
		UserID:           req.UserID,
		TenantID:         req.TenantID,
		RealmID:          req.RealmID,
		TokenHash:        tokenHash,
		InvitationType:   req.InvitationType,
		InvitedByAdminID: req.InvitedByAdminID,
		InvitedByUserID:  req.InvitedByUserID,
		Email:            req.Email,
		ExpiresAt:        time.Now().Add(time.Duration(expiryHours) * time.Hour),
		Status:           models.InvitationStatusPending,
	}

	if req.CustomMessage != "" {
		invitation.CustomMessage = &req.CustomMessage
	}

	if err := s.invitationRepo.Create(ctx, invitation); err != nil {
		logger.Error("Failed to create invitation", zap.Error(err))
		return nil, "", fmt.Errorf("failed to create invitation")
	}

	// Update user's activation status
	if err := s.userRepo.UpdateActivationStatus(ctx, req.UserID, string(models.UserActivationPendingInvitation)); err != nil {
		logger.Warn("Failed to update user activation status", zap.Error(err))
	}

	// Send invitation email if requested
	if req.SendEmail {
		if err := s.sendInvitationEmail(ctx, invitation, rawToken, user); err != nil {
			logger.Error("Failed to send invitation email", zap.Error(err))
			// Don't fail the whole operation if email fails
		} else {
			// Update email sent tracking
			if err := s.invitationRepo.UpdateEmailSent(ctx, invitation.ID); err != nil {
				logger.Warn("Failed to update email sent tracking", zap.Error(err))
			}
		}
	}

	logger.Info("Invitation created",
		zap.String("invitation_id", invitation.ID.String()),
		zap.String("user_id", req.UserID.String()),
		zap.String("email", req.Email),
	)

	return invitation.ToResponse(), rawToken, nil
}

// ValidateToken validates an invitation token
func (s *InvitationService) ValidateToken(ctx context.Context, rawToken string) (*models.ValidateInvitationResponse, error) {
	tokenHash, err := crypto.HashToken(rawToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash token: %w", err)
	}

	invitation, err := s.invitationRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		logger.Error("Failed to get invitation", zap.Error(err))
		return &models.ValidateInvitationResponse{
			Valid: false,
			Error: "invalid token",
		}, nil
	}

	if invitation == nil {
		return &models.ValidateInvitationResponse{
			Valid: false,
			Error: "invitation not found",
		}, nil
	}

	if !invitation.IsValid() {
		var errorMsg string
		switch {
		case invitation.IsExpired():
			errorMsg = "invitation has expired"
		case invitation.IsAccepted():
			errorMsg = "invitation has already been used"
		case invitation.IsRevoked():
			errorMsg = "invitation has been revoked"
		default:
			errorMsg = "invitation is no longer valid"
		}
		return &models.ValidateInvitationResponse{
			Valid: false,
			Error: errorMsg,
		}, nil
	}

	// Get tenant name for display
	tenantName := "Your Organization" // Default

	return &models.ValidateInvitationResponse{
		Valid:          true,
		Email:          invitation.Email,
		TenantName:     tenantName,
		InvitationType: invitation.InvitationType,
		ExpiresAt:      &invitation.ExpiresAt,
	}, nil
}

// AcceptInvitation accepts an invitation and sets up the user's password
func (s *InvitationService) AcceptInvitation(ctx context.Context, req *models.SetupAccountRequest, ipAddress, userAgent string) (*models.LoginResponse, error) {
	// Validate passwords match
	if req.Password != req.ConfirmPassword {
		return nil, fmt.Errorf("passwords do not match")
	}

	// Hash the token to find the invitation
	tokenHash, err := crypto.HashToken(req.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to hash token: %w", err)
	}

	invitation, err := s.invitationRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		logger.Error("Failed to get invitation", zap.Error(err))
		return nil, fmt.Errorf("invalid or expired invitation")
	}

	if invitation == nil {
		return nil, fmt.Errorf("invitation not found")
	}

	if !invitation.IsValid() {
		if invitation.IsExpired() {
			return nil, fmt.Errorf("invitation has expired")
		}
		if invitation.IsAccepted() {
			return nil, fmt.Errorf("invitation has already been used")
		}
		return nil, fmt.Errorf("invitation is no longer valid")
	}

	// Get the user
	user, err := s.userRepo.GetByID(ctx, invitation.UserID)
	if err != nil {
		logger.Error("Failed to get user", zap.Error(err))
		return nil, fmt.Errorf("failed to process invitation")
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Hash the new password
	passwordHash, err := crypto.HashPassword(req.Password, nil)
	if err != nil {
		logger.Error("Failed to hash password", zap.Error(err))
		return nil, fmt.Errorf("failed to set password")
	}

	// Update user with password and activate
	user.PasswordHash = &passwordHash
	user.ActivationStatus = string(models.UserActivationActive)
	user.IsActive = true
	user.IsEmailVerified = true
	now := time.Now()
	user.PasswordChangedAt = &now

	if err := s.userRepo.Update(ctx, user); err != nil {
		logger.Error("Failed to update user", zap.Error(err))
		return nil, fmt.Errorf("failed to activate account")
	}

	// Mark invitation as accepted
	if err := s.invitationRepo.MarkAsAccepted(ctx, invitation.ID, ipAddress); err != nil {
		logger.Error("Failed to mark invitation as accepted", zap.Error(err))
	}

	// Get roles and permissions
	roles, err := s.userRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		logger.Warn("Failed to get user roles", zap.Error(err))
		roles = []models.Role{}
	}

	permissions, err := s.userRepo.GetUserPermissions(ctx, user.ID)
	if err != nil {
		logger.Warn("Failed to get user permissions", zap.Error(err))
		permissions = []models.Permission{}
	}

	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}

	permNames := make([]string, len(permissions))
	for i, p := range permissions {
		permNames[i] = p.Name
	}

	// Create session
	session, err := s.createSession(ctx, user.ID, ipAddress, userAgent)
	if err != nil {
		logger.Error("Failed to create session", zap.Error(err))
		return nil, fmt.Errorf("failed to create session")
	}

	// Generate tokens
	accessToken, err := s.tokenService.GenerateAccessToken(ctx, user, session.ID, roleNames, permNames)
	if err != nil {
		logger.Error("Failed to generate access token", zap.Error(err))
		return nil, fmt.Errorf("failed to generate tokens")
	}

	// Update last login
	user.LastLoginAt = &now
	user.LastLoginIP = &ipAddress
	if err := s.userRepo.Update(ctx, user); err != nil {
		logger.Warn("Failed to update user last login", zap.Error(err))
	}

	// Log successful account setup
	s.auditService.LogLogin(ctx, user.TenantID, &user.ID, ipAddress, userAgent, true, "invitation")

	user.Roles = roles
	user.Permissions = permissions

	logger.Info("Invitation accepted, account activated",
		zap.String("user_id", user.ID.String()),
		zap.String("email", user.Email),
	)

	response := user.ToResponse()

	// TenantSlug is not carried by ToResponse() (c-338); populate it here
	// the same way t-451 did for /me and auth_service.go/auth_webauthn_service.go
	// already do for password/WebAuthn login.
	if s.tenantRepo != nil {
		if tenant, err := s.tenantRepo.GetByID(ctx, user.TenantID); err == nil && tenant != nil {
			response.TenantSlug = tenant.Slug
		}
	}

	// Phase 3 (mig 233): RefreshToken left empty — iam_refresh_tokens is
	// dropped, rotation flows through /oauth/token via the BFF's internal
	// OIDC dance after the redirect.
	return &models.LoginResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.config.AccessTokenExpiry.Seconds()),
		User:        response,
	}, nil
}

// ResendInvitation resends an invitation email
func (s *InvitationService) ResendInvitation(ctx context.Context, userID uuid.UUID, force bool) (*models.InvitationResponse, error) {
	// Get existing invitation
	invitation, err := s.invitationRepo.GetByUserID(ctx, userID)
	if err != nil {
		logger.Error("Failed to get invitation", zap.Error(err))
		return nil, fmt.Errorf("failed to get invitation")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		logger.Error("Failed to get user", zap.Error(err))
		return nil, fmt.Errorf("failed to get user")
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	var rawToken string

	if invitation == nil || invitation.IsExpired() || force {
		// Create new invitation
		req := &models.CreateInvitationRequest{
			UserID:         userID,
			TenantID:       user.TenantID,
			InvitationType: models.InvitationTypeTenantAdmin, // Default
			Email:          user.Email,
			SendEmail:      true,
		}
		if user.RealmID != uuid.Nil {
			req.RealmID = &user.RealmID
		}

		resp, _, err := s.CreateInvitation(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ResendInvitation: CreateInvitation failed: %w", err)
		}
		return resp, nil
	}

	// Check rate limit
	if !invitation.CanResendEmail() {
		return nil, fmt.Errorf("please wait before requesting another email")
	}

	// Generate new token if old one is about to expire (less than 24 hours)
	extendExpiry := time.Until(invitation.ExpiresAt) < 24*time.Hour
	rawToken, err = s.refreshInvitationToken(ctx, invitation, extendExpiry)
	if err != nil {
		return nil, err
	}

	// Send email
	if err := s.sendInvitationEmail(ctx, invitation, rawToken, user); err != nil {
		logger.Error("Failed to send invitation email", zap.Error(err))
		return nil, fmt.Errorf("failed to send email")
	}

	// Update email sent tracking
	if err := s.invitationRepo.UpdateEmailSent(ctx, invitation.ID); err != nil {
		logger.Warn("Failed to update email sent tracking", zap.Error(err))
	}

	// Refresh invitation data
	if refreshed, _ := s.invitationRepo.GetByID(ctx, invitation.ID); refreshed != nil {
		invitation = refreshed
	}

	logger.Info("Invitation email resent",
		zap.String("invitation_id", invitation.ID.String()),
		zap.String("email", invitation.Email),
	)

	return invitation.ToResponse(), nil
}

// RevokeInvitation revokes an invitation
// refreshInvitationToken generates a fresh secure token, hashes it, and updates the repo.
// When extendExpiry is true a new full-length expiry is set; otherwise the existing expiry is kept.
func (s *InvitationService) refreshInvitationToken(ctx context.Context, invitation *models.UserInvitation, extendExpiry bool) (string, error) {
	rawToken, err := crypto.GenerateSecureToken()
	if err != nil {
		logger.Error("Failed to generate token", zap.Error(err))
		return "", fmt.Errorf("failed to generate token")
	}
	tokenHash, err := crypto.HashToken(rawToken)
	if err != nil {
		logger.Error("Failed to hash token", zap.Error(err))
		return "", fmt.Errorf("failed to hash token")
	}
	expiry := invitation.ExpiresAt
	if extendExpiry {
		expiry = time.Now().Add(DefaultInvitationExpiry)
	}
	if err := s.invitationRepo.UpdateTokenHash(ctx, invitation.ID, tokenHash, expiry); err != nil {
		logger.Error("Failed to update token", zap.Error(err))
		return "", fmt.Errorf("failed to update invitation")
	}
	if extendExpiry {
		invitation.ExpiresAt = expiry
	}
	return rawToken, nil
}

// RevokeInvitation cancels any pending invitation for the given user.
func (s *InvitationService) RevokeInvitation(ctx context.Context, userID uuid.UUID) error {
	if err := s.invitationRepo.RevokePendingByUserID(ctx, userID); err != nil {
		logger.Error("Failed to revoke invitation", zap.Error(err))
		return fmt.Errorf("failed to revoke invitation")
	}

	logger.Info("Invitation revoked", zap.String("user_id", userID.String()))
	return nil
}

// GetPendingInvitation gets the pending invitation for a user
func (s *InvitationService) GetPendingInvitation(ctx context.Context, userID uuid.UUID) (*models.InvitationResponse, error) {
	invitation, err := s.invitationRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("GetPendingInvitation: %w", err)
	}
	if invitation == nil {
		return nil, nil
	}
	return invitation.ToResponse(), nil
}

// ExpireOldInvitations expires old invitations (for cron job)
func (s *InvitationService) ExpireOldInvitations(ctx context.Context) (int64, error) {
	count, err := s.invitationRepo.ExpireOldInvitations(ctx)
	if err != nil {
		return 0, fmt.Errorf("ExpireOldInvitations: %w", err)
	}

	if count > 0 {
		logger.Info("Expired old invitations", zap.Int64("count", count))
	}

	return count, nil
}

// Helper function to send invitation email
func (s *InvitationService) sendInvitationEmail(ctx context.Context, invitation *models.UserInvitation, rawToken string, user *models.User) error {
	// Resolved per tenant (falls back to the static default) via the same
	// ConfigProvider path SendTeamInvitation uses, so this link and the
	// sender alignment in EmailService.sendEmail can never diverge from a
	// tenant's configured frontend_url. See EmailService.ResolveFrontendURL.
	baseURL := strings.TrimRight(s.emailService.ResolveFrontendURL(ctx, invitation.TenantID), "/")
	setupURL := fmt.Sprintf("%s/setup-account?token=%s", baseURL, rawToken)

	// Get username for email
	var username string
	if user.FirstName != nil && *user.FirstName != "" {
		username = *user.FirstName
	} else {
		username = user.Username
	}

	// Send invitation email
	return s.emailService.SendInvitation(invitation.TenantID, invitation.Email, setupURL, username, "Your Organization")
}

// Helper function to create session
func (s *InvitationService) createSession(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (*models.Session, error) {
	sessionToken, err := crypto.GenerateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("createSession: GenerateSecureToken failed: %w", err)
	}

	deviceInfo := "Account Setup"

	sessionTokenHash, err := crypto.HashToken(sessionToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash session token: %w", err)
	}

	session := &models.Session{
		UserID:           userID,
		SessionTokenHash: sessionTokenHash,
		DeviceInfo:       &deviceInfo,
		IPAddress:        &ipAddress,
		UserAgent:        &userAgent,
		ExpiresAt:        time.Now().Add(s.config.SessionExpiry),
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("createSession: %w", err)
	}

	return session, nil
}

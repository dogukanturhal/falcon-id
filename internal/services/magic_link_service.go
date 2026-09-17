// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
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
	// MagicLinkExpiry is the default expiry time for magic links
	MagicLinkExpiry = 15 * time.Minute
	// MaxMagicLinksPerHour is the max number of magic links per email per hour
	MaxMagicLinksPerHour = 5
	// MaxMagicLinksPerIPPerHour is the max number of magic links per IP per hour
	MaxMagicLinksPerIPPerHour = 10
)

// magicLinkServiceMagicRepo defines the magic link repository methods needed by MagicLinkService.
type magicLinkServiceMagicRepo interface {
	CountRecentByEmail(ctx context.Context, email string, since time.Time) (int, error)
	CountRecentByIP(ctx context.Context, ip string, since time.Time) (int, error)
	Create(ctx context.Context, link *models.MagicLink) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*models.MagicLink, error)
	MarkAsUsed(ctx context.Context, id uuid.UUID) error
	DeleteExpired(ctx context.Context) (int64, error)
}

// magicLinkServiceUserRepo defines the user repository methods needed by MagicLinkService.
type magicLinkServiceUserRepo interface {
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error)
	Update(ctx context.Context, user *models.User) error
}

// magicLinkServiceSessionRepo defines the session repository methods needed by MagicLinkService.
type magicLinkServiceSessionRepo interface {
	Create(ctx context.Context, session *models.Session) error
}

// MagicLinkService is an exported type.
type MagicLinkService struct {
	config       *config.Config
	magicRepo    magicLinkServiceMagicRepo
	userRepo     magicLinkServiceUserRepo
	sessionRepo  magicLinkServiceSessionRepo
	tokenService *TokenService
	emailService *EmailService
	auditService *AuditService
	tenantRepo   *repositories.TenantRepository
}

// SetTenantRepository injects the tenant repository for tenant slug resolution.
func (s *MagicLinkService) SetTenantRepository(tenantRepo *repositories.TenantRepository) {
	s.tenantRepo = tenantRepo
}

// NewMagicLinkService is an exported function.
func NewMagicLinkService(
	cfg *config.Config,
	magicRepo magicLinkServiceMagicRepo,
	userRepo magicLinkServiceUserRepo,
	sessionRepo magicLinkServiceSessionRepo,
	tokenService *TokenService,
	emailService *EmailService,
	auditService *AuditService,
) *MagicLinkService {
	return &MagicLinkService{
		config:       cfg,
		magicRepo:    magicRepo,
		userRepo:     userRepo,
		sessionRepo:  sessionRepo,
		tokenService: tokenService,
		emailService: emailService,
		auditService: auditService,
	}
}

// RequestMagicLink sends a magic link to the user's email
func (s *MagicLinkService) RequestMagicLink(ctx context.Context, tenantID uuid.UUID, email, ipAddress, userAgent string) error {
	// Rate limit by email
	hourAgo := time.Now().Add(-time.Hour)
	emailCount, err := s.magicRepo.CountRecentByEmail(ctx, email, hourAgo)
	if err != nil {
		logger.Error("Failed to count recent magic links by email", zap.Error(err))
		return fmt.Errorf("failed to process request")
	}
	if emailCount >= MaxMagicLinksPerHour {
		logger.Warn("Magic link rate limit exceeded for email",
			zap.String("email", email),
			zap.Int("count", emailCount),
		)
		// Don't reveal this to prevent enumeration
		return nil
	}

	// Rate limit by IP
	ipCount, err := s.magicRepo.CountRecentByIP(ctx, ipAddress, hourAgo)
	if err != nil {
		logger.Error("Failed to count recent magic links by IP", zap.Error(err))
		return fmt.Errorf("failed to process request")
	}
	if ipCount >= MaxMagicLinksPerIPPerHour {
		logger.Warn("Magic link rate limit exceeded for IP",
			zap.String("ip", ipAddress),
			zap.Int("count", ipCount),
		)
		return nil
	}

	user, err := s.userRepo.GetByEmail(ctx, tenantID, email)
	if err != nil {
		logger.Error("Failed to get user by email", zap.Error(err))
		return fmt.Errorf("failed to process request")
	}

	// If user doesn't exist, silently return (prevent enumeration)
	if user == nil {
		logger.Info("Magic link requested for non-existent email", zap.String("email", email))
		return nil
	}

	// Check if user is active
	if !user.IsActive {
		logger.Info("Magic link requested for inactive user", zap.String("email", email))
		return nil
	}

	// Check if user is locked
	if user.IsLocked {
		logger.Info("Magic link requested for locked user", zap.String("email", email))
		return nil
	}

	// Generate magic link token
	token, err := crypto.GenerateSecureToken()
	if err != nil {
		logger.Error("Failed to generate magic link token", zap.Error(err))
		return fmt.Errorf("failed to generate token")
	}

	// Create magic link record
	tokenHash, err := crypto.HashToken(token)
	if err != nil {
		logger.Error("Failed to hash token", zap.Error(err))
		return fmt.Errorf("failed to hash token")
	}

	magicLink := &models.MagicLink{
		UserID:    &user.ID,
		Email:     email,
		TokenHash: tokenHash,
		IPAddress: &ipAddress,
		UserAgent: &userAgent,
		ExpiresAt: time.Now().Add(MagicLinkExpiry),
	}

	if err := s.magicRepo.Create(ctx, magicLink); err != nil {
		logger.Error("Failed to create magic link", zap.Error(err))
		return fmt.Errorf("failed to create magic link")
	}

	// Generate the magic link URL
	baseURL := s.config.FrontendURL
	if baseURL == "" {
		baseURL = defaultFrontendURL
	}
	magicLinkURL := fmt.Sprintf("%s/login/magic-link?token=%s", baseURL, token)

	// Get username for email
	var username string
	if user.FirstName != nil && *user.FirstName != "" {
		username = *user.FirstName
	} else {
		username = user.Username
	}

	// Send email
	if err := s.emailService.SendMagicLink(user.TenantID, email, magicLinkURL, username); err != nil {
		logger.Error("Failed to send magic link email",
			zap.Error(err),
			zap.String("email", email),
		)
		// Don't return error to user to prevent enumeration
	}

	logger.Info("Magic link sent",
		zap.String("email", email),
		zap.String("user_id", user.ID.String()),
	)

	return nil
}

// VerifyMagicLink verifies a magic link token and returns login tokens
func (s *MagicLinkService) VerifyMagicLink(ctx context.Context, token, ipAddress, userAgent string) (*models.LoginResponse, error) {
	// Hash the token
	tokenHash, err := crypto.HashToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to hash token: %w", err)
	}

	// Find the magic link
	magicLink, err := s.magicRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		logger.Error("Failed to get magic link", zap.Error(err))
		return nil, fmt.Errorf("invalid or expired link")
	}

	if magicLink == nil {
		logger.Warn("Magic link not found", zap.String("token_hash", tokenHash[:16]))
		return nil, fmt.Errorf("invalid or expired link")
	}

	// Check if already used
	if magicLink.IsUsed() {
		logger.Warn("Magic link already used", zap.String("id", magicLink.ID.String()))
		return nil, fmt.Errorf("link has already been used")
	}

	// Check if expired
	if magicLink.IsExpired() {
		logger.Warn("Magic link expired", zap.String("id", magicLink.ID.String()))
		return nil, fmt.Errorf("link has expired")
	}

	// Mark as used
	if err := s.magicRepo.MarkAsUsed(ctx, magicLink.ID); err != nil {
		logger.Error("Failed to mark magic link as used", zap.Error(err))
		return nil, fmt.Errorf("failed to process login")
	}

	// Get user
	if magicLink.UserID == nil {
		return nil, fmt.Errorf("invalid link")
	}

	user, err := s.userRepo.GetByID(ctx, *magicLink.UserID)
	if err != nil {
		logger.Error("Failed to get user", zap.Error(err))
		return nil, fmt.Errorf("failed to process login")
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check if user is still active
	if !user.IsActive {
		return nil, fmt.Errorf("account is disabled")
	}

	if user.IsLocked {
		return nil, fmt.Errorf("account is locked")
	}

	// Get roles and permissions
	roles, err := s.userRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	permissions, err := s.userRepo.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
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
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Generate tokens
	accessToken, err := s.tokenService.GenerateAccessToken(ctx, user, session.ID, roleNames, permNames)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	user.LastLoginIP = &ipAddress
	if err := s.userRepo.Update(ctx, user); err != nil {
		logger.Error("Failed to update user last login", zap.Error(err))
	}

	// Log successful login
	s.auditService.LogLogin(ctx, user.TenantID, &user.ID, ipAddress, userAgent, true, "magic_link")

	user.Roles = roles
	user.Permissions = permissions

	logger.Info("Magic link login successful",
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
	// dropped, BFF runs the OAuth dance after the redirect for the
	// rotatable token pair.
	return &models.LoginResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.config.AccessTokenExpiry.Seconds()),
		User:        response,
	}, nil
}

func (s *MagicLinkService) createSession(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (*models.Session, error) {
	sessionToken, err := crypto.GenerateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("createSession: GenerateSecureToken failed: %w", err)
	}

	sessionTokenHash, err := crypto.HashToken(sessionToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash session token: %w", err)
	}

	deviceInfo := "Magic Link"

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

// CleanupExpired removes expired magic links
func (s *MagicLinkService) CleanupExpired(ctx context.Context) (int64, error) {
	count, err := s.magicRepo.DeleteExpired(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired magic links: %w", err)
	}

	if count > 0 {
		logger.Info("Cleaned up expired magic links", zap.Int64("count", count))
	}

	return count, nil
}

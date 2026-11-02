// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

// AdminHandler is an exported type.
type AdminHandler struct {
	accessTerminator adminAccessTerminator
	userService           *services.UserService
	roleService           *services.RoleService
	sessionRepo           *repositories.SessionRepository
	idpRepo               *repositories.IdentityProviderRepository
	ldapService           *services.LDAPService
	auditService          *services.AuditService
	mfaService            *services.MFAService
	passwordPolicyService *services.PasswordPolicyService
	rateLimitService      *services.RateLimitService
	ipRuleService         *services.IPRuleService
	deviceService         *services.DeviceService
	ldapSyncHistoryRepo   *repositories.LDAPSyncHistoryRepository
	tokenService          *services.TokenService
	tokenBlacklist        *redis.TokenBlacklist
	encryptionService     *crypto.EncryptionService
	logger                *zap.Logger
}

// NewAdminHandler is an exported function.
func NewAdminHandler(
	userService *services.UserService,
	roleService *services.RoleService,
	sessionRepo *repositories.SessionRepository,
	idpRepo *repositories.IdentityProviderRepository,
	ldapService *services.LDAPService,
	auditService *services.AuditService,
	log *zap.Logger,
) *AdminHandler {
	return &AdminHandler{
		userService:  userService,
		roleService:  roleService,
		sessionRepo:  sessionRepo,
		idpRepo:      idpRepo,
		ldapService:  ldapService,
		auditService: auditService,
		logger:       log,
	}
}

// adminAccessTerminator is the single access-termination path (satisfied by
// *services.UserAccessTerminator).
type adminAccessTerminator interface {
	TerminateUserAccessWith(ctx context.Context, userID, tenantID uuid.UUID, reason string, opts services.TerminateOptions) error
	TerminateSession(ctx context.Context, userID, tenantID, sessionID uuid.UUID, reason string) error
}

// SetAccessTerminator wires the access terminator used by session revoke endpoints.
func (h *AdminHandler) SetAccessTerminator(t adminAccessTerminator) {
	h.accessTerminator = t
}

// SetMFAService sets the MFA service (called after initialization)
func (h *AdminHandler) SetMFAService(mfaService *services.MFAService) {
	h.mfaService = mfaService
}

// SetPasswordPolicyService sets the password policy service (called after initialization)
func (h *AdminHandler) SetPasswordPolicyService(service *services.PasswordPolicyService) {
	h.passwordPolicyService = service
}

// SetRateLimitService sets the rate limit service (called after initialization)
func (h *AdminHandler) SetRateLimitService(service *services.RateLimitService) {
	h.rateLimitService = service
}

// SetIPRuleService sets the IP rule service (called after initialization)
func (h *AdminHandler) SetIPRuleService(service *services.IPRuleService) {
	h.ipRuleService = service
}

// SetDeviceService sets the device service (called after initialization)
func (h *AdminHandler) SetDeviceService(service *services.DeviceService) {
	h.deviceService = service
}

// SetTokenService wires the token service so admin session revocation also
// revokes the refresh tokens bound to the revoked sessions (called after initialization)
func (h *AdminHandler) SetTokenService(svc *services.TokenService) {
	h.tokenService = svc
}

// SetTokenBlacklist sets the token blacklist for session revocation (called after initialization)
func (h *AdminHandler) SetTokenBlacklist(blacklist *redis.TokenBlacklist) {
	h.tokenBlacklist = blacklist
}

// SetLDAPSyncHistoryRepo sets the LDAP sync history repository (called after initialization)
func (h *AdminHandler) SetLDAPSyncHistoryRepo(repo *repositories.LDAPSyncHistoryRepository) {
	h.ldapSyncHistoryRepo = repo
}

// SetEncryptionService sets the encryption service for encrypting IDP secrets (called after initialization)
func (h *AdminHandler) SetEncryptionService(service *crypto.EncryptionService) {
	h.encryptionService = service
}

// validateUserTenantAccess validates that a user belongs to the requester's tenant.
// SECURITY (CVE-HEXX-IAM-002): This function prevents Insecure Direct Object Reference (IDOR) attacks
// by ensuring admins can only access/modify users within their own tenant.
// Platform admins (exampletenant tenant) are allowed to access users across all tenants.
//
// Returns:
// - nil if access is allowed (user is in same tenant OR requester is platform admin)
// - error with 404 message if access denied (returns 404 instead of 403 to prevent tenant enumeration)
func (h *AdminHandler) validateUserTenantAccess(ctx context.Context, targetUserID uuid.UUID, currentUser *models.CurrentUser) error {
	if currentUser.IsPlatformAdmin && currentUser.TenantID.String() == models.HexxlockInternalTenantID {
		h.logger.Debug("Platform admin accessing cross-tenant user",
			zap.String("admin_id", currentUser.ID.String()),
			zap.String("target_user_id", targetUserID.String()),
		)
		return nil
	}

	targetUser, err := h.userService.GetByID(ctx, targetUserID)
	if err != nil {
		h.logger.Warn("User not found during tenant validation",
			zap.String("target_user_id", targetUserID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("user not found")
	}

	if targetUser.TenantID != currentUser.TenantID {
		h.logger.Warn("Cross-tenant user access attempt blocked",
			zap.String("requester_id", currentUser.ID.String()),
			zap.String("requester_tenant", currentUser.TenantID.String()),
			zap.String("target_user_id", targetUserID.String()),
			zap.String("target_user_tenant", targetUser.TenantID.String()),
		)
		return fmt.Errorf("user not found")
	}

	return nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// auth_account_service.go contains user profile, password, session management,
// and impersonation methods of AuthService.
// Extracted from auth_service.go to keep files under 800 lines.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

// knownModules is the canonical set of ExampleSuite business module slugs.
var knownModules = []string{
	"hr", "crm", "inventory", "invoicing", "marketing", "accounting",
	"plm", "qms", "sd", "pm", "cmms", "fico", "mm", "ppscm", "ecommerce",
}

// deriveEntitledModules returns the list of business modules a user can access
// based on their role names, permission names, and whether they have
// all-modules access (platform/tenant admins).
func deriveEntitledModules(roleNames, permNames []string, allModulesAccess bool) []string {
	if allModulesAccess {
		return knownModules
	}
	seen := make(map[string]bool)
	// Extract module prefix from permissions like "crm:contacts:read"
	for _, p := range permNames {
		parts := strings.SplitN(p, ":", 2)
		if len(parts) >= 2 {
			mod := strings.ToLower(parts[0])
			for _, km := range knownModules {
				if mod == km {
					seen[mod] = true
					break
				}
			}
		}
	}
	// Check role names for module matches (e.g. "hr_manager")
	for _, r := range roleNames {
		rl := strings.ToLower(r)
		for _, km := range knownModules {
			if strings.HasPrefix(rl, km+"_") || rl == km {
				seen[km] = true
			}
		}
	}
	modules := make([]string, 0, len(seen))
	for m := range seen {
		modules = append(modules, m)
	}
	return modules
}

// GetCurrentUser returns the current user's information
func (s *AuthService) GetCurrentUser(ctx context.Context, userID uuid.UUID) (*models.UserResponse, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("GetCurrentUser: failed to get user: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Get direct roles
	roles, err := s.userRepo.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("GetCurrentUser: failed to get user roles: %w", err)
	}

	permissions, err := s.userRepo.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("GetCurrentUser: failed to get user permissions: %w", err)
	}

	user.Roles = roles
	user.Permissions = permissions

	// Get effective roles (direct + group-inherited) if group service is available
	response := user.ToResponse()

	// TenantSlug is populated at login (see auth_service.go's tenantCtx.TenantSlug
	// handling) but /me re-derives UserResponse from scratch via ToResponse(),
	// which never carries a slug (c-338: the field exists on the struct and its
	// own doc comment says "for frontend tenant context persistence", but nothing
	// on this path ever set it — same lookup as login, same nil-safe repo guard).
	if s.tenantRepo != nil {
		if tenant, err := s.tenantRepo.GetByID(ctx, user.TenantID); err == nil && tenant != nil {
			response.TenantSlug = tenant.Slug
		}
	}

	if s.groupService != nil {
		effectiveRoles, err := s.groupService.GetUserEffectiveRoles(ctx, userID)
		if err != nil {
			logger.Warn("Failed to get effective roles for user", zap.Error(err))
		} else {
			response.EffectiveRoles = effectiveRoles
		}
	}

	// Derive and attach entitled modules so the /me endpoint also exposes them.
	roleNames := make([]string, 0, len(roles))
	isPlatformAdmin := false
	isTenantAdmin := false
	for _, r := range roles {
		roleNames = append(roleNames, r.Name)
		if r.Name == "platform_admin" {
			isPlatformAdmin = true
		}
		if r.Name == roleNameAdmin || r.Name == "super_admin" || r.Name == "tenant_admin" {
			isTenantAdmin = true
		}
	}
	allModulesAccess := isPlatformAdmin || isTenantAdmin
	permNames := make([]string, 0, len(permissions))
	for _, p := range permissions {
		permNames = append(permNames, p.Name)
	}
	response.Modules = deriveEntitledModules(roleNames, permNames, allModulesAccess)

	return response, nil
}

// UpdateProfile updates the current user's profile
func (s *AuthService) UpdateProfile(ctx context.Context, userID uuid.UUID, req *models.UpdateProfileRequest) (*models.UserResponse, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("UpdateProfile: failed to get user: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Update allowed fields
	if req.FirstName != nil {
		user.FirstName = req.FirstName
	}
	if req.LastName != nil {
		user.LastName = req.LastName
	}
	if req.DisplayName != nil {
		user.DisplayName = req.DisplayName
	}
	if req.Phone != nil {
		user.Phone = req.Phone
	}
	if req.AvatarURL != nil {
		user.AvatarURL = req.AvatarURL
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update profile: %w", err)
	}

	// Log audit
	s.auditService.LogUserAction(ctx, user.TenantID, &userID, &userID, "profile_updated", true, map[string]interface{}{
		"updated_fields": []string{"first_name", "last_name", "display_name", "phone"},
	})

	// Reload with roles and permissions
	return s.GetCurrentUser(ctx, userID)
}

// ChangePassword changes a user's password
func (s *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, currentSessionID uuid.UUID, currentPassword, newPassword string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("ChangePassword: failed to get user: %w", err)
	}

	if user == nil {
		return fmt.Errorf("user not found")
	}

	// Check if user is federated
	if user.FederationType != nil && *user.FederationType == federationTypeLDAP {
		return fmt.Errorf("password change not supported for LDAP users")
	}

	// Verify current password
	if user.PasswordHash == nil {
		return fmt.Errorf("no password set")
	}

	valid, err := crypto.VerifyPassword(currentPassword, *user.PasswordHash)
	if err != nil || !valid {
		return fmt.Errorf("current password is incorrect")
	}

	// Validate new password
	policy := &crypto.PasswordPolicy{
		MinLength:      s.config.PasswordMinLength,
		RequireUpper:   s.config.PasswordRequireUpper,
		RequireLower:   s.config.PasswordRequireLower,
		RequireDigit:   s.config.PasswordRequireDigit,
		RequireSpecial: s.config.PasswordRequireSpecial,
	}

	if err := crypto.ValidatePassword(newPassword, policy); err != nil {
		return fmt.Errorf("ChangePassword: password validation failed: %w", err)
	}

	// ASVS V6 / NIST 800-63B — reject breached passwords on password-change.
	if err := assertPasswordNotBreached(ctx, s.breachChecker, newPassword); err != nil {
		return fmt.Errorf("ChangePassword: %w", err)
	}

	// Hash new password
	hash, err := crypto.HashPassword(newPassword, nil)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update user
	user.PasswordHash = &hash
	now := time.Now()
	user.PasswordChangedAt = &now
	user.MustChangePassword = false

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Security audit: password changed successfully
	logger.SecurityAudit.Info("Security audit: password changed",
		zap.String("event", "auth.password.changed"),
		zap.String("user_id", userID.String()),
		zap.String("username", user.Username),
		zap.Time("timestamp", time.Now().UTC()),
	)

	// Revoke OAuth tokens across every relying party so old creds can't
	// continue to mint access tokens (Phase 3.1 — flipped from the
	// now-no-op'd RevokeAllUserRefreshTokensExceptSession against the
	// dropped iam_refresh_tokens table). The "except session" semantic
	// from the pre-Phase-3 path is dropped intentionally — a password
	// change SHOULD force re-login on every device including the current
	// one (NIST SP 800-63B-4 §5.1.1.2 + Auth0/Okta default behavior on
	// password change). The current session ends below via
	// EndAllUserSessionsExcept; any subsequent OAuth-token usage from
	// the current device fails with "invalid_grant: token revoked"
	// causing the BFF to redirect to login.
	_ = s.tokenService.RevokeAllUserOAuthTokens(ctx, userID, "password_change")

	// End all sessions except current
	_ = s.sessionRepo.EndAllUserSessionsExcept(ctx, userID, currentSessionID, "password_change")

	// Publish CAEPasswordChanged so receivers (Talon IAP, SSE
	// subscribers) immediately re-evaluate any other active session
	// for this user. The DB-layer revocations above already make those
	// sessions unusable on next API call, but receivers that hold
	// access tokens in memory or have outstanding requests benefit
	// from the push signal. nil-safe (no-op when CAEService isn't
	// wired or Redis is unavailable).
	if s.caeService != nil {
		_ = s.caeService.PublishEvent(ctx, CAEEvent{
			Type:      CAEPasswordChanged,
			UserID:    userID,
			TenantID:  user.TenantID,
			Timestamp: time.Now().UTC(),
			Metadata: map[string]string{
				"current_session_id": currentSessionID.String(),
				"reason":             "user_initiated_change",
			},
		})
	}

	// Phase C (2026-05-26): out-of-band email notification on the
	// security-critical "password changed" event. Canonical
	// Microsoft / Google / Auth0 pattern — gives the legitimate user
	// a tripwire if their session was stolen and an attacker used
	// step-up to rotate the password.
	if s.securityNotifier != nil {
		s.securityNotifier.NotifyPasswordChanged(ctx, user, BuildEventContext("", "", ""))
	}

	return nil
}

// GetActiveSessions returns all active sessions for a user
func (s *AuthService) GetActiveSessions(ctx context.Context, userID uuid.UUID, currentSessionID *uuid.UUID) ([]models.SessionResponse, error) {
	sessions, err := s.sessionRepo.GetActiveSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("GetActiveSessions: failed to get sessions: %w", err)
	}

	result := make([]models.SessionResponse, len(sessions))
	for i, session := range sessions {
		result[i] = *session.ToResponse(currentSessionID)
	}

	return result, nil
}

// RevokeSession ends a specific session
func (s *AuthService) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("RevokeSession: failed to get session: %w", err)
	}

	if session == nil {
		return fmt.Errorf("session not found")
	}

	if session.UserID != userID {
		return fmt.Errorf("session does not belong to user")
	}

	return s.sessionRepo.EndSession(ctx, sessionID, "revoked")
}

// parseDeviceInfo extracts device type from user agent string
func parseDeviceInfo(userAgent string) string {
	if strings.Contains(strings.ToLower(userAgent), "mobile") {
		return "Mobile"
	}
	if strings.Contains(strings.ToLower(userAgent), "tablet") {
		return "Tablet"
	}
	return "Desktop"
}

// GetLoginHistory returns a user's login attempt history with pagination.
//
// Sourced from iam_login_risk_events (v0.232.241 +). Previous backing
// store was iam_sessions, which only persists post-auth — failed
// attempts (blocked / MFA-failed / wrong-password past failure-threshold)
// never appeared in the History tab, an obvious gap from a credential-
// stuffing detection POV. iam_login_risk_events records every attempt
// with an `outcome` ∈ {allowed, mfa_challenged, blocked} that drives the
// user-visible status label.
//
// riskService is a HARD dependency. Production wires it via NewAuthService;
// tests that exercise this path must wire a stub. There is no legacy
// fallback — the sessions-only view was incomplete and the tier-1 contract
// is "every attempt is visible to the user it concerns."
func (s *AuthService) GetLoginHistory(ctx context.Context, userID uuid.UUID, page, pageSize int) (*models.LoginHistoryResponse, error) {
	if s.riskService == nil {
		return nil, fmt.Errorf("GetLoginHistory: risk service not configured")
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	events, total, err := s.riskService.GetUserLoginHistoryPaginated(ctx, userID, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to get login history: %w", err)
	}

	history := make([]models.LoginHistoryEntry, len(events))
	for i, ev := range events {
		history[i] = *ev.ToLoginHistoryEntry()
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	return &models.LoginHistoryResponse{
		History:    history,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// UpdateSessionActivity updates the last activity timestamp for a session (heartbeat).
// This updates both PostgreSQL (authoritative last_activity_at + sliding expires_at)
// and refreshes the Redis session cache TTL to prevent cache eviction for active sessions.
// The sliding expires_at is extended by SESSION_IDLE_TIMEOUT, capped by max_expires_at,
// ensuring background tabs with periodic heartbeats keep sessions alive.
func (s *AuthService) UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error {
	// Update PostgreSQL (authoritative) — extends both last_activity_at and expires_at
	if err := s.sessionRepo.UpdateLastActivity(ctx, sessionID); err != nil {
		return err
	}

	// Also refresh the Redis session cache TTL so active sessions stay cached.
	// This is best-effort -- failure does not affect the heartbeat response.
	if s.sessionCache != nil {
		if err := s.sessionCache.Refresh(ctx, sessionID); err != nil {
			logger.Warn("Failed to refresh Redis session cache TTL during heartbeat",
				zap.Error(err),
				zap.String("session_id", sessionID.String()),
			)
		}
	}

	return nil
}

// GenerateImpersonationTokens creates tokens for an impersonated user
func (s *AuthService) GenerateImpersonationTokens(
	ctx context.Context,
	targetUser *models.User,
	roles []string,
	permissions []string,
	impersonatorID uuid.UUID,
	impersonationSessionID uuid.UUID,
) (accessToken string, refreshToken string, expiresIn int, err error) {
	// Create a temporary session ID for the impersonation
	sessionID := uuid.New()

	// Generate impersonation access token (with special claims)
	accessToken, err = s.tokenService.GenerateImpersonationAccessToken(
		ctx,
		targetUser,
		sessionID,
		roles,
		permissions,
		impersonatorID,
		impersonationSessionID,
	)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to generate access token: %w", err)
	}

	// For impersonation, we don't generate a refresh token
	// The admin must end impersonation and re-impersonate if needed
	// This is a security measure to prevent long-lived impersonation

	// Impersonation tokens expire in 15 minutes
	expiresIn = 15 * 60

	return accessToken, "", expiresIn, nil
}

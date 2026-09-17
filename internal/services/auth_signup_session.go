// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// auth_signup_session.go: session issuance for self-service signup.
//
// IssueSessionForNewUser lets SignupService.CompleteSignup hand a
// freshly-provisioned user a real session instead of forcing a second,
// separate hosted-login round trip. It is NOT a parallel/weaker token
// path: it runs the identical tail of AuthService.Login (steps 7-12 —
// role/permission resolution, the admin-passkey-required policy gate,
// session creation, access-token minting, buildLoginResponse) that every
// password login goes through. The only things skipped are steps 1-6
// (tenant/credential resolution and the MFA challenge), and both are
// skipped for a reason specific to this call site, not as a shortcut:
//   - Tenant is already known (CompleteSignup just provisioned it).
//   - Credentials were already verified at InitiateSignup (password) and
//     VerifyEmail (email ownership via one-time token) — re-checking a
//     password here would mean holding it in memory across the whole
//     three-step signup flow for no security benefit.
//   - MFA: a user this function is called for has, by construction, just
//     been created by provisionUser/CreateForSignup, which never enrolls
//     an MFA factor. HasAnyMFAFactor is therefore always false here. This
//     function verifies that invariant explicitly and refuses to mint a
//     session if it ever turns out false — it does not silently mark MFA
//     as satisfied the way a bypass would.
import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

func (s *AuthService) IssueSessionForNewUser(
	ctx context.Context,
	tenantID uuid.UUID,
	user *models.User,
	ipAddress, userAgent string,
) (*models.LoginResponse, error) {
	// Verify the "no MFA factor yet" invariant rather than assuming it.
	// If a future change ever attaches a factor during signup, this must
	// fail closed and route the caller through Login/CompleteMFALogin
	// instead of minting an unchallenged session.
	hasFactor, err := s.userRepo.HasAnyMFAFactor(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("check user MFA factor inventory: %w", err)
	}
	if hasFactor {
		return nil, fmt.Errorf("new signup user unexpectedly has an MFA factor enrolled — refusing to mint an unchallenged session")
	}

	tenantCtx := &tenantContext{TenantID: tenantID}
	if s.tenantRepo != nil {
		if tenant, err := s.tenantRepo.GetByID(ctx, tenantID); err == nil && tenant != nil {
			tenantCtx.TenantSlug = tenant.Slug
		}
	}

	roleNames, roles, permNames, permissions, err := s.getUserRolesAndPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get user roles and permissions: %w", err)
	}

	// Same admin-passkey-required policy gate a normal Login goes
	// through. A signup that self-assigns the tenant admin role (the
	// common "you created it, you own it" case) must not skip this.
	if interrupt, err := s.maybePasskeyEnrollmentInterrupt(ctx, tenantCtx, user, &models.LoginRequest{}, ipAddress, userAgent, true, nil, roleNames); err != nil {
		return nil, fmt.Errorf("admin passkey gate: %w", err)
	} else if interrupt != nil {
		return interrupt, nil
	}

	session, err := s.createSessionWithInvalidation(ctx, user.ID, ipAddress, userAgent, []string{"pwd"}, false)
	if err != nil {
		return nil, fmt.Errorf("create session with invalidation: %w", err)
	}

	accessToken, err := s.generateAccessToken(ctx, user, session.ID, roleNames, permNames, "")
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	if err := s.updateUserLoginInfo(ctx, user, ipAddress); err != nil {
		logger.Error("Failed to update user login info after signup session issuance", zap.Error(err))
	}

	resp, err := s.buildLoginResponse(ctx, tenantCtx, user, roles, permissions, accessToken, false, true, nil)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

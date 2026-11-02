// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// bootstrapAdminUser creates the initial platform admin if none exists.
// This follows the Keycloak/ArgoCD pattern: env-var-triggered, idempotent,
// uses the app's own service layer for hash compatibility.
//
// Activation is controlled by two environment variables:
//
//	FALCON_ADMIN_EMAIL    — the email address for the bootstrap admin account
//	FALCON_ADMIN_PASSWORD — the plaintext password (hashed by UserService)
//
// When neither variable is set the function returns immediately, making it a
// no-op in deployments that do not need bootstrap.  The function is safe to
// call on every restart: the existence check ensures it is idempotent.
func bootstrapAdminUser(services *Services, repos *Repositories) {
	adminEmail := os.Getenv("FALCON_ADMIN_EMAIL")
	adminPassword := os.Getenv("FALCON_ADMIN_PASSWORD")
	if adminEmail == "" || adminPassword == "" {
		return // No bootstrap requested
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tenantID := uuid.MustParse(models.HexxlockInternalTenantID)

	// Idempotency check: skip creation when the account already exists.
	existing, err := repos.User.GetByEmail(ctx, tenantID, adminEmail)
	if err != nil {
		logger.Error("bootstrapAdminUser: failed to check for existing user",
			zap.String("email", adminEmail),
			zap.Error(err),
		)
		return
	}
	if existing != nil {
		logger.Info("bootstrapAdminUser: admin user already exists, skipping",
			zap.String("email", adminEmail),
		)
		return
	}

	// Realm — deterministic, fail-closed.
	//
	// `exampletenant` is the platform-tenant sentinel. Per
	// internal/models/well_known_ids.go it lives in the platform realm
	// (WellKnownRealmPlatform), isolated from the customer realms. We
	// thread the realm explicitly because the realm_tenants assignment
	// may not yet exist at bootstrap time (e.g. on a fresh DB seeded
	// declaratively by Keystone where data rows are operator-managed),
	// and OWASP Multi-Tenant + RFC 9700 §4 forbid silently defaulting
	// security-critical scope identifiers.
	//
	// Pre-check: refuse to run when the platform realm row is missing
	// rather than letting the user be created with a dangling realm_id
	// (foreign-key check would catch it on insert anyway, but failing
	// here surfaces the operator-action requirement clearly).
	platformRealmID := models.WellKnownRealmPlatform
	if platformRealm, realmErr := repos.Realm.GetByID(ctx, platformRealmID); realmErr != nil {
		logger.Error("bootstrapAdminUser: cannot verify platform realm; refusing to bootstrap",
			zap.String("realm_id", platformRealmID.String()),
			zap.Error(realmErr),
		)
		return
	} else if platformRealm == nil {
		logger.Error("bootstrapAdminUser: platform realm row missing — bootstrapPlatformRealm should have run first",
			zap.String("realm_id", platformRealmID.String()),
			zap.String("hint", "Confirm cmd/realm_bootstrap.go:bootstrapPlatformRealm runs before bootstrapAdminUser; check pod logs for bootstrapPlatformRealm error path. Manual recovery: INSERT INTO realms (id, slug, display_name, type, status) VALUES ('"+platformRealmID.String()+"', 'platform', 'HexxLock Platform', 'platform', 'active');"),
		)
		return
	}

	firstName := "Platform"
	lastName := "Admin"
	req := &models.CreateUserRequest{
		TenantID:  tenantID,
		RealmID:   &platformRealmID,
		Username:  extractUsernameFromEmail(adminEmail),
		Email:     adminEmail,
		Password:  adminPassword,
		FirstName: &firstName,
		LastName:  &lastName,
	}

	// Use the app's own UserService so that password hashing, policy
	// validation, audit logging, and event publishing all execute through
	// the same code path as a normal admin-created user.
	user, err := services.User.Create(ctx, req, nil)
	if err != nil {
		logger.Error("bootstrapAdminUser: failed to create admin user",
			zap.String("email", adminEmail),
			zap.Error(err),
		)
		return
	}

	// Mark the account as email-verified — this is an operator-bootstrapped
	// account, not a self-service registration that requires email confirmation.
	if dbUser, getErr := repos.User.GetByID(ctx, user.ID); getErr == nil && dbUser != nil {
		dbUser.IsEmailVerified = true
		if updateErr := repos.User.Update(ctx, dbUser); updateErr != nil {
			logger.Warn("bootstrapAdminUser: could not mark email as verified",
				zap.String("user_id", user.ID.String()),
				zap.Error(updateErr),
			)
		}
	}

	// Assign platform_admin and iam_admin roles.
	// GetByName returns a single role; call it twice to keep the repository
	// interface unchanged (no GetByNames batch method exists).
	//
	// OPS_STRICT_PLATFORM_ROLES: standing platform_admin / iam_admin is
	// reserved for the single break-glass account (OPS_BREAK_GLASS_EMAIL;
	// unset = the account created from FALCON_ADMIN_EMAIL). Any other
	// bootstrap account is created without them and gets platform authority
	// through JIT elevation only.
	roleNames := []string{"platform_admin", "iam_admin"}
	if opsStrictPlatformRoles() && !isBreakGlassBootstrap(adminEmail) {
		logger.Warn("bootstrapAdminUser: OPS_STRICT_PLATFORM_ROLES is on and this account is not the break-glass account; not assigning standing platform_admin/iam_admin",
			zap.String("email", adminEmail),
		)
		roleNames = nil
	}
	var roleIDs []uuid.UUID
	for _, name := range roleNames {
		role, roleErr := repos.Role.GetByName(ctx, tenantID, name)
		if roleErr != nil {
			logger.Warn("bootstrapAdminUser: could not look up role",
				zap.String("role", name),
				zap.Error(roleErr),
			)
			continue
		}
		if role == nil {
			logger.Warn("bootstrapAdminUser: role not found in tenant",
				zap.String("role", name),
				zap.String("tenant_id", tenantID.String()),
			)
			continue
		}
		roleIDs = append(roleIDs, role.ID)
	}

	if len(roleIDs) > 0 {
		if assignErr := repos.User.AssignRoles(ctx, user.ID, roleIDs, nil); assignErr != nil {
			logger.Error("bootstrapAdminUser: failed to assign admin roles",
				zap.String("user_id", user.ID.String()),
				zap.Error(assignErr),
			)
			return
		}
	}

	logger.Info("bootstrapAdminUser: platform admin bootstrapped successfully",
		zap.String("email", adminEmail),
		zap.String("username", user.Username),
		zap.String("user_id", user.ID.String()),
		zap.String("tenant", "exampletenant"),
	)
}

// opsStrictPlatformRoles reads OPS_STRICT_PLATFORM_ROLES (default false).
func opsStrictPlatformRoles() bool {
	v, err := strconv.ParseBool(strings.TrimSpace(os.Getenv("OPS_STRICT_PLATFORM_ROLES")))
	return err == nil && v
}

// isBreakGlassBootstrap reports whether email is the break-glass account:
// OPS_BREAK_GLASS_EMAIL when set, otherwise the FALCON_ADMIN_EMAIL account.
func isBreakGlassBootstrap(email string) bool {
	bg := strings.TrimSpace(os.Getenv("OPS_BREAK_GLASS_EMAIL"))
	return bg == "" || strings.EqualFold(bg, strings.TrimSpace(email))
}

// extractUsernameFromEmail derives a username from an email address by taking
// the local part (before the @) and lowercasing it.  This matches the pattern
// used for the seeded admin account in migration 000 ("admin").
func extractUsernameFromEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 && parts[0] != "" {
		return strings.ToLower(parts[0])
	}
	return strings.ToLower(email)
}

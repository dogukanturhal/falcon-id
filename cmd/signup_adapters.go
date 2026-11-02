// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/authorization"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ---------------------------------------------------------------------------
// signupTenantCreatorAdapter
//
// Adapts repositories.TenantRepository to services.SignupTenantCreator.
// The signup flow calls CreateTenant(ctx, *models.CreateTenantRequest) and
// expects back a *models.Tenant. The underlying repo Create takes a pre-built
// *models.Tenant, so we do the mapping here.
// ---------------------------------------------------------------------------

type signupTenantCreatorAdapter struct {
	repo      *repositories.TenantRepository
	realmRepo *repositories.RealmRepository // Optional: assigns tenant to default realm
}

func (a *signupTenantCreatorAdapter) CreateTenant(ctx context.Context, req *models.CreateTenantRequest) (*models.Tenant, error) {
	// Slug validation — the public signup endpoint is the most exposed
	// tenant-create path. Reject malformed slugs and reserved slugs
	// with the same generic error to prevent the slug-tenant-
	// enumeration class (Push Security SaaS-attacks catalog).
	//
	// Format check (a-z0-9-, 3..63 chars) AND reserved-list check
	// collapse into one "slug unavailable" response. Format and
	// reserved are NOT distinguished to the caller.
	if !models.IsValidSlug(req.Slug) || models.IsReservedSlug(req.Slug) {
		return nil, fmt.Errorf("signup: slug unavailable")
	}

	// Reuse the ID tenant-management already minted for this same tenant
	// (see models.CreateTenantRequest.ID) so both systems agree on one
	// tenant identity. Falls back to a fresh ID when unset, so any other
	// caller of this adapter (e.g. tests) is unaffected.
	tenantID := uuid.New()
	if req.ID != nil {
		tenantID = *req.ID
	}

	tenant := &models.Tenant{
		ID:          tenantID,
		Name:        req.Name,
		Slug:        req.Slug,
		DisplayName: req.DisplayName,
		Status:      "active",
		Type:        models.TenantType(req.Type),
		Plan:        req.Plan,
		MaxUsers:    req.MaxUsers,
		MaxStorage:  req.MaxStorage,
		Settings:    make(map[string]interface{}),
		Metadata:    make(map[string]interface{}),
	}

	if req.BillingEmail != "" {
		tenant.BillingEmail = &req.BillingEmail
	}

	if err := a.repo.Create(ctx, tenant); err != nil {
		return nil, fmt.Errorf("signup: create tenant: %w", err)
	}

	// Explicitly assign new tenant to default realm (not relying on fallback)
	if a.realmRepo != nil {
		if err := a.realmRepo.AssignTenant(ctx, models.DefaultRealmID, tenant.ID, nil); err != nil {
			// Non-fatal: tenant is created, realm assignment is best-effort.
			// GetTenantRealm will still fall back to default realm.
			fmt.Printf("signup: warning: failed to assign tenant %s to default realm: %v\n", tenant.ID, err)
		}
	}

	return tenant, nil
}

// GetByID resolves a tenant by ID. Used by the signup flow's personal-
// account path to look up the shared `hexxlock-consumer` tenant
// (models.WellKnownTenantConsumer) instead of minting a fresh per-user
// "personal-<rand>" tenant. See services/signup_service.go::provisionTenant
// for the industry-standard B2C rationale.
func (a *signupTenantCreatorAdapter) GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	return a.repo.GetByID(ctx, id)
}

// ---------------------------------------------------------------------------
// signupUserCreatorAdapter
//
// Adapts services.UserService to services.SignupUserCreator.
// UserService.Create takes an extra createdBy *uuid.UUID parameter and
// returns *models.UserResponse. The signup flow expects (*models.User, error).
// ---------------------------------------------------------------------------

type signupUserCreatorAdapter struct {
	svc *services.UserService
}

func (a *signupUserCreatorAdapter) SignupPasswordPolicy() services.SignupPasswordPolicy {
	return a.svc.SignupPasswordPolicy()
}

func (a *signupUserCreatorAdapter) PrepareSignupCredential(ctx context.Context, password string) (*services.PreparedSignupCredential, error) {
	return a.svc.PrepareSignupCredential(ctx, password)
}

func (a *signupUserCreatorAdapter) CreateForSignup(ctx context.Context, req *models.CreateUserRequest, credential *services.PreparedSignupCredential) (*models.User, error) {
	resp, err := a.svc.CreatePreparedForSignup(ctx, req, credential)
	if err != nil {
		return nil, err
	}

	// Map UserResponse back to the minimal User the signup service needs.
	user := &models.User{
		ID:        resp.ID,
		TenantID:  resp.TenantID,
		Username:  resp.Username,
		Email:     resp.Email,
		FirstName: resp.FirstName,
		LastName:  resp.LastName,
		IsActive:  resp.IsActive,
		CreatedAt: resp.CreatedAt,
	}

	return user, nil
}

// ---------------------------------------------------------------------------
// signupUserLookupAdapter
//
// Adapts repositories.UserRepository to services.SignupUserLookup.
// The signup service needs GetByEmail(ctx, email string) without a tenantID.
// We delegate to the global cross-tenant lookup which uses the email_hash index.
// ---------------------------------------------------------------------------

type signupUserLookupAdapter struct {
	repo *repositories.UserRepository
}

func (a *signupUserLookupAdapter) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	return a.repo.GetByEmailGlobal(ctx, email)
}

// ---------------------------------------------------------------------------
// consumerRoleAssignerAdapter
//
// Implements services.ConsumerRoleAssigner — assigns the `consumer_user`
// role (bootstrapped by cmd/consumer_role_bootstrap.go) to a freshly
// signed-up personal user. Two-step: resolve role-by-name + assign to user.
// ---------------------------------------------------------------------------

type consumerRoleAssignerAdapter struct {
	roleRepo *repositories.RoleRepository
	userRepo *repositories.UserRepository
}

func (a *consumerRoleAssignerAdapter) AssignConsumerRole(ctx context.Context, userID uuid.UUID) error {
	role, err := a.roleRepo.GetByName(ctx, models.WellKnownTenantConsumer, ConsumerUserRoleName)
	if err != nil {
		return fmt.Errorf("consumerRoleAssigner: lookup %s: %w", ConsumerUserRoleName, err)
	}
	if role == nil {
		return fmt.Errorf("consumerRoleAssigner: role %s not found in consumer tenant — bootstrap did not run", ConsumerUserRoleName)
	}
	return a.userRepo.AssignRoles(ctx, userID, []uuid.UUID{role.ID}, nil /* no acting user for self-service signup */)
}

// ---------------------------------------------------------------------------
// founderRoleAssignerAdapter
//
// Implements services.FounderRoleAssigner — grants the founding user of a
// brand-new business-account tenant that tenant's "org_admin" role.
//
// Unlike consumerRoleAssignerAdapter (whose role lives in the single
// well-known consumer tenant and is bootstrapped once at pod startup by
// cmd/consumer_role_bootstrap.go), a business signup mints a FRESH tenant
// per signup, so there is no fixed tenant ID to pre-seed a role into at
// boot. Instead this adapter lazily ensures the org_admin role exists for
// the specific tenant it's called with, the first time a founder needs it.
//
// "org_admin" is the exact role name internal/handlers/onboarding_slug_handler.go
// (tenantSlugAdminRoles) and internal/middleware/auth_admin.go
// (defaultTenantAdminRoles / scopedTenantAdminRoles) already recognize as
// tenant-admin-level — no changes needed on the authorization-check side.
// ---------------------------------------------------------------------------

// OrgAdminRoleName is the well-known tenant-scoped role granted to the
// founding user of every self-service business signup. Exported so tests
// / other callers can reference it without re-declaring the magic string.
const OrgAdminRoleName = authorization.OrgAdminRoleName

var orgAdminTeamPermissionNames = []string{
	"iam:invitations:read",
	"iam:invitations:create",
	"iam:invitations:delete",
	"iam:users:read",
	"iam:users:update",
	"iam:users:delete",
	"iam:service_accounts:read",
	"iam:service_principals:read",
	// WO#20 developer access (tenant API keys + webhooks); registered by
	// selfRegisterPermissions and backfilled for existing tenants by 0029.
	"iam:api_keys:read",
	"iam:api_keys:manage",
	"iam:webhooks:read",
	"iam:webhooks:manage",
	"core:roles:read",
	// core:users:read and core:permissions:read gate GET /users and
	// GET /permissions (see cmd/routes.go permCoreUsersRead /
	// permCorePermsRead) — the exact two endpoints Settings > Team's
	// useTeamUsers()/useRoles() call alongside GET /roles (already covered
	// by core:roles:read above). Without these, org_admin could see the
	// roles list but Team page would 403 loading users/permissions.
	//
	// NOTE: before cmd/main.go's selfRegisterCorePermissions fix (t-acmeapp-
	// rbac), NONE of the "core:*" names in this list existed in the
	// iam_permissions catalog at all (only "iam:*" was self-registered at
	// startup). GrantPermissionsByName is fail-closed on any unresolved
	// name (see internal/repositories/role_repository.go), so this whole
	// call — and therefore org_admin role creation/grant for EVERY
	// business-account signup — has been failing (logged as a non-fatal
	// Warn in PostSignupProvisioner, so no error surfaced to the founder or
	// an operator) since "core:roles:read" was first added to this list.
	// This is the actual root cause of "Settings > Team is unusable".
	"core:users:read",
	"core:permissions:read",
}

type founderRoleAssignerAdapter struct {
	roleRepo        *repositories.RoleRepository
	userRepo        *repositories.UserRepository
	tenantBootstrap *services.TenantBootstrapService
}

// AssignFounderRole idempotently ensures tenantID has an org_admin role
// row, then assigns it to userID.
//
// Idempotency:
//   - Role lookup-or-create: GetByName first; if a concurrent call (e.g. a
//     duplicate signup-completion trigger) raced us and created it first,
//     Create's error is not treated as fatal — we re-fetch by name and
//     proceed with whatever row now exists.
//   - Role assignment: userRepo.GrantRoles uses ON CONFLICT DO NOTHING, so a
//     retry cannot duplicate the founder grant or remove roles added later.
func (a *founderRoleAssignerAdapter) AssignFounderRole(ctx context.Context, tenantID, userID uuid.UUID) error {
	role, err := a.roleRepo.GetByName(ctx, tenantID, OrgAdminRoleName)
	if err != nil {
		return fmt.Errorf("founderRoleAssigner: lookup %s: %w", OrgAdminRoleName, err)
	}

	if role == nil {
		desc := "Tenant administrator. Auto-granted to the founding user of a self-service business signup (see services.PostSignupProvisioner.AssignFounderRole). Full administrative access to this tenant."
		newRole := &models.Role{
			ID:          uuid.New(),
			TenantID:    tenantID,
			Name:        OrgAdminRoleName,
			DisplayName: "Organization Admin",
			Description: &desc,
			IsSystem:    true,
			IsDefault:   false,
			Priority:    100,
		}
		if createErr := a.roleRepo.Create(ctx, newRole); createErr != nil {
			// Re-fetch rather than failing outright: a concurrent caller may
			// have created the same tenant's org_admin role between our
			// GetByName and Create (e.g. a retried signup-completion call).
			existing, getErr := a.roleRepo.GetByName(ctx, tenantID, OrgAdminRoleName)
			if getErr != nil || existing == nil {
				return fmt.Errorf("founderRoleAssigner: create %s role: %w", OrgAdminRoleName, createErr)
			}
			newRole = existing
		}
		role = newRole
	}
	if err := a.roleRepo.GrantPermissionsByName(ctx, role.ID, orgAdminTeamPermissionNames); err != nil {
		return fmt.Errorf("founderRoleAssigner: grant %s permissions: %w", OrgAdminRoleName, err)
	}
	if err := a.userRepo.GrantRoles(ctx, userID, []uuid.UUID{role.ID}, nil /* no acting user for self-service signup */); err != nil {
		return err
	}
	if a.tenantBootstrap == nil {
		return fmt.Errorf("founderRoleAssigner: SpiceDB bootstrap is unavailable")
	}
	result, err := a.tenantBootstrap.BootstrapRolePermissions(ctx, tenantID, role.ID, orgAdminTeamPermissionNames)
	if err != nil || result == nil || len(result.Errors) > 0 || result.RelationshipsWritten != len(orgAdminTeamPermissionNames) {
		return fmt.Errorf("founderRoleAssigner: synchronize %s permissions to SpiceDB", OrgAdminRoleName)
	}

	if _, err := a.tenantBootstrap.BootstrapUserRole(ctx, tenantID, userID, role.ID); err != nil {
		return fmt.Errorf("founderRoleAssigner: synchronize %s membership to SpiceDB: %w", OrgAdminRoleName, err)
	}
	return nil
}

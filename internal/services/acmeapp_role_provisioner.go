// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"errors"
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// acmeappUserRoleAssigner is the subset of UserRepository needed to assign the
// signup user their initial role(s). Kept minimal/interface-scoped so this file
// does not need to depend on the full UserRepository surface.
type acmeappUserRoleAssigner interface {
	AssignRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error
}

// AcmeAppRoleDefinition describes one of AcmeApp's (AcmeWeb) system roles: its
// identity plus the exact permission names it should be granted. Permission
// names use the "module:resource:action" convention; a trailing "*" action
// means "every action currently registered for this module:resource".
type AcmeAppRoleDefinition struct {
	Name        string
	DisplayName string
	Description string
	// IsDefault marks the role auto-assigned to a user who is invited without
	// an explicit role selection. Exactly one role in the catalog should set this.
	IsDefault bool
	// Priority gates who may grant/revoke this role (see RoleService.Create's
	// C-1/C-2 checks) - higher number outranks lower. Owner is highest.
	Priority int
	// Permissions are permission catalog names this role should hold. A name
	// not found in the catalog at provisioning time is skipped with a warning
	// (e.g. because the owning service, such as the business module, has not yet
	// self-registered its module) rather than failing the whole provision -
	// this keeps tenant provisioning resilient to service-registration order.
	Permissions []string
}

// acmeappBaselinePermissions are granted to EVERY AcmeApp role on top of its
// own list (see acmeappRolePermissionNames). They are the reads the app shell
// needs on every load for any user: the company switcher / company gate call
// GET /api/v1/legal-entities, which business guards with
// core:legal_entities:read. Without this baseline a non-owner would get a 403
// there once business authz is enforced. Add a permission here only if every
// user needs it to load the app.
var acmeappBaselinePermissions = []string{
	"core:legal_entities:read",
}

// acmeappRolePermissionNames is the role's own permission list plus the
// baseline, de-duplicated, in a stable order. The single source both the
// signup path and the reconcile path grant from.
func acmeappRolePermissionNames(def AcmeAppRoleDefinition) []string {
	return withBaselinePermissions(def.Permissions)
}

// AcmeAppRoleCatalog is the real, code-derived AcmeApp role model.
//
// Design rationale (see also cmd/main.go's selfRegisterCorePermissions doc
// comment for the core/iam namespace finding this catalog depends on):
//
//   - "Send" is a irreversible, cost-incurring, deliverability-risk action and
//     is NEVER bundled into a generic campaigns:create/update grant. Only
//     Owner, Admin, and Marketing Manager may send. Editor may draft/edit
//     campaigns but not send them - this requires the `marketing:campaigns:send`
//     permission (registered by the marketing module's own catalog; until
//     that module registers it, this grant is a no-op - see the provisioning
//     warning log for exactly this case).
//   - "Export" of contacts/leads is personal-data egress (KVKK/GDPR) and is
//     never bundled into a generic leads:read/update grant. Only Owner, Admin,
//     and Analyst (who need it for offline analysis/reporting) may export.
//     Marketing Manager and Editor can read/manage leads but not export them.
//     Like send, `marketing:leads:export` is a companion permission registered by
//     the marketing module; it is a no-op grant until the module registers it.
//   - Billing is its own role (the "financial admin"), e.g. for an outside
//     bookkeeper who should not get IAM/team-management access. Owner and
//     Admin manage billing directly (`core:billing:read`/`manage`); Billing
//     can read, request a change that an Owner/Admin approves
//     (`core:billing:request`) and edit the invoice profile
//     (`core:billing_profile:update`), but holds no direct `manage`. Existing
//     tenants' Billing roles lose `manage` through AcmeAppRetiredGrants /
//     RevokeRetiredGrants (a one-shot step), never through the startup sync.
var AcmeAppRoleCatalog = []AcmeAppRoleDefinition{
	{
		Name:        "owner",
		DisplayName: "Owner",
		Description: "Full control of the tenant, including billing, team management, and every marketing capability. Automatically assigned to the signup user.",
		Priority:    100,
		Permissions: []string{
			"iam:users:read", "iam:users:create", "iam:users:update", "iam:users:delete",
			"iam:roles:read", "iam:roles:create", "iam:roles:update", "iam:roles:delete",
			"iam:permissions:read",
			"iam:invitations:read", "iam:invitations:create", "iam:invitations:delete",
			"core:users:read", "core:users:update",
			"core:roles:read", "core:roles:create", "core:roles:update", "core:roles:delete",
			"core:permissions:read",
			"core:billing:read", "core:billing:manage", "core:billing_profile:update",
			"core:reports:read",
			"core:settings:read", "core:settings:update",
			"account:sod:manage",
			"marketing:campaigns:read", "marketing:campaigns:create", "marketing:campaigns:update", "marketing:campaigns:delete", "marketing:campaigns:send",
			"marketing:leads:read", "marketing:leads:create", "marketing:leads:update", "marketing:leads:delete", "marketing:leads:export",
			"marketing:segments:read", "marketing:segments:create", "marketing:segments:update", "marketing:segments:delete",
			"marketing:workflows:read", "marketing:workflows:create", "marketing:workflows:update", "marketing:workflows:delete",
			"marketing:templates:read", "marketing:templates:create", "marketing:templates:update", "marketing:templates:delete",
			"marketing:channels:read", "marketing:channels:update",
			"marketing:analytics:read",
			"marketing:scoring:read", "marketing:scoring:update", "marketing:scoring:delete",
			"marketing:consent:read", "marketing:consent:update",
			"marketing:deliverability:read", "marketing:deliverability:update", "marketing:deliverability:delete",
		},
	},
	{
		Name:        "admin",
		DisplayName: "Admin",
		Description: "Manages team members, roles and billing and has full marketing access, but is not the tenant Owner.",
		Priority:    90,
		Permissions: []string{
			"iam:users:read", "iam:users:create", "iam:users:update",
			"iam:roles:read", "iam:roles:create", "iam:roles:update",
			"iam:permissions:read",
			"iam:invitations:read", "iam:invitations:create", "iam:invitations:delete",
			"core:users:read", "core:users:update",
			"core:roles:read", "core:roles:create", "core:roles:update",
			"core:permissions:read",
			"core:billing:read", "core:billing:manage", "core:billing_profile:update",
			"core:settings:read", "core:settings:update",
			"core:legal_entities:read", "core:legal_entities:create", "core:legal_entities:update",
			"account:sod:manage",
			"marketing:campaigns:read", "marketing:campaigns:create", "marketing:campaigns:update", "marketing:campaigns:delete", "marketing:campaigns:send",
			"marketing:leads:read", "marketing:leads:create", "marketing:leads:update", "marketing:leads:delete", "marketing:leads:export",
			"marketing:segments:read", "marketing:segments:create", "marketing:segments:update", "marketing:segments:delete",
			"marketing:workflows:read", "marketing:workflows:create", "marketing:workflows:update", "marketing:workflows:delete",
			"marketing:templates:read", "marketing:templates:create", "marketing:templates:update", "marketing:templates:delete",
			"marketing:channels:read", "marketing:channels:update",
			"marketing:analytics:read",
			"marketing:scoring:read", "marketing:scoring:update", "marketing:scoring:delete",
			"marketing:consent:read", "marketing:consent:update",
			"marketing:deliverability:read", "marketing:deliverability:update", "marketing:deliverability:delete",
		},
	},
	{
		Name:        "marketing_manager",
		DisplayName: "Marketing Manager",
		Description: "Owns marketing strategy end to end, including sending campaigns, but cannot manage team members/roles or billing.",
		Priority:    70,
		Permissions: []string{
			"core:users:read",
			"core:settings:read",
			"marketing:campaigns:read", "marketing:campaigns:create", "marketing:campaigns:update", "marketing:campaigns:delete", "marketing:campaigns:send",
			"marketing:leads:read", "marketing:leads:create", "marketing:leads:update", "marketing:leads:delete",
			"marketing:segments:read", "marketing:segments:create", "marketing:segments:update", "marketing:segments:delete",
			"marketing:workflows:read", "marketing:workflows:create", "marketing:workflows:update", "marketing:workflows:delete",
			"marketing:templates:read", "marketing:templates:create", "marketing:templates:update", "marketing:templates:delete",
			"marketing:channels:read", "marketing:channels:update",
			"marketing:analytics:read",
			"marketing:scoring:read", "marketing:scoring:update",
			"marketing:consent:read", "marketing:consent:update",
			"marketing:deliverability:read",
		},
	},
	{
		Name:        "editor",
		DisplayName: "Editor",
		IsDefault:   true,
		Description: "Drafts and edits campaigns, templates, and workflows but cannot send campaigns, export contacts, or manage the team. Default role for new invitees.",
		Priority:    50,
		Permissions: []string{
			"marketing:campaigns:read", "marketing:campaigns:create", "marketing:campaigns:update",
			"marketing:leads:read", "marketing:leads:create", "marketing:leads:update",
			"marketing:segments:read", "marketing:segments:create", "marketing:segments:update",
			"marketing:workflows:read", "marketing:workflows:create", "marketing:workflows:update",
			"marketing:templates:read", "marketing:templates:create", "marketing:templates:update",
			"marketing:channels:read",
			"marketing:analytics:read",
			"marketing:scoring:read",
			"marketing:consent:read",
			"core:settings:read",
		},
	},
	{
		Name:        "analyst",
		DisplayName: "Analyst",
		Description: "Read-only access to marketing data and reporting, plus contact export for offline analysis. Cannot create/edit/send campaigns.",
		Priority:    40,
		Permissions: []string{
			"marketing:campaigns:read",
			"marketing:leads:read", "marketing:leads:export",
			"marketing:segments:read",
			"marketing:workflows:read",
			"marketing:templates:read",
			"marketing:channels:read",
			"marketing:analytics:read",
			"marketing:scoring:read",
			"marketing:consent:read",
			"marketing:deliverability:read",
			"core:reports:read",
			"core:settings:read",
		},
	},
	{
		Name:        "billing",
		DisplayName: "Billing",
		Description: "Views the tenant's subscription and invoices, edits the invoice profile and requests billing changes for Owner/Admin approval. No access to marketing data, contacts, or team management.",
		Priority:    30,
		Permissions: []string{
			"core:billing:read", "core:billing:request", "core:billing_profile:update",
			"core:settings:read",
		},
	},
}

// AcmeAppRetiredGrant is a catalog grant that was removed from a system role.
// The additive startup sync never deletes, so retired grants are removed only
// by the explicit RevokeRetiredGrants step (a tenant may deliberately re-add
// one later, and the startup sync must not strip it again on every deploy).
type AcmeAppRetiredGrant struct {
	Role       string
	Permission string
}

// AcmeAppRetiredGrants lists the grants RevokeRetiredGrants removes.
var AcmeAppRetiredGrants = []AcmeAppRetiredGrant{
	{Role: "billing", Permission: "core:billing:manage"},
}

// acmeappRolePermissionRevoker is implemented by the real RoleRepository;
// separate from roleServiceRoleRepo so the many role-repo fakes do not need it.
type acmeappRolePermissionRevoker interface {
	RevokePermissionsByName(ctx context.Context, roleID uuid.UUID, permissionNames []string) error
}

// acmeappSpiceDBRevoker removes role grants from SpiceDB
// (implemented by *TenantBootstrapService).
type acmeappSpiceDBRevoker interface {
	RevokeRolePermissions(ctx context.Context, tenantID, roleID uuid.UUID, permissions []string) (*BootstrapResult, error)
}

// AcmeAppRoleProvisioner creates the real AcmeApp system role model
// for a tenant and assigns the tenant's Owner role to a given user, writing
// both the relational grants (iam_role_permissions, read by the UI and
// authorize/batch) and the SpiceDB tuples (what RequirePermission/CheckPermission
// actually enforces) synchronously and idempotently.
//
// This is the "wiring" deliverable: creating roles that are never referenced
// by any provisioning path fixes nothing for future tenants. Call
// ProvisionTenantAndAssignOwner from tenant/signup provisioning so every new
// business-tenant signup gets it automatically - see SignupService.
type AcmeAppRoleProvisioner struct {
	roleRepo        roleServiceRoleRepo
	permissionRepo  roleServicePermissionRepo
	userRoleRepo    acmeappUserRoleAssigner
	tenantBootstrap *TenantBootstrapService
	spicedbRevoker  acmeappSpiceDBRevoker
}

// NewAcmeAppRoleProvisioner constructs a AcmeAppRoleProvisioner. tenantBootstrap
// may be nil in tests that only assert the relational (Postgres) side; in that
// case SpiceDB writes are skipped (mirrors RoleService.Create's nil-safety).
func NewAcmeAppRoleProvisioner(
	roleRepo roleServiceRoleRepo,
	permissionRepo roleServicePermissionRepo,
	userRoleRepo acmeappUserRoleAssigner,
	tenantBootstrap *TenantBootstrapService,
) *AcmeAppRoleProvisioner {
	p := &AcmeAppRoleProvisioner{
		roleRepo:        roleRepo,
		permissionRepo:  permissionRepo,
		userRoleRepo:    userRoleRepo,
		tenantBootstrap: tenantBootstrap,
	}
	if tenantBootstrap != nil {
		p.spicedbRevoker = tenantBootstrap
	}
	return p
}

// ProvisionTenantAndAssignOwner is idempotent: if the tenant already has an
// "owner" role, it assumes the AcmeApp role model was already provisioned
// (e.g. by a retried signup) and returns without creating duplicate roles.
// It does NOT reassign the owner role in that case - a retried signup must
// not silently re-grant Owner to a different caller.
func (p *AcmeAppRoleProvisioner) ProvisionTenantAndAssignOwner(ctx context.Context, tenantID, ownerUserID uuid.UUID) error {
	ownerRoleID, alreadyProvisioned, err := p.provisionRoles(ctx, tenantID, "ProvisionTenantAndAssignOwner")
	if err != nil {
		return err
	}
	if alreadyProvisioned {
		return nil
	}

	// Assign the signup user to Owner in Postgres (iam_user_roles) ...
	if err := p.userRoleRepo.AssignRoles(ctx, ownerUserID, []uuid.UUID{ownerRoleID}, nil); err != nil {
		return fmt.Errorf("ProvisionTenantAndAssignOwner: assign owner role to user: %w", err)
	}

	// ... and directly/synchronously in SpiceDB (not via the async
	// Kafka+reconciler path UserService.SetUserRoles uses), so the signup
	// user can pass RequirePermission checks immediately after signup
	// completes, with no reconciler-lag window. Also grants tenant#admin so
	// the owner passes the `tenant->admin` fallback branch of
	// access_grant#check even before/if a specific permission grant lags.
	if p.tenantBootstrap != nil {
		if _, err := p.tenantBootstrap.BootstrapUserRole(ctx, tenantID, ownerUserID, ownerRoleID); err != nil {
			logger.Log.Warn("Failed to sync owner role assignment to SpiceDB (reconciler will repair)",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", ownerUserID.String()),
				zap.Error(err),
			)
		}
		if _, err := p.tenantBootstrap.BootstrapUserMembership(ctx, tenantID, ownerUserID, true); err != nil {
			logger.Log.Warn("Failed to sync owner tenant-admin membership to SpiceDB (reconciler will repair)",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", ownerUserID.String()),
				zap.Error(err),
			)
		}
	}

	logger.Log.Info("Provisioned AcmeApp role model for tenant",
		zap.String("tenant_id", tenantID.String()),
		zap.String("owner_user_id", ownerUserID.String()),
		zap.Int("roles_created", len(AcmeAppRoleCatalog)),
	)

	return nil
}

// ProvisionTenantRoles creates the AcmeApp role catalog for a
// tenant WITHOUT assigning any role to any user. It is the backfill
// counterpart to ProvisionTenantAndAssignOwner: existing tenants (signed up
// before this role model shipped, or provisioned by another path such as
// the platform's own internal seed) need the six roles to exist so Settings ->
// Team is non-empty and so an operator can deliberately grant a role to a
// specific person afterwards - but auto-assigning Owner to an existing user
// during a backfill would silently change that user's effective
// permissions, which is never appropriate for a mechanical backfill run
// against a live tenant.
//
// Idempotent via the same "owner role already exists" check as
// ProvisionTenantAndAssignOwner: running this twice for the same tenant is
// a no-op the second time and returns rolesCreated=false, ownerRoleID as
// looked up from the existing row (not the zero value), with no error.
func (p *AcmeAppRoleProvisioner) ProvisionTenantRoles(ctx context.Context, tenantID uuid.UUID) (rolesCreated bool, ownerRoleID uuid.UUID, err error) {
	newOwnerRoleID, alreadyProvisioned, err := p.provisionRoles(ctx, tenantID, "ProvisionTenantRoles")
	if err != nil {
		return false, uuid.Nil, err
	}
	if alreadyProvisioned {
		existingOwner, getErr := p.roleRepo.GetByName(ctx, tenantID, "owner")
		if getErr != nil {
			return false, uuid.Nil, fmt.Errorf("ProvisionTenantRoles: re-check existing owner role: %w", getErr)
		}
		if existingOwner == nil {
			return false, uuid.Nil, fmt.Errorf("ProvisionTenantRoles: owner role reported already-provisioned but GetByName now returns nil (race?)")
		}
		return false, existingOwner.ID, nil
	}

	logger.Log.Info("Backfilled AcmeApp role model for tenant (no user assigned)",
		zap.String("tenant_id", tenantID.String()),
		zap.Int("roles_created", len(AcmeAppRoleCatalog)),
	)

	return true, newOwnerRoleID, nil
}

// provisionRoles is the shared role-creation core used by both
// ProvisionTenantAndAssignOwner and ProvisionTenantRoles: it creates every
// role in AcmeAppRoleCatalog (relational + SpiceDB access_grant tuples) for
// tenantID and returns the "owner" role's ID. It performs no user
// assignment of any kind - callers decide separately whether/who to assign.
//
// alreadyProvisioned=true means the tenant already had an "owner" role and
// NOTHING was created or modified; callers must treat this as a genuine
// no-op, not merely skip the loop, since re-running Create for an existing
// role name would either duplicate rows or fail a uniqueness constraint
// depending on the repo implementation - this check is what makes the
// whole provisioner idempotent.
func (p *AcmeAppRoleProvisioner) provisionRoles(ctx context.Context, tenantID uuid.UUID, callerName string) (ownerRoleID uuid.UUID, alreadyProvisioned bool, err error) {
	existingOwner, err := p.roleRepo.GetByName(ctx, tenantID, "owner")
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("%s: check existing owner role: %w", callerName, err)
	}
	if existingOwner != nil {
		logger.Log.Info("AcmeApp role model already provisioned for tenant, skipping",
			zap.String("tenant_id", tenantID.String()),
		)
		return uuid.Nil, true, nil
	}

	// Load the permission catalog once and index by name, so role creation
	// below doesn't do one query per permission per role.
	//
	// This MUST be scoped to the exact modules AcmeAppRoleCatalog
	// references (permissionRepo.ListByModules), never the unscoped
	// permissionRepo.List(ctx) - List() is `... ORDER BY module, resource,
	// action LIMIT 1000` with no pagination, and iam_permissions is a
	// single GLOBAL catalog shared by every module on the platform
	// (accounting, cmms, crm, fico, hr, inventory, marketing, qms, sd,
	// ... - 2149 rows as of 2026-09-19, comfortably past 1000). Under
	// List(), "marketing" sorts alphabetically after roughly a dozen
	// other modules and is cut off entirely, and "iam" itself gets cut
	// mid-module (invitations/permissions survive, roles/users don't) -
	// silently starving every AcmeApp role of most of its catalog
	// permissions, on both this backfill AND the live
	// ProvisionTenantAndAssignOwner signup path. Confirmed by running
	// this backfill against hexxlock with the old List(ctx) call: owner
	// got 14/53 grants, admin 10/47, marketing_manager 1/29, editor
	// 0/19, analyst 1/11 (billing's 2/2 happened to survive only because
	// "billing" is a resource under "core", not a module past the cutoff).
	acmeappModules := acmeappReferencedModules()
	allPerms, err := p.permissionRepo.ListByModules(ctx, acmeappModules)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("%s: list permission catalog for modules %v: %w", callerName, acmeappModules, err)
	}
	permByName := make(map[string]uuid.UUID, len(allPerms))
	for _, perm := range allPerms {
		permByName[perm.Name] = perm.ID
	}

	for _, def := range AcmeAppRoleCatalog {
		role := &models.Role{
			ID:          uuid.New(),
			TenantID:    tenantID,
			Name:        def.Name,
			DisplayName: def.DisplayName,
			Description: strPtr(def.Description),
			// IsSystem is deliberately false: these are the tenant's own
			// self-service-assignable business roles (Owner/Admin/Marketing
			// Manager/Editor/Analyst/Billing), not platform system roles.
			// RoleService computes Editable = !role.IsSystem && priority < max,
			// and the self-service list filters on is_system=false BEFORE
			// priority is considered — so is_system=true hid all six roles from
			// the picker entirely, leaving "Invite teammate" with no options.
			// Protection against deletion/rename comes from the priority-ceiling
			// checks in Update/Delete, not from this flag.
			IsSystem:    false,
			IsDefault:   def.IsDefault,
			Priority:    def.Priority,
		}
		if err := p.roleRepo.Create(ctx, role); err != nil {
			return uuid.Nil, false, fmt.Errorf("%s: create role %q: %w", callerName, def.Name, err)
		}

		var permIDs []uuid.UUID
		var permNames []string
		for _, permName := range acmeappRolePermissionNames(def) {
			id, ok := permByName[permName]
			if !ok {
				// Not fatal: the owning module (e.g. the business module's marketing
				// module) may not have self-registered this permission yet.
				// The reconciler / a later re-provision is not automatic here,
				// so this is logged loudly rather than silently dropped.
				logger.Log.Warn("AcmeApp role catalog references unknown permission; grant skipped",
					zap.String("tenant_id", tenantID.String()),
					zap.String("role", def.Name),
					zap.String("permission", permName),
				)
				continue
			}
			permIDs = append(permIDs, id)
			permNames = append(permNames, permName)
		}

		if len(permIDs) > 0 {
			if err := p.roleRepo.AssignPermissions(ctx, role.ID, permIDs, nil); err != nil {
				return uuid.Nil, false, fmt.Errorf("%s: assign permissions for role %q: %w", callerName, def.Name, err)
			}
		}

		if p.tenantBootstrap != nil && len(permNames) > 0 {
			if _, err := p.tenantBootstrap.BootstrapRolePermissions(ctx, tenantID, role.ID, permNames); err != nil {
				logger.Log.Warn("Failed to sync AcmeApp role permissions to SpiceDB (reconciler will repair)",
					zap.String("tenant_id", tenantID.String()),
					zap.String("role", def.Name),
					zap.Error(err),
				)
			}
		}

		if def.Name == "owner" {
			ownerRoleID = role.ID
			p.grantOwnerBasePermissions(ctx, tenantID, role.ID)
		}
	}

	if ownerRoleID == uuid.Nil {
		return uuid.Nil, false, fmt.Errorf("%s: owner role missing from AcmeAppRoleCatalog (programming error)", callerName)
	}

	return ownerRoleID, false, nil
}

// acmeappModulePermissionGranter is the optional role-repo capability to grant
// a role every catalog permission of whole modules (RoleRepository
// .GrantModulePermissionsToRole, insert-only). Asserted at call time, like
// acmeappRolePermissionRevoker, so the narrow roleServiceRoleRepo interface
// stays unchanged.
type acmeappModulePermissionGranter interface {
	GrantModulePermissionsToRole(ctx context.Context, roleID uuid.UUID, modules []string) (int64, error)
}

// grantOwnerBasePermissions gives the owner role the full ownerBaseModules
// ("core", "jobs") permission sets independent of any module entitlement, so a
// brand-new tenant's owner can load the app shell (company switcher, company
// setup) before anything is entitled. Same mechanism as
// ModuleAccessProvisioner.grantOwnerPermissions: insert-only relational grant,
// then a SpiceDB mirror. Non-fatal: failures are logged (the startup reconcile
// retries) so signup is never blocked.
func (p *AcmeAppRoleProvisioner) grantOwnerBasePermissions(ctx context.Context, tenantID, ownerRoleID uuid.UUID) {
	granter, ok := p.roleRepo.(acmeappModulePermissionGranter)
	if !ok {
		logger.Log.Warn("AcmeApp owner base grant skipped: role repository cannot grant module permissions",
			zap.String("tenant_id", tenantID.String()))
		return
	}
	_, err := granter.GrantModulePermissionsToRole(ctx, ownerRoleID, ownerBaseModules)
	if err != nil {
		logger.Log.Warn("AcmeApp owner base grant failed (reconcile will repair)",
			zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return
	}
	if p.tenantBootstrap == nil {
		return
	}
	catalog, err := p.permissionRepo.ListByModules(ctx, ownerBaseModules)
	if err != nil {
		logger.Log.Warn("AcmeApp owner base grant: cannot list permissions for SpiceDB sync (reconcile will repair)",
			zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return
	}
	names := make([]string, 0, len(catalog))
	for _, perm := range catalog {
		names = append(names, perm.Name)
	}
	if _, err := p.tenantBootstrap.BootstrapRolePermissions(ctx, tenantID, ownerRoleID, names); err != nil {
		logger.Log.Warn("AcmeApp owner base grant: SpiceDB write failed (reconcile will repair)",
			zap.String("tenant_id", tenantID.String()), zap.Error(err))
	}
}

// ReconcileTenantRolePermissions tops up permission grants for a tenant that
// already has the full AcmeApp role catalog (all six roles created) but one
// or more of those roles is missing catalog permissions it should have -
// e.g. a tenant provisioned while provisionRoles still called the truncating
// permissionRepo.List(ctx) (see that function's doc comment) instead of the
// now-fixed ListByModules. It is intentionally NOT part of ProvisionTenantRoles'
// idempotency check: that check treats "owner role exists" as "fully
// provisioned, nothing to do", which is exactly the assumption this method
// exists to repair when it turns out to be false for a given tenant.
//
// Purely additive and safe to run repeatedly against any tenant, in any
// state, including ones this provisioner never touched:
//   - Relational grants go through RoleRepository.GrantPermissionsByName,
//     which is "INSERT ... ON CONFLICT (role_id, permission_id) DO NOTHING" -
//     it can only add rows, never remove or replace a role's existing
//     grants. AssignPermissions (used by provisionRoles for a brand-new
//     role, which has nothing to lose) is never used here because it
//     DELETEs a role's existing grants before inserting.
//   - SpiceDB writes reuse the same BootstrapRolePermissions ->
//     WriteRolePermission path as provisionRoles, which SpiceDB performs as
//     OPERATION_TOUCH - re-writing an already-present tuple is a no-op, so
//     passing every resolvable catalog permission name per role (not a
//     hand-diffed "missing" subset) is safe and avoids reading SpiceDB back
//     just to compute a diff.
//   - A role name from AcmeAppRoleCatalog that does not exist for this
//     tenant (e.g. ProvisionTenantRoles was never run at all) is skipped
//     with a warning, not created - creating roles is provisionRoles' job,
//     not this method's.
//   - No role outside AcmeAppRoleCatalog is read or written, and no user is
//     ever assigned a role by this method.
//
// Returns the number of catalog permission names granted (resolved +
// written, not necessarily newly-added, since ON CONFLICT DO NOTHING and
// OPERATION_TOUCH make re-granting an existing permission a safe no-op) per
// role name actually present for the tenant.
func (p *AcmeAppRoleProvisioner) ReconcileTenantRolePermissions(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	acmeappModules := acmeappReferencedModules()
	allPerms, err := p.permissionRepo.ListByModules(ctx, acmeappModules)
	if err != nil {
		return nil, fmt.Errorf("ReconcileTenantRolePermissions: list permission catalog for modules %v: %w", acmeappModules, err)
	}
	permByName := make(map[string]uuid.UUID, len(allPerms))
	for _, perm := range allPerms {
		permByName[perm.Name] = perm.ID
	}

	grantCounts := make(map[string]int, len(AcmeAppRoleCatalog))
	for _, def := range AcmeAppRoleCatalog {
		role, err := p.roleRepo.GetByName(ctx, tenantID, def.Name)
		if err != nil {
			return nil, fmt.Errorf("ReconcileTenantRolePermissions: get role %q: %w", def.Name, err)
		}
		if role == nil {
			logger.Log.Warn("AcmeApp reconcile: catalog role missing for tenant, skipping (run ProvisionTenantRoles first to create it)",
				zap.String("tenant_id", tenantID.String()),
				zap.String("role", def.Name),
			)
			continue
		}

		var permNames []string
		for _, permName := range acmeappRolePermissionNames(def) {
			if _, ok := permByName[permName]; !ok {
				logger.Log.Warn("AcmeApp reconcile: role catalog references unknown permission; grant skipped",
					zap.String("tenant_id", tenantID.String()),
					zap.String("role", def.Name),
					zap.String("permission", permName),
				)
				continue
			}
			permNames = append(permNames, permName)
		}
		if def.Name == "owner" {
			p.grantOwnerBasePermissions(ctx, tenantID, role.ID)
		}
		if len(permNames) == 0 {
			continue
		}

		if err := p.roleRepo.GrantPermissionsByName(ctx, role.ID, permNames); err != nil {
			return nil, fmt.Errorf("ReconcileTenantRolePermissions: grant permissions for role %q: %w", def.Name, err)
		}

		if p.tenantBootstrap != nil {
			if _, err := p.tenantBootstrap.BootstrapRolePermissions(ctx, tenantID, role.ID, permNames); err != nil {
				logger.Log.Warn("AcmeApp reconcile: failed to sync role permissions to SpiceDB",
					zap.String("tenant_id", tenantID.String()),
					zap.String("role", def.Name),
					zap.Error(err),
				)
			}
		}

		grantCounts[def.Name] = len(permNames)

		logger.Log.Info("AcmeApp reconcile: top-up grant applied for role",
			zap.String("tenant_id", tenantID.String()),
			zap.String("role", def.Name),
			zap.Int("permission_count", len(permNames)),
		)
	}

	return grantCounts, nil
}

// RevokeRetiredGrants removes every AcmeAppRetiredGrants pair from the tenant's
// matching system role in Postgres and SpiceDB. Only the listed pairs are
// touched, only on roles with that name, and a tenant missing the role is
// skipped. Idempotent: the Postgres delete and the SpiceDB DELETE are no-ops
// when the grant is already gone. Returns the number of grants processed per
// role name. NOT part of the startup sync (see AcmeAppRetiredGrant).
func (p *AcmeAppRoleProvisioner) RevokeRetiredGrants(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	revoker, ok := p.roleRepo.(acmeappRolePermissionRevoker)
	if !ok {
		return nil, fmt.Errorf("RevokeRetiredGrants: role repository cannot revoke permissions")
	}
	byRole := make(map[string][]string)
	for _, g := range AcmeAppRetiredGrants {
		byRole[g.Role] = append(byRole[g.Role], g.Permission)
	}
	counts := make(map[string]int, len(byRole))
	for roleName, perms := range byRole {
		role, err := p.roleRepo.GetByName(ctx, tenantID, roleName)
		if err != nil {
			return nil, fmt.Errorf("RevokeRetiredGrants: get role %q: %w", roleName, err)
		}
		if role == nil {
			continue
		}
		if err := revoker.RevokePermissionsByName(ctx, role.ID, perms); err != nil {
			return nil, fmt.Errorf("RevokeRetiredGrants: revoke for role %q: %w", roleName, err)
		}
		if p.spicedbRevoker != nil {
			res, err := p.spicedbRevoker.RevokeRolePermissions(ctx, tenantID, role.ID, perms)
			if err != nil {
				return nil, fmt.Errorf("RevokeRetiredGrants: spicedb revoke for role %q: %w", roleName, err)
			}
			if len(res.Errors) > 0 {
				return nil, fmt.Errorf("RevokeRetiredGrants: spicedb revoke for role %q: %w", roleName, errors.Join(res.Errors...))
			}
			// Revoke may over-delete (wildcards); restore tuples still covered
			// by the role's remaining relational grants.
			if p.tenantBootstrap != nil {
				remaining, err := p.roleRepo.GetRolePermissions(ctx, role.ID)
				if err != nil {
					return nil, fmt.Errorf("RevokeRetiredGrants: reload permissions for role %q: %w", roleName, err)
				}
				names := make([]string, 0, len(remaining))
				for _, perm := range remaining {
					names = append(names, perm.Name)
				}
				if len(names) > 0 {
					if _, err := p.tenantBootstrap.BootstrapRolePermissions(ctx, tenantID, role.ID, names); err != nil {
						return nil, fmt.Errorf("RevokeRetiredGrants: re-sync role %q: %w", roleName, err)
					}
				}
			}
		}
		counts[roleName] = len(perms)
		logger.Log.Info("AcmeApp retired grants revoked for role",
			zap.String("tenant_id", tenantID.String()),
			zap.String("role", roleName),
			zap.Strings("permissions", perms),
		)
	}
	return counts, nil
}

// RevokeAllTenantRetiredGrants runs RevokeRetiredGrants for every tenant that
// has the AcmeApp "owner" role. A failing tenant is counted and logged.
func (p *AcmeAppRoleProvisioner) RevokeAllTenantRetiredGrants(ctx context.Context) (*AcmeAppGrantSyncSummary, error) {
	lister, ok := p.roleRepo.(acmeappTenantLister)
	if !ok {
		return nil, fmt.Errorf("RevokeAllTenantRetiredGrants: role repository cannot list tenants")
	}
	tenantIDs, err := lister.ListTenantIDsWithRoleName(ctx, "owner")
	if err != nil {
		return nil, fmt.Errorf("RevokeAllTenantRetiredGrants: %w", err)
	}
	sum := &AcmeAppGrantSyncSummary{}
	for _, tenantID := range tenantIDs {
		if err := ctx.Err(); err != nil {
			return sum, err
		}
		sum.Tenants++
		if _, err := p.RevokeRetiredGrants(ctx, tenantID); err != nil {
			sum.Failed++
			logger.Log.Warn("AcmeApp retired-grant revoke failed for tenant",
				zap.String("tenant_id", tenantID.String()),
				zap.Error(err),
			)
		}
	}
	return sum, nil
}

// acmeappTenantLister is implemented by the real RoleRepository; it is a
// separate interface (not part of roleServiceRoleRepo) so the many role-repo
// fakes do not need it.
type acmeappTenantLister interface {
	ListTenantIDsWithRoleName(ctx context.Context, name string) ([]uuid.UUID, error)
}

// AcmeAppGrantSyncSummary reports a ReconcileAllTenantRolePermissions run.
type AcmeAppGrantSyncSummary struct {
	Tenants int `json:"tenants"`
	Failed  int `json:"failed"`
}

// ReconcileAllTenantRolePermissions runs ReconcileTenantRolePermissions for
// every tenant that has the AcmeApp "owner" role, so catalog permissions added
// after a tenant was provisioned (e.g. core:settings:*) reach existing tenants.
// Additive and idempotent (see ReconcileTenantRolePermissions); a failing
// tenant is counted and logged, it does not stop the others.
func (p *AcmeAppRoleProvisioner) ReconcileAllTenantRolePermissions(ctx context.Context) (*AcmeAppGrantSyncSummary, error) {
	lister, ok := p.roleRepo.(acmeappTenantLister)
	if !ok {
		return nil, fmt.Errorf("ReconcileAllTenantRolePermissions: role repository cannot list tenants")
	}
	tenantIDs, err := lister.ListTenantIDsWithRoleName(ctx, "owner")
	if err != nil {
		return nil, fmt.Errorf("ReconcileAllTenantRolePermissions: %w", err)
	}
	sum := &AcmeAppGrantSyncSummary{}
	for _, tenantID := range tenantIDs {
		if err := ctx.Err(); err != nil {
			return sum, err
		}
		sum.Tenants++
		if _, err := p.ReconcileTenantRolePermissions(ctx, tenantID); err != nil {
			sum.Failed++
			logger.Log.Warn("AcmeApp grant sync failed for tenant",
				zap.String("tenant_id", tenantID.String()),
				zap.Error(err),
			)
		}
	}
	return sum, nil
}

// acmeappReferencedModules returns the distinct "module" prefixes (the part
// before the first ':') referenced anywhere in AcmeAppRoleCatalog, e.g.
// ["core", "iam", "marketing"]. Used to scope permissionRepo.ListByModules
// so the lookup never depends on iam_permissions' total row count across
// every module on the platform.
func acmeappReferencedModules() []string {
	seen := make(map[string]bool)
	var modules []string
	for _, m := range ownerBaseModules {
		seen[m] = true
		modules = append(modules, m)
	}
	for _, def := range AcmeAppRoleCatalog {
		for _, permName := range acmeappRolePermissionNames(def) {
			idx := strings.IndexByte(permName, ':')
			if idx <= 0 {
				continue
			}
			module := permName[:idx]
			if !seen[module] {
				seen[module] = true
				modules = append(modules, module)
			}
		}
	}
	return modules
}

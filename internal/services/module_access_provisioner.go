// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// moduleAccessTemplates is the slice of TemplateRoleProvisioner the module
// access provisioner needs.
type moduleAccessTemplates interface {
	ProvisionForModuleGrant(ctx context.Context, tenantID uuid.UUID, module string) (int, error)
	// EnsureBaselineForModule tops up the shared baseline on the module's
	// already-instantiated template roles.
	EnsureBaselineForModule(ctx context.Context, tenantID uuid.UUID, module string) (int, error)
}

// moduleAccessRoleRepo is the subset of RoleRepository used to find canonical
// tenant roles and their holders.
type moduleAccessRoleRepo interface {
	GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error)
	GetByTemplateKeyForTenant(ctx context.Context, tenantID uuid.UUID, templateKey string) (*models.Role, error)
	ListActiveHolderIDs(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error)
	GrantModulePermissionsToRole(ctx context.Context, roleID uuid.UUID, modules []string) (int64, error)
}

// moduleAccessPermLister lists the permission catalog of modules, to mirror
// owner grants to SpiceDB by name.
type moduleAccessPermLister interface {
	ListByModules(ctx context.Context, modules []string) ([]models.Permission, error)
}

// moduleAccessRolePermSpiceDB mirrors role->permission grants to SpiceDB.
type moduleAccessRolePermSpiceDB interface {
	BootstrapRolePermissions(ctx context.Context, tenantID, roleID uuid.UUID, permissions []string) (*BootstrapResult, error)
}

// moduleAccessUserRepo is the subset of UserRepository used to grant roles.
type moduleAccessUserRepo interface {
	GrantRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error
}

// moduleAccessSpiceDB mirrors a granted role to SpiceDB.
type moduleAccessSpiceDB interface {
	BootstrapUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error)
}

// moduleAccessEntitlements lists the (tenant, module) pairs that currently
// grant access.
type moduleAccessEntitlements interface {
	ListGrantingTenantModules(ctx context.Context) ([]repositories.TenantModuleGrant, error)
}

// moduleAccessLocker serializes EnsureModuleAccess per tenant across replicas.
type moduleAccessLocker interface {
	WithLock(ctx context.Context, key string, fn func(context.Context) error) error
}

// ModuleAccessResult reports what one EnsureModuleAccess call did.
type ModuleAccessResult struct {
	TenantID                uuid.UUID `json:"tenant_id"`
	EntitlementCode         string    `json:"entitlement_code"`
	OwnerPermissionsGranted int64     `json:"owner_permissions_granted"`
	AdminPermissionsGranted int64     `json:"admin_permissions_granted"`
	RolesProvisioned        int       `json:"roles_provisioned"`
	OwnersFound             int       `json:"owners_found"`
	GrantsMade              int       `json:"grants_made"`
	MissingTemplates        []string  `json:"missing_templates,omitempty"`
	RolesAlreadyHeld        int       `json:"roles_already_held"`
	Errors                  []string  `json:"errors,omitempty"`
}

// ModuleAccessReconcileSummary aggregates a multi-tenant reconcile.
type ModuleAccessReconcileSummary struct {
	Tenants                 int                  `json:"tenants"`
	Results                 []ModuleAccessResult `json:"results"`
	RolesProvisioned        int                  `json:"roles_provisioned"`
	GrantsMade              int                  `json:"grants_made"`
	OwnerPermissionsGranted int64                `json:"owner_permissions_granted"`
	AdminPermissionsGranted int64                `json:"admin_permissions_granted"`
	Failed                  int                  `json:"failed"`
}

// ModuleAccessProvisioner turns an entitlement into usable access: it
// materializes the module's role templates for the tenant and grants the
// module's owner-admin roles to the tenant's "owner" holders (the same path
// signup uses for the AcmeApp catalog). Idempotent and safe to re-run.
type ModuleAccessProvisioner struct {
	templates    moduleAccessTemplates
	roleRepo     moduleAccessRoleRepo
	userRepo     moduleAccessUserRepo
	bootstrap    moduleAccessSpiceDB // may be nil
	entitlements moduleAccessEntitlements
	locker       moduleAccessLocker // may be nil

	// Optional owner-permission side effects (see SetOwnerPermissionSync).
	permLister moduleAccessPermLister
	rolePermSp moduleAccessRolePermSpiceDB
	sessions   SessionCache
}

// SetOwnerPermissionSync wires the optional side effects of granting the
// owner role a module's full permission set: SpiceDB role-permission tuples
// (written by name, like template grants) and session invalidation so owners
// pick the new permissions up (like a user role change). Any may be nil.
func (p *ModuleAccessProvisioner) SetOwnerPermissionSync(perms moduleAccessPermLister, spice moduleAccessRolePermSpiceDB, sessions SessionCache) {
	p.permLister = perms
	p.rolePermSp = spice
	p.sessions = sessions
}

// NewModuleAccessProvisioner constructs a ModuleAccessProvisioner. bootstrap
// and locker may be nil (SpiceDB mirror / cross-replica locking skipped).
func NewModuleAccessProvisioner(
	templates moduleAccessTemplates,
	roleRepo moduleAccessRoleRepo,
	userRepo moduleAccessUserRepo,
	bootstrap moduleAccessSpiceDB,
	entitlements moduleAccessEntitlements,
	locker moduleAccessLocker,
) *ModuleAccessProvisioner {
	return &ModuleAccessProvisioner{
		templates:    templates,
		roleRepo:     roleRepo,
		userRepo:     userRepo,
		bootstrap:    bootstrap,
		entitlements: entitlements,
		locker:       locker,
	}
}

// EnsureModuleAccess materializes the role templates of every permission
// module behind entitlementCode and grants the module's owner-admin roles to
// the tenant's owners. A role that already has an active holder is left alone
// (an admin who removed everyone else's access is not overridden unless the
// role ends up with no holders at all).
func (p *ModuleAccessProvisioner) EnsureModuleAccess(ctx context.Context, tenantID uuid.UUID, entitlementCode string) (*ModuleAccessResult, error) {
	res := &ModuleAccessResult{TenantID: tenantID, EntitlementCode: entitlementCode}
	modules := PermissionModulesForEntitlement(entitlementCode)
	if len(modules) == 0 {
		return res, nil
	}

	run := func(ctx context.Context) error { return p.ensure(ctx, res, modules) }
	if p.locker != nil {
		if err := p.locker.WithLock(ctx, "module-access:"+tenantID.String(), run); err != nil {
			return res, err
		}
		return res, nil
	}
	return res, run(ctx)
}

func (p *ModuleAccessProvisioner) ensure(ctx context.Context, res *ModuleAccessResult, modules []string) error {
	tenantID := res.TenantID
	for _, module := range modules {
		n, err := p.templates.ProvisionForModuleGrant(ctx, tenantID, module)
		if err != nil {
			return fmt.Errorf("EnsureModuleAccess: provision %q: %w", module, err)
		}
		res.RolesProvisioned += n
		if _, err := p.templates.EnsureBaselineForModule(ctx, tenantID, module); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: template baseline: %v", module, err))
		}
	}

	ownerRole, err := p.roleRepo.GetByName(ctx, tenantID, "owner")
	if err != nil {
		return fmt.Errorf("EnsureModuleAccess: look up owner role: %w", err)
	}
	var owners []uuid.UUID
	if ownerRole != nil {
		owners, err = p.roleRepo.ListActiveHolderIDs(ctx, ownerRole.ID)
		if err != nil {
			return fmt.Errorf("EnsureModuleAccess: list owners: %w", err)
		}
	}
	res.OwnersFound = len(owners)
	if ownerRole == nil {
		logger.Log.Warn("Module access: tenant has no owner role, skipping owner permission grant",
			zap.String("tenant_id", tenantID.String()),
			zap.String("entitlement_code", res.EntitlementCode),
		)
	} else {
		p.grantDefaultRolePermissions(ctx, res, ownerRole, owners, ownerPermissionModules(modules), "owner")
	}

	// The AcmeApp catalog's canonical tenant admin is the exact "admin" role.
	// It receives active-HR permissions only through the HR entitlement path;
	// custom roles and platform-admin identities are never selected here.
	if adminModules := DefaultAdminPermissionModules[res.EntitlementCode]; len(adminModules) > 0 {
		adminRole, err := p.roleRepo.GetByName(ctx, tenantID, "admin")
		if err != nil {
			return fmt.Errorf("EnsureModuleAccess: look up admin role: %w", err)
		}
		if isCanonicalAcmeAppRole(adminRole, "admin") {
			admins, err := p.roleRepo.ListActiveHolderIDs(ctx, adminRole.ID)
			if err != nil {
				return fmt.Errorf("EnsureModuleAccess: list admins: %w", err)
			}
			p.grantDefaultRolePermissions(ctx, res, adminRole, admins, adminModules, "admin")
		}
	}
	if len(owners) == 0 {
		logger.Log.Info("Module access: tenant has no active owners, skipping owner grants",
			zap.String("tenant_id", tenantID.String()),
			zap.String("entitlement_code", res.EntitlementCode),
		)
		return nil
	}

	for _, key := range EntitlementOwnerTemplateKeys[res.EntitlementCode] {
		role, err := p.roleRepo.GetByTemplateKeyForTenant(ctx, tenantID, key)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: look up role: %v", key, err))
			continue
		}
		if role == nil {
			res.MissingTemplates = append(res.MissingTemplates, key)
			logger.Log.Warn("Module access: owner template has no role for tenant (template missing or inactive)",
				zap.String("tenant_id", tenantID.String()),
				zap.String("template_key", key),
			)
			continue
		}
		holders, err := p.roleRepo.ListActiveHolderIDs(ctx, role.ID)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: list holders: %v", key, err))
			continue
		}
		if len(holders) > 0 {
			res.RolesAlreadyHeld++
			continue
		}
		for _, userID := range owners {
			if err := p.userRepo.GrantRoles(ctx, userID, []uuid.UUID{role.ID}, nil); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("%s: grant to %s: %v", key, userID, err))
				continue
			}
			res.GrantsMade++
			if p.bootstrap == nil {
				continue
			}
			if _, err := p.bootstrap.BootstrapUserRole(ctx, tenantID, userID, role.ID); err != nil {
				logger.Log.Warn("Module access: SpiceDB role write failed (reconciler will repair)",
					zap.String("tenant_id", tenantID.String()),
					zap.String("user_id", userID.String()),
					zap.String("role_id", role.ID.String()),
					zap.Error(err),
				)
			}
		}
	}
	return nil
}

// isCanonicalAcmeAppRole limits default-role reconciliation to the seeded
// identity emitted by AcmeAppRoleCatalog. An exact role name alone is not
// enough because older tenants may have a custom role with that name.
func isCanonicalAcmeAppRole(role *models.Role, name string) bool {
	if role == nil {
		return false
	}
	for _, def := range AcmeAppRoleCatalog {
		if def.Name != name {
			continue
		}
		return role.Name == def.Name &&
			role.DisplayName == def.DisplayName &&
			role.IsSystem == false &&
			role.IsDefault == def.IsDefault &&
			role.Priority == def.Priority
	}
	return false
}

// ownerBaseModules are the shared permission modules every module entitlement
// relies on (legal entities, items, parties, settings...): no entitlement maps
// to them, so without this an owner could not create the company that the
// company-scoped modules require. "jobs" is the cross-module bulk-jobs
// surface (imports/exports/bulk actions of every module), ungated by
// entitlement in business like core.
var ownerBaseModules = []string{"core", "jobs"}

// ownerPermissionModules is the module list the owner role is granted for one
// entitlement: its permission modules plus ownerBaseModules.
func ownerPermissionModules(modules []string) []string {
	out := append([]string{}, modules...)
	for _, base := range ownerBaseModules {
		if !slices.Contains(out, base) {
			out = append(out, base)
		}
	}
	return out
}

// grantDefaultRolePermissions gives a canonical default role every catalog
// permission of the entitled modules. It always replays the SpiceDB mirror so
// a prior partial mirror failure is repaired even when the relational insert is
// now a no-op.
func (p *ModuleAccessProvisioner) grantDefaultRolePermissions(ctx context.Context, res *ModuleAccessResult, role *models.Role, holders []uuid.UUID, modules []string, roleName string) {
	tenantID := res.TenantID
	n, err := p.roleRepo.GrantModulePermissionsToRole(ctx, role.ID, modules)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("%s permissions: %v", roleName, err))
		return
	}
	if roleName == "owner" {
		res.OwnerPermissionsGranted += n
	} else {
		res.AdminPermissionsGranted += n
	}

	if p.rolePermSp != nil && p.permLister != nil {
		catalog, err := p.permLister.ListByModules(ctx, modules)
		if err != nil {
			logger.Log.Warn("Module access: cannot list permissions for SpiceDB sync (reconciler will repair)",
				zap.String("tenant_id", tenantID.String()), zap.Error(err))
		} else {
			names := make([]string, 0, len(catalog))
			for _, perm := range catalog {
				names = append(names, perm.Name)
			}
			if _, err := p.rolePermSp.BootstrapRolePermissions(ctx, tenantID, role.ID, names); err != nil {
				logger.Log.Warn("Module access: SpiceDB default-role permission write failed (reconciler will repair)",
					zap.String("tenant_id", tenantID.String()), zap.Error(err))
			}
		}
	}

	if n == 0 || p.sessions == nil || len(holders) == 0 {
		return
	}
	version, err := p.sessions.IncrementRoleVersion(ctx, tenantID)
	if err != nil {
		logger.Log.Warn("Module access: failed to increment role version",
			zap.String("tenant_id", tenantID.String()), zap.Error(err))
	}
	for _, userID := range holders {
		if err := p.sessions.InvalidateUserSessionsByRoleVersion(ctx, userID, version); err != nil {
			logger.Log.Warn("Module access: failed to invalidate owner sessions",
				zap.String("user_id", userID.String()), zap.Error(err))
		}
		msg := struct {
			Type      string    `json:"type"`
			TenantID  uuid.UUID `json:"tenant_id"`
			UserID    uuid.UUID `json:"user_id"`
			Timestamp time.Time `json:"timestamp"`
			Reason    string    `json:"reason"`
		}{"role_changed", tenantID, userID, time.Now(), "Default role module permissions granted"}
		if err := p.sessions.PublishPermissionInvalidation(ctx, msg); err != nil {
			logger.Log.Warn("Module access: failed to publish permission invalidation",
				zap.String("user_id", userID.String()), zap.Error(err))
		}
	}
}

// ReconcileTenant runs EnsureModuleAccess for every granting entitlement of
// tenantID.
func (p *ModuleAccessProvisioner) ReconcileTenant(ctx context.Context, tenantID uuid.UUID) (*ModuleAccessReconcileSummary, error) {
	return p.reconcile(ctx, func(g repositories.TenantModuleGrant) bool { return g.TenantID == tenantID })
}

// ReconcileAll runs EnsureModuleAccess for every granting entitlement of every
// tenant.
func (p *ModuleAccessProvisioner) ReconcileAll(ctx context.Context) (*ModuleAccessReconcileSummary, error) {
	return p.reconcile(ctx, func(repositories.TenantModuleGrant) bool { return true })
}

// ReconcilePermissionModule runs EnsureModuleAccess for every granting
// entitlement whose code covers the permission module (used when a module
// registers new permissions or templates).
func (p *ModuleAccessProvisioner) ReconcilePermissionModule(ctx context.Context, permissionModule string) (*ModuleAccessReconcileSummary, error) {
	codes := map[string]bool{}
	for _, c := range EntitlementCodesForPermissionModule(permissionModule) {
		codes[c] = true
	}
	return p.reconcile(ctx, func(g repositories.TenantModuleGrant) bool { return codes[g.ModuleCode] })
}

func (p *ModuleAccessProvisioner) reconcile(ctx context.Context, keep func(repositories.TenantModuleGrant) bool) (*ModuleAccessReconcileSummary, error) {
	grants, err := p.entitlements.ListGrantingTenantModules(ctx)
	if err != nil {
		return nil, fmt.Errorf("ModuleAccessProvisioner.reconcile: %w", err)
	}
	sum := &ModuleAccessReconcileSummary{}
	tenants := map[uuid.UUID]bool{}
	for _, g := range grants {
		if !keep(g) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return sum, err
		}
		tenants[g.TenantID] = true
		res, err := p.EnsureModuleAccess(ctx, g.TenantID, g.ModuleCode)
		if err != nil {
			sum.Failed++
			res.Errors = append(res.Errors, err.Error())
			logger.Log.Warn("Module access reconcile failed for tenant module",
				zap.String("tenant_id", g.TenantID.String()),
				zap.String("entitlement_code", g.ModuleCode),
				zap.Error(err),
			)
		}
		sum.RolesProvisioned += res.RolesProvisioned
		sum.GrantsMade += res.GrantsMade
		sum.OwnerPermissionsGranted += res.OwnerPermissionsGranted
		sum.AdminPermissionsGranted += res.AdminPermissionsGranted
		sum.Results = append(sum.Results, *res)
	}
	sum.Tenants = len(tenants)
	sort.SliceStable(sum.Results, func(i, j int) bool { return sum.Results[i].TenantID.String() < sum.Results[j].TenantID.String() })
	return sum, nil
}

// moduleAccessHookTimeout bounds one inline EnsureModuleAccess call made from
// the entitlement write path.
const moduleAccessHookTimeout = 30 * time.Second

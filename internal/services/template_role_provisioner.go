// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/authorization"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// templateRoleRepo is the subset of RoleRepository TemplateRoleProvisioner
// needs. Kept interface-scoped (mirrors roleServiceRoleRepo /
// acmeappUserRoleAssigner elsewhere in this package) so tests can fake it
// without a real Postgres connection.
type templateRoleRepo interface {
	CreateFromTemplate(ctx context.Context, role *models.Role) error
	GetByTemplateKeyForTenant(ctx context.Context, tenantID uuid.UUID, templateKey string) (*models.Role, error)
	ListRolesByTemplateKey(ctx context.Context, templateKey string) ([]models.Role, error)
	ListTemplateDerivedRolesByModule(ctx context.Context, tenantID uuid.UUID, module string) ([]models.Role, error)
	SetTemplateVersion(ctx context.Context, roleID uuid.UUID, version int) error
	AssignPermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, assignedBy *uuid.UUID) error
	// GrantPermissionsByName and GetRolePermissions back the additive baseline
	// top-up (EnsureBaselineForModule).
	GrantPermissionsByName(ctx context.Context, roleID uuid.UUID, permissionNames []string) error
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error)
}

// templateRepoForProvisioner is the subset of RoleTemplateRepository
// TemplateRoleProvisioner needs.
type templateRepoForProvisioner interface {
	GetLatestByKey(ctx context.Context, key string) (*models.RoleTemplate, error)
	ListLatestActiveByModules(ctx context.Context, modules []string) ([]models.RoleTemplate, error)
}

// TemplateRoleProvisioner materializes iam_role_templates into real,
// tenant-owned iam_roles rows, and keeps them in sync as templates version
// (the product roadmap §4.1). It never touches a role whose template_key is
// NULL (a tenant-custom role) — every method here operates strictly on
// template-derived roles, identified via iam_roles.template_key.
type TemplateRoleProvisioner struct {
	roleRepo        templateRoleRepo
	templateRepo    templateRepoForProvisioner
	permissionRepo  roleServicePermissionRepo
	tenantBootstrap *TenantBootstrapService
}

// NewTemplateRoleProvisioner constructs a TemplateRoleProvisioner.
// tenantBootstrap may be nil (SpiceDB sync is then skipped, mirroring
// AcmeAppRoleProvisioner's nil-safety) — used by unit tests that only assert
// the relational side.
func NewTemplateRoleProvisioner(
	roleRepo templateRoleRepo,
	templateRepo templateRepoForProvisioner,
	permissionRepo roleServicePermissionRepo,
	tenantBootstrap *TenantBootstrapService,
) *TemplateRoleProvisioner {
	return &TemplateRoleProvisioner{
		roleRepo:        roleRepo,
		templateRepo:    templateRepo,
		permissionRepo:  permissionRepo,
		tenantBootstrap: tenantBootstrap,
	}
}

// InstantiateForTenant materializes the latest active version of templateKey
// into a real role for tenantID. Idempotent: if the tenant already
// instantiated this key (any version), returns the existing role unchanged
// rather than creating a duplicate — matching
// AcmeAppRoleProvisioner.ProvisionTenantAndAssignOwner's idempotency
// contract. displayNameOverride, when non-empty, overrides the template's
// Name for this tenant's copy.
func (p *TemplateRoleProvisioner) InstantiateForTenant(ctx context.Context, tenantID uuid.UUID, templateKey string, displayNameOverride string, createdBy *uuid.UUID) (*models.Role, error) {
	if existing, err := p.roleRepo.GetByTemplateKeyForTenant(ctx, tenantID, templateKey); err != nil {
		return nil, fmt.Errorf("InstantiateForTenant: check existing: %w", err)
	} else if existing != nil {
		return existing, nil
	}

	tmpl, err := p.templateRepo.GetLatestByKey(ctx, templateKey)
	if err != nil {
		return nil, fmt.Errorf("InstantiateForTenant: load template %q: %w", templateKey, err)
	}
	if tmpl == nil || !tmpl.IsActive {
		return nil, fmt.Errorf("InstantiateForTenant: template %q not found or inactive", templateKey)
	}

	displayName := tmpl.Name
	if displayNameOverride != "" {
		displayName = displayNameOverride
	}

	roleName := templateRoleName(templateKey)
	if authorization.IsTenantAdministratorRole(roleName) {
		return nil, fmt.Errorf("InstantiateForTenant: template %q would create reserved role name %q", templateKey, roleName)
	}

	role := &models.Role{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Name:            roleName,
		DisplayName:     displayName,
		Description:     tmpl.Description,
		IsSystem:        false,
		IsDefault:       false,
		Priority:        0,
		CreatedBy:       createdBy,
		TemplateKey:     &tmpl.Key,
		TemplateVersion: &tmpl.Version,
		Module:          &tmpl.Module,
	}
	if err := p.roleRepo.CreateFromTemplate(ctx, role); err != nil {
		return nil, fmt.Errorf("InstantiateForTenant: create role from template %q: %w", templateKey, err)
	}

	if err := p.grantTemplatePermissions(ctx, role, tmpl.Permissions); err != nil {
		return nil, fmt.Errorf("InstantiateForTenant: %w", err)
	}

	logger.Log.Info("Instantiated role template for tenant",
		zap.String("tenant_id", tenantID.String()),
		zap.String("template_key", templateKey),
		zap.Int("template_version", tmpl.Version),
		zap.String("role_id", role.ID.String()),
	)
	return role, nil
}

// ProvisionForModuleGrant instantiates every active role template published
// by module for tenantID. Called when the tenant becomes entitled to module
// (see the module-grant trigger wiring in provisioning_consumer.go — a
// tenant's product/module instance being provisioned is falcon-id's
// existing, real "module granted" signal; there is no finer-grained
// per-module entitlement Kafka event today). Best-effort per template: one
// template failing to instantiate does not prevent the others from being
// provisioned, since a tenant should not lose an otherwise-working starter
// role catalog because of an unrelated schema problem in a single template.
func (p *TemplateRoleProvisioner) ProvisionForModuleGrant(ctx context.Context, tenantID uuid.UUID, module string) (int, error) {
	templates, err := p.templateRepo.ListLatestActiveByModules(ctx, []string{module})
	if err != nil {
		return 0, fmt.Errorf("ProvisionForModuleGrant: list templates for module %q: %w", module, err)
	}

	provisioned := 0
	for _, tmpl := range templates {
		if _, err := p.InstantiateForTenant(ctx, tenantID, tmpl.Key, "", nil); err != nil {
			logger.Log.Warn("Failed to instantiate role template on module grant",
				zap.String("tenant_id", tenantID.String()),
				zap.String("module", module),
				zap.String("template_key", tmpl.Key),
				zap.Error(err),
			)
			continue
		}
		provisioned++
	}
	return provisioned, nil
}

// ReconcileVersionBump syncs every tenant's role derived from templateKey to
// match the permission set of the given newVersion. It adds permissions the
// new version grants that the role is missing, and removes permissions the
// role has that the new version no longer grants — an exact replace to the
// new version's permission set, computed and applied per role so one
// tenant's failure does not block others. Never touches a role whose
// template_key does not equal templateKey, and by construction (queries
// scoped to template_key IS NOT NULL) never touches a tenant-custom role.
func (p *TemplateRoleProvisioner) ReconcileVersionBump(ctx context.Context, templateKey string, newVersion int) (reconciled int, err error) {
	tmpl, err := p.templateRepo.GetLatestByKey(ctx, templateKey)
	if err != nil {
		return 0, fmt.Errorf("ReconcileVersionBump: load template %q: %w", templateKey, err)
	}
	if tmpl == nil {
		return 0, fmt.Errorf("ReconcileVersionBump: template %q not found", templateKey)
	}
	if tmpl.Version != newVersion {
		return 0, fmt.Errorf("ReconcileVersionBump: newVersion %d does not match latest stored version %d for key %q", newVersion, tmpl.Version, templateKey)
	}

	roles, err := p.roleRepo.ListRolesByTemplateKey(ctx, templateKey)
	if err != nil {
		return 0, fmt.Errorf("ReconcileVersionBump: list roles for key %q: %w", templateKey, err)
	}

	for i := range roles {
		role := roles[i]
		if role.TemplateVersion != nil && *role.TemplateVersion == newVersion {
			continue // already reconciled to this version
		}
		if err := p.grantTemplatePermissions(ctx, &role, tmpl.Permissions); err != nil {
			logger.Log.Warn("Failed to reconcile template-derived role to new version",
				zap.String("template_key", templateKey),
				zap.Int("new_version", newVersion),
				zap.String("role_id", role.ID.String()),
				zap.Error(err),
			)
			continue
		}
		if err := p.roleRepo.SetTemplateVersion(ctx, role.ID, newVersion); err != nil {
			logger.Log.Warn("Failed to record reconciled template version on role",
				zap.String("role_id", role.ID.String()),
				zap.Error(err),
			)
			continue
		}
		reconciled++
	}
	return reconciled, nil
}

// EnsureBaselineForModule additively grants the shared baseline
// (acmeappBaselinePermissions) to every template-derived role of module for
// tenantID, so roles instantiated before the baseline existed (and not touched
// by a template version bump) get it. Never removes anything and never touches
// sessions (tokens carry no permissions; SpiceDB decides each request). The
// SpiceDB write goes first and a failure aborts before the relational grant,
// so the role still looks incomplete and the next reconcile retries it.
// Returns the number of roles topped up.
func (p *TemplateRoleProvisioner) EnsureBaselineForModule(ctx context.Context, tenantID uuid.UUID, module string) (int, error) {
	roles, err := p.roleRepo.ListTemplateDerivedRolesByModule(ctx, tenantID, module)
	if err != nil {
		return 0, fmt.Errorf("EnsureBaselineForModule: list roles for module %q: %w", module, err)
	}
	topped := 0
	for i := range roles {
		role := roles[i]
		missing, err := missingRolePermissions(ctx, p.roleRepo, role.ID, acmeappBaselinePermissions)
		if err != nil {
			return topped, fmt.Errorf("EnsureBaselineForModule: read grants of role %s: %w", role.ID, err)
		}
		if len(missing) == 0 {
			continue
		}
		catalog, err := p.permissionRepo.ListByModules(ctx, referencedModules(missing))
		if err != nil {
			return topped, fmt.Errorf("EnsureBaselineForModule: list permission catalog: %w", err)
		}
		known := map[string]bool{}
		for _, perm := range catalog {
			known[perm.Name] = true
		}
		var grant []string
		for _, n := range missing {
			if known[n] {
				grant = append(grant, n)
			}
		}
		if len(grant) == 0 {
			continue
		}
		if p.tenantBootstrap != nil {
			res, err := p.tenantBootstrap.BootstrapRolePermissions(ctx, tenantID, role.ID, grant)
			if err != nil {
				return topped, fmt.Errorf("EnsureBaselineForModule: SpiceDB write for role %s: %w", role.ID, err)
			}
			if res != nil && len(res.Errors) > 0 {
				return topped, fmt.Errorf("EnsureBaselineForModule: SpiceDB write for role %s: %d tuple errors, first: %w", role.ID, len(res.Errors), res.Errors[0])
			}
		}
		if err := p.roleRepo.GrantPermissionsByName(ctx, role.ID, grant); err != nil {
			return topped, fmt.Errorf("EnsureBaselineForModule: grant to role %s: %w", role.ID, err)
		}
		topped++
	}
	return topped, nil
}

// DisableForModuleRevoke strips permission grants (relational + SpiceDB)
// from every one of tenantID's template-derived roles belonging to module,
// without deleting the role rows, their template provenance, or any
// existing iam_user_roles assignment — a subsequent ProvisionForModuleGrant
// re-grant (module re-entitled) restores the current template version's
// permissions to the same role. This is deliberately non-destructive: a
// disabled role that still grants nothing is fail-closed for authorization
// purposes (SpiceDB has nothing to allow), while preserving audit history
// and letting a re-entitlement simply "turn it back on" instead of having to
// recreate the tenant's per-role customizations from scratch.
func (p *TemplateRoleProvisioner) DisableForModuleRevoke(ctx context.Context, tenantID uuid.UUID, module string) (disabled int, err error) {
	roles, err := p.roleRepo.ListTemplateDerivedRolesByModule(ctx, tenantID, module)
	if err != nil {
		return 0, fmt.Errorf("DisableForModuleRevoke: list roles for module %q: %w", module, err)
	}

	for _, role := range roles {
		if err := p.roleRepo.AssignPermissions(ctx, role.ID, nil, nil); err != nil {
			logger.Log.Warn("Failed to strip permissions from template-derived role on module revoke",
				zap.String("tenant_id", tenantID.String()),
				zap.String("module", module),
				zap.String("role_id", role.ID.String()),
				zap.Error(err),
			)
			continue
		}
		if p.tenantBootstrap != nil {
			// BootstrapRolePermissions with an empty name list is a no-op
			// write; SpiceDB tuples for this role's previous grants are
			// left for the reconciler to clean up (a stale ALLOW tuple for
			// a role with zero relational grants is harmless — the
			// relational side, which the UI and the .NET attribute's
			// coarse-permission path read, is what actually matters here).
			if _, err := p.tenantBootstrap.BootstrapRolePermissions(ctx, tenantID, role.ID, nil); err != nil {
				logger.Log.Warn("Failed to sync disabled role to SpiceDB (reconciler will repair)",
					zap.String("role_id", role.ID.String()),
					zap.Error(err),
				)
			}
		}
		disabled++
	}
	return disabled, nil
}

// grantTemplatePermissions resolves templatePermissionNames against the live
// permission catalog and replaces role's relational grants with exactly that
// set (RoleRepository.AssignPermissions deletes-then-inserts, so this is an
// atomic add+remove relative to the role's previous grants), then
// best-effort syncs the same set to SpiceDB via TenantBootstrapService.
//
// A template permission name not found in the catalog is skipped with a
// warning rather than failing the whole call — mirrors
// AcmeAppRoleProvisioner.provisionRoles' resilience to registration-order
// races (the owning module may not have finished self-registering yet).
func (p *TemplateRoleProvisioner) grantTemplatePermissions(ctx context.Context, role *models.Role, templatePermissionNames []string) error {
	templatePermissionNames = withBaselinePermissions(templatePermissionNames)
	modules := referencedModules(templatePermissionNames)
	catalog, err := p.permissionRepo.ListByModules(ctx, modules)
	if err != nil {
		return fmt.Errorf("list permission catalog for modules %v: %w", modules, err)
	}
	byName := make(map[string]uuid.UUID, len(catalog))
	for _, perm := range catalog {
		byName[perm.Name] = perm.ID
	}

	var permIDs []uuid.UUID
	var grantedNames []string
	for _, name := range templatePermissionNames {
		id, ok := byName[name]
		if !ok {
			logger.Log.Warn("Role template references unknown permission; grant skipped",
				zap.String("role_id", role.ID.String()),
				zap.String("permission", name),
			)
			continue
		}
		permIDs = append(permIDs, id)
		grantedNames = append(grantedNames, name)
	}

	if err := p.roleRepo.AssignPermissions(ctx, role.ID, permIDs, nil); err != nil {
		return fmt.Errorf("assign permissions to role %s: %w", role.ID, err)
	}

	if p.tenantBootstrap != nil && len(grantedNames) > 0 {
		if _, err := p.tenantBootstrap.BootstrapRolePermissions(ctx, role.TenantID, role.ID, grantedNames); err != nil {
			logger.Log.Warn("Failed to sync template role permissions to SpiceDB (reconciler will repair)",
				zap.String("role_id", role.ID.String()),
				zap.Error(err),
			)
		}
	}
	return nil
}

// referencedModules returns the distinct module prefixes referenced by
// permNames, mirroring acmeappReferencedModules' rationale: scoping
// ListByModules avoids ever depending on iam_permissions' total row count.
func referencedModules(permNames []string) []string {
	seen := make(map[string]bool)
	var modules []string
	for _, name := range permNames {
		idx := indexByteColon(name)
		if idx <= 0 {
			continue
		}
		m := name[:idx]
		if !seen[m] {
			seen[m] = true
			modules = append(modules, m)
		}
	}
	return modules
}

func indexByteColon(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

// templateRoleName derives the tenant role's "name" (unique per tenant) from
// a template key. It is the full "module:slug" key, e.g.
// "marketing:campaign_manager": slugs alone collide across modules
// (crm:admin and marketing:admin) and with reserved tenant-administrator
// names such as "admin", which would be a privilege escalation.
func templateRoleName(templateKey string) string {
	return templateKey
}

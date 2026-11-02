// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"html"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

const auditActionCategoryPermissionManagement = "permission_management"

// permissionServicePermissionRepo defines the permission repository methods needed by PermissionService.
type permissionServicePermissionRepo interface {
	RegisterPermissionsBatch(ctx context.Context, permissions []*models.Permission) (registered, updated int, err error)
	DeprecateUnlistedInModule(ctx context.Context, module string, activePermissionNames []string, sunsetWindow time.Duration) (int, error)
	List(ctx context.Context) ([]models.Permission, error)
	ListByModule(ctx context.Context, module string) ([]models.Permission, error)
	ListByModules(ctx context.Context, modules []string) ([]models.Permission, error)
	GetModules(ctx context.Context) ([]string, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Permission, error)
	GetByName(ctx context.Context, name string) (*models.Permission, error)
	Create(ctx context.Context, perm *models.Permission) error
	Update(ctx context.Context, id uuid.UUID, displayName *string, description *string) error
	DeleteIfNotInUse(ctx context.Context, id uuid.UUID) error
}

// validSegment validates module/resource/action segments: lowercase alphanumeric with hyphens/underscores.
var validSegment = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,49}$`)

// validatePermissionSegment validates a single segment of a permission name.
func validatePermissionSegment(field, value string) error {
	if !validSegment.MatchString(value) {
		return fmt.Errorf("%s must be lowercase alphanumeric with hyphens/underscores (1-50 chars, start with letter)", field)
	}
	if strings.Contains(value, "*") {
		return fmt.Errorf("%s cannot contain wildcards", field)
	}
	return nil
}

// sanitizeString sanitizes a string by escaping HTML entities and trimming whitespace.
func sanitizeString(s string) string {
	return strings.TrimSpace(html.EscapeString(s))
}

// SpiceDBPermSyncer defines the contract for syncing permission grants to SpiceDB.
// Implementations must be safe to call after a successful DB write; errors are
// non-fatal — they are logged but do not roll back the database change.
type SpiceDBPermSyncer interface {
	// SyncPermissionGrant writes the access_grant relationship for the given
	// permission name to SpiceDB. permissionName is the canonical dotted form,
	// e.g. "crm:contacts:read".
	SyncPermissionGrant(ctx context.Context, permissionName string) error

	// DeletePermissionGrant removes the access_grant relationship for the given
	// permission name from SpiceDB.
	DeletePermissionGrant(ctx context.Context, permissionName string) error
}

// PermissionService handles permission-related business logic
type PermissionService struct {
	permissionRepo     permissionServicePermissionRepo
	auditService       *AuditService
	spicedbSyncer      SpiceDBPermSyncer
	entitlementChecker ModuleEntitlementChecker

	// Role templates (the product roadmap §4.1) — all optional/nil-safe. A
	// deployment that never calls SetRoleTemplateRepo behaves exactly as
	// before RegisterModuleRequest.RoleTemplates existed: a manifest that
	// tries to use it gets a clear error instead of a nil-pointer panic
	// (see RegisterModule).
	roleTemplateRepo      roleTemplateFullRepo
	roleTemplateValidator *RoleTemplateValidator
	templateProvisioner   *TemplateRoleProvisioner
	moduleAccessReconcile permissionModuleReconciler
}

// permissionModuleReconciler re-runs module-access provisioning for tenants
// already entitled to a permission module whose permissions or role templates
// were just registered.
type permissionModuleReconciler interface {
	ReconcilePermissionModule(ctx context.Context, permissionModule string) (*ModuleAccessReconcileSummary, error)
}

// SetModuleAccessReconciler wires the first-registration reconcile.
// Optional: nil skips it.
func (s *PermissionService) SetModuleAccessReconciler(r permissionModuleReconciler) {
	s.moduleAccessReconcile = r
}

// templateModuleReconcileTimeout bounds the detached reconcile fired after a
// module registers new permissions or templates.
const templateModuleReconcileTimeout = 5 * time.Minute

// roleTemplateFullRepo is the subset of RoleTemplateRepository
// PermissionService.RegisterModule needs to persist and idempotency-check
// role templates.
type roleTemplateFullRepo interface {
	roleTemplateLatestLookup
	Create(ctx context.Context, t *models.RoleTemplate) error
}

// SetRoleTemplateSupport wires the role-template repository, validator and
// provisioner into RegisterModule. All three are constructed together
// because ReconcileVersionBump (via provisioner) depends on the same
// repository the validator/create path uses — see cmd/services.go for the
// concrete wiring.
func (s *PermissionService) SetRoleTemplateSupport(repo roleTemplateFullRepo, validator *RoleTemplateValidator, provisioner *TemplateRoleProvisioner) {
	s.roleTemplateRepo = repo
	s.roleTemplateValidator = validator
	s.templateProvisioner = provisioner
}

// SetSpiceDBSyncer wires an optional SpiceDB sync callback. When set, Create() and
// Delete() will attempt to keep SpiceDB in sync after successful DB writes.
// Errors from the syncer are logged but never propagate to the caller.
func (s *PermissionService) SetSpiceDBSyncer(syncer SpiceDBPermSyncer) {
	s.spicedbSyncer = syncer
}

// SetModuleEntitlementChecker wires an optional module entitlement checker.
// When set, tenant-aware listing methods filter permissions to the modules the
// tenant is subscribed to. Errors from the checker are fail-closed (spec 23
// §1.4): a module whose entitlement check errors is excluded from the
// result, and a repo-level failure propagates as an error instead of
// silently returning every module.
func (s *PermissionService) SetModuleEntitlementChecker(checker ModuleEntitlementChecker) {
	s.entitlementChecker = checker
}

// toTitle converts a string to title case (first letter uppercase)
func toTitle(s string) string {
	if s == "" {
		return s
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// NewPermissionService creates a new permission service
func NewPermissionService(
	permissionRepo permissionServicePermissionRepo,
	auditService *AuditService,
) *PermissionService {
	return &PermissionService{
		permissionRepo: permissionRepo,
		auditService:   auditService,
	}
}

// RegisterModule registers all permissions for a module
func (s *PermissionService) RegisterModule(ctx context.Context, req *models.RegisterModuleRequest) (*models.RegisterModuleResponse, error) {
	if req.Module == "" {
		return nil, fmt.Errorf("module name is required")
	}

	if len(req.Permissions) == 0 {
		return nil, fmt.Errorf("at least one permission is required")
	}

	// Build permissions list
	var permissions []*models.Permission
	for _, permDef := range req.Permissions {
		if permDef.Resource == "" {
			return nil, fmt.Errorf("resource name is required")
		}
		if len(permDef.Actions) == 0 {
			return nil, fmt.Errorf("at least one action is required for resource %s", permDef.Resource)
		}

		for _, action := range permDef.Actions {
			if action == "" {
				continue
			}

			// Create permission name in format: module:resource:action
			name := fmt.Sprintf("%s:%s:%s", req.Module, permDef.Resource, action)

			// Generate display name if not provided
			displayName := permDef.DisplayName
			if displayName == "" {
				displayName = fmt.Sprintf("%s %s %s", toTitle(req.Module), toTitle(permDef.Resource), toTitle(action))
			} else {
				displayName = fmt.Sprintf("%s - %s", displayName, toTitle(action))
			}

			perm := &models.Permission{
				Module:      req.Module,
				Resource:    permDef.Resource,
				Action:      action,
				Name:        name,
				DisplayName: displayName,
				IsSystem:    false,
				Source:      "service",
			}

			if permDef.Description != "" {
				perm.Description = &permDef.Description
			}

			permissions = append(permissions, perm)
		}
	}

	// Register all permissions
	registered, updated, err := s.permissionRepo.RegisterPermissionsBatch(ctx, permissions)
	if err != nil {
		return nil, fmt.Errorf("failed to register permissions: %w", err)
	}

	// Prune mode — soft-deprecate catalog rows for this module that did
	// NOT show up in the manifest. The deprecation lifecycle then runs
	// independently: monitoring picks up the deprecated rows, a separate
	// sweep hard-deletes anything past `sunset_at` once
	// `iam_role_permissions` referential checks pass.
	deprecated := 0
	if req.Prune {
		// Build the active-name set from the payload we just registered.
		// names match the (module:resource:action) shape that the catalog
		// stores in iam_permissions.name and that the repository's
		// idempotent UPDATE uses to compute the orphan set.
		activeNames := make([]string, 0, len(permissions))
		for _, p := range permissions {
			activeNames = append(activeNames, p.Name)
		}
		deprecated, err = s.permissionRepo.DeprecateUnlistedInModule(
			ctx,
			req.Module,
			activeNames,
			defaultDeprecationSunsetWindow,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to deprecate unlisted permissions: %w", err)
		}
	}

	// Convert to response format
	permResponses := make([]models.PermissionResponse, len(permissions))
	for i, perm := range permissions {
		permResponses[i] = *perm.ToResponse()
	}

	templateResponses, _, err := s.registerRoleTemplates(ctx, req, permissions)
	if err != nil {
		return nil, err
	}

	// Registration is also the durable repair point for already-entitled
	// tenants. Re-run even when every catalog row already exists: a previous
	// role or SpiceDB write may have partially failed, while an idempotent
	// catalog upsert reports registered == 0. Detached and best-effort: it must
	// neither delay nor fail registration.
	if s.moduleAccessReconcile != nil {
		go func(module string, r permissionModuleReconciler) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Log.Error("module access: reconcile after registration panicked",
						zap.String("module", module), zap.Any("panic", rec))
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), templateModuleReconcileTimeout)
			defer cancel()
			if _, err := r.ReconcilePermissionModule(ctx, module); err != nil {
				logger.Log.Warn("module access: reconcile after registration failed",
					zap.String("module", module), zap.Error(err))
			}
		}(req.Module, s.moduleAccessReconcile)
	}

	return &models.RegisterModuleResponse{
		Module:        req.Module,
		Registered:    registered,
		Updated:       updated,
		Deprecated:    deprecated,
		Permissions:   permResponses,
		RoleTemplates: templateResponses,
	}, nil
}

// registerRoleTemplates validates and persists req.RoleTemplates (a no-op,
// returning nil, when the request has none — every RegisterModule caller
// that doesn't use this feature is unaffected). See RoleTemplateValidator
// for the ownership/monotonic-version rules enforced here.
func (s *PermissionService) registerRoleTemplates(ctx context.Context, req *models.RegisterModuleRequest, registeredPermissions []*models.Permission) (responses []models.RoleTemplateResponse, firstRegistration bool, err error) {
	if len(req.RoleTemplates) == 0 {
		return nil, false, nil
	}
	if s.roleTemplateRepo == nil {
		return nil, false, fmt.Errorf("role_templates: role template registration is not enabled on this deployment")
	}

	permissionNamesInRequest := make(map[string]bool, len(registeredPermissions))
	for _, p := range registeredPermissions {
		permissionNamesInRequest[p.Name] = true
	}

	existingModulePermissions := make(map[string]bool)
	catalogModules := append([]string{req.Module}, req.Dependencies...)
	existing, err := s.permissionRepo.ListByModules(ctx, catalogModules)
	if err != nil {
		return nil, false, fmt.Errorf("role_templates: load existing catalog for validation: %w", err)
	}
	for _, p := range existing {
		existingModulePermissions[p.Name] = true
	}

	validator := s.roleTemplateValidator
	if validator == nil {
		validator = NewRoleTemplateValidator(s.roleTemplateRepo)
	}
	if err := validator.ValidateManifest(ctx, req.Module, req.Dependencies, permissionNamesInRequest, existingModulePermissions, req.RoleTemplates); err != nil {
		return nil, false, err
	}

	responses = make([]models.RoleTemplateResponse, 0, len(req.RoleTemplates))
	for _, def := range req.RoleTemplates {
		latest, err := s.roleTemplateRepo.GetLatestByKey(ctx, def.Key)
		if err != nil {
			return nil, false, fmt.Errorf("role_templates: key %q: look up latest version: %w", def.Key, err)
		}
		if latest != nil && latest.Version == def.Version {
			// Validator already confirmed identical content. Retry the idempotent
			// reconcile in case a previous per-tenant template update failed.
			responses = append(responses, *latest.ToResponse())
			if s.templateProvisioner != nil {
				if _, reconcileErr := s.templateProvisioner.ReconcileVersionBump(ctx, def.Key, def.Version); reconcileErr != nil {
					logger.Log.Warn("role_templates: reconcile-on-registration retry failed",
						zap.String("key", def.Key),
						zap.Int("version", def.Version),
						zap.Error(reconcileErr),
					)
				}
			}
			continue
		}

		rt := &models.RoleTemplate{
			Key:              def.Key,
			Version:          def.Version,
			Module:           req.Module,
			Name:             def.Name,
			NameI18n:         def.NameI18n,
			DescriptionI18n:  def.DescriptionI18n,
			Permissions:      def.Permissions,
			SpiceDBRelations: def.SpiceDBRelations,
		}
		if def.Description != "" {
			rt.Description = &def.Description
		}
		if err := s.roleTemplateRepo.Create(ctx, rt); err != nil {
			return nil, false, fmt.Errorf("role_templates: key %q: create version %d: %w", def.Key, def.Version, err)
		}
		responses = append(responses, *rt.ToResponse())
		if latest == nil {
			firstRegistration = true
		}

		// A version bump on an already-registered key must reconcile every
		// tenant's existing role derived from it (add/remove permissions to
		// match the new version). Best-effort: this runs inside the
		// service-startup RegisterModule call path, so a reconcile failure
		// must never fail registration itself — ReconcileVersionBump already
		// logs and skips individual role failures internally.
		if latest != nil && s.templateProvisioner != nil {
			if _, reconcileErr := s.templateProvisioner.ReconcileVersionBump(ctx, def.Key, def.Version); reconcileErr != nil {
				logger.Log.Warn("role_templates: reconcile-on-version-bump failed",
					zap.String("key", def.Key),
					zap.Int("version", def.Version),
					zap.Error(reconcileErr),
				)
			}
		}
	}
	return responses, firstRegistration, nil
}

// defaultDeprecationSunsetWindow is the time between soft-deprecation and the
// earliest moment a sweep job is permitted to hard-delete a permission row.
// 30 days mirrors the AWS managed-policy deprecation window and gives
// operators a generous detection-and-revert margin before a permission
// actually disappears from the catalog. Overridable by sweep tooling.
const defaultDeprecationSunsetWindow = 30 * 24 * time.Hour

// List returns all permissions
func (s *PermissionService) List(ctx context.Context) (*models.PermissionListResponse, error) {
	permissions, err := s.permissionRepo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}

	result := make([]models.PermissionResponse, len(permissions))
	for i, perm := range permissions {
		result[i] = *perm.ToResponse()
	}

	return &models.PermissionListResponse{
		Permissions: result,
		Total:       int64(len(permissions)),
	}, nil
}

// ListByModule returns permissions for a specific module
func (s *PermissionService) ListByModule(ctx context.Context, module string) (*models.PermissionListResponse, error) {
	permissions, err := s.permissionRepo.ListByModule(ctx, module)
	if err != nil {
		return nil, fmt.Errorf("ListByModule: %w", err)
	}

	result := make([]models.PermissionResponse, len(permissions))
	for i, perm := range permissions {
		result[i] = *perm.ToResponse()
	}

	return &models.PermissionListResponse{
		Permissions: result,
		Total:       int64(len(permissions)),
	}, nil
}

// ListByModules returns permissions filtered to the given modules.
// Enforces a maximum of 50 modules to prevent abuse.
func (s *PermissionService) ListByModules(ctx context.Context, modules []string) (*models.PermissionListResponse, error) {
	if len(modules) > 50 {
		return nil, fmt.Errorf("too many modules requested (max 50)")
	}
	permissions, err := s.permissionRepo.ListByModules(ctx, modules)
	if err != nil {
		return nil, fmt.Errorf("ListByModules: %w", err)
	}

	result := make([]models.PermissionResponse, len(permissions))
	for i, perm := range permissions {
		result[i] = *perm.ToResponse()
	}

	return &models.PermissionListResponse{
		Permissions: result,
		Total:       int64(len(permissions)),
	}, nil
}

// ListModules returns all registered modules
func (s *PermissionService) ListModules(ctx context.Context) ([]string, error) {
	return s.permissionRepo.GetModules(ctx)
}

// ListGroupedByModule returns permissions grouped by module
func (s *PermissionService) ListGroupedByModule(ctx context.Context) ([]models.PermissionsByModule, error) {
	permissions, err := s.permissionRepo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("ListGroupedByModule: %w", err)
	}

	// Group by module
	moduleMap := make(map[string][]models.PermissionResponse)
	for _, perm := range permissions {
		moduleMap[perm.Module] = append(moduleMap[perm.Module], *perm.ToResponse())
	}

	result := make([]models.PermissionsByModule, 0, len(moduleMap))
	for module, perms := range moduleMap {
		result = append(result, models.PermissionsByModule{
			Module:      module,
			Permissions: perms,
		})
	}

	return result, nil
}

// getEntitledModules returns the modules a tenant is subscribed to.
// Always includes "core" and "iam". Returns (nil, nil) when no entitlement
// checker is wired at all, which is a deliberate "filtering disabled"
// configuration, not a runtime failure — callers fall back to the
// unfiltered list in that case.
//
// Per spec 23 §1.4, this is fail-CLOSED, not fail-open: a repo/entitlement
// check outage must never make the permission catalog show everything.
//   - If the module list itself can't be loaded, the whole check is
//     unavailable: return an empty set plus the error, so callers can
//     surface "temporarily unavailable" instead of showing all modules.
//   - If a single module's entitlement check errors, that module is
//     excluded from the result (narrower, not wider, than a correct answer).
func (s *PermissionService) getEntitledModules(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	if s.entitlementChecker == nil {
		return nil, nil
	}

	allModules, err := s.permissionRepo.GetModules(ctx)
	if err != nil {
		// Fail-closed: entitlement is unavailable, not "everything".
		return []string{}, fmt.Errorf("getEntitledModules: %w", err)
	}

	// Universal modules always included
	entitled := make([]string, len(UniversalModules))
	copy(entitled, UniversalModules)
	seen := make(map[string]bool, len(UniversalModules))
	for _, m := range UniversalModules {
		seen[m] = true
	}

	for _, module := range allModules {
		if seen[module] {
			continue
		}
		ok, err := s.entitlementChecker.IsTenantEntitled(ctx, tenantID, module)
		if err != nil {
			// Fail-closed: exclude the module if its check errors, rather
			// than assuming entitlement.
			logger.Warn("module entitlement check failed, excluding module (fail-closed)",
				zap.Error(err),
				zap.String("tenant_id", tenantID.String()),
				zap.String("module", module),
			)
			continue
		}
		if ok {
			entitled = append(entitled, module)
			seen[module] = true
		}
	}

	return entitled, nil
}

// ListForTenant returns permissions filtered to the modules the tenant is subscribed to.
// Falls back to returning all permissions only when no entitlement checker is wired;
// an entitlement-check error is propagated (fail-closed) rather than falling back.
func (s *PermissionService) ListForTenant(ctx context.Context, tenantID uuid.UUID) (*models.PermissionListResponse, error) {
	modules, err := s.getEntitledModules(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListForTenant: %w", err)
	}
	if modules == nil {
		return s.List(ctx)
	}
	return s.ListByModules(ctx, modules)
}

// ListGroupedByModuleForTenant returns permissions grouped by module, filtered by
// the tenant's subscribed modules.
func (s *PermissionService) ListGroupedByModuleForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.PermissionsByModule, error) {
	modules, err := s.getEntitledModules(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListGroupedByModuleForTenant: %w", err)
	}
	if modules == nil {
		return s.ListGroupedByModule(ctx)
	}

	permissions, err := s.permissionRepo.ListByModules(ctx, modules)
	if err != nil {
		return nil, fmt.Errorf("ListGroupedByModuleForTenant: %w", err)
	}

	moduleMap := make(map[string][]models.PermissionResponse)
	for _, perm := range permissions {
		moduleMap[perm.Module] = append(moduleMap[perm.Module], *perm.ToResponse())
	}

	result := make([]models.PermissionsByModule, 0, len(moduleMap))
	for module, perms := range moduleMap {
		result = append(result, models.PermissionsByModule{
			Module:      module,
			Permissions: perms,
		})
	}

	return result, nil
}

// ListModulesForTenant returns only the module names the tenant is entitled to.
// Falls back to all modules only when no entitlement checker is wired; an
// entitlement-check error is propagated (fail-closed) rather than falling back.
func (s *PermissionService) ListModulesForTenant(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	modules, err := s.getEntitledModules(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListModulesForTenant: %w", err)
	}
	if modules == nil {
		return s.ListModules(ctx)
	}
	return modules, nil
}

// GetByID returns a single permission by ID
func (s *PermissionService) GetByID(ctx context.Context, id uuid.UUID) (*models.PermissionResponse, error) {
	perm, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	if perm == nil {
		return nil, fmt.Errorf("permission not found")
	}
	return perm.ToResponse(), nil
}

// Create creates a new permission with strict validation and audit logging.
func (s *PermissionService) Create(ctx context.Context, req *models.CreatePermissionRequest, auditLog *models.PlatformAuditLog) (*models.PermissionResponse, error) {
	// Validate segments
	if err := validatePermissionSegment("module", req.Module); err != nil {
		return nil, fmt.Errorf("invalid module: %w", err)
	}
	if err := validatePermissionSegment("resource", req.Resource); err != nil {
		return nil, fmt.Errorf("invalid resource: %w", err)
	}
	if err := validatePermissionSegment("action", req.Action); err != nil {
		return nil, fmt.Errorf("invalid action: %w", err)
	}

	// Sanitize and validate display_name
	displayName := sanitizeString(req.DisplayName)
	if displayName == "" {
		return nil, fmt.Errorf("display_name is required")
	}
	if len(displayName) > 255 {
		return nil, fmt.Errorf("display_name must be at most 255 characters")
	}

	// Sanitize description
	var description *string
	if req.Description != nil {
		d := sanitizeString(*req.Description)
		if len(d) > 2000 {
			return nil, fmt.Errorf("description must be at most 2000 characters")
		}
		description = &d
	}

	// Server-computed name
	name := fmt.Sprintf("%s:%s:%s", req.Module, req.Resource, req.Action)

	// Check for duplicate
	existing, err := s.permissionRepo.GetByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("Create: check duplicate: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("permission with name %q already exists", name)
	}

	perm := &models.Permission{
		Module:      req.Module,
		Resource:    req.Resource,
		Action:      req.Action,
		Name:        name,
		DisplayName: displayName,
		Description: description,
		IsSystem:    false,
		Source:      "admin",
	}

	if err := s.permissionRepo.Create(ctx, perm); err != nil {
		return nil, fmt.Errorf("Create: %w", err)
	}

	// Best-effort SpiceDB sync — non-blocking, errors are logged but do not
	// roll back the database write.
	if s.spicedbSyncer != nil {
		if syncErr := s.spicedbSyncer.SyncPermissionGrant(ctx, perm.Name); syncErr != nil {
			logger.Warn("Failed to sync permission grant to SpiceDB (non-fatal)",
				zap.String("permission", perm.Name),
				zap.Error(syncErr),
			)
		}
	}

	// Audit log
	if s.auditService != nil && auditLog != nil {
		auditLog.Action = "permission_create"
		auditLog.ActionCategory = auditActionCategoryPermissionManagement
		auditLog.TargetResourceType = auditResourceTypePermission
		auditLog.TargetResourceID = &perm.ID
		auditLog.Details = map[string]interface{}{
			"name":         perm.Name,
			"module":       perm.Module,
			"resource":     perm.Resource,
			"action":       perm.Action,
			"display_name": perm.DisplayName,
		}
		auditLog.Success = true
		if err := s.auditService.LogPlatformAction(ctx, auditLog); err != nil {
			logger.Error("Failed to log permission create audit", zap.Error(err))
		}
	}

	return perm.ToResponse(), nil
}

// Update updates a permission's display_name and/or description with audit logging.
func (s *PermissionService) Update(ctx context.Context, id uuid.UUID, req *models.UpdatePermissionRequest, auditLog *models.PlatformAuditLog) (*models.PermissionResponse, error) {
	// Fetch existing
	existing, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("Update: %w", err)
	}
	if existing == nil {
		return nil, fmt.Errorf("permission not found")
	}

	// Sanitize and validate display_name
	var displayName *string
	if req.DisplayName != nil {
		d := sanitizeString(*req.DisplayName)
		if d == "" {
			return nil, fmt.Errorf("display_name cannot be empty")
		}
		if len(d) > 255 {
			return nil, fmt.Errorf("display_name must be at most 255 characters")
		}
		displayName = &d
	}

	// Sanitize description
	var description *string
	if req.Description != nil {
		d := sanitizeString(*req.Description)
		if len(d) > 2000 {
			return nil, fmt.Errorf("description must be at most 2000 characters")
		}
		description = &d
	}

	if err := s.permissionRepo.Update(ctx, id, displayName, description); err != nil {
		return nil, fmt.Errorf("Update: %w", err)
	}

	// Re-fetch updated permission
	updated, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("Update: re-fetch: %w", err)
	}

	// Audit log
	if s.auditService != nil && auditLog != nil {
		details := map[string]interface{}{
			"permission_name": existing.Name,
		}
		if displayName != nil {
			details["old_display_name"] = existing.DisplayName
			details["new_display_name"] = *displayName
		}
		if description != nil {
			details["description_updated"] = true
		}
		auditLog.Action = "permission_update"
		auditLog.ActionCategory = auditActionCategoryPermissionManagement
		auditLog.TargetResourceType = auditResourceTypePermission
		auditLog.TargetResourceID = &id
		auditLog.Details = details
		auditLog.Success = true
		if err := s.auditService.LogPlatformAction(ctx, auditLog); err != nil {
			logger.Error("Failed to log permission update audit", zap.Error(err))
		}
	}

	return updated.ToResponse(), nil
}

// Delete deletes a permission if it is not in use and not a system permission, with audit logging.
func (s *PermissionService) Delete(ctx context.Context, id uuid.UUID, auditLog *models.PlatformAuditLog) error {
	// Fetch for audit log details before deletion
	existing, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("permission not found")
	}

	if err := s.permissionRepo.DeleteIfNotInUse(ctx, id); err != nil {
		return fmt.Errorf("Delete: %w", err)
	}

	// Best-effort SpiceDB sync — non-blocking, errors are logged but do not
	// fail the delete operation.
	if s.spicedbSyncer != nil {
		if syncErr := s.spicedbSyncer.DeletePermissionGrant(ctx, existing.Name); syncErr != nil {
			logger.Warn("Failed to remove permission grant from SpiceDB (non-fatal)",
				zap.String("permission", existing.Name),
				zap.Error(syncErr),
			)
		}
	}

	// Audit log (severity: CRITICAL)
	if s.auditService != nil && auditLog != nil {
		auditLog.Action = "permission_delete"
		auditLog.ActionCategory = auditActionCategoryPermissionManagement
		auditLog.TargetResourceType = auditResourceTypePermission
		auditLog.TargetResourceID = &id
		auditLog.Details = map[string]interface{}{
			"name":         existing.Name,
			"module":       existing.Module,
			"resource":     existing.Resource,
			"action":       existing.Action,
			"display_name": existing.DisplayName,
			"severity":     "CRITICAL",
		}
		auditLog.Success = true
		if err := s.auditService.LogPlatformAction(ctx, auditLog); err != nil {
			logger.Error("Failed to log permission delete audit", zap.Error(err))
		}
	}

	return nil
}

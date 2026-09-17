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
}

// SetSpiceDBSyncer wires an optional SpiceDB sync callback. When set, Create() and
// Delete() will attempt to keep SpiceDB in sync after successful DB writes.
// Errors from the syncer are logged but never propagate to the caller.
func (s *PermissionService) SetSpiceDBSyncer(syncer SpiceDBPermSyncer) {
	s.spicedbSyncer = syncer
}

// SetModuleEntitlementChecker wires an optional module entitlement checker.
// When set, tenant-aware listing methods filter permissions to the modules the
// tenant is subscribed to. Errors from the checker are fail-open.
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

	return &models.RegisterModuleResponse{
		Module:      req.Module,
		Registered:  registered,
		Updated:     updated,
		Deprecated:  deprecated,
		Permissions: permResponses,
	}, nil
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
// Always includes "core" and "iam". Returns nil (no filtering) when the
// entitlement checker is not configured or on any error (fail-open).
func (s *PermissionService) getEntitledModules(ctx context.Context, tenantID uuid.UUID) []string {
	if s.entitlementChecker == nil {
		return nil
	}

	allModules, err := s.permissionRepo.GetModules(ctx)
	if err != nil {
		return nil // fail-open
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
			// Fail-open: include module if check errors
			entitled = append(entitled, module)
			seen[module] = true
			continue
		}
		if ok {
			entitled = append(entitled, module)
			seen[module] = true
		}
	}

	return entitled
}

// ListForTenant returns permissions filtered to the modules the tenant is subscribed to.
// Falls back to returning all permissions on error or when no entitlement checker is wired.
func (s *PermissionService) ListForTenant(ctx context.Context, tenantID uuid.UUID) (*models.PermissionListResponse, error) {
	modules := s.getEntitledModules(ctx, tenantID)
	if modules == nil {
		return s.List(ctx)
	}
	return s.ListByModules(ctx, modules)
}

// ListGroupedByModuleForTenant returns permissions grouped by module, filtered by
// the tenant's subscribed modules.
func (s *PermissionService) ListGroupedByModuleForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.PermissionsByModule, error) {
	modules := s.getEntitledModules(ctx, tenantID)
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
// Falls back to all modules when no entitlement checker is wired.
func (s *PermissionService) ListModulesForTenant(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	modules := s.getEntitledModules(ctx, tenantID)
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

// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// PermissionResolver provides permission resolution for v2 (SpiceDB-based) tokens.
// Unlike v1 tokens which store permissions in Redis session, v2 tokens resolve
// permissions directly from SpiceDB at check time.
type PermissionResolver struct {
	client *Client
}

// NewPermissionResolver creates a new permission resolver.
func NewPermissionResolver(client *Client) *PermissionResolver {
	return &PermissionResolver{
		client: client,
	}
}

// HasPermission checks if a user has a specific permission.
// Permission format: "module.action" (e.g., "crm.view", "accounting.create")
// or "resource:id.action" (e.g., "document:123.edit")
func (r *PermissionResolver) HasPermission(ctx context.Context, tenantID, userID uuid.UUID, permission string) (bool, error) {
	if r.client == nil {
		return false, fmt.Errorf("SpiceDB client not initialized")
	}

	// Parse permission string
	objectType, objectID, action := parsePermission(permission)

	return r.client.CheckPermission(ctx, tenantID, userID, objectType, objectID, action)
}

// HasAnyPermission checks if user has ANY of the specified permissions.
func (r *PermissionResolver) HasAnyPermission(ctx context.Context, tenantID, userID uuid.UUID, permissions []string) (bool, error) {
	for _, perm := range permissions {
		allowed, err := r.HasPermission(ctx, tenantID, userID, perm)
		if err != nil {
			continue // Try next permission on error
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

// HasAllPermissions checks if user has ALL of the specified permissions.
func (r *PermissionResolver) HasAllPermissions(ctx context.Context, tenantID, userID uuid.UUID, permissions []string) (bool, error) {
	for _, perm := range permissions {
		allowed, err := r.HasPermission(ctx, tenantID, userID, perm)
		if err != nil {
			return false, fmt.Errorf("HasAllPermissions: HasPermission failed: %w", err)
		}
		if !allowed {
			return false, nil
		}
	}
	return true, nil
}

// CanAccessResource checks if user can perform an action on a specific resource.
// This is the primary method for ReBAC (Relationship-Based Access Control).
func (r *PermissionResolver) CanAccessResource(ctx context.Context, tenantID, userID uuid.UUID, resourceType, resourceID, action string) (bool, error) {
	return r.client.CheckPermission(ctx, tenantID, userID, resourceType, resourceID, action)
}

// FilterAccessibleResources filters a list of resources to only those the user can access.
// Uses native CheckBulkPermissions API for a single gRPC call.
func (r *PermissionResolver) FilterAccessibleResources(ctx context.Context, tenantID, userID uuid.UUID, resourceType string, resourceIDs []string, action string) ([]string, error) {
	if len(resourceIDs) == 0 {
		return []string{}, nil
	}

	// Native bulk check — single gRPC call
	results, err := r.client.CheckBulkPermissions(ctx, tenantID, userID, resourceType, resourceIDs, action)
	if err != nil {
		return nil, fmt.Errorf("bulk permission check failed: %w", err)
	}

	// Filter to accessible resources
	var accessible []string
	for _, id := range resourceIDs {
		if results[id] {
			accessible = append(accessible, id)
		}
	}

	return accessible, nil
}

// GetEffectivePermissions returns the effective permissions a user has.
// Note: This is expensive as SpiceDB doesn't support "list all permissions" directly.
// Use sparingly, primarily for UI display purposes.
func (r *PermissionResolver) GetEffectivePermissions(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	// First, get user's roles from SpiceDB
	roles, err := r.client.LookupUserRoles(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup user roles: %w", err)
	}

	// For each role, we would need to expand permissions
	// This requires schema knowledge and is computationally expensive
	// In practice, permissions are checked on-demand, not listed

	// Return role-based pseudo-permissions
	var permissions []string
	for _, roleID := range roles {
		// Add role membership as a pseudo-permission
		permissions = append(permissions, fmt.Sprintf("role:%s", roleID))
	}

	return permissions, nil
}

// CheckModuleAccess verifies user can access a specific module.
func (r *PermissionResolver) CheckModuleAccess(ctx context.Context, tenantID, userID uuid.UUID, module string) (bool, error) {
	return r.client.CheckModulePermission(ctx, tenantID, userID, module, "access")
}

// CheckModuleAction verifies user can perform a specific action in a module.
func (r *PermissionResolver) CheckModuleAction(ctx context.Context, tenantID, userID uuid.UUID, module, action string) (bool, error) {
	return r.client.CheckModulePermission(ctx, tenantID, userID, module, action)
}

// parsePermission parses a permission string into object type, object ID, and action.
// Supported formats:
//   - "module:resource:action" -> objectType="access_grant", objectID=PermissionToSpiceDBID(perm), action="check"
//   - "module.action"          -> objectType="module_module", objectID="default", action=action
//   - "resource:id.action"     -> objectType=resource, objectID=id, action=action
//   - "resource.action"        -> objectType=resource, objectID="default", action=action
func parsePermission(permission string) (objectType, objectID, action string) {
	// Handle module:resource:action format (IAM permission convention)
	// e.g. "crm:contacts:read" has exactly 3 colon-separated parts
	parts := strings.Split(permission, ":")
	if len(parts) == 3 {
		objectType = "access_grant"
		objectID = PermissionToSpiceDBID(permission)
		action = "check"
		return objectType, objectID, action
	}

	// Check for resource:id.action format (exactly 2 colon-separated parts with dot in remainder)
	if colonIdx := strings.Index(permission, ":"); colonIdx > 0 {
		resourcePart := permission[:colonIdx]
		remainder := permission[colonIdx+1:]

		if dotIdx := strings.LastIndex(remainder, "."); dotIdx > 0 {
			objectType = resourcePart
			objectID = remainder[:dotIdx]
			action = remainder[dotIdx+1:]
			return objectType, objectID, action
		}
	}

	// Check for module.action format
	if dotIdx := strings.LastIndex(permission, "."); dotIdx > 0 {
		modulePart := permission[:dotIdx]
		actionPart := permission[dotIdx+1:]

		// Determine if this is a module permission or general permission
		if isModuleName(modulePart) {
			objectType = fmt.Sprintf("%s_module", modulePart)
			objectID = spicedbObjectDefault
			action = actionPart
		} else {
			objectType = modulePart
			objectID = spicedbObjectDefault
			action = actionPart
		}
		return objectType, objectID, action
	}

	// Fallback: treat as action on tenant
	objectType = spicedbObjectTypeTenant
	objectID = spicedbObjectDefault
	action = permission
	return objectType, objectID, action
}

// matchWildcard reports whether target matches pattern.
//
// Supported patterns:
//   - "*"    — matches any string
//   - "x.*"  — matches any string that starts with the prefix "x." (module wildcard)
//   - exact  — literal equality check
func matchWildcard(pattern, target string) bool {
	if pattern == "*" {
		return true
	}

	// Module wildcard: "crm.*" matches "crm.view", "crm.edit", etc.
	if len(pattern) > 2 && pattern[len(pattern)-2:] == ".*" {
		prefix := pattern[:len(pattern)-1] // retain the trailing dot, e.g. "crm."
		return len(target) >= len(prefix) && target[:len(prefix)] == prefix
	}

	return pattern == target
}

// moduleRegistry holds the set of known module names for parsePermission.
// It is initialised with the built-in module list and can be extended at
// runtime via RegisterModules (GAP 6).
//
// Access is intentionally not guarded by a mutex: RegisterModules is designed
// to be called once at startup (before the HTTP server begins serving), so
// concurrent writes during normal operation do not occur.  If you need to
// register modules after startup in tests, use setModuleRegistry / cloneModuleRegistry.
var moduleRegistry = map[string]bool{
	// Business modules
	"crm":        true,
	"hr":         true,
	"accounting": true,
	"inventory":  true,
	"invoicing":  true,
	"pm":         true,
	"marketing":  true,

	// SAP-style modules
	"ppscm": true, // Production Planning & Supply Chain Management
	"sd":    true, // Sales & Distribution
	"fico":  true, // Financial Accounting & Controlling
	"mm":    true, // Materials Management
	"qms":   true, // Quality Management System
	"plm":   true, // Product Lifecycle Management
	"cmms":  true, // Computerized Maintenance Management System

	// Platform modules
	"cms":            true, // Content Management System
	"helpdesk":       true,
	"documents":      true,
	"workflow":       true,
	"custom_objects": true,
	"reporting":      true,
	"ecommerce":      true,

	// System modules
	"settings": true,
	"admin":    true,
}

// RegisterModules adds module names to the active registry.
// Call this at service startup after loading module definitions from the
// database so that dynamically-provisioned modules are recognised by
// parsePermission when the "module.action" permission format is used.
//
// Names are lowercased before insertion — lookups via isModuleName are also
// case-insensitive, so "MyModule" and "mymodule" resolve to the same entry.
//
// Note: for the canonical "module:resource:action" permission format
// (e.g. "crm:contacts:read") isModuleName is NOT invoked — that path uses
// the access_grant SpiceDB object type directly.  RegisterModules only
// affects the legacy "module.action" dot-format path.
func RegisterModules(names []string) {
	for _, n := range names {
		moduleRegistry[strings.ToLower(n)] = true
	}
}

// setModuleRegistry replaces the active registry wholesale.
// Intended for use in tests only (via cloneModuleRegistry + defer).
func setModuleRegistry(r map[string]bool) {
	moduleRegistry = r
}

// cloneModuleRegistry returns a shallow copy of the active registry.
// Intended for use in tests only, to save/restore state around a test run.
func cloneModuleRegistry() map[string]bool {
	clone := make(map[string]bool, len(moduleRegistry))
	for k, v := range moduleRegistry {
		clone[k] = v
	}
	return clone
}

// isModuleName checks if a string is a known module name using the dynamic
// registry.  Add entries via RegisterModules at startup.
func isModuleName(name string) bool {
	return moduleRegistry[strings.ToLower(name)]
}

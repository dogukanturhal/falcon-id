// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// PermissionGrantBoundaryErrorCode identifies the specific ADR-A10 permission
// boundary violation a grant attempt tripped. These codes are surfaced
// byte-for-byte in the HTTP error body (`{"error": "...", "code": "..."}"`)
// so BFF/UI callers can render the right message without string-matching
// on prose.
type PermissionGrantBoundaryErrorCode string

const (
	// CodeEntitlementMissingForModule is returned when a permission's
	// module is not part of the tenant's entitled module set (17-module-
	// account.md §12.2 "resource set" / 23-authorization-rbac-abac-rebac.md
	// §3.2's server-side write-time guard).
	CodeEntitlementMissingForModule PermissionGrantBoundaryErrorCode = "entitlement_missing_for_module"

	// CodePlatformRoleRequiresInternalTenant is returned when a caller
	// attempts to grant a platform-scoped permission (module "platform")
	// to a role outside the exampletenant tenant
	// (00000000-0000-0000-0000-000000000002).
	CodePlatformRoleRequiresInternalTenant PermissionGrantBoundaryErrorCode = "platform_role_requires_internal_tenant"
)

// PermissionGrantBoundaryError is a sentinel error type carrying the ADR-A10
// error code alongside a human-readable message. Handlers use
// errors.As to map it to the correct HTTP status/body without the service
// layer importing net/http.
type PermissionGrantBoundaryError struct {
	Code    PermissionGrantBoundaryErrorCode
	Message string
}

func (e *PermissionGrantBoundaryError) Error() string {
	return e.Message
}

// newEntitlementMissingError builds the entitlement_missing_for_module error
// for the given module.
func newEntitlementMissingError(module string) *PermissionGrantBoundaryError {
	return &PermissionGrantBoundaryError{
		Code:    CodeEntitlementMissingForModule,
		Message: fmt.Sprintf("tenant is not entitled to module %q; grant refused", module),
	}
}

// newPlatformBoundaryError builds the platform_role_requires_internal_tenant
// error.
func newPlatformBoundaryError() *PermissionGrantBoundaryError {
	return &PermissionGrantBoundaryError{
		Code:    CodePlatformRoleRequiresInternalTenant,
		Message: "platform-scoped permissions can only be granted within the exampletenant tenant",
	}
}

// hexxlockInternalTenantID is the parsed form of
// models.HexxlockInternalTenantID, computed once.
var hexxlockInternalTenantID = uuid.MustParse(models.HexxlockInternalTenantID)

// platformModuleName is the reserved module name for platform-scoped
// permissions (e.g. "platform:applications:read"), per
// 17-module-account.md §12.2's three-planes model: only the
// exampletenant tenant may hold any `platform:*` permission.
const platformModuleName = "platform"

// CheckPermissionGrantBoundary is the ADR-A10 write-time permission
// boundary guard (17-module-account.md §12.2, 23-authorization-rbac-abac-
// rebac.md §3.2/§12.2). It must be called before ANY write that grants a
// permission to a role, regardless of which HTTP surface the write comes
// through (internal service-to-service grant-permission action, or the
// tenant-admin AssignPermissions/PUT permissions replace path).
//
// Two checks, in order:
//  1. Platform-scope boundary: a permission whose module is "platform" may
//     only be granted to a role that belongs to the exampletenant
//     tenant (00000000-0000-0000-0000-000000000002). Any other tenant gets
//     platform_role_requires_internal_tenant, independent of entitlement
//     state — a tenant can never "buy" the platform module.
//  2. Entitlement boundary: for any other module, the granting tenant must
//     be entitled to that module (UniversalModules "core"/"iam" are always
//     entitled). This delegates to RoleService.EntitledModules, which is
//     already fail-closed: when no ModuleEntitlementChecker is wired
//     (e.g. the r1-entitlements work hasn't merged yet), only "core"/"iam"
//     are considered entitled, so every other module's grant is refused
//     rather than silently allowed.
func (s *RoleService) CheckPermissionGrantBoundary(ctx context.Context, tenantID uuid.UUID, permission *models.Permission) error {
	if permission == nil {
		return errors.New("CheckPermissionGrantBoundary: nil permission")
	}

	if permission.Module == platformModuleName {
		if tenantID != hexxlockInternalTenantID {
			return newPlatformBoundaryError()
		}
		// Platform permissions granted within the internal tenant are not
		// subject to the module-entitlement check below — the internal
		// tenant does not "buy" its own platform module.
		return nil
	}

	entitledModules, err := s.EntitledModules(ctx, tenantID)
	if err != nil {
		// Fail closed: an entitlement lookup failure must never be
		// interpreted as "entitled".
		return fmt.Errorf("CheckPermissionGrantBoundary: entitlement lookup failed: %w", err)
	}

	for _, m := range entitledModules {
		if m == permission.Module {
			return nil
		}
	}

	return newEntitlementMissingError(permission.Module)
}

// checkGrantBoundaryForIDs resolves each permission ID and applies
// CheckPermissionGrantBoundary to it, failing on the first violation.
func (s *RoleService) checkGrantBoundaryForIDs(ctx context.Context, tenantID uuid.UUID, permissionIDs []uuid.UUID) error {
	for _, pid := range permissionIDs {
		perm, err := s.permissionRepo.GetByID(ctx, pid)
		if err != nil {
			return fmt.Errorf("checkGrantBoundaryForIDs: resolve permission %s: %w", pid, err)
		}
		if perm == nil {
			return fmt.Errorf("checkGrantBoundaryForIDs: permission %s not found", pid)
		}
		if err := s.CheckPermissionGrantBoundary(ctx, tenantID, perm); err != nil {
			return err
		}
	}
	return nil
}

// GrantPermission additively grants a single permission to a role —
// the service-layer implementation backing
// POST /internal/v1/roles/{id}/actions/grant-permission. Unlike
// AssignPermissions (which replaces a role's entire permission set), this
// is purely additive: it never removes an existing grant, mirroring
// RoleRepository.GrantPermissionsByName's ON CONFLICT DO NOTHING semantics.
//
// The ADR-A10 boundary check runs before any write. sodService, when
// wired, is notified afterwards (warn-mode SoD is evaluated on every
// role-assignment write, per 23-authorization-rbac-abac-rebac.md §5.2) —
// a SoD failure is logged, never returned, since role-permission grants
// (unlike user-role assignments) do not yet carry a "target user" to
// evaluate against; SoD evaluation itself always runs against the
// affected role's members via RoleService callers that DO have a user
// (see sod_service.go).
func (s *RoleService) GrantPermission(ctx context.Context, roleID, permissionID uuid.UUID, grantedBy *uuid.UUID) (*models.Permission, error) {
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("GrantPermission: get role: %w", err)
	}
	if role == nil {
		return nil, fmt.Errorf("GrantPermission: role not found")
	}

	permission, err := s.permissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		return nil, fmt.Errorf("GrantPermission: resolve permission: %w", err)
	}
	if permission == nil {
		return nil, fmt.Errorf("GrantPermission: permission not found")
	}

	if err := s.guardAPIKeyRoleGrant(ctx, role, []uuid.UUID{permissionID}); err != nil {
		return nil, err
	}

	if grantedBy != nil {
		if err := s.checkCallerCoversPermissions(ctx, *grantedBy, role.TenantID, []uuid.UUID{permissionID}); err != nil {
			return nil, err
		}
	}

	if err := s.CheckPermissionGrantBoundary(ctx, role.TenantID, permission); err != nil {
		return nil, err
	}

	if err := s.roleRepo.GrantPermissionsByName(ctx, roleID, []string{permission.Name}); err != nil {
		return nil, fmt.Errorf("GrantPermission: %w", err)
	}

	return permission, nil
}

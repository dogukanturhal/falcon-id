// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// RoleAPIKeyUsage counts the active tenant API keys that act with a role.
type RoleAPIKeyUsage interface {
	CountActiveTenantKeysByRole(ctx context.Context, tenantID, roleID uuid.UUID) (int, error)
}

// RoleUsedByAPIKeysError is returned when a permission that API keys may never
// hold would be added to a role that active API keys already use. The forbidden
// filter otherwise runs only at key creation, so the grant is refused (never
// silently stripped); the operator must revoke the keys first.
type RoleUsedByAPIKeysError struct {
	Permission string
	KeyCount   int
}

func (e *RoleUsedByAPIKeysError) Error() string {
	return fmt.Sprintf("permission %s cannot be granted to this role: %d active API key(s) use it; revoke them first",
		e.Permission, e.KeyCount)
}

// SetAPIKeyRoleUsage wires the active-key lookup. Nil disables the guard
// (developer API keys flag off).
func (s *RoleService) SetAPIKeyRoleUsage(u RoleAPIKeyUsage) {
	s.apiKeyUsage = u
}

// guardAPIKeyRoleGrant refuses adding an API-key-forbidden permission to a role
// that an active API key holds. Only permissions the role does not already have
// count as additions.
func (s *RoleService) guardAPIKeyRoleGrant(ctx context.Context, role *models.Role, permissionIDs []uuid.UUID) error {
	if s.apiKeyUsage == nil || len(permissionIDs) == 0 {
		return nil
	}
	names, err := s.permissionRepo.GetPermissionNamesByIDs(ctx, permissionIDs)
	if err != nil {
		return fmt.Errorf("resolve permission names: %w", err)
	}
	current, err := s.roleRepo.GetRolePermissions(ctx, role.ID)
	if err != nil {
		return fmt.Errorf("load role permissions: %w", err)
	}
	have := make(map[string]struct{}, len(current))
	for _, p := range current {
		have[p.Name] = struct{}{}
	}
	forbidden := ""
	for _, id := range permissionIDs {
		name := names[id]
		if _, held := have[name]; held || !PermissionForbiddenForAPIKey(name) {
			continue
		}
		forbidden = name
		break
	}
	if forbidden == "" {
		return nil
	}
	n, err := s.apiKeyUsage.CountActiveTenantKeysByRole(ctx, role.TenantID, role.ID)
	if err != nil {
		return fmt.Errorf("count API keys using role: %w", err)
	}
	if n > 0 {
		return &RoleUsedByAPIKeysError{Permission: forbidden, KeyCount: n}
	}
	return nil
}

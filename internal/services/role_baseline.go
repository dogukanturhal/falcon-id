// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// withBaselinePermissions returns names plus acmeappBaselinePermissions,
// de-duplicated, in a stable order. Every role-provisioning path (AcmeApp
// catalog roles and module role templates) grants through it so the shell
// baseline lives in one place.
func withBaselinePermissions(names []string) []string {
	out := make([]string, 0, len(names)+len(acmeappBaselinePermissions))
	for _, list := range [][]string{names, acmeappBaselinePermissions} {
		for _, name := range list {
			if !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	return out
}

// rolePermissionReader reads a role's currently granted permissions.
type rolePermissionReader interface {
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error)
}

// missingRolePermissions returns the names the role does not hold yet.
func missingRolePermissions(ctx context.Context, repo rolePermissionReader, roleID uuid.UUID, names []string) ([]string, error) {
	held, err := repo.GetRolePermissions(ctx, roleID)
	if err != nil {
		return nil, err
	}
	have := make(map[string]bool, len(held))
	for _, perm := range held {
		have[perm.Name] = true
	}
	var missing []string
	for _, n := range names {
		if !have[n] {
			missing = append(missing, n)
		}
	}
	return missing, nil
}

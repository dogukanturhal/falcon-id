// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authorization contains role contracts shared by request middleware
// and persistence invariants. It intentionally depends on no application layer.
package authorization

import "strings"

const OrgAdminRoleName = "org_admin"

var tenantAdministratorRoleNames = []string{
	"admin",
	OrgAdminRoleName,
	"owner",
	"platform_admin",
	"super_admin",
}

// TenantAdministratorRoleNames returns normalized names suitable for SQL
// lower(name) comparisons. Callers cannot mutate the canonical set.
func TenantAdministratorRoleNames() []string {
	return append([]string(nil), tenantAdministratorRoleNames...)
}

// IsTenantAdministratorRole uses the same case-insensitive semantics as role
// middleware. iam_admin and priority alone intentionally confer no access.
func IsTenantAdministratorRole(name string) bool {
	for _, role := range tenantAdministratorRoleNames {
		if strings.EqualFold(name, role) {
			return true
		}
	}
	return false
}

// IsTenantScopedAdministratorRole is used after the verified platform-admin
// bypass. A bare platform_admin role must not bypass tenant scoping.
func IsTenantScopedAdministratorRole(name string) bool {
	return !strings.EqualFold(name, "platform_admin") && IsTenantAdministratorRole(name)
}

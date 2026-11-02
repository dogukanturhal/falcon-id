// SPDX-License-Identifier: AGPL-3.0-or-later

package authorization

import "strings"

// Tenant role ranks, highest wins. Mirrors the existing role vocabulary in
// tenantAdministratorRoleNames: owner > admin / org_admin > any other role.
const (
	rankNone     = 0
	rankMember   = 1
	rankAdmin    = 2
	rankOwner    = 3
	rankPlatform = 4
)

// TenantRoleRank returns the highest rank among the given role names.
func TenantRoleRank(roleNames []string) int {
	best := rankNone
	for _, n := range roleNames {
		r := rankMember
		switch strings.ToLower(strings.TrimSpace(n)) {
		case "":
			continue
		case "owner":
			r = rankOwner
		case "admin", OrgAdminRoleName:
			r = rankAdmin
		case "platform_admin", "super_admin":
			r = rankPlatform
		}
		if r > best {
			best = r
		}
	}
	return best
}

// CanActOnRank reports whether an actor may take a destructive credential
// action (e.g. remove MFA) against a target: the actor must strictly outrank
// the target.
func CanActOnRank(actorRoles, targetRoles []string) bool {
	return TenantRoleRank(actorRoles) > TenantRoleRank(targetRoles)
}

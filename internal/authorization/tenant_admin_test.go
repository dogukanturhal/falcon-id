// SPDX-License-Identifier: AGPL-3.0-or-later

package authorization

import "testing"

func TestTenantAdministratorRoleNamesAreExact(t *testing.T) {
	for _, name := range []string{"admin", "org_admin", "owner", "platform_admin", "super_admin", "OWNER"} {
		if !IsTenantAdministratorRole(name) {
			t.Errorf("expected %q to be a tenant administrator role", name)
		}
	}
	for _, name := range []string{"iam_admin", "billing_admin", "administrator", "member"} {
		if IsTenantAdministratorRole(name) {
			t.Errorf("did not expect %q to be a tenant administrator role", name)
		}
	}
}

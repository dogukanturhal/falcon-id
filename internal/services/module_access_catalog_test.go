// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/authorization"
)

func TestModuleAccessCatalog_AllElevenCodesPresent(t *testing.T) {
	codes := []string{"pre_accounting", "sales", "inventory", "production", "quality_maintenance", "projects", "payroll", "hr", "accounting", "crm", "marketing"}
	for _, c := range codes {
		assert.NotEmpty(t, EntitlementPermissionModules[c], c)
		assert.NotEmpty(t, EntitlementOwnerTemplateKeys[c], c)
	}
	assert.Len(t, EntitlementPermissionModules, len(codes))
	assert.Len(t, EntitlementOwnerTemplateKeys, len(codes))
}

func TestModuleAccessCatalog_OwnerKeysBelongToCodeModules(t *testing.T) {
	for code, keys := range EntitlementOwnerTemplateKeys {
		for _, k := range keys {
			assert.Contains(t, EntitlementPermissionModules[code], templateKeyModule(k), "code %s key %s", code, k)
		}
	}
}

func TestModuleAccessCatalog_ReverseIndexConsistent(t *testing.T) {
	for code, mods := range EntitlementPermissionModules {
		for _, m := range mods {
			assert.Contains(t, EntitlementCodesForPermissionModule(m), code)
		}
	}
	assert.ElementsMatch(t, []string{"inventory"}, EntitlementCodesForPermissionModule("inventory"))
	assert.ElementsMatch(t, []string{"inventory"}, EntitlementCodesForPermissionModule("mm"))
	assert.Equal(t, []string{"qms", "cmms"}, PermissionModulesForEntitlement("quality_maintenance"))
	assert.Nil(t, EntitlementCodesForPermissionModule("nope"))
	require.Nil(t, PermissionModulesForEntitlement("nope"))
}

func TestModuleAccessCatalog_NoOwnerKeyIsTenantAdminName(t *testing.T) {
	for _, keys := range EntitlementOwnerTemplateKeys {
		for _, k := range keys {
			assert.False(t, authorization.IsTenantAdministratorRole(templateRoleName(k)), k)
		}
	}
}

func TestModuleAccessCatalog_PreAccountingOwnersGetManager(t *testing.T) {
	assert.Equal(t, []string{"preaccounting:manager"}, EntitlementOwnerTemplateKeys["pre_accounting"])
}

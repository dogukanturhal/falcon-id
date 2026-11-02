// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import "strings"

// EntitlementPermissionModules maps a business entitlement code (the
// module_code of iam_tenant_module_entitlements) to the IAM permission
// modules (the "<module>:" prefix of iam_permissions / iam_role_templates)
// it unlocks. Mirrors the business API's
// ModuleEntitlementMiddlewareOptions.SegmentEntitlementCodes; "projects" is
// registered by PmModule (legacy IModule.Id "pm"), so both prefixes map to it.
var EntitlementPermissionModules = map[string][]string{
	"pre_accounting":      {"preaccounting"},
	"sales":               {"sd"},
	"inventory":           {"inventory", "mm"},
	"production":          {"ppscm", "plm"},
	"quality_maintenance": {"qms", "cmms"},
	"projects":            {"projects", "pm"},
	"payroll":             {"payroll"},
	"hr":                  {"hr"},
	"accounting":          {"accounting"},
	"crm":                 {"crm"},
	"marketing":           {"marketing"},
}

// EntitlementOwnerTemplateKeys names, per entitlement code, the role
// templates whose tenant roles are granted to the tenant's "owner" holders
// when the module becomes entitled (the module's "admin" roles).
var EntitlementOwnerTemplateKeys = map[string][]string{
	"marketing":           {"marketing:admin"},
	"crm":                 {"crm:admin"},
	"pre_accounting":      {"preaccounting:manager"},
	"accounting":          {"accounting:manager"},
	"inventory":           {"inventory:admin", "mm:purchasing_officer"},
	"sales":               {"sd:manager"},
	"hr":                  {"hr:hr_manager", "hr:settings_admin"},
	"payroll":             {"payroll:specialist", "payroll:approver"},
	"production":          {"ppscm:production_manager"},
	"quality_maintenance": {"qms:quality_manager", "cmms:maintenance_manager"},
	"projects":            {"projects:project_admin"},
}

// DefaultAdminPermissionModules declares the entitlement-scoped catalog
// permissions held by the canonical AcmeApp "admin" role. It intentionally
// names modules, never wildcard role names: only active HR entitlements can
// grant this access, and tenant-custom or platform-admin roles are excluded.
var DefaultAdminPermissionModules = map[string][]string{
	"hr": {"hr"},
}

// entitlementCodesByPermissionModule is the reverse index of
// EntitlementPermissionModules.
var entitlementCodesByPermissionModule = map[string][]string{}

func init() {
	for code, mods := range EntitlementPermissionModules {
		for _, m := range mods {
			entitlementCodesByPermissionModule[m] = append(entitlementCodesByPermissionModule[m], code)
		}
	}
}

// PermissionModulesForEntitlement returns the permission modules an
// entitlement code unlocks (nil for an unknown code).
func PermissionModulesForEntitlement(code string) []string {
	return append([]string(nil), EntitlementPermissionModules[code]...)
}

// EntitlementCodesForPermissionModule returns the entitlement codes that
// unlock a permission module (nil for an unknown module).
func EntitlementCodesForPermissionModule(module string) []string {
	return append([]string(nil), entitlementCodesByPermissionModule[module]...)
}

// templateKeyModule returns the "<module>" prefix of a template key.
func templateKeyModule(key string) string {
	if i := strings.IndexByte(key, ':'); i > 0 {
		return key[:i]
	}
	return key
}

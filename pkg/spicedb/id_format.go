// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import "strings"

// PermissionToSpiceDBID translates an IAM permission name containing colons
// into a SpiceDB-safe ObjectId.
//
// SpiceDB ObjectId regex: ^(([a-zA-Z0-9/_|\-=+]{1,})|\*)$
// Colons are NOT allowed, so we replace them with double underscores.
// Double underscore avoids collision with single underscores that appear
// in action names (e.g., "reset_password", "bulk_operations").
//
// Examples:
//
//	"crm:contacts:read"  -> "crm__contacts__read"
//	"billing"            -> "billing"  (passthrough, no colons)
func PermissionToSpiceDBID(permission string) string {
	return strings.ReplaceAll(permission, ":", "__")
}

// IDToPermission reverses the translation performed by PermissionToSpiceDBID.
//
// Examples:
//
//	"crm__contacts__read" -> "crm:contacts:read"
//	"billing"             -> "billing"  (passthrough)
func IDToPermission(spicedbID string) string {
	return strings.ReplaceAll(spicedbID, "__", ":")
}

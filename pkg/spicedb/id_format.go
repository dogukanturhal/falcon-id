// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"fmt"
	"regexp"
	"strings"
)

// objectIDPattern is SpiceDB's ObjectId charset minus the lone-"*" alternative:
// a permission name must never become the wildcard object id.
var objectIDPattern = regexp.MustCompile(`^[a-zA-Z0-9/_|\-=+]{1,}$`)

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

// PermissionToSpiceDBIDChecked is PermissionToSpiceDBID plus validation against
// the SpiceDB ObjectId regex. Write paths must use it so a name that cannot be
// an object id (e.g. an unexpanded wildcard "core:parties:*") fails loudly
// instead of reaching SpiceDB as an InvalidArgument.
func PermissionToSpiceDBIDChecked(permission string) (string, error) {
	id := PermissionToSpiceDBID(permission)
	if !objectIDPattern.MatchString(id) {
		return "", fmt.Errorf("permission %q maps to invalid SpiceDB object id %q", permission, id)
	}
	return id, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"strings"
)

// PermissionCatalog supplies the authoritative set of concrete (non-wildcard)
// permission names that wildcard grants are expanded against.
type PermissionCatalog interface {
	ListConcreteNames(ctx context.Context) ([]string, error)
}

func isWildcardPermission(name string) bool {
	return strings.Contains(name, "*")
}

// expandPermissionPatterns resolves wildcard permission names against the
// concrete catalog. SpiceDB holds one access_grant object per concrete
// permission and the check path never looks for a wildcard object, so a
// wildcard grant is only effective as the set of concrete grants it covers.
//
// Concrete names pass through unchanged. The only supported wildcard form is
// "module:resource:*": exactly three colon segments, last segment exactly "*",
// no other "*". Output is de-duplicated in first-seen order.
//
// Wildcards that match nothing are returned in unmatched and must not be
// written. Module-level "module:*:*" rows (registered for every module and held
// by every owner) are not expandable and are returned in moduleLevel so callers
// can keep them out of the per-role warning. Anything else malformed
// ("core:*", "core:parties:re*", "cor*") lands in unmatched.
func expandPermissionPatterns(names, catalog []string) (concrete, unmatched, moduleLevel []string) {
	seen := make(map[string]struct{}, len(names))
	add := func(n string) {
		if _, dup := seen[n]; dup {
			return
		}
		seen[n] = struct{}{}
		concrete = append(concrete, n)
	}
	for _, name := range names {
		if !isWildcardPermission(name) {
			add(name)
			continue
		}
		parts := strings.Split(name, ":")
		if len(parts) == 3 && parts[0] != "" && !strings.Contains(parts[0], "*") && parts[1] == "*" && parts[2] == "*" {
			moduleLevel = append(moduleLevel, name)
			continue
		}
		if len(parts) != 3 || parts[2] != "*" || strings.Count(name, "*") != 1 {
			unmatched = append(unmatched, name)
			continue
		}
		prefix := name[:len(name)-1]
		matched := false
		for _, c := range catalog {
			if strings.HasPrefix(c, prefix) {
				add(c)
				matched = true
			}
		}
		if !matched {
			unmatched = append(unmatched, name)
		}
	}
	return concrete, unmatched, moduleLevel
}

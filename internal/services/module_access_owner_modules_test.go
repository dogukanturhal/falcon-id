// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"slices"
	"testing"
)

func TestOwnerPermissionModules_AddsBaseModulesOnce(t *testing.T) {
	got := ownerPermissionModules([]string{"inventory", "mm"})
	if !slices.Equal(got, []string{"inventory", "mm", "core", "jobs"}) {
		t.Fatalf("got %v", got)
	}
	if got := ownerPermissionModules([]string{"core", "crm", "jobs"}); !slices.Equal(got, []string{"core", "crm", "jobs"}) {
		t.Fatalf("base module duplicated: %v", got)
	}
	in := []string{"hr"}
	_ = ownerPermissionModules(in)
	if !slices.Equal(in, []string{"hr"}) {
		t.Fatalf("input mutated: %v", in)
	}
}

// business gates /api/v1/plm under the production entitlement
// (ModuleEntitlementMiddlewareOptions), so its owner must receive plm too.
func TestPermissionModulesForEntitlement_ProductionIncludesPLM(t *testing.T) {
	if got := PermissionModulesForEntitlement("production"); !slices.Contains(got, "plm") {
		t.Fatalf("production modules %v lack plm", got)
	}
}

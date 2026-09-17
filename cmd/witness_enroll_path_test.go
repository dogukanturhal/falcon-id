// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
)

// TestWitnessEnrollPagePath_StaysInSyncWithHandlersExport pins the
// invariant that the local copy of the witness enrollment page path
// in cmd/routes_admin.go matches the canonical constant exported by
// the handlers package.
//
// Why two copies: the `handlers` identifier is taken as a function
// parameter name in registerOAuthRoutes (cmd/routes_admin.go), so
// `handlers.WitnessEnrollPagePath` would refer to a struct field,
// not the package constant. Rather than rename the param and touch
// every call site, the local const lives next to the route
// registration; this test catches drift.
func TestWitnessEnrollPagePath_StaysInSyncWithHandlersExport(t *testing.T) {
	if witnessEnrollPagePath != handlers.WitnessEnrollPagePath {
		t.Fatalf("witnessEnrollPagePath drift: cmd has %q, handlers package exports %q — both must agree so the Tauri wizard's deep-link target stays canonical",
			witnessEnrollPagePath, handlers.WitnessEnrollPagePath)
	}
}

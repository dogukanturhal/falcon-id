// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

// bootstrapPlatformRealm must not panic when the control-plane DB (and
// therefore repos.Realm) is not configured.
func TestBootstrapPlatformRealm_NilRealmRepo_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("bootstrapPlatformRealm panicked: %v", r)
		}
	}()
	bootstrapPlatformRealm(&Repositories{})
	bootstrapPlatformRealm(nil)
}

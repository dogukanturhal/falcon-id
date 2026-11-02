// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import "testing"

func TestIsKnownProduct_SlugAlias(t *testing.T) {
	for slug, want := range map[string]bool{"acmeweb": true, "acmeapp": true, "nope": false} {
		if got := IsKnownProduct(slug); got != want {
			t.Errorf("IsKnownProduct(%q)=%v want %v", slug, got, want)
		}
	}
}

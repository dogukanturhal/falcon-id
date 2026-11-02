// SPDX-License-Identifier: AGPL-3.0-or-later

package authorization

import "testing"

func TestCanActOnRank(t *testing.T) {
	cases := []struct {
		actor, target []string
		want          bool
	}{
		{[]string{"admin"}, []string{"owner"}, false},
		{[]string{"admin"}, []string{"admin"}, false},
		{[]string{"admin"}, []string{"org_admin"}, false},
		{[]string{"admin"}, []string{"member"}, true},
		{[]string{"owner"}, []string{"admin"}, true},
		{[]string{"owner"}, []string{"owner"}, false},
		{[]string{"Admin", "viewer"}, []string{"OWNER"}, false},
		{[]string{"admin"}, nil, true},
	}
	for _, c := range cases {
		if got := CanActOnRank(c.actor, c.target); got != c.want {
			t.Errorf("CanActOnRank(%v,%v)=%v want %v", c.actor, c.target, got, c.want)
		}
	}
}

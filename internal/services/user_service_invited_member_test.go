// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import "testing"

func TestSplitPersonName(t *testing.T) {
	cases := []struct{ in, first, last string }{
		{"Deniz Celik", "Deniz", "Celik"},
		{"  Ada   Lovelace King ", "Ada", "Lovelace King"},
		{"Cher", "Cher", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		first, last := splitPersonName(c.in)
		if first != c.first || last != c.last {
			t.Errorf("splitPersonName(%q) = (%q, %q), want (%q, %q)", c.in, first, last, c.first, c.last)
		}
	}
}

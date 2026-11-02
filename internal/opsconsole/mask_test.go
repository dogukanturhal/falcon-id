// SPDX-License-Identifier: AGPL-3.0-or-later

package opsconsole

import "testing"

func TestMasks(t *testing.T) {
	cases := []struct{ got, want string }{
		{MaskEmail("jane@dummy.com"), "j***@d***.com"},
		{MaskEmail("a@b.co.uk"), "a***@b***.uk"},
		{MaskEmail("noatsign"), "n***"},
		{MaskName("Jane Doe"), "J*** D***"},
		{MaskName(""), ""},
		{MaskPhone("+90 532 123 45 67"), "*******67"},
		{MaskPhone("7"), "*******"},
		{MaskUsername("jane@x.io"), "j***@x***.io"},
		{MaskUsername("jdoe"), "j***"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q want %q", c.got, c.want)
		}
	}
}

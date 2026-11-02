// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import "testing"

func TestIsPhishingResistantAMR(t *testing.T) {
	cases := map[string]struct {
		amr  []string
		want bool
	}{
		"passkey login":  {[]string{"hwk", "user", "mfa"}, true},
		"passkey stepup": {[]string{"pwd", "mfa", "hwk"}, true},
		"totp":           {[]string{"pwd", "otp", "mfa"}, false},
		"email otp":      {[]string{"pwd", "mfa"}, false},
		"sms":            {[]string{"pwd", "sms", "mfa"}, false},
		"password only":  {[]string{"pwd"}, false},
		"empty":          {nil, false},
	}
	for name, c := range cases {
		if got := IsPhishingResistantAMR(c.amr); got != c.want {
			t.Errorf("%s: got %v want %v", name, got, c.want)
		}
	}
}

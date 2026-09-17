// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"testing"
)

func TestValidateIANATimezone(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		tz      string
		wantErr bool
	}{
		{"UTC", "UTC", false},
		{"Europe/Istanbul", "Europe/Istanbul", false},
		{"America/New_York", "America/New_York", false},
		{"Asia/Tokyo", "Asia/Tokyo", false},
		{"empty string", "", true},
		{"garbage", "Not/ATimezone", true},
		{"trailing slash", "Europe/", true},
		{"Local alias", "Local", false}, // "Local" is accepted by time.LoadLocation
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateIANATimezone(tc.tz)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateIANATimezone(%q) error=%v, wantErr=%v", tc.tz, err, tc.wantErr)
			}
		})
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"fmt"
	"time"
)

// validateIANATimezone returns an error if tz is not a valid IANA timezone
// identifier recognised by the Go standard library's time.LoadLocation.
// An empty string is treated as invalid — callers should pass "UTC" explicitly.
func validateIANATimezone(tz string) error {
	if tz == "" {
		return fmt.Errorf("timezone must not be empty; use 'UTC' for the default")
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return fmt.Errorf("invalid IANA timezone %q: %w", tz, err)
	}
	return nil
}

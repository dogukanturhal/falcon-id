// SPDX-License-Identifier: AGPL-3.0-or-later

// Package crypto provides cryptographic utility functions.
package crypto

import (
	"crypto/subtle"
)

// SecureCompare performs constant-time string comparison.
// This prevents timing attacks when comparing secrets.
// Returns true if strings are equal, false otherwise.
func SecureCompare(a, b string) bool {
	// Convert to byte slices for constant-time comparison
	aBytes := []byte(a)
	bBytes := []byte(b)

	// subtle.ConstantTimeCompare requires equal length slices
	// If lengths differ, we still do a comparison to maintain constant time
	if len(aBytes) != len(bBytes) {
		// Compare against a dummy to maintain constant time
		// but always return false for length mismatch
		dummy := make([]byte, len(aBytes))
		subtle.ConstantTimeCompare(aBytes, dummy)
		return false
	}

	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}

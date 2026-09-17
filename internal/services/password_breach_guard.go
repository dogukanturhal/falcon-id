// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// breachChecker reports whether a plaintext password appears in a known
// public-breach corpus. pkg/hibp.Client satisfies it via the Have I Been
// Pwned k-anonymity range API (only the first 5 chars of the SHA-1 hash ever
// leave the process). Declared as a narrow interface so the password-set
// flows depend on a capability, not the concrete HIBP client, and so tests
// can substitute a deterministic checker.
type breachChecker interface {
	IsCompromised(ctx context.Context, password string) (bool, int, error)
}

// assertPasswordNotBreached rejects a password that appears in a known data
// breach (NIST SP 800-63B §5.1.1.2 / ASVS V6: "verifiers SHALL compare the
// prospective secret against a list of known compromised values").
//
// FAIL-OPEN on any HIBP error (timeout, outage, non-200): a transient failure
// of an external, best-effort enrichment service MUST NOT block a legitimate
// user from setting a password (availability). The gap is always logged so the
// SOC can see when breach-coverage is degraded. checker==nil (unwired: local /
// air-gapped / test) is likewise a silent no-op.
func assertPasswordNotBreached(ctx context.Context, checker breachChecker, password string) error {
	if checker == nil {
		return nil
	}
	breached, count, err := checker.IsCompromised(ctx, password)
	if err != nil {
		logger.Warn("HIBP breach check unavailable — failing open (password accepted, breach coverage degraded)",
			zap.Error(err))
		return nil
	}
	if breached {
		return fmt.Errorf("password appears in %d known data breaches; choose a password that has not been exposed", count)
	}
	return nil
}

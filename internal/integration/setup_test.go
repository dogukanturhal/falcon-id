// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"os"
	"testing"

	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// TestMain initializes the global logger and crypto primitives before any test
// runs.  The services package uses:
//   - pkg/logger.Info/Warn/Error — panics if Log is nil
//   - pkg/crypto.HashToken      — returns an error if InitDefaultTokenHasher
//     was not called (which the services treat as fatal in production but we
//     need to bootstrap in tests)
func TestMain(m *testing.M) {
	logger.InitLogger("debug", "test")

	// TokenHashSalt must be at least 16 hex-encoded bytes.
	// The value below matches testutil.NewTestConfig().TokenHashSalt.
	if err := crypto.InitDefaultTokenHasher("test-token-hash-salt"); err != nil {
		panic("failed to init token hasher: " + err.Error())
	}

	os.Exit(m.Run())
}

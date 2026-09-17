// SPDX-License-Identifier: AGPL-3.0-or-later

// Package migrations embeds bundled.lock — the record mapping each falcon-id
// SQL migration to the released Keystone bundle (or baseline) that applies it
// in production. Embedding makes the lock travel WITH the compiled binary, so
// the deploy-ordering gate (cmd/keystone-migration-gate) and the PR-time
// schema-gap test always evaluate the exact migration HEAD the image was built
// against, with no runtime filesystem dependency.
//
// The .sql migration files in this directory are NOT embedded here; they are
// read from the filesystem by the tenant provisioner and the CI checker. See
// internal/migrations/bundlelock for the lock file format + rationale.
package migrations

import (
	"bytes"
	_ "embed"

	"github.com/dogukanturhal/falcon-id/internal/migrations/bundlelock"
)

//go:embed bundled.lock
var bundledLock []byte

// BundledLock returns the raw embedded bundled.lock bytes.
func BundledLock() []byte {
	out := make([]byte, len(bundledLock))
	copy(out, bundledLock)
	return out
}

// LockEntries parses the embedded bundled.lock.
func LockEntries() ([]bundlelock.Entry, error) {
	return bundlelock.Parse(bytes.NewReader(bundledLock))
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations

import (
	"embed"
	"fmt"
	"io/fs"
)

// sqlFS embeds the canonical DDL of every applied migration so tests (notably
// the PR-time schema-gap test) can apply the REAL migration SQL — not a
// hand-copied approximation — when reconstructing the last-released schema.
//
//go:embed *.sql
var sqlFS embed.FS

// ReadSQL returns the bytes of the named migration file (basename), e.g.
// "0009_oauth_token_family.sql".
func ReadSQL(name string) ([]byte, error) {
	b, err := sqlFS.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("read embedded migration %q: %w", name, err)
	}
	return b, nil
}

// SQLFS returns the embedded migration filesystem (read-only).
func SQLFS() fs.FS { return sqlFS }

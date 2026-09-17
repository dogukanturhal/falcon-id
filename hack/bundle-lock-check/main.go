// SPDX-License-Identifier: AGPL-3.0-or-later

// Command bundle-lock-check is a build-time guard that makes it impossible to
// merge a falcon-id SQL migration without recording the released Keystone
// MigrationBundle (or baseline) that applies it to production.
//
// # The failure mode it closes (2026-07-21 P1 SSO outage)
//
// falcon-id migrations (internal/migrations/000N_*.sql) are applied in prod by
// the Keystone MigrationBundle operator in the SEPARATE the GitOps repository
// repo — NOT by pkg/database.Migrator. The a52ed36 merge added migration 0009
// (iam_oauth_tokens.token_family_id) and code that writes that column, but no
// bundle was ever rendered, so the column never got added and every
// /oauth/token exchange 400'd cluster-wide. Nothing in falcon-id's own CI could
// see the cross-repo gap.
//
// bundled.lock is the in-repo record of the migration<->bundle mapping. This
// checker enforces three invariants against it:
//
//  1. COVERAGE — every internal/migrations/000N_*.sql has a lock entry. A
//     migration file with no entry means someone added a migration without
//     rendering/recording its released bundle. This is the exact recurrence
//     guard for the outage.
//  2. NO STALE ENTRIES — every lock entry names a migration file that still
//     exists, so a deleted/renamed migration cannot leave a dangling claim.
//  3. NO CONTENT DRIFT — the lock's recorded SHA-256 matches the migration
//     file's current bytes. Editing a migration after its bundle was released
//     means the released bundle no longer reflects the file; the fix is to
//     render a NEW bundle and update the lock, not to silently mutate history.
//
// Run with `go run ./hack/bundle-lock-check`. Exits 0 on clean, non-zero with a
// structured report on any violation. Purely offline + deterministic (no
// network, no DB) so it is a fast, reliable pre-merge gate.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/dogukanturhal/falcon-id/internal/migrations/bundlelock"
)

// migrationFilePattern matches an applied migration filename, e.g.
// "0009_oauth_token_family.sql". Mirrors pkg/database.migrationFilePattern.
var migrationFilePattern = regexp.MustCompile(`^\d+_.+\.sql$`)

func main() {
	migrationsDir := "internal/migrations"
	if v := os.Getenv("FALCON_MIGRATIONS_DIR"); v != "" {
		migrationsDir = v
	}
	lockPath := filepath.Join(migrationsDir, "bundled.lock")

	problems, err := check(migrationsDir, lockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bundle-lock-check: %v\n", err)
		os.Exit(2)
	}
	if len(problems) > 0 {
		fmt.Fprintln(os.Stderr, "bundle-lock-check: FAILED")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Every internal/migrations/000N_*.sql migration MUST have a matching")
		fmt.Fprintln(os.Stderr, "entry in internal/migrations/bundled.lock recording the RELEASED Keystone")
		fmt.Fprintln(os.Stderr, "bundle (or 'baseline') that applies it in production. See the file header")
		fmt.Fprintln(os.Stderr, "and docs/adr/0001-keystone-migration-bundle-deploy-ordering.md.")
		fmt.Fprintln(os.Stderr, "")
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "  - %s\n", p)
		}
		os.Exit(1)
	}
	fmt.Printf("bundle-lock-check: OK — %s covers every migration in %s\n", lockPath, migrationsDir)
}

// check returns a sorted list of human-readable problems. A non-nil error is a
// structural failure (dir/lock unreadable) rather than a policy violation.
func check(migrationsDir, lockPath string) ([]string, error) {
	files, err := listMigrations(migrationsDir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no migration files found in %s", migrationsDir)
	}

	entries, err := bundlelock.Load(lockPath)
	if err != nil {
		return nil, err
	}
	byFile := bundlelock.ByFile(entries)

	var problems []string

	// (1) COVERAGE + (3) DRIFT: every migration file has an entry whose hash matches.
	for _, f := range files {
		e, ok := byFile[f]
		if !ok {
			problems = append(problems, fmt.Sprintf(
				"migration %q has NO bundled.lock entry — render + merge its Keystone bundle in "+
					"the GitOps repository, then add: %s  v0.232.NNN  <sha256>", f, f))
			continue
		}
		got, err := bundlelock.FileSHA256(filepath.Join(migrationsDir, f))
		if err != nil {
			return nil, err
		}
		if got != e.SHA256 {
			problems = append(problems, fmt.Sprintf(
				"migration %q content DRIFT — bundled.lock records sha256 %s but the file is now %s; "+
					"the released bundle %q no longer reflects this file. Render a new bundle + update the lock.",
				f, short(e.SHA256), short(got), e.Vehicle))
		}
	}

	// (2) NO STALE ENTRIES: every lock entry points at an existing migration.
	fileSet := make(map[string]struct{}, len(files))
	for _, f := range files {
		fileSet[f] = struct{}{}
	}
	for _, e := range entries {
		if _, ok := fileSet[e.File]; !ok {
			problems = append(problems, fmt.Sprintf(
				"bundled.lock references %q (vehicle %q) but that migration file does not exist — "+
					"remove the stale entry", e.File, e.Vehicle))
		}
	}

	sort.Strings(problems)
	return problems, nil
}

// listMigrations returns the basenames of every applied migration in dir.
func listMigrations(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir %s: %w", dir, err)
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if migrationFilePattern.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}

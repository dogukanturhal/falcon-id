// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bundlelock parses and validates internal/migrations/bundled.lock —
// the committed record that maps every falcon-id SQL migration
// (internal/migrations/000N_*.sql) to the vehicle that RELEASED its schema
// change to production.
//
// # Why this exists (2026-07-21 OAuth migration-gap P1 outage)
//
// falcon-id migrations are NOT applied by pkg/database.Migrator on the
// production databases. The authoritative applier is the Keystone
// MigrationBundle operator (GitOps via the separate the GitOps repository repo):
// each 000N_*.sql must be rendered into a MigrationBundle CR committed at
// platform/keystone/resources/falcon-id/migration-bundles/falcon-id-v0.232.NNN.yaml
// and applied by the operator BEFORE the falcon-id image that depends on the
// schema change rolls (the "deploy-ordering gate" in every bundle header).
//
// The a52ed36 merge shipped migration 0009 (iam_oauth_tokens.token_family_id)
// plus code writing that column but never rendered a bundle, so the column was
// never added and every /oauth/token exchange 400'd. Because the bundle lives
// in a SEPARATE repo, nothing in falcon-id's own CI could see the gap.
//
// bundled.lock closes that blind spot: it is the in-repo, reviewable source of
// truth for "which migration has a released bundle". The CI guardrail
// (hack/bundle-lock-check) fails when a migration file has no lock entry — the
// exact recurrence guard — and when a locked migration's content drifts from
// the hash recorded when it was bundled. The PR-time schema-gap test
// (Fix C) reads the same lock to build a database migrated only to the
// last-released bundle set.
//
// # File format
//
// Line-oriented, go.sum-style, so it stays diff-friendly and trivially
// reviewable:
//
//		# comment lines start with '#'
//		<migration-file>  <vehicle>  <sha256-hex>
//
//	  - <migration-file> is the basename, e.g. 0009_oauth_token_family.sql.
//	  - <vehicle> is either a released Keystone bundle version "vMAJOR.MINOR.PATCH"
//	    (e.g. v0.232.262) OR the literal "baseline" when the DDL was folded into
//	    the Keystone SchemaDefinition baseline (schema-definition-main.yaml) rather
//	    than shipped as a discrete versioned bundle.
//	  - <sha256-hex> is the lowercase hex SHA-256 of the migration file's bytes,
//	    recorded when the bundle was released, so post-release edits are caught.
package bundlelock

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// BaselineVehicle is the reserved vehicle token for a migration whose DDL was
// folded into the Keystone SchemaDefinition baseline instead of a discrete
// versioned MigrationBundle. Baselined migrations are always-released (the
// baseline is applied before any incremental bundle).
const BaselineVehicle = "baseline"

// versionRe matches a released Keystone bundle version, e.g. v0.232.262.
var versionRe = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// sha256Re matches a lowercase 64-char hex SHA-256 digest.
var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Entry is one parsed line of bundled.lock.
type Entry struct {
	// File is the migration filename (basename), e.g. 0009_oauth_token_family.sql.
	File string
	// Vehicle is the raw release vehicle: a bundle version ("v0.232.262") or
	// BaselineVehicle ("baseline").
	Vehicle string
	// SHA256 is the recorded lowercase-hex SHA-256 of the migration file bytes.
	SHA256 string
}

// IsBaseline reports whether this migration was released via the Keystone
// SchemaDefinition baseline rather than a versioned bundle.
func (e Entry) IsBaseline() bool { return e.Vehicle == BaselineVehicle }

// version returns the parsed (major, minor, patch) of a versioned-bundle entry.
// ok is false for baseline entries.
func (e Entry) version() (v [3]int, ok bool) {
	m := versionRe.FindStringSubmatch(e.Vehicle)
	if m == nil {
		return v, false
	}
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// Parse reads bundled.lock content and returns its entries in file order,
// validating the format. It rejects malformed lines, bad vehicles, bad
// digests, and duplicate migration filenames so a broken lock fails loudly
// rather than silently under-reporting the released set.
func Parse(r io.Reader) ([]Entry, error) {
	var entries []Entry
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("bundled.lock:%d: expected 3 fields <file> <vehicle> <sha256>, got %d: %q", lineNo, len(fields), line)
		}
		file, vehicle, digest := fields[0], fields[1], fields[2]
		if vehicle != BaselineVehicle && !versionRe.MatchString(vehicle) {
			return nil, fmt.Errorf("bundled.lock:%d: invalid vehicle %q (want %q or vMAJOR.MINOR.PATCH)", lineNo, vehicle, BaselineVehicle)
		}
		if !sha256Re.MatchString(digest) {
			return nil, fmt.Errorf("bundled.lock:%d: invalid sha256 %q (want 64 lowercase hex chars)", lineNo, digest)
		}
		if _, dup := seen[file]; dup {
			return nil, fmt.Errorf("bundled.lock:%d: duplicate entry for %q", lineNo, file)
		}
		seen[file] = struct{}{}
		entries = append(entries, Entry{File: file, Vehicle: vehicle, SHA256: digest})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read bundled.lock: %w", err)
	}
	return entries, nil
}

// Load reads and parses the lock file at path.
func Load(path string) ([]Entry, error) {
	f, err := os.Open(path) //nolint:gosec // path is a build-time constant / flag, not user input
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only handle
	return Parse(f)
}

// ByFile indexes entries by migration filename.
func ByFile(entries []Entry) map[string]Entry {
	m := make(map[string]Entry, len(entries))
	for _, e := range entries {
		m[e.File] = e
	}
	return m
}

// Head returns the highest released versioned-bundle entry (the schema HEAD the
// current code expects to be applied). Baseline entries are ignored for
// ordering. ok is false when the lock has no versioned bundles at all.
func Head(entries []Entry) (Entry, bool) {
	var best Entry
	var bestV [3]int
	found := false
	for _, e := range entries {
		v, ok := e.version()
		if !ok {
			continue
		}
		if !found || less(bestV, v) {
			best, bestV, found = e, v, true
		}
	}
	return best, found
}

// less reports whether version a sorts before version b.
func less(a, b [3]int) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// FileSHA256 returns the lowercase-hex SHA-256 of the file at path.
func FileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // path derived from the migrations dir listing
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum), nil
}

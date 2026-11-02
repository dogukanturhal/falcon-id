// SPDX-License-Identifier: AGPL-3.0-or-later

// Command keystone-migration-gate is the fail-closed, falcon-id-owned half of
// the deploy-ordering gate for the 2026-07-21 OAuth migration-gap remediation.
//
// # What it enforces
//
// The falcon-id image's schema HEAD is the highest released Keystone bundle
// version recorded in internal/migrations/bundled.lock. In production those
// bundles are applied by the Keystone MigrationBundle operator, which records
// each applied version in the per-database keystone_schema_migrations tracking
// table. The deploy-ordering rule in every bundle header is: apply the bundle
// FIRST, verify, THEN roll the code. If the code rolls before its schema bundle
// is applied, every request that touches the new column fails (exactly the
// token_family_id outage: /oauth/token returned 0x200, all 400).
//
// This binary connects to the target database and asserts that the HEAD bundle
// version from bundled.lock IS present in keystone_schema_migrations. It exits:
//
//	0  — HEAD bundle is applied (or the lock has only baseline entries, so there
//	     is no versioned bundle to gate on). Safe to roll the code.
//	1  — HEAD bundle is NOT applied. Schema is behind code — FAIL CLOSED.
//	2  — usage / connectivity / configuration error.
//
// # Where it runs
//
// It is designed to be invoked from an Argo PreSync hook Job (or a Deployment
// initContainer) in the GitOps repository so the falcon-id workload cannot become
// Healthy until its schema is caught up. Wiring that hook lives in
// the GitOps repository / <gitops-bootstrap-repo> and is out of this repo's scope — see
// docs/adr/0001-keystone-migration-bundle-deploy-ordering.md. Shipping the check
// in the falcon-id image guarantees the gate uses the SAME HEAD-bundle
// definition the code was built against.
//
// The query uses the official keystone-sdk migration.Runner.IsApplied so the
// tracking-table contract stays owned by Keystone, not reimplemented here.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	kmig "github.com/dogukanturhal/keystone-sdk/go/migration"

	"github.com/dogukanturhal/falcon-id/internal/migrations"
	"github.com/dogukanturhal/falcon-id/internal/migrations/bundlelock"
	"github.com/dogukanturhal/falcon-id/pkg/database"
)

func main() {
	var (
		lockPath      string
		schema        string
		trackingTable string
		timeout       time.Duration
	)
	flag.StringVar(&lockPath, "lock", "", "Override bundled.lock path (default: the copy embedded in this binary)")
	flag.StringVar(&schema, "schema", "public", "PostgreSQL schema holding the Keystone tracking table")
	flag.StringVar(&trackingTable, "tracking-table", "keystone_schema_migrations", "Keystone migration tracking table name")
	flag.DurationVar(&timeout, "timeout", 15*time.Second, "Overall DB timeout")
	flag.Parse()

	// Default to the lock embedded at build time so the gate reflects the exact
	// migration HEAD this image was compiled against; --lock overrides for tests.
	entries, err := loadLock(lockPath)
	if err != nil {
		fatal("load lock: %v", err)
	}
	head, ok := bundlelock.Head(entries)
	if !ok {
		// No versioned bundle recorded — only baseline migrations, which the
		// SchemaDefinition baseline applies before any incremental. Nothing to
		// gate on.
		fmt.Println("keystone-migration-gate: no versioned bundle in lock (baseline only) — nothing to gate; OK")
		return
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		fatal("DATABASE_URL environment variable is required")
	}

	db, err := database.NewPostgresDB(databaseURL)
	if err != nil {
		fatal("connect to database: %v", err)
	}
	defer db.Close()

	runner, err := kmig.NewRunner(db.Pool, schema, trackingTable, "")
	if err != nil {
		fatal("init keystone migration runner: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Every versioned bundle in the lock must be applied, not just HEAD: a missing
	// or dirty intermediate bundle means the schema is not what this image expects.
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsBaseline() || seen[e.Vehicle] {
			continue
		}
		seen[e.Vehicle] = true
		applied, rec, err := runner.IsApplied(ctx, e.Vehicle)
		if err != nil {
			fatal("query %s.%s for %s: %v", schema, trackingTable, e.Vehicle, err)
		}
		if !applied {
			fmt.Fprintf(os.Stderr,
				"keystone-migration-gate: FAIL CLOSED — bundle %s (from %s; HEAD is %s) is NOT applied in %s.%s.\n"+
					"The falcon-id image at this migration HEAD MUST NOT roll until Keystone has applied its\n"+
					"bundle. Apply the bundle in the GitOps repository first, verify, THEN retry the rollout.\n",
				e.Vehicle, e.File, head.Vehicle, schema, trackingTable)
			os.Exit(1)
		}
		if rec != nil && rec.Dirty {
			fmt.Fprintf(os.Stderr,
				"keystone-migration-gate: FAIL CLOSED — bundle %s is recorded DIRTY in %s.%s "+
					"(a prior apply did not complete cleanly). Resolve the failed migration before rolling.\n",
				e.Vehicle, schema, trackingTable)
			os.Exit(1)
		}
	}

	fmt.Printf("keystone-migration-gate: OK — HEAD bundle %s (%s) is applied in %s.%s; safe to roll.\n",
		head.Vehicle, head.File, schema, trackingTable)
}

// loadLock returns the parsed lock entries: from path when non-empty, else the
// build-time embedded copy.
func loadLock(path string) ([]bundlelock.Entry, error) {
	if path != "" {
		return bundlelock.Load(path)
	}
	return migrations.LockEntries()
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "keystone-migration-gate: "+format+"\n", args...)
	os.Exit(2)
}

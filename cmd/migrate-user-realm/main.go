// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main provides the migrate-user-realm CLI utility.
//
// Sprint-1 #5: an early version of bootstrapAdminUser (FI!135) created the
// platform admin (dogukanturhal@example.com) in WellKnownRealmShared
// (00000000-0000-0000-0000-000000000001) instead of WellKnownRealmPlatform
// (00000000-0000-0000-0000-000000000003). FI!137 added a fail-closed gate
// that requires explicit realm threading, but it cannot retroactively fix
// the row that the older version created. This CLI is the operator-run
// fix.
//
// Why a CLI (and not a boot-time auto-fix):
//
//   - Boot-time auto-fix would re-run on every pod start, which is the
//     wrong semantics for a one-time data correction. Adding a "did we
//     already migrate?" guard pollutes the boot path with cleanup state.
//   - A CLI is auditable: the operator runs it once, the Job finishes,
//     the cleanup is done. The same pattern as cmd/resetpw.
//   - Per the brief: "build a one-off realm-migration tool in falcon-id
//     (NOT a SQL UPDATE)". This is that tool.
//
// Safety
//
//   - Default mode is DRY-RUN. The tool reports what it WOULD do without
//     touching the database. Pass --confirm to apply.
//   - All scope identifiers (--user-id OR --email, --tenant-id,
//     --from-realm, --to-realm) are required. No defaults — explicit
//     intent is a security property here, per the same RFC 9700 §4 +
//     OWASP Multi-Tenant rationale that drove FI!137's fail-closed gate.
//   - Pre-flight: target realm must exist (repos.Realm.GetByID); if it
//     doesn't, the FK insert would fail anyway but we surface a clearer
//     error here.
//   - Atomic UPDATE with WHERE id=$1 AND tenant_id=$2 AND realm_id=$3 —
//     a second run is a no-op (RowsAffected=0) which the tool reports as
//     "already migrated".
//
// Usage:
//
//	migrate-user-realm \
//	  --email=dogukanturhal@example.com \
//	  --tenant-id=00000000-0000-0000-0000-000000000002 \
//	  --from-realm=00000000-0000-0000-0000-000000000001 \
//	  --to-realm=00000000-0000-0000-0000-000000000003 \
//	  --confirm
//
// Required environment variables:
//
//	DATABASE_URL    — PostgreSQL DSN for the data-plane database
//	ENCRYPTION_KEY  — 32-byte AES-256 key used for PII encryption (must
//	                  match the running falcon-id pod so GetByEmail can
//	                  resolve the encrypted email_hash to the user row)
//
// The tool exits 0 on successful migration, 0 also when a no-op (already
// migrated), and non-zero on any error.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/database"
)

func main() {
	var (
		userIDStr  string
		emailStr   string
		tenantStr  string
		fromStr    string
		toStr      string
		confirm    bool
	)

	flag.StringVar(&userIDStr, "user-id", "", "User UUID (alternative to --email; preferred when known)")
	flag.StringVar(&emailStr, "email", "", "Plaintext email address (alternative to --user-id)")
	flag.StringVar(&tenantStr, "tenant-id", "", "Tenant UUID owning the user (required)")
	flag.StringVar(&fromStr, "from-realm", "", "Current realm UUID — must match user's row (required)")
	flag.StringVar(&toStr, "to-realm", "", "Target realm UUID (required, must already exist in realms table)")
	flag.BoolVar(&confirm, "confirm", false, "Apply the change. Default is dry-run.")
	flag.Parse()

	if (userIDStr == "" && emailStr == "") || (userIDStr != "" && emailStr != "") {
		fatal("exactly one of --user-id or --email must be provided")
	}
	if tenantStr == "" || fromStr == "" || toStr == "" {
		fatal("--tenant-id, --from-realm, --to-realm are all required")
	}

	tenantID, err := uuid.Parse(tenantStr)
	if err != nil {
		fatal("invalid --tenant-id %q: %v", tenantStr, err)
	}
	fromRealmID, err := uuid.Parse(fromStr)
	if err != nil {
		fatal("invalid --from-realm %q: %v", fromStr, err)
	}
	toRealmID, err := uuid.Parse(toStr)
	if err != nil {
		fatal("invalid --to-realm %q: %v", toStr, err)
	}
	if fromRealmID == toRealmID {
		fatal("--from-realm and --to-realm are the same (%s) — no migration to do", fromRealmID)
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		fatal("DATABASE_URL environment variable is required")
	}
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		fatal("ENCRYPTION_KEY environment variable is required")
	}

	// --- Infrastructure ---

	db, err := database.NewPostgresDB(databaseURL)
	if err != nil {
		fatal("failed to connect to database: %v", err)
	}
	defer db.Close()

	encSvc, err := crypto.NewEncryptionService(encryptionKey)
	if err != nil {
		fatal("failed to initialise encryption service: %v", err)
	}

	userRepo := repositories.NewUserRepository(db.Pool)
	userRepo.SetEncryptionService(encSvc)
	realmRepo := repositories.NewRealmRepository(db.Pool)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// --- Resolve user ---

	var userID uuid.UUID
	var resolvedRealmID uuid.UUID
	var resolvedTenantID uuid.UUID

	if userIDStr != "" {
		userID, err = uuid.Parse(userIDStr)
		if err != nil {
			fatal("invalid --user-id %q: %v", userIDStr, err)
		}
		u, lookupErr := userRepo.GetByID(ctx, userID)
		if lookupErr != nil {
			fatal("failed to look up user by id %s: %v", userID, lookupErr)
		}
		if u == nil {
			fatal("user %s not found", userID)
		}
		resolvedRealmID = u.RealmID
		resolvedTenantID = u.TenantID
	} else {
		u, lookupErr := userRepo.GetByEmail(ctx, tenantID, emailStr)
		if lookupErr != nil {
			fatal("failed to look up user by email %q in tenant %s: %v", emailStr, tenantID, lookupErr)
		}
		if u == nil {
			fatal("user with email %q not found in tenant %s", emailStr, tenantID)
		}
		userID = u.ID
		resolvedRealmID = u.RealmID
		resolvedTenantID = u.TenantID
	}

	// Cross-check: tenant must match what the caller specified, otherwise
	// the operator may be migrating the wrong user (typo, copy-paste from
	// the wrong context, etc.).
	if resolvedTenantID != tenantID {
		fatal(
			"user %s belongs to tenant %s, not %s — refusing to migrate (cross-tenant safety)",
			userID, resolvedTenantID, tenantID,
		)
	}

	// --- Pre-flight: target realm exists ---

	targetRealm, err := realmRepo.GetByID(ctx, toRealmID)
	if err != nil {
		fatal("failed to look up target realm %s: %v", toRealmID, err)
	}
	if targetRealm == nil {
		fatal(
			"target realm %s does not exist — seed it first (cmd/realm_bootstrap.go runs at pod startup; or operator INSERT)",
			toRealmID,
		)
	}

	// --- No-op detection ---

	if resolvedRealmID == toRealmID {
		fmt.Printf("user %s is already in realm %s — nothing to do\n", userID, toRealmID)
		os.Exit(0)
	}
	if resolvedRealmID != fromRealmID {
		fatal(
			"user %s is in realm %s, not the expected --from-realm %s — refusing to migrate",
			userID, resolvedRealmID, fromRealmID,
		)
	}

	// --- Report ---

	fmt.Printf("\n=== migrate-user-realm ===\n")
	fmt.Printf("  user_id     : %s\n", userID)
	fmt.Printf("  tenant_id   : %s\n", tenantID)
	fmt.Printf("  current realm_id (from): %s\n", resolvedRealmID)
	fmt.Printf("  target  realm_id (to):   %s (slug=%s, type=%s)\n",
		targetRealm.ID, targetRealm.Slug, targetRealm.Type)
	fmt.Printf("  mode        : ")
	if confirm {
		fmt.Printf("APPLY (--confirm set)\n\n")
	} else {
		fmt.Printf("DRY RUN (pass --confirm to apply)\n\n")
		fmt.Printf("Would issue:\n")
		fmt.Printf("  UPDATE iam_users SET realm_id = %s, updated_at = NOW()\n", toRealmID)
		fmt.Printf("    WHERE id = %s AND tenant_id = %s AND realm_id = %s\n",
			userID, tenantID, fromRealmID)
		fmt.Printf("\nNo changes applied.\n")
		os.Exit(0)
	}

	// --- Apply ---

	if err := userRepo.MigrateRealm(ctx, userID, tenantID, fromRealmID, toRealmID, nil); err != nil {
		fatal("MigrateRealm failed: %v", err)
	}

	fmt.Printf("Migration applied successfully:\n")
	fmt.Printf("  user_id   : %s\n", userID)
	fmt.Printf("  tenant_id : %s\n", tenantID)
	fmt.Printf("  realm_id  : %s -> %s\n", fromRealmID, toRealmID)
	fmt.Printf("\nFollow-up: bounce sessions for the migrated user (their existing\n")
	fmt.Printf("session/refresh tokens may carry the old realm context):\n")
	fmt.Printf("  DELETE FROM iam_oauth_tokens WHERE user_id = '%s';\n", userID)
	fmt.Printf("  DELETE FROM iam_sessions     WHERE user_id = '%s';\n", userID)
	fmt.Printf("(Run via the admin API or as a follow-up SQL — out of scope here.)\n")
}

func fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprint(os.Stderr, "migrate-user-realm: "+msg)
	os.Exit(1)
}

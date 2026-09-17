// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main provides the resetpw CLI utility.
//
// resetpw resets a user's password through the application's own repository
// layer, guaranteeing that the argon2id hash, PII decryption/re-encryption,
// and password-change timestamp are all handled identically to a normal
// in-app password reset.
//
// Usage:
//
//	resetpw <email> <new-password>
//
// Required environment variables:
//
//	DATABASE_URL    — PostgreSQL DSN for the data-plane database
//	ENCRYPTION_KEY  — 32-byte AES-256 key used for PII encryption (must match
//	                  the running application)
//
// The tool exits 0 on success and non-zero on any error.  It is safe to run
// multiple times (idempotent: each run simply overwrites the hash).
package main

import (
	"context"
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
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "Usage: resetpw <email> <new-password>")
		os.Exit(1)
	}

	email := os.Args[1]
	newPassword := os.Args[2]

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

	// --- Look up user ---

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// GetByEmail requires a tenantID but the user might exist in any tenant.
	// We search the exampletenant tenant first (most common admin case),
	// then fall back to a nil UUID scan.  The underlying query uses the
	// email_hash index which is tenant-scoped; we therefore try known
	// well-known tenant IDs in order.
	tenantIDs := []uuid.UUID{
		uuid.MustParse("00000000-0000-0000-0000-000000000002"), // exampletenant
		uuid.MustParse("00000000-0000-0000-0000-000000000001"), // default
		uuid.MustParse("00000000-0000-0000-0000-000000000004"), // consumer
	}

	// Look up user across known tenant IDs.
	type userResult struct {
		id             uuid.UUID
		tenantID       uuid.UUID
		passwordHash   *string
		isEmailVerified bool
	}
	var result *userResult

	for _, tid := range tenantIDs {
		u, lookupErr := userRepo.GetByEmail(ctx, tid, email)
		if lookupErr != nil {
			continue
		}
		if u == nil {
			continue
		}
		result = &userResult{
			id:             u.ID,
			tenantID:       u.TenantID,
			passwordHash:   u.PasswordHash,
			isEmailVerified: u.IsEmailVerified,
		}
		break
	}

	if result == nil {
		fatal("user with email %q not found in any known tenant", email)
	}

	// --- Hash the new password (same as UserService.Create) ---

	hash, err := crypto.HashPassword(newPassword, nil)
	if err != nil {
		fatal("failed to hash password: %v", err)
	}

	// --- Fetch full user struct for Update (repository requires all fields) ---

	fullUser, err := userRepo.GetByID(ctx, result.id)
	if err != nil || fullUser == nil {
		fatal("failed to fetch user by ID %s: %v", result.id, err)
	}

	now := time.Now().UTC()
	fullUser.PasswordHash = &hash
	fullUser.PasswordChangedAt = &now
	fullUser.MustChangePassword = false
	fullUser.FailedLoginAttempts = 0
	fullUser.LastFailedLoginAt = nil
	fullUser.IsLocked = false
	fullUser.LockReason = nil

	if err := userRepo.Update(ctx, fullUser); err != nil {
		fatal("failed to update user: %v", err)
	}

	fmt.Printf("Password reset successfully for %s (user_id=%s, tenant_id=%s)\n",
		email,
		result.id,
		result.tenantID,
	)
}

func fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprint(os.Stderr, "resetpw: "+msg)
	os.Exit(1)
}

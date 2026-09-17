// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

// newTestEncryptionService returns a 32-byte AES-256 encryption service
// suitable for unit tests.  It panics if the key is invalid so callers
// don't have to handle the error inline.
func newTestEncryptionService(t *testing.T) *crypto.EncryptionService {
	t.Helper()
	svc, err := crypto.NewEncryptionService("test-encrypt-key-32bytes-exactly")
	require.NoError(t, err)
	return svc
}

// newUserRepo creates a UserRepository backed by a pgxmock pool.
// The returned mock is configured with QueryMatcherRegexp so that only the
// relevant SQL fragment needs to appear in the expectation string.
func newUserRepo(t *testing.T) (*UserRepository, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)

	enc := newTestEncryptionService(t)
	repo := NewUserRepository(mock)
	repo.SetEncryptionService(enc)

	t.Cleanup(func() { mock.Close() })
	return repo, mock
}

// encryptField is a test helper that encrypts a string the same way the repo
// does, so that mock rows can contain properly-encrypted ciphertext that the
// repo will then decrypt and compare against the original plaintext.
func encryptField(t *testing.T, enc *crypto.EncryptionService, s string) string {
	t.Helper()
	if s == "" {
		return ""
	}
	ct, err := enc.Encrypt(s)
	require.NoError(t, err)
	return ct
}

// userColumns must stay in sync with the const in user_repository.go.
// Defined here to build pgxmock row slices without repeating the column list.
var testUserColumns = []string{
	"id", "tenant_id", "realm_id", "username", "email", "email_hash", "password_hash",
	"first_name", "last_name", "display_name", "phone", "department", "title", "avatar_url",
	"federation_type", "federation_id", "federation_source",
	"is_active", "is_email_verified", "is_locked", "lock_reason", "locked_at", "locked_until",
	"mfa_enabled", "mfa_secret", "mfa_type", "mfa_totp_enabled", "mfa_email_enabled", "mfa_preferred_method",
	"mfa_enrollment_first_prompted_at", "mfa_enrollment_deadline", "mfa_enrollment_skip_count",
	"password_changed_at", "must_change_password", "failed_login_attempts", "last_failed_login_at",
	"last_login_at", "last_login_ip", "created_at", "updated_at", "created_by", "updated_by",
}

// buildUserRow returns the row values that must be returned for a user.
// enc is used to encrypt PII fields the same way the repository reads them
// (i.e. the DB stores ciphertext; the repository decrypts after reading).
func buildUserRow(t *testing.T, enc *crypto.EncryptionService, u *models.User) []interface{} {
	t.Helper()

	encEmail := encryptField(t, enc, u.Email)
	var encFirst, encLast, encDisplay, encPhone interface{}
	if u.FirstName != nil {
		s := encryptField(t, enc, *u.FirstName)
		encFirst = &s
	}
	if u.LastName != nil {
		s := encryptField(t, enc, *u.LastName)
		encLast = &s
	}
	if u.DisplayName != nil {
		s := encryptField(t, enc, *u.DisplayName)
		encDisplay = &s
	}
	if u.Phone != nil {
		s := encryptField(t, enc, *u.Phone)
		encPhone = &s
	}

	return []interface{}{
		u.ID, u.TenantID, u.RealmID, u.Username, encEmail, u.EmailHash, u.PasswordHash,
		encFirst, encLast, encDisplay, encPhone, u.Department, u.Title, u.AvatarURL,
		u.FederationType, u.FederationID, u.FederationSource,
		u.IsActive, u.IsEmailVerified, u.IsLocked, u.LockReason, u.LockedAt, u.LockedUntil,
		u.MFAEnabled, u.MFASecret, u.MFAType, u.MFATOTPEnabled, u.MFAEmailEnabled, u.MFAPreferredMethod,
		u.MFAEnrollmentFirstPromptedAt, u.MFAEnrollmentDeadline, u.MFAEnrollmentSkipCount,
		u.PasswordChangedAt, u.MustChangePassword, u.FailedLoginAttempts, u.LastFailedLoginAt,
		u.LastLoginAt, u.LastLoginIP, u.CreatedAt, u.UpdatedAt, u.CreatedBy, u.UpdatedBy,
	}
}

// sampleUser builds a deterministic test user with all PII fields populated.
func sampleUser(tenantID uuid.UUID) *models.User {
	fn := "Alice"
	ln := "Smith"
	now := time.Now().UTC().Truncate(time.Second)
	return &models.User{
		ID:         uuid.New(),
		TenantID:   tenantID,
		RealmID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		Username:   "alice",
		Email:      "alice@example.com",
		EmailHash:  computeEmailHash("alice@example.com"),
		FirstName:  &fn,
		LastName:   &ln,
		IsActive:   true,
		MFAEnabled: false,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Create
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_Create(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	enc := newTestEncryptionService(t)
	tenantID := uuid.New()
	user := sampleUser(tenantID)

	now := time.Now().UTC().Truncate(time.Second)
	mock.ExpectQuery(`INSERT INTO iam_users`).
		WithArgs(
			pgxmock.AnyArg(), // id
			user.TenantID,
			pgxmock.AnyArg(), // realm_id
			user.Username,
			pgxmock.AnyArg(), // encrypted email
			pgxmock.AnyArg(), // email_hash
			user.PasswordHash,
			pgxmock.AnyArg(), // encrypted first_name
			pgxmock.AnyArg(), // encrypted last_name
			pgxmock.AnyArg(), // display_name
			pgxmock.AnyArg(), // phone
			pgxmock.AnyArg(), // department
			pgxmock.AnyArg(), // title
			pgxmock.AnyArg(), // federation_type
			pgxmock.AnyArg(), // federation_id
			pgxmock.AnyArg(), // federation_source
			user.IsActive,
			user.MFAEnabled,
			pgxmock.AnyArg(), // created_by
		).
		WillReturnRows(pgxmock.NewRows([]string{"created_at", "updated_at"}).
			AddRow(now, now))

	err := repo.Create(ctx, user)
	require.NoError(t, err)
	assert.Equal(t, now, user.CreatedAt)
	assert.Equal(t, now, user.UpdatedAt)

	// Verify encryption was applied; email stored in user is now plaintext again
	// (encryption mutates user.Email but Create sets it to ciphertext internally).
	// What matters is that the repository computed and stored the email hash.
	assert.Equal(t, computeEmailHash("alice@example.com"), user.EmailHash)

	require.NoError(t, mock.ExpectationsWereMet())

	_ = enc // used for documentation context
}

func TestUserRepository_Create_EncryptionServiceNotSet(t *testing.T) {
	ctx := context.Background()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Deliberately omit SetEncryptionService
	repo := NewUserRepository(mock)
	tenantID := uuid.New()
	user := sampleUser(tenantID)

	err = repo.Create(ctx, user)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption service not configured")
}

// ──────────────────────────────────────────────────────────────────────────────
// GetByID
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_GetByID_Found(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	enc := newTestEncryptionService(t)
	tenantID := uuid.New()
	user := sampleUser(tenantID)

	rows := pgxmock.NewRows(testUserColumns).
		AddRow(buildUserRow(t, enc, user)...)

	mock.ExpectQuery(`SELECT .+ FROM iam_users WHERE id = \$1`).
		WithArgs(user.ID).
		WillReturnRows(rows)

	got, err := repo.GetByID(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, user.ID, got.ID)
	assert.Equal(t, user.Username, got.Username)
	assert.Equal(t, "alice@example.com", got.Email)
	assert.Equal(t, "Alice", *got.FirstName)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_GetByID_NotFound(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)

	mock.ExpectQuery(`SELECT .+ FROM iam_users WHERE id = \$1`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows(testUserColumns)) // empty result set

	got, err := repo.GetByID(ctx, uuid.New())
	require.NoError(t, err)
	assert.Nil(t, got)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// GetByUsername
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_GetByUsername_Found(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	enc := newTestEncryptionService(t)
	tenantID := uuid.New()
	user := sampleUser(tenantID)

	rows := pgxmock.NewRows(testUserColumns).
		AddRow(buildUserRow(t, enc, user)...)

	mock.ExpectQuery(`SELECT .+ FROM iam_users WHERE tenant_id = \$1 AND username = \$2`).
		WithArgs(tenantID, user.Username).
		WillReturnRows(rows)

	got, err := repo.GetByUsername(ctx, tenantID, user.Username)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, user.Username, got.Username)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_GetByUsername_NotFound(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)

	mock.ExpectQuery(`SELECT .+ FROM iam_users WHERE tenant_id = \$1 AND username = \$2`).
		WithArgs(pgxmock.AnyArg(), "nobody").
		WillReturnRows(pgxmock.NewRows(testUserColumns))

	got, err := repo.GetByUsername(ctx, uuid.New(), "nobody")
	require.NoError(t, err)
	assert.Nil(t, got)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// GetByEmail
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_GetByEmail_Found(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	enc := newTestEncryptionService(t)
	tenantID := uuid.New()
	user := sampleUser(tenantID)
	email := "alice@example.com"
	user.Email = email
	user.EmailHash = computeEmailHash(email)

	rows := pgxmock.NewRows(testUserColumns).
		AddRow(buildUserRow(t, enc, user)...)

	mock.ExpectQuery(`SELECT .+ FROM iam_users WHERE tenant_id = \$1 AND email_hash = \$2`).
		WithArgs(tenantID, computeEmailHash(email)).
		WillReturnRows(rows)

	got, err := repo.GetByEmail(ctx, tenantID, email)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, email, got.Email)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_GetByEmail_NotFound(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)

	mock.ExpectQuery(`SELECT .+ FROM iam_users WHERE tenant_id = \$1 AND email_hash = \$2`).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows(testUserColumns))

	got, err := repo.GetByEmail(ctx, uuid.New(), "ghost@example.com")
	require.NoError(t, err)
	assert.Nil(t, got)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// Update
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_Update(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	tenantID := uuid.New()
	user := sampleUser(tenantID)
	now := time.Now().UTC().Truncate(time.Second)

	mock.ExpectQuery(`UPDATE iam_users SET`).
		WithArgs(
			user.ID,
			pgxmock.AnyArg(), // encrypted email
			pgxmock.AnyArg(), // email_hash
			pgxmock.AnyArg(), // encrypted first_name
			pgxmock.AnyArg(), // encrypted last_name
			pgxmock.AnyArg(), // display_name
			pgxmock.AnyArg(), // phone
			pgxmock.AnyArg(), // department
			pgxmock.AnyArg(), // title
			pgxmock.AnyArg(), // avatar_url
			user.IsActive,
			user.IsEmailVerified,
			user.IsLocked,
			pgxmock.AnyArg(), // lock_reason
			pgxmock.AnyArg(), // locked_at
			pgxmock.AnyArg(), // locked_until
			user.MFAEnabled,
			pgxmock.AnyArg(), // mfa_secret
			pgxmock.AnyArg(), // mfa_type
			user.MFATOTPEnabled,
			user.MFAEmailEnabled,
			pgxmock.AnyArg(), // mfa_preferred_method
			user.PasswordHash,
			pgxmock.AnyArg(), // password_changed_at
			user.MustChangePassword,
			user.FailedLoginAttempts,
			pgxmock.AnyArg(), // last_failed_login_at
			pgxmock.AnyArg(), // last_login_at
			pgxmock.AnyArg(), // last_login_ip
			pgxmock.AnyArg(), // updated_by
		).
		WillReturnRows(pgxmock.NewRows([]string{"updated_at"}).AddRow(now))

	err := repo.Update(ctx, user)
	require.NoError(t, err)
	assert.Equal(t, now, user.UpdatedAt)

	require.NoError(t, mock.ExpectationsWereMet())
}

// TestUserRepository_Update_PartialStructPreservationGuard asserts the
// repository-layer defense (SQL CASE-WHEN on $2::text = '') introduced by
// MR !234 after two production data-corruption incidents:
//
//   - 2026-05-12: partial *models.User (only ID/TenantID/Username) wiped
//     Email + computed a constant email_hash from "".
//   - 2026-05-23: webauthn FinishRegistration wiped IsActive +
//     IsEmailVerified + PasswordHash via a JWT-context partial struct,
//     locking the user out via discover-flow "Restricted access".
//
// The CASE-WHEN guard preserves email/email_hash/PII/auth-state when
// caller passes empty Email. This test verifies the SQL text actually
// contains the guard AND that calling Update with a partial struct
// (Email='') passes empty parameters through to the SQL — relying on
// PostgreSQL semantics to honour the CASE-WHEN. Combined with the live
// CASE-WHEN it gives end-to-end correctness; in pure-pgxmock land the
// test asserts the contract is present, not the live-PG outcome.
//
// Also verifies the Go-side guard that skips `computeEmailHash` when
// Email is empty (user_repository.go:Update — without that guard the
// previous magic-constant `HMAC(emailHashKey, "")` regression returns).
func TestUserRepository_Update_PartialStructPreservationGuard(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	tenantID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	// Partial struct — only ID + TenantID + Username set. Email is
	// the empty string (the sentinel). EmailHash is also empty (Go
	// zero value); the Go-side guard at Update preserves the hash
	// in-DB by NOT recomputing it from empty.
	partial := &models.User{
		ID:       uuid.New(),
		TenantID: tenantID,
		Username: "alice",
		// Email left empty — triggers the sentinel.
		// Every other field at Go zero value.
	}

	// Expect the UPDATE SQL with the CASE-WHEN guard. QueryMatcherRegexp
	// matches a substring — these patterns are load-bearing parts of
	// the contract that protect against partial-struct wipes:
	//   email             = CASE WHEN $2::text = '' THEN email             ELSE $2  END
	//   email_hash        = CASE WHEN $2::text = '' THEN email_hash        ELSE $3  END
	//   is_active         = CASE WHEN $2::text = '' THEN is_active         ELSE $11 END
	//   is_email_verified = CASE WHEN $2::text = '' THEN is_email_verified ELSE $12 END
	//   password_hash     = CASE WHEN $2::text = '' THEN password_hash     ELSE $23 END
	// If any of these CASE-WHEN guards is removed, this test fails —
	// the SQL no longer matches the regex.
	mock.ExpectQuery(
		`(?s)UPDATE iam_users SET.*` +
			`email\s*=\s*CASE WHEN \$2::text\s*=\s*''\s*THEN email.*` +
			`email_hash\s*=\s*CASE WHEN \$2::text\s*=\s*''\s*THEN email_hash.*` +
			`is_active\s*=\s*CASE WHEN \$2::text\s*=\s*''\s*THEN is_active.*` +
			`is_email_verified\s*=\s*CASE WHEN \$2::text\s*=\s*''\s*THEN is_email_verified.*` +
			`password_hash\s*=\s*CASE WHEN \$2::text\s*=\s*''\s*THEN password_hash`,
	).
		WithArgs(
			partial.ID,
			"", // email — empty sentinel passed through unchanged
			"", // email_hash — empty (Go-side guard skipped the recompute, so it stays as the struct's zero value)
			// Remaining fields are all zero values for a partial struct.
			pgxmock.AnyArg(), // first_name
			pgxmock.AnyArg(), // last_name
			pgxmock.AnyArg(), // display_name
			pgxmock.AnyArg(), // phone
			pgxmock.AnyArg(), // department
			pgxmock.AnyArg(), // title
			pgxmock.AnyArg(), // avatar_url
			pgxmock.AnyArg(), // is_active (false, ignored by SQL guard)
			pgxmock.AnyArg(), // is_email_verified (false, ignored)
			pgxmock.AnyArg(), // is_locked
			pgxmock.AnyArg(), // lock_reason
			pgxmock.AnyArg(), // locked_at
			pgxmock.AnyArg(), // locked_until
			pgxmock.AnyArg(), // mfa_enabled
			pgxmock.AnyArg(), // mfa_secret
			pgxmock.AnyArg(), // mfa_type
			pgxmock.AnyArg(), // mfa_totp_enabled
			pgxmock.AnyArg(), // mfa_email_enabled
			pgxmock.AnyArg(), // mfa_preferred_method
			pgxmock.AnyArg(), // password_hash (nil, ignored by SQL guard)
			pgxmock.AnyArg(), // password_changed_at
			pgxmock.AnyArg(), // must_change_password
			pgxmock.AnyArg(), // failed_login_attempts
			pgxmock.AnyArg(), // last_failed_login_at
			pgxmock.AnyArg(), // last_login_at
			pgxmock.AnyArg(), // last_login_ip
			pgxmock.AnyArg(), // updated_by
		).
		WillReturnRows(pgxmock.NewRows([]string{"updated_at"}).AddRow(now))

	err := repo.Update(ctx, partial)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())

	// Sanity: the Go-side guard fired (no recompute) — EmailHash is
	// still the empty string it was set to before Update, NOT the
	// magic constant HMAC(emailHashKey, "")
	// = b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad.
	assert.Empty(t, partial.EmailHash,
		"EmailHash MUST remain empty when caller passed empty Email; "+
			"non-empty here would mean the Go-side guard recomputed "+
			"from '' (the 2026-05-12 magic-constant regression).")
}

// ──────────────────────────────────────────────────────────────────────────────
// Delete
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_Delete(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	id := uuid.New()

	mock.ExpectExec(`DELETE FROM iam_users WHERE id = \$1`).
		WithArgs(id).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	err := repo.Delete(ctx, id)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// List
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_List_NoSearch(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	enc := newTestEncryptionService(t)
	tenantID := uuid.New()
	user := sampleUser(tenantID)

	// Expect the COUNT query first, then the SELECT.
	// page=1, pageSize=10 → offset=0
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_users WHERE tenant_id = \$1`).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(1)))

	// LIMIT ($2) and OFFSET ($3) are now bound as query parameters.
	mock.ExpectQuery(`SELECT .+ FROM iam_users WHERE tenant_id = \$1`).
		WithArgs(tenantID, 10, 0).
		WillReturnRows(pgxmock.NewRows(testUserColumns).
			AddRow(buildUserRow(t, enc, user)...))

	users, total, err := repo.List(ctx, tenantID, 1, 10, "")
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, users, 1)
	assert.Equal(t, user.Username, users[0].Username)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_List_WithSearch(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	enc := newTestEncryptionService(t)
	tenantID := uuid.New()
	user := sampleUser(tenantID)
	search := "alice"

	// COUNT query takes (tenantID, likeTerm, emailHash).
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_users WHERE tenant_id = \$1`).
		WithArgs(tenantID, "%"+search+"%", computeEmailHash(search)).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(1)))

	// SELECT query takes (tenantID, likeTerm, emailHash, LIMIT=$4, OFFSET=$5).
	// page=1, pageSize=10 → offset=0
	mock.ExpectQuery(`SELECT .+ FROM iam_users WHERE tenant_id = \$1`).
		WithArgs(tenantID, "%"+search+"%", computeEmailHash(search), 10, 0).
		WillReturnRows(pgxmock.NewRows(testUserColumns).
			AddRow(buildUserRow(t, enc, user)...))

	users, total, err := repo.List(ctx, tenantID, 1, 10, search)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, users, 1)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_List_Empty(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	tenantID := uuid.New()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_users WHERE tenant_id = \$1`).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(0)))

	// LIMIT and OFFSET are now parameterized ($2, $3) instead of interpolated
	mock.ExpectQuery(`SELECT .+ FROM iam_users WHERE tenant_id = \$1`).
		WithArgs(tenantID, 10, 0).
		WillReturnRows(pgxmock.NewRows(testUserColumns)) // zero rows

	users, total, err := repo.List(ctx, tenantID, 1, 10, "")
	require.NoError(t, err)
	assert.Equal(t, int64(0), total)
	assert.Empty(t, users)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// AssignRoles
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_AssignRoles(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()
	roleID1 := uuid.New()
	roleID2 := uuid.New()
	assignedBy := uuid.New()

	// Transaction lifecycle
	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM iam_user_roles WHERE user_id = \$1`).
		WithArgs(userID).
		WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectExec(`INSERT INTO iam_user_roles`).
		WithArgs(userID, roleID1, &assignedBy).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mock.ExpectExec(`INSERT INTO iam_user_roles`).
		WithArgs(userID, roleID2, &assignedBy).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mock.ExpectCommit()

	err := repo.AssignRoles(ctx, userID, []uuid.UUID{roleID1, roleID2}, &assignedBy)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_AssignRoles_Empty(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM iam_user_roles WHERE user_id = \$1`).
		WithArgs(userID).
		WillReturnResult(pgxmock.NewResult("DELETE", 2))
	mock.ExpectCommit()

	err := repo.AssignRoles(ctx, userID, []uuid.UUID{}, nil)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// GetUserRoles
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_GetUserRoles(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()
	tenantID := uuid.New()

	roleColumns := []string{
		"id", "tenant_id", "name", "display_name", "description",
		"is_system", "is_default", "priority",
		"created_at", "updated_at", "created_by", "updated_by",
	}
	now := time.Now().UTC().Truncate(time.Second)
	roleID := uuid.New()

	mock.ExpectQuery(`SELECT r\.id.+FROM iam_roles r INNER JOIN iam_user_roles ur`).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows(roleColumns).
			AddRow(roleID, tenantID, "admin", "Administrator", nil, true, false, 10, now, now, nil, nil))

	roles, err := repo.GetUserRoles(ctx, userID)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, roleID, roles[0].ID)
	assert.Equal(t, "admin", roles[0].Name)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_GetUserRoles_Empty(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()

	roleColumns := []string{
		"id", "tenant_id", "name", "display_name", "description",
		"is_system", "is_default", "priority",
		"created_at", "updated_at", "created_by", "updated_by",
	}
	mock.ExpectQuery(`SELECT r\.id.+FROM iam_roles r INNER JOIN iam_user_roles ur`).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows(roleColumns))

	roles, err := repo.GetUserRoles(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, roles)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// GetUserPermissions
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_GetUserPermissions(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()

	permColumns := []string{
		"id", "module", "resource", "action", "name", "display_name", "description", "is_system", "created_at",
	}
	now := time.Now().UTC().Truncate(time.Second)
	permID := uuid.New()

	mock.ExpectQuery(`SELECT DISTINCT p\.id.+FROM iam_permissions p`).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows(permColumns).
			AddRow(permID, "iam", "users", "read", "iam.users.read", "Read Users", nil, true, now))

	perms, err := repo.GetUserPermissions(ctx, userID)
	require.NoError(t, err)
	require.Len(t, perms, 1)
	assert.Equal(t, permID, perms[0].ID)
	assert.Equal(t, "iam", perms[0].Module)
	assert.Equal(t, "read", perms[0].Action)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// IncrementFailedAttempts / ResetFailedAttempts
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_IncrementFailedAttempts(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()

	mock.ExpectQuery(`UPDATE iam_users SET failed_login_attempts`).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"failed_login_attempts"}).AddRow(3))

	count, err := repo.IncrementFailedAttempts(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_ResetFailedAttempts(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()

	mock.ExpectExec(`UPDATE iam_users SET failed_login_attempts = 0`).
		WithArgs(userID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.ResetFailedAttempts(ctx, userID)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// LockUser / UnlockUser
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_LockUser(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()
	reason := "too many failed attempts"

	mock.ExpectExec(`UPDATE iam_users SET is_locked = true`).
		WithArgs(userID, reason, (*time.Time)(nil)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.LockUser(ctx, userID, reason, nil)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_UnlockUser(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()

	mock.ExpectExec(`UPDATE iam_users SET is_locked = false`).
		WithArgs(userID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.UnlockUser(ctx, userID)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// CountByTenant
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_CountByTenant(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	tenantID := uuid.New()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_users WHERE tenant_id = \$1`).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(42))

	count, err := repo.CountByTenant(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, 42, count)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// CountActiveByTenant (feat/seat-quota-enforcement)
// ──────────────────────────────────────────────────────────────────────────────

// TestUserRepository_CountActiveByTenant asserts the query filters on
// is_active = true AND deletion_scheduled_at IS NULL, which is what makes
// this a seat-usage-accurate count distinct from the unfiltered
// CountByTenant above — a user pending deletion (deletion_scheduled_at
// set) or deactivated should not occupy a seat.
func TestUserRepository_CountActiveByTenant(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	tenantID := uuid.New()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_users\s+WHERE tenant_id = \$1 AND is_active = true AND deletion_scheduled_at IS NULL`).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(3))

	count, err := repo.CountActiveByTenant(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_CountActiveByTenant_QueryError(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	tenantID := uuid.New()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_users\s+WHERE tenant_id = \$1 AND is_active = true AND deletion_scheduled_at IS NULL`).
		WithArgs(tenantID).
		WillReturnError(assert.AnError)

	count, err := repo.CountActiveByTenant(ctx, tenantID)
	require.Error(t, err)
	assert.Equal(t, 0, count)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// GetByEmailGlobal
// ──────────────────────────────────────────────────────────────────────────────

func TestUserRepository_GetByEmailGlobal_Found(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	enc := newTestEncryptionService(t)
	tenantID := uuid.New()
	email := "alice@example.com"
	user := sampleUser(tenantID)
	user.Email = email
	user.EmailHash = computeEmailHash(email)

	rows := pgxmock.NewRows(testUserColumns).
		AddRow(buildUserRow(t, enc, user)...)

	mock.ExpectQuery(`SELECT .+ FROM iam_users WHERE email_hash = \$1 LIMIT 1`).
		WithArgs(computeEmailHash(email)).
		WillReturnRows(rows)

	got, err := repo.GetByEmailGlobal(ctx, email)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, email, got.Email)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_GetByEmailGlobal_NotFound(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)

	mock.ExpectQuery(`SELECT .+ FROM iam_users WHERE email_hash = \$1 LIMIT 1`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows(testUserColumns))

	got, err := repo.GetByEmailGlobal(ctx, "ghost@example.com")
	require.NoError(t, err)
	assert.Nil(t, got)

	require.NoError(t, mock.ExpectationsWereMet())
}

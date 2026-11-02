// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// TestUpdateUserLoginInfo_SignupShapedUser_DoesNotWipePassword is a
// regression/control test for the 2026-09-18 incident: every self-service
// signup's password_hash was nulled out roughly one second after
// CreatePreparedForSignup persisted it.
//
// Root cause: AuthService.IssueSessionForNewUser (auth_signup_session.go),
// called from SignupService.CompleteSignup to mint a session for the
// brand-new account, hands updateUserLoginInfo a *models.User built by
// cmd/signup_adapters.go's signupUserCreatorAdapter.CreateForSignup from a
// *models.UserResponse — a response DTO that deliberately never carries
// PasswordHash. That struct's Email IS populated (needed for the JWT), so
// UserRepository.Update's partial-struct guard (keyed on `email == ''`)
// did not fire, and Update wrote password_hash = '' (the struct's zero
// value) over the hash CreatePreparedForSignup had just set.
//
// This test builds the EXACT shape of user struct
// signupUserCreatorAdapter.CreateForSignup produces (Email set,
// PasswordHash nil) and drives it through the real
// AuthService.updateUserLoginInfo against a pgxmock-backed
// UserRepository. The only SQL expectation registered is the narrow
// UpdateLoginInfo statement (three columns, no password_hash in the
// column list) plus ResetFailedAttempts. If updateUserLoginInfo is ever
// changed back to call the write-all-columns UserRepository.Update, the
// query pgxmock receives will not match either expectation and
// mock.ExpectationsWereMet()/the exec itself will fail — this is the
// control: revert the fix and this test breaks, proving the assertion is
// about is about behavior (which statement runs, and that it cannot
// touch password_hash), not merely "an update happened".
func TestUpdateUserLoginInfo_SignupShapedUser_DoesNotWipePassword(t *testing.T) {
	ctx := context.Background()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer mock.Close()

	userRepo := repositories.NewUserRepository(mock)
	authSvc := NewAuthService(newAuthCfg(), userRepo, nil, nil, nil, nil, nil, nil)

	userID := uuid.New()
	ip := "203.0.113.42"

	// Exactly the shape signupUserCreatorAdapter.CreateForSignup builds:
	// Email populated (defeats the empty-email guard), PasswordHash left
	// at its zero value (nil) because UserResponse never carries it.
	signupShapedUser := &models.User{
		ID:       userID,
		TenantID: uuid.New(),
		Username: "forest_x61",
		Email:    "forest_x61@hotmail.com",
		IsActive: true,
		// PasswordHash intentionally left nil — this is the exact
		// condition that triggered the incident.
	}
	require.Nil(t, signupShapedUser.PasswordHash, "sanity check: this struct must not carry a password hash, matching CreateForSignup's mapping")

	// Only expectation: the targeted UpdateLoginInfo statement. Its
	// column list has no password_hash — structurally cannot wipe it.
	mock.ExpectExec(`^UPDATE iam_users SET last_login_at = \$2, last_login_ip = \$3, failed_login_attempts = 0, updated_at = NOW\(\) WHERE id = \$1$`).
		WithArgs(userID, pgxmock.AnyArg(), ip).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectExec(`UPDATE iam_users SET failed_login_attempts = 0, last_failed_login_at = NULL`).
		WithArgs(userID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err = authSvc.updateUserLoginInfo(ctx, signupShapedUser, ip)
	require.NoError(t, err)

	// If updateUserLoginInfo had instead called the full-column Update(),
	// pgxmock would see a completely different SQL statement (containing
	// "password_hash" in its SET clause) that matches neither expectation
	// above, and either the Exec call itself or this check would fail.
	require.NoError(t, mock.ExpectationsWereMet(),
		"updateUserLoginInfo must persist login info via a targeted statement that cannot touch password_hash")
}

// TestUpdateUserLoginInfo_FullUserStruct_StillWorks is the control's
// control: the same method, called with a FULLY populated user (the
// shape every non-signup caller — plain login, MFA, WebAuthn — passes),
// must still succeed via the same narrow statement. This guards against
// a fix that "solves" the incident by making updateUserLoginInfo require
// a full struct (which would silently do nothing, or panic, for the
// signup case) instead of genuinely using a targeted update for everyone.
func TestUpdateUserLoginInfo_FullUserStruct_StillWorks(t *testing.T) {
	ctx := context.Background()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer mock.Close()

	userRepo := repositories.NewUserRepository(mock)
	authSvc := NewAuthService(newAuthCfg(), userRepo, nil, nil, nil, nil, nil, nil)

	userID := uuid.New()
	ip := "198.51.100.9"
	hash := "$argon2id$v=19$...fullyloadeduser...hash"
	oldLogin := time.Now().Add(-24 * time.Hour)

	fullUser := &models.User{
		ID:                  userID,
		TenantID:            uuid.New(),
		Username:            "dogukanturhal",
		Email:               "dogukanturhal@example.com",
		PasswordHash:        &hash,
		IsActive:            true,
		IsEmailVerified:     true,
		FailedLoginAttempts: 2,
		LastLoginAt:         &oldLogin,
	}

	mock.ExpectExec(`^UPDATE iam_users SET last_login_at = \$2, last_login_ip = \$3, failed_login_attempts = 0, updated_at = NOW\(\) WHERE id = \$1$`).
		WithArgs(userID, pgxmock.AnyArg(), ip).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectExec(`UPDATE iam_users SET failed_login_attempts = 0, last_failed_login_at = NULL`).
		WithArgs(userID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err = authSvc.updateUserLoginInfo(ctx, fullUser, ip)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())

	// PasswordHash pointer in memory is untouched by this call (it was
	// never part of the mutation), confirming the in-memory struct still
	// reflects the caller-supplied hash for anything downstream that
	// reads user.PasswordHash after this call.
	require.NotNil(t, fullUser.PasswordHash)
	require.Equal(t, hash, *fullUser.PasswordHash)
}

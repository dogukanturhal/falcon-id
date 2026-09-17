// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// auth_credentials_service_test.go covers the security-critical credential
// paths of AuthService:
//
//   - dummyPasswordHash initialisation (timing-attack prevention)
//   - verifyMFACode nil-guard
//   - validateTenantSlug injection prevention
//   - authenticateLDAP nil-guard
//   - crypto.VerifyPassword / crypto.ValidatePassword coverage (used by authenticateLocal)
//
// The concrete-pointer dependency graph of AuthService prevents full
// DB-backed unit tests for Login/authenticateLocal; those are covered by the
// integration suite.  This file tests everything that can be exercised in
// process with no database.

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// ---------------------------------------------------------------------------
// TestDummyPasswordHash — init-time timing-attack guard
// ---------------------------------------------------------------------------

// TestDummyPasswordHash_Initialised confirms that dummyPasswordHash was
// generated at package init time.  A regression here would mean unknown users
// do NOT pay the argon2id cost, enabling username enumeration via timing.
func TestDummyPasswordHash_Initialised(t *testing.T) {
	assert.NotEmpty(t, dummyPasswordHash,
		"dummyPasswordHash must be set by init() to prevent username enumeration via timing")
	assert.Greater(t, len(dummyPasswordHash), 20,
		"dummyPasswordHash must be a real argon2id hash, not a stub placeholder")
}

// TestDummyPasswordHash_IsValidArgon2id ensures the dummy hash can be fed to
// VerifyPassword without parse errors.  If this fails, every failed-username
// login would return early (different timing from a failed-password login).
func TestDummyPasswordHash_IsValidArgon2id(t *testing.T) {
	valid, err := crypto.VerifyPassword("any_random_password", dummyPasswordHash)
	require.NoError(t, err,
		"dummyPasswordHash must be a parseable argon2id hash so timing is constant")
	assert.False(t, valid, "random password must not match the dummy hash")
}

// ---------------------------------------------------------------------------
// TestVerifyMFACode — nil-guard (MFA service not wired)
// ---------------------------------------------------------------------------

func TestVerifyMFACode_NilMFAService_ReturnsFalse(t *testing.T) {
	svc := &AuthService{
		config:     newAuthCfg(),
		mfaService: nil,
	}
	user := &models.User{ID: uuid.New()}

	// Must return false (deny) and must NOT panic when MFA service is nil.
	ok := svc.verifyMFACode(context.Background(), user, "123456")
	assert.False(t, ok, "nil MFA service must deny all MFA verifications")
}

// ---------------------------------------------------------------------------
// TestAuthenticateLDAP — nil-guard (LDAP service not wired)
// ---------------------------------------------------------------------------

func TestAuthenticateLDAP_NoLDAPService_ReturnsError(t *testing.T) {
	svc := &AuthService{
		config:      newAuthCfg(),
		ldapService: nil,
	}

	_, err := svc.authenticateLDAP(context.Background(), uuid.New(), "user", "pass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LDAP authentication not available")
}

// ---------------------------------------------------------------------------
// TestValidateTenantSlug — SECURITY: injection / traversal / reserved-name
// ---------------------------------------------------------------------------

func TestValidateTenantSlug_SecurityBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		slug        string
		wantErr     bool
		errContains string
	}{
		// --- Valid slugs ---
		{name: "simple lowercase", slug: "acmecorp", wantErr: false},
		{name: "with hyphens", slug: "acme-corp-ltd", wantErr: false},
		{name: "starts with digit", slug: "1acme", wantErr: false},
		{name: "ends with digit", slug: "acme1", wantErr: false},
		{name: "max length (63)", slug: fmt.Sprintf("%063s", "a"), wantErr: false},

		// --- Security-critical rejections ---
		{
			name:    "SQL injection semicolon",
			slug:    "'; DROP TABLE tenants;--",
			wantErr: true,
		},
		{
			name:    "path traversal",
			slug:    "../etc/passwd",
			wantErr: true,
		},
		{
			name:    "uppercase letters",
			slug:    "UpperCase",
			wantErr: true,
		},
		{
			name:    "leading hyphen",
			slug:    "-badstart",
			wantErr: true,
		},
		{
			name:    "trailing hyphen",
			slug:    "badend-",
			wantErr: true,
		},
		{
			name:    "spaces",
			slug:    "with spaces",
			wantErr: true,
		},
		{
			name:    "special chars",
			slug:    "test!@#$",
			wantErr: true,
		},
		{
			name:        "empty string",
			slug:        "",
			wantErr:     true,
			errContains: "empty",
		},
		{
			name:        "too long slug",
			slug:        "a" + fmt.Sprintf("%063d", 0), // 64 chars
			wantErr:     true,
			errContains: "at most 63",
		},
		{
			name:        "consecutive hyphens",
			slug:        "test--slug",
			wantErr:     true,
			errContains: "consecutive hyphens",
		},
		// --- Reserved slug rejections ---
		{
			name:        "reserved: admin",
			slug:        "admin",
			wantErr:     true,
			errContains: "reserved",
		},
		{
			name:        "reserved: api",
			slug:        "api",
			wantErr:     true,
			errContains: "reserved",
		},
		{
			name:        "reserved: www",
			slug:        "www",
			wantErr:     true,
			errContains: "reserved",
		},
		{
			name:        "reserved: localhost",
			slug:        "localhost",
			wantErr:     true,
			errContains: "reserved",
		},
		{
			name:        "reserved: default",
			slug:        "default",
			wantErr:     true,
			errContains: "reserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTenantSlug(tt.slug)
			if tt.wantErr {
				require.Error(t, err, "slug %q should be rejected", tt.slug)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err, "slug %q should be accepted", tt.slug)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestPasswordVerification — crypto layer exercised by authenticateLocal
// ---------------------------------------------------------------------------

// TestPasswordVerification_TableDriven covers the crypto.VerifyPassword path
// that authenticateLocal delegates to.  These same inputs are exercised
// inside the service at auth time; testing them at the crypto boundary
// documents the security contract without needing a database.
func TestPasswordVerification_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		plaintext  string
		hashedFrom string // password used to create the hash
		wantValid  bool
	}{
		{
			name:       "correct password",
			plaintext:  "MySecretPass@1",
			hashedFrom: "MySecretPass@1",
			wantValid:  true,
		},
		{
			name:       "wrong password",
			plaintext:  "WrongPass@1",
			hashedFrom: "MySecretPass@1",
			wantValid:  false,
		},
		{
			name:       "empty plaintext against real hash",
			plaintext:  "",
			hashedFrom: "MySecretPass@1",
			wantValid:  false,
		},
		{
			name:       "unicode password round-trip",
			plaintext:  "Ünïcödé@Pässwörd!9",
			hashedFrom: "Ünïcödé@Pässwörd!9",
			wantValid:  true,
		},
		{
			name:       "case-sensitive rejection",
			plaintext:  "mysecretpass@1",
			hashedFrom: "MySecretPass@1",
			wantValid:  false,
		},
		{
			name:       "leading space not equal",
			plaintext:  " MySecretPass@1",
			hashedFrom: "MySecretPass@1",
			wantValid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := crypto.HashPassword(tt.hashedFrom, nil)
			require.NoError(t, err)

			valid, err := crypto.VerifyPassword(tt.plaintext, hash)
			require.NoError(t, err)
			assert.Equal(t, tt.wantValid, valid)
		})
	}
}

// ---------------------------------------------------------------------------
// TestValidatePassword — policy enforcement (NIST SP 800-63B subset)
// ---------------------------------------------------------------------------

func TestValidatePassword_PolicyEnforcement(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "valid strong password",
			password: "StrongP@ss123!",
			wantErr:  false,
		},
		{
			name:        "too short",
			password:    "Sh@rt1",
			wantErr:     true,
			errContains: "at least",
		},
		{
			name:        "missing uppercase",
			password:    "alllowercase@123",
			wantErr:     true,
			errContains: "uppercase",
		},
		{
			name:        "missing lowercase",
			password:    "ALLUPPERCASE@123",
			wantErr:     true,
			errContains: "lowercase",
		},
		{
			name:        "missing digit",
			password:    "NoDigitPass@word",
			wantErr:     true,
			errContains: "digit",
		},
		{
			name:        "missing special character",
			password:    "NoSpecialChar123",
			wantErr:     true,
			errContains: "special",
		},
		{
			name:        "common password blocked",
			password:    "Password123!",
			wantErr:     true,
			errContains: "common",
		},
		{
			name:        "product-specific common password",
			password:    "Hexxlock@123!",
			wantErr:     true,
			errContains: "common",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := crypto.ValidatePassword(tt.password, crypto.DefaultPasswordPolicy)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestValidatePasswordWithContext_UserContextPrevention ensures that passwords
// containing the user's own identifiers (username, email local-part) are
// rejected.  This maps to the PreventUserContext policy flag used in production.
func TestValidatePasswordWithContext_UserContextPrevention(t *testing.T) {
	t.Run("username in password", func(t *testing.T) {
		err := crypto.ValidatePasswordWithContext(
			"johndoeIsStrong@1",
			"johndoe",
			"johndoe@example.com",
			crypto.DefaultPasswordPolicy,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "username")
	})

	t.Run("email local-part in password", func(t *testing.T) {
		// Use a username short enough (<3 chars) that it cannot trigger the
		// username check, so only the email check fires.
		err := crypto.ValidatePasswordWithContext(
			"BobMarleyIsSecure@9",
			"bm",
			"bobmarley@example.com",
			crypto.DefaultPasswordPolicy,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email")
	})

	t.Run("unrelated strong password accepted", func(t *testing.T) {
		err := crypto.ValidatePasswordWithContext(
			"Tr0pic@lFish!99",
			"johndoe",
			"johndoe@example.com",
			crypto.DefaultPasswordPolicy,
		)
		require.NoError(t, err)
	})
}

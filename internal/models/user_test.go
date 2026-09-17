// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== CreateUserRequest validation ====================

func TestCreateUserRequest_Validation(t *testing.T) {
	validTenantID := uuid.New()

	tests := []struct {
		name      string
		req       CreateUserRequest
		wantValid bool
		wantField string
	}{
		{
			name: "valid minimal request",
			req: CreateUserRequest{
				TenantID: validTenantID,
				Username: "alice",
				Email:    "alice@example.com",
			},
			wantValid: true,
		},
		{
			name: "valid request with password and optional fields",
			req: CreateUserRequest{
				TenantID:    validTenantID,
				Username:    "alice",
				Email:       "alice@example.com",
				Password:    "Passw0rd!",
				FirstName:   strPtr("Alice"),
				LastName:    strPtr("Smith"),
				DisplayName: strPtr("Alice Smith"),
				Phone:       strPtr("+1-555-0100"),
				Department:  strPtr("Engineering"),
				Title:       strPtr("Engineer"),
			},
			wantValid: true,
		},
		{
			name: "missing tenant_id (zero UUID counts as empty for required)",
			req: CreateUserRequest{
				Username: "alice",
				Email:    "alice@example.com",
			},
			wantValid: false,
			wantField: "TenantID",
		},
		{
			name: "missing username",
			req: CreateUserRequest{
				TenantID: validTenantID,
				Email:    "alice@example.com",
			},
			wantValid: false,
			wantField: "Username",
		},
		{
			name: "username too short (2 chars, min is 3)",
			req: CreateUserRequest{
				TenantID: validTenantID,
				Username: "ab",
				Email:    "alice@example.com",
			},
			wantValid: false,
			wantField: "Username",
		},
		{
			name: "missing email",
			req: CreateUserRequest{
				TenantID: validTenantID,
				Username: "alice",
			},
			wantValid: false,
			wantField: "Email",
		},
		{
			name: "invalid email format",
			req: CreateUserRequest{
				TenantID: validTenantID,
				Username: "alice",
				Email:    "not-an-email",
			},
			wantValid: false,
			wantField: "Email",
		},
		{
			name: "password too short when provided (7 chars, min is 8)",
			req: CreateUserRequest{
				TenantID: validTenantID,
				Username: "alice",
				Email:    "alice@example.com",
				Password: "short7!",
			},
			wantValid: false,
			wantField: "Password",
		},
		{
			name: "password at minimum length (8 chars) is valid",
			req: CreateUserRequest{
				TenantID: validTenantID,
				Username: "alice",
				Email:    "alice@example.com",
				Password: "exactly8",
			},
			wantValid: true,
		},
		{
			name: "empty password is valid (omitempty)",
			req: CreateUserRequest{
				TenantID: validTenantID,
				Username: "alice",
				Email:    "alice@example.com",
				Password: "",
			},
			wantValid: true,
		},
		{
			name: "username at maximum length (255 chars) is valid",
			req: CreateUserRequest{
				TenantID: validTenantID,
				Username: string(make([]byte, 255)),
				Email:    "alice@example.com",
			},
			wantValid: true,
		},
		{
			name: "username exceeds maximum length (256 chars)",
			req: CreateUserRequest{
				TenantID: validTenantID,
				Username: string(make([]byte, 256)),
				Email:    "alice@example.com",
			},
			wantValid: false,
			wantField: "Username",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ve := validateStruct(t, tt.req)
			if tt.wantValid {
				assert.Nil(t, ve, "expected no validation errors")
				return
			}
			require.NotNil(t, ve, "expected validation errors but got none")
			assert.True(t, hasFieldError(ve, tt.wantField),
				"expected error on field %q, got: %v", tt.wantField, ve)
		})
	}
}

// ==================== UpdateUserRequest validation ====================

func TestUpdateUserRequest_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       UpdateUserRequest
		wantValid bool
		wantField string
	}{
		{
			name:      "valid empty update (all fields optional)",
			req:       UpdateUserRequest{},
			wantValid: true,
		},
		{
			name: "valid update with all fields populated",
			req: UpdateUserRequest{
				FirstName:          strPtr("Alice"),
				LastName:           strPtr("Smith"),
				DisplayName:        strPtr("Alice Smith"),
				Phone:              strPtr("+1-555-0100"),
				Department:         strPtr("Engineering"),
				Title:              strPtr("Engineer"),
				AvatarURL:          strPtr("https://example.com/avatar.png"),
				IsActive:           boolPtr(true),
				MustChangePassword: boolPtr(false),
				RoleIDs:            []uuid.UUID{uuid.New()},
			},
			wantValid: true,
		},
		{
			name: "first_name exceeds max length (101 chars)",
			req: UpdateUserRequest{
				FirstName: strPtr(string(make([]byte, 101))),
			},
			wantValid: false,
			wantField: "FirstName",
		},
		{
			name: "last_name exceeds max length (101 chars)",
			req: UpdateUserRequest{
				LastName: strPtr(string(make([]byte, 101))),
			},
			wantValid: false,
			wantField: "LastName",
		},
		{
			name: "display_name at max (255 chars) is valid",
			req: UpdateUserRequest{
				DisplayName: strPtr(string(make([]byte, 255))),
			},
			wantValid: true,
		},
		{
			name: "display_name exceeds max (256 chars)",
			req: UpdateUserRequest{
				DisplayName: strPtr(string(make([]byte, 256))),
			},
			wantValid: false,
			wantField: "DisplayName",
		},
		{
			name: "phone exceeds max length (51 chars)",
			req: UpdateUserRequest{
				Phone: strPtr(string(make([]byte, 51))),
			},
			wantValid: false,
			wantField: "Phone",
		},
		{
			name: "avatar_url as plain string is valid (no url format check)",
			req: UpdateUserRequest{
				AvatarURL: strPtr("avatars/user-id/file.jpg"),
			},
			wantValid: true,
		},
		{
			name: "valid avatar_url with https scheme",
			req: UpdateUserRequest{
				AvatarURL: strPtr("https://cdn.example.com/avatar.png"),
			},
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ve := validateStruct(t, tt.req)
			if tt.wantValid {
				assert.Nil(t, ve, "expected no validation errors")
				return
			}
			require.NotNil(t, ve, "expected validation errors but got none")
			assert.True(t, hasFieldError(ve, tt.wantField),
				"expected error on field %q, got: %v", tt.wantField, ve)
		})
	}
}

// ==================== User.ToResponse ====================

func TestUser_ToResponse(t *testing.T) {
	t.Run("should map all non-sensitive fields correctly", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		realmID := uuid.New()
		createdBy := uuid.New()
		updatedBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		lastLogin := now.Add(-1 * time.Hour)

		hash := "$2a$10$examplePasswordHash"
		mfaSecret := "MFASECRETKEY"
		firstName := "Alice"
		lastName := "Smith"
		displayName := "Alice Smith"
		phone := "+1-555-0100"
		department := "Engineering"
		title := "Engineer"
		avatarURL := "https://example.com/avatar.png"
		fedType := "ldap"
		lockReason := "too many attempts"
		lockedAt := now.Add(-2 * time.Hour)
		lockedUntil := now.Add(1 * time.Hour)
		mfaType := "totp"
		mfaPreferred := "totp"
		pwChangedAt := now.Add(-30 * 24 * time.Hour)
		lastLoginIP := "192.168.1.1"
		lastFailedLogin := now.Add(-5 * time.Minute)

		u := &User{
			ID:                  id,
			TenantID:            tenantID,
			RealmID:             realmID,
			Username:            "alice",
			Email:               "alice@example.com",
			EmailHash:           "sha256hashofemailhere",
			PasswordHash:        &hash,
			FirstName:           &firstName,
			LastName:            &lastName,
			DisplayName:         &displayName,
			Phone:               &phone,
			Department:          &department,
			Title:               &title,
			AvatarURL:           &avatarURL,
			FederationType:      &fedType,
			IsActive:            true,
			IsEmailVerified:     true,
			IsLocked:            false,
			LockReason:          &lockReason,
			LockedAt:            &lockedAt,
			LockedUntil:         &lockedUntil,
			ActivationStatus:    "active",
			MFAEnabled:          true,
			MFASecret:           &mfaSecret,
			MFAType:             &mfaType,
			MFATOTPEnabled:      true,
			MFAEmailEnabled:     false,
			MFAPreferredMethod:  &mfaPreferred,
			PasswordChangedAt:   &pwChangedAt,
			MustChangePassword:  false,
			FailedLoginAttempts: 3,
			LastFailedLoginAt:   &lastFailedLogin,
			LastLoginAt:         &lastLogin,
			LastLoginIP:         &lastLoginIP,
			CreatedAt:           now,
			UpdatedAt:           now,
			CreatedBy:           &createdBy,
			UpdatedBy:           &updatedBy,
		}

		resp := u.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id, resp.ID)
		assert.Equal(t, tenantID, resp.TenantID)
		assert.Equal(t, "alice", resp.Username)
		assert.Equal(t, "alice@example.com", resp.Email)
		assert.Equal(t, &firstName, resp.FirstName)
		assert.Equal(t, &lastName, resp.LastName)
		assert.Equal(t, &displayName, resp.DisplayName)
		assert.Equal(t, &phone, resp.Phone)
		assert.Equal(t, &department, resp.Department)
		assert.Equal(t, &title, resp.Title)
		assert.Equal(t, &avatarURL, resp.AvatarURL)
		assert.Equal(t, &fedType, resp.FederationType)
		assert.True(t, resp.IsActive)
		assert.True(t, resp.IsEmailVerified)
		assert.False(t, resp.IsLocked)
		assert.Equal(t, "active", resp.ActivationStatus)
		assert.True(t, resp.MFAEnabled)
		assert.Equal(t, &mfaType, resp.MFAType)
		assert.True(t, resp.MFATOTPEnabled)
		assert.False(t, resp.MFAEmailEnabled)
		assert.Equal(t, &mfaPreferred, resp.MFAPreferredMethod)
		assert.Equal(t, &lastLogin, resp.LastLoginAt)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
	})

	t.Run("should NOT include PasswordHash in response", func(t *testing.T) {
		hash := "$2a$10$secrethash"
		u := &User{
			ID:           uuid.New(),
			TenantID:     uuid.New(),
			Username:     "alice",
			Email:        "alice@example.com",
			PasswordHash: &hash,
		}

		// Marshal the response: PasswordHash must not appear.
		resp := u.ToResponse()
		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &m))

		assert.NotContains(t, m, "password_hash",
			"PasswordHash must not be serialised in UserResponse")
		assert.NotContains(t, m, "password",
			"password must not appear in UserResponse")
	})

	t.Run("should NOT include MFASecret in response", func(t *testing.T) {
		secret := "TOTP_SECRET_BASE32"
		u := &User{
			ID:        uuid.New(),
			TenantID:  uuid.New(),
			Username:  "alice",
			Email:     "alice@example.com",
			MFASecret: &secret,
		}

		resp := u.ToResponse()
		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &m))

		assert.NotContains(t, m, "mfa_secret",
			"MFASecret must not be serialised in UserResponse")
	})

	t.Run("should NOT include EmailHash in response", func(t *testing.T) {
		u := &User{
			ID:        uuid.New(),
			TenantID:  uuid.New(),
			Username:  "alice",
			Email:     "alice@example.com",
			EmailHash: "sha256-hash-of-email",
		}

		resp := u.ToResponse()
		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &m))

		assert.NotContains(t, m, "email_hash",
			"EmailHash must not be serialised in UserResponse")
	})

	t.Run("should NOT include FailedLoginAttempts in response", func(t *testing.T) {
		u := &User{
			ID:                  uuid.New(),
			TenantID:            uuid.New(),
			Username:            "alice",
			Email:               "alice@example.com",
			FailedLoginAttempts: 5,
		}

		resp := u.ToResponse()
		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &m))

		assert.NotContains(t, m, "failed_login_attempts",
			"FailedLoginAttempts must not be serialised in UserResponse")
	})

	t.Run("should NOT include LastFailedLoginAt in response", func(t *testing.T) {
		lastFailed := time.Now().Add(-5 * time.Minute)
		u := &User{
			ID:                uuid.New(),
			TenantID:          uuid.New(),
			Username:          "alice",
			Email:             "alice@example.com",
			LastFailedLoginAt: &lastFailed,
		}

		resp := u.ToResponse()
		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &m))

		assert.NotContains(t, m, "last_failed_login_at",
			"LastFailedLoginAt must not be serialised in UserResponse")
	})

	t.Run("should include roles in response", func(t *testing.T) {
		roleID := uuid.New()
		u := &User{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			Username: "alice",
			Email:    "alice@example.com",
			Roles: []Role{
				{
					ID:          roleID,
					TenantID:    uuid.New(),
					Name:        "admin",
					DisplayName: "Administrator",
				},
			},
		}

		resp := u.ToResponse()
		require.NotNil(t, resp)
		require.Len(t, resp.Roles, 1, "response must include one role")
		assert.Equal(t, roleID, resp.Roles[0].ID)
		assert.Equal(t, "admin", resp.Roles[0].Name)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		u := &User{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			Username: "alice",
			Email:    "alice@example.com",
		}

		resp1 := u.ToResponse()
		resp2 := u.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})

	t.Run("should handle nil optional pointer fields", func(t *testing.T) {
		u := &User{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			Username: "alice",
			Email:    "alice@example.com",
		}

		resp := u.ToResponse()
		require.NotNil(t, resp)

		assert.Nil(t, resp.FirstName)
		assert.Nil(t, resp.LastName)
		assert.Nil(t, resp.DisplayName)
		assert.Nil(t, resp.Phone)
		assert.Nil(t, resp.Department)
		assert.Nil(t, resp.Title)
		assert.Nil(t, resp.AvatarURL)
		assert.Nil(t, resp.FederationType)
		assert.Nil(t, resp.MFAType)
		assert.Nil(t, resp.MFAPreferredMethod)
		assert.Nil(t, resp.LastLoginAt)
		assert.Empty(t, resp.Roles)
		assert.Empty(t, resp.Permissions)
	})
}

// ==================== User JSON serialisation (model-level json:"-" tags) ====================

func TestUser_JSONMarshal_SensitiveFieldsExcluded(t *testing.T) {
	hash := "$2a$10$examplePasswordHash"
	secret := "TOTP_BASE32_SECRET" //nolint:gosec // test fixture value, not a real credential
	lastFailed := time.Now().Add(-1 * time.Minute)

	u := &User{
		ID:                  uuid.New(),
		TenantID:            uuid.New(),
		Username:            "alice",
		Email:               "alice@example.com",
		EmailHash:           "sha256hashedvalue",
		PasswordHash:        &hash,
		MFASecret:           &secret,
		FailedLoginAttempts: 3,
		LastFailedLoginAt:   &lastFailed,
	}

	data, err := json.Marshal(u)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &m))

	// Fields with json:"-" must not appear.
	assert.NotContains(t, m, "email_hash",
		"EmailHash (json:\"-\") must be omitted from JSON")
	assert.NotContains(t, m, "password_hash",
		"PasswordHash (json:\"-\") must be omitted from JSON")
	assert.NotContains(t, m, "mfa_secret",
		"MFASecret (json:\"-\") must be omitted from JSON")
	assert.NotContains(t, m, "failed_login_attempts",
		"FailedLoginAttempts (json:\"-\") must be omitted from JSON")
	assert.NotContains(t, m, "last_failed_login_at",
		"LastFailedLoginAt (json:\"-\") must be omitted from JSON")

	// Public fields must still be present.
	assert.Contains(t, m, "id")
	assert.Contains(t, m, "username")
	assert.Contains(t, m, "email")
}

// ==================== User.GetFullName ====================

func TestUser_GetFullName(t *testing.T) {
	tests := []struct {
		name     string
		user     User
		expected string
	}{
		{
			name: "should return display_name when set and non-empty",
			user: User{
				Username:    "alice",
				FirstName:   strPtr("Alice"),
				LastName:    strPtr("Smith"),
				DisplayName: strPtr("Alice S."),
			},
			expected: "Alice S.",
		},
		{
			name: "should fall back to first+last when display_name is nil",
			user: User{
				Username:  "alice",
				FirstName: strPtr("Alice"),
				LastName:  strPtr("Smith"),
			},
			expected: "Alice Smith",
		},
		{
			name: "should fall back to first+last when display_name is empty string",
			user: User{
				Username:    "alice",
				FirstName:   strPtr("Alice"),
				LastName:    strPtr("Smith"),
				DisplayName: strPtr(""),
			},
			expected: "Alice Smith",
		},
		{
			name: "should use only first name when last name is nil",
			user: User{
				Username:  "alice",
				FirstName: strPtr("Alice"),
			},
			expected: "Alice ",
		},
		{
			name: "should use only last name when first name is nil",
			user: User{
				Username: "alice",
				LastName: strPtr("Smith"),
			},
			expected: " Smith",
		},
		{
			name: "should fall back to username when first and last name are both nil",
			user: User{
				Username: "alice",
			},
			expected: "alice",
		},
		{
			name: "should fall back to username when first and last name are both empty",
			user: User{
				Username:  "alice",
				FirstName: strPtr(""),
				LastName:  strPtr(""),
			},
			expected: "alice",
		},
		{
			name: "display_name takes priority over first+last and username",
			user: User{
				Username:    "alice",
				FirstName:   strPtr("Alice"),
				LastName:    strPtr("Smith"),
				DisplayName: strPtr("Alicia"),
			},
			expected: "Alicia",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.user.GetFullName())
		})
	}
}

// ==================== GetFullName is deterministic ====================

func TestUser_GetFullName_Deterministic(t *testing.T) {
	u := &User{
		Username:    "alice",
		FirstName:   strPtr("Alice"),
		DisplayName: strPtr("Alicia"),
	}

	first := u.GetFullName()
	second := u.GetFullName()
	assert.Equal(t, first, second, "GetFullName must be deterministic")
}

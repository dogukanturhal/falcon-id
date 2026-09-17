// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validate is a package-level validator for use in auth model tests.
// It mirrors the validator instance gin uses internally: gin reads the
// "binding" struct tag, so we register that same tag name here.
var validate = func() *validator.Validate {
	v := validator.New()
	v.SetTagName("binding")
	return v
}()

// validateStruct runs go-playground/validator on a struct and returns the
// ValidationErrors if any, or nil when the struct is valid.
func validateStruct(t *testing.T, s interface{}) validator.ValidationErrors {
	t.Helper()
	err := validate.Struct(s)
	if err == nil {
		return nil
	}
	var ve validator.ValidationErrors
	require.ErrorAs(t, err, &ve, "expected ValidationErrors, got: %v", err)
	return ve
}

// hasFieldError returns true when the ValidationErrors slice contains at least
// one error for the given field name.
func hasFieldError(ve validator.ValidationErrors, field string) bool {
	for _, fe := range ve {
		if fe.Field() == field {
			return true
		}
	}
	return false
}

// ==================== LoginRequest ====================

func TestLoginRequest_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       LoginRequest
		wantValid bool
		wantField string // first expected invalid field (empty when wantValid=true)
	}{
		{
			name: "valid request with username and password",
			req: LoginRequest{
				Username: "alice",
				Password: "s3cr3t!",
			},
			wantValid: true,
		},
		{
			name: "valid request with all optional fields populated",
			req: LoginRequest{
				Username:           "alice",
				Password:           "s3cr3t!",
				TenantID:           "00000000-0000-0000-0000-000000000001",
				TenantSlug:         "my-tenant",
				RealmID:            "realm-abc",
				MFACode:            "123456",
				PreferredMFAMethod: "totp",
				RememberMe:         true,
				DeviceID:           "device-xyz",
				ClientID:           "client-abc",
			},
			wantValid: true,
		},
		{
			name: "missing username",
			req: LoginRequest{
				Password: "s3cr3t!",
			},
			wantValid: false,
			wantField: "Username",
		},
		{
			name: "missing password",
			req: LoginRequest{
				Username: "alice",
			},
			wantValid: false,
			wantField: "Password",
		},
		{
			name:      "missing both username and password",
			req:       LoginRequest{},
			wantValid: false,
			wantField: "Username",
		},
		{
			name: "username too long (256 chars)",
			req: LoginRequest{
				Username: string(make([]byte, 256)),
				Password: "s3cr3t!",
			},
			wantValid: false,
			wantField: "Username",
		},
		{
			name: "password too long (1025 chars)",
			req: LoginRequest{
				Username: "alice",
				Password: string(make([]byte, 1025)),
			},
			wantValid: false,
			wantField: "Password",
		},
		{
			name: "invalid PreferredMFAMethod value",
			req: LoginRequest{
				Username:           "alice",
				Password:           "s3cr3t!",
				PreferredMFAMethod: "sms", // only totp|email are valid
			},
			wantValid: false,
			wantField: "PreferredMFAMethod",
		},
		{
			name: "PreferredMFAMethod totp is valid",
			req: LoginRequest{
				Username:           "alice",
				Password:           "s3cr3t!",
				PreferredMFAMethod: "totp",
			},
			wantValid: true,
		},
		{
			name: "PreferredMFAMethod email is valid",
			req: LoginRequest{
				Username:           "alice",
				Password:           "s3cr3t!",
				PreferredMFAMethod: "email",
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

// ==================== RefreshRequest ====================

func TestRefreshRequest_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       RefreshRequest
		wantValid bool
		wantField string
	}{
		{
			name:      "valid request with refresh_token",
			req:       RefreshRequest{RefreshToken: "eyJhbGciOi..."}, //nolint:gosec // test fixture value, not a real credential
			wantValid: true,
		},
		{
			name:      "missing refresh_token",
			req:       RefreshRequest{},
			wantValid: false,
			wantField: "RefreshToken",
		},
		{
			name: "refresh_token at max length (4096 bytes) is valid",
			req: RefreshRequest{
				RefreshToken: string(make([]byte, 4096)),
			},
			wantValid: true,
		},
		{
			name: "refresh_token exceeds max length (4097 bytes)",
			req: RefreshRequest{
				RefreshToken: string(make([]byte, 4097)),
			},
			wantValid: false,
			wantField: "RefreshToken",
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

// ==================== PasswordChangeRequest ====================

func TestPasswordChangeRequest_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       PasswordChangeRequest
		wantValid bool
		wantField string
	}{
		{
			name: "valid request",
			req: PasswordChangeRequest{
				CurrentPassword: "oldpass",
				NewPassword:     "newpass8",
			},
			wantValid: true,
		},
		{
			name: "missing current_password",
			req: PasswordChangeRequest{
				NewPassword: "newpass8",
			},
			wantValid: false,
			wantField: "CurrentPassword",
		},
		{
			name: "missing new_password",
			req: PasswordChangeRequest{
				CurrentPassword: "oldpass",
			},
			wantValid: false,
			wantField: "NewPassword",
		},
		{
			name: "new_password too short (7 chars, min is 8)",
			req: PasswordChangeRequest{
				CurrentPassword: "oldpass",
				NewPassword:     "short7!",
			},
			wantValid: false,
			wantField: "NewPassword",
		},
		{
			name: "new_password at minimum length (8 chars)",
			req: PasswordChangeRequest{
				CurrentPassword: "oldpass",
				NewPassword:     "exactly8",
			},
			wantValid: true,
		},
		{
			name: "new_password exceeds max (1025 chars)",
			req: PasswordChangeRequest{
				CurrentPassword: "oldpass",
				NewPassword:     string(make([]byte, 1025)),
			},
			wantValid: false,
			wantField: "NewPassword",
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

// ==================== PasswordResetRequest ====================

func TestPasswordResetRequest_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       PasswordResetRequest
		wantValid bool
		wantField string
	}{
		{
			name:      "valid request with proper email",
			req:       PasswordResetRequest{Email: "user@example.com"},
			wantValid: true,
		},
		{
			name:      "missing email",
			req:       PasswordResetRequest{},
			wantValid: false,
			wantField: "Email",
		},
		{
			name:      "invalid email format - no at sign",
			req:       PasswordResetRequest{Email: "notanemail"},
			wantValid: false,
			wantField: "Email",
		},
		{
			name:      "invalid email format - missing domain",
			req:       PasswordResetRequest{Email: "user@"},
			wantValid: false,
			wantField: "Email",
		},
		{
			name:      "valid subdomain email",
			req:       PasswordResetRequest{Email: "user@mail.example.com"},
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

// ==================== PasswordResetConfirmRequest ====================

func TestPasswordResetConfirmRequest_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       PasswordResetConfirmRequest
		wantValid bool
		wantField string
	}{
		{
			name: "valid request",
			req: PasswordResetConfirmRequest{
				Token:       "reset-token-abc123",
				NewPassword: "newpass8",
			},
			wantValid: true,
		},
		{
			name: "missing token",
			req: PasswordResetConfirmRequest{
				NewPassword: "newpass8",
			},
			wantValid: false,
			wantField: "Token",
		},
		{
			name: "missing new_password",
			req: PasswordResetConfirmRequest{
				Token: "reset-token-abc123",
			},
			wantValid: false,
			wantField: "NewPassword",
		},
		{
			name: "new_password too short (7 chars, min is 8)",
			req: PasswordResetConfirmRequest{
				Token:       "reset-token-abc123",
				NewPassword: "short7!",
			},
			wantValid: false,
			wantField: "NewPassword",
		},
		{
			name: "token at max length (512 chars) is valid",
			req: PasswordResetConfirmRequest{
				Token:       string(make([]byte, 512)),
				NewPassword: "newpass8",
			},
			wantValid: true,
		},
		{
			name: "token exceeds max (513 chars)",
			req: PasswordResetConfirmRequest{
				Token:       string(make([]byte, 513)),
				NewPassword: "newpass8",
			},
			wantValid: false,
			wantField: "Token",
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

// ==================== MFASetupRequest ====================

func TestMFASetupRequest_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       MFASetupRequest
		wantValid bool
		wantField string
	}{
		{
			name:      "valid request with type totp",
			req:       MFASetupRequest{Type: "totp"},
			wantValid: true,
		},
		{
			name:      "valid request with type sms",
			req:       MFASetupRequest{Type: "sms"},
			wantValid: true,
		},
		{
			name:      "valid request with type email",
			req:       MFASetupRequest{Type: "email"},
			wantValid: true,
		},
		{
			name:      "missing type",
			req:       MFASetupRequest{},
			wantValid: false,
			wantField: "Type",
		},
		{
			name:      "invalid type value",
			req:       MFASetupRequest{Type: "authenticator"},
			wantValid: false,
			wantField: "Type",
		},
		{
			name:      "type with uppercase is invalid (oneof is case-sensitive)",
			req:       MFASetupRequest{Type: "TOTP"},
			wantValid: false,
			wantField: "Type",
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

// ==================== Claims.IsImpersonated ====================

func TestClaims_IsImpersonated(t *testing.T) {
	impersonatorID := uuid.New()
	impersonationSessionID := uuid.New()

	tests := []struct {
		name     string
		claims   Claims
		expected bool
	}{
		{
			name:     "should return false when ImpersonatorID is nil",
			claims:   Claims{},
			expected: false,
		},
		{
			name: "should return true when ImpersonatorID is set",
			claims: Claims{
				ImpersonatorID: &impersonatorID,
			},
			expected: true,
		},
		{
			name: "should return true when both ImpersonatorID and ImpersonationSessionID are set",
			claims: Claims{
				ImpersonatorID:         &impersonatorID,
				ImpersonationSessionID: &impersonationSessionID,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.claims.IsImpersonated())
		})
	}
}

// ==================== CurrentUser.HasPermission ====================

func TestCurrentUser_HasPermission(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		check       string
		expected    bool
	}{
		{
			name:        "should return true for exact match",
			permissions: []string{"core:users:read"},
			check:       "core:users:read",
			expected:    true,
		},
		{
			name:        "should return true for wildcard *",
			permissions: []string{"*"},
			check:       "any:permission:here",
			expected:    true,
		},
		{
			name:        "should return true for trailing wildcard pattern",
			permissions: []string{"core:users:*"},
			check:       "core:users:write",
			expected:    true,
		},
		{
			name:        "should return true for mid-segment wildcard",
			permissions: []string{"core:*:read"},
			check:       "core:roles:read",
			expected:    true,
		},
		{
			name:        "should return false when no match",
			permissions: []string{"core:users:read"},
			check:       "core:roles:write",
			expected:    false,
		},
		{
			name:        "should return false for empty permissions list",
			permissions: []string{},
			check:       "core:users:read",
			expected:    false,
		},
		{
			name:        "should match any of multiple permissions",
			permissions: []string{"core:roles:write", "core:users:read"},
			check:       "core:users:read",
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &CurrentUser{Permissions: tt.permissions}
			assert.Equal(t, tt.expected, u.HasPermission(tt.check))
		})
	}
}

// ==================== CurrentUser.HasRole ====================

func TestCurrentUser_HasRole(t *testing.T) {
	tests := []struct {
		name     string
		roles    []string
		check    string
		expected bool
	}{
		{
			name:     "should return true for exact role match",
			roles:    []string{"admin", "user"},
			check:    "admin",
			expected: true,
		},
		{
			name:     "should return false when role is absent",
			roles:    []string{"user"},
			check:    "admin",
			expected: false,
		},
		{
			name:     "should return false for empty roles list",
			roles:    []string{},
			check:    "admin",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &CurrentUser{Roles: tt.roles}
			assert.Equal(t, tt.expected, u.HasRole(tt.check))
		})
	}
}

// ==================== CurrentUser.HasAnyPermission ====================

func TestCurrentUser_HasAnyPermission(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		check       []string
		expected    bool
	}{
		{
			name:        "should return true when at least one permission matches",
			permissions: []string{"core:users:read"},
			check:       []string{"core:users:write", "core:users:read"},
			expected:    true,
		},
		{
			name:        "should return false when none match",
			permissions: []string{"core:roles:read"},
			check:       []string{"core:users:read", "core:users:write"},
			expected:    false,
		},
		{
			name:        "should return false for empty check list",
			permissions: []string{"core:users:read"},
			check:       []string{},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &CurrentUser{Permissions: tt.permissions}
			assert.Equal(t, tt.expected, u.HasAnyPermission(tt.check...))
		})
	}
}

// ==================== CurrentUser.HasAllPermissions ====================

func TestCurrentUser_HasAllPermissions(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		check       []string
		expected    bool
	}{
		{
			name:        "should return true when all permissions present",
			permissions: []string{"core:users:read", "core:users:write"},
			check:       []string{"core:users:read", "core:users:write"},
			expected:    true,
		},
		{
			name:        "should return false when one permission is missing",
			permissions: []string{"core:users:read"},
			check:       []string{"core:users:read", "core:users:write"},
			expected:    false,
		},
		{
			name:        "should return true for empty check list",
			permissions: []string{},
			check:       []string{},
			expected:    true,
		},
		{
			name:        "should return true with wildcard covering all",
			permissions: []string{"*"},
			check:       []string{"core:users:read", "admin:roles:write"},
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &CurrentUser{Permissions: tt.permissions}
			assert.Equal(t, tt.expected, u.HasAllPermissions(tt.check...))
		})
	}
}

// ==================== CurrentUser.IsPlatformTenant ====================

func TestCurrentUser_IsPlatformTenant(t *testing.T) {
	platformID, err := uuid.Parse(HexxlockInternalTenantID)
	require.NoError(t, err, "HexxlockInternalTenantID must be a valid UUID")

	tests := []struct {
		name     string
		tenantID uuid.UUID
		expected bool
	}{
		{
			name:     "should return true for exampletenant tenant ID",
			tenantID: platformID,
			expected: true,
		},
		{
			name:     "should return false for a regular tenant ID",
			tenantID: uuid.New(),
			expected: false,
		},
		{
			name:     "should return false for zero UUID",
			tenantID: uuid.Nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &CurrentUser{TenantID: tt.tenantID}
			assert.Equal(t, tt.expected, u.IsPlatformTenant())
		})
	}
}

// ==================== HexxlockInternalTenantID constant ====================

func TestHexxlockInternalTenantID_IsValidUUID(t *testing.T) {
	parsed, err := uuid.Parse(HexxlockInternalTenantID)
	require.NoError(t, err, "HexxlockInternalTenantID must parse as a valid UUID")
	assert.Equal(t, HexxlockInternalTenantID, parsed.String())
}

// ==================== AuditLog struct field presence ====================

func TestAuditLog_FieldsAndJSONTags(t *testing.T) {
	t.Run("should marshal all public fields to JSON", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		userID := uuid.New()
		username := "alice"
		action := "user.login"
		resourceType := "session"
		resourceID := uuid.New()
		ip := "127.0.0.1"
		userAgent := "Go-Test/1.0"
		errMsg := "invalid credentials"
		now := time.Now().Truncate(time.Second)

		al := &AuditLog{
			ID:           id,
			TenantID:     tenantID,
			UserID:       &userID,
			Username:     &username,
			Action:       action,
			ResourceType: &resourceType,
			ResourceID:   &resourceID,
			Details:      map[string]interface{}{"key": "value"},
			IPAddress:    &ip,
			UserAgent:    &userAgent,
			Success:      false,
			ErrorMessage: &errMsg,
			Archived:     false,
			CreatedAt:    now,
		}

		data, err := json.Marshal(al)
		require.NoError(t, err)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &m))

		assert.Contains(t, m, "id")
		assert.Contains(t, m, "tenant_id")
		assert.Contains(t, m, "user_id")
		assert.Contains(t, m, "username")
		assert.Contains(t, m, "action")
		assert.Contains(t, m, "resource_type")
		assert.Contains(t, m, "resource_id")
		assert.Contains(t, m, "details")
		assert.Contains(t, m, "ip_address")
		assert.Contains(t, m, "success")
		assert.Contains(t, m, "error_message")
		assert.Contains(t, m, "created_at")
	})

	t.Run("should omit nil optional fields from JSON", func(t *testing.T) {
		al := &AuditLog{
			ID:        uuid.New(),
			TenantID:  uuid.New(),
			Action:    "system.startup",
			Success:   true,
			CreatedAt: time.Now(),
		}

		data, err := json.Marshal(al)
		require.NoError(t, err)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &m))

		// Optional pointer fields with omitempty must be absent.
		assert.NotContains(t, m, "user_id")
		assert.NotContains(t, m, "username")
		assert.NotContains(t, m, "resource_type")
		assert.NotContains(t, m, "resource_id")
		assert.NotContains(t, m, "ip_address")
		assert.NotContains(t, m, "user_agent")
		assert.NotContains(t, m, "error_message")
		assert.NotContains(t, m, "archive_date")
		assert.NotContains(t, m, "archive_location")
		assert.NotContains(t, m, "correlation_id")
	})
}

// ==================== matchWildcard (package-private) ====================

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		permission string
		expected   bool
	}{
		{
			name:       "trailing wildcard matches sub-permission",
			pattern:    "core:users:*",
			permission: "core:users:read",
			expected:   true,
		},
		{
			name:       "trailing wildcard matches different action",
			pattern:    "core:users:*",
			permission: "core:users:write",
			expected:   true,
		},
		{
			name:       "trailing wildcard does not match different resource",
			pattern:    "core:users:*",
			permission: "core:roles:read",
			expected:   false,
		},
		{
			name:       "mid-segment wildcard matches any resource",
			pattern:    "core:*:read",
			permission: "core:roles:read",
			expected:   true,
		},
		{
			name:       "mid-segment wildcard does not match different action",
			pattern:    "core:*:read",
			permission: "core:roles:write",
			expected:   false,
		},
		{
			name:       "leading wildcard matches any module",
			pattern:    "*:users:read",
			permission: "admin:users:read",
			expected:   true,
		},
		{
			name:       "exact match without wildcards",
			pattern:    "core:users:read",
			permission: "core:users:read",
			expected:   true,
		},
		{
			name:       "no match without wildcards",
			pattern:    "core:users:read",
			permission: "core:users:write",
			expected:   false,
		},
		{
			name:       "short trailing wildcard pattern",
			pattern:    "core:*",
			permission: "core:users",
			expected:   true,
		},
		{
			name:       "short trailing wildcard does not match different module",
			pattern:    "core:*",
			permission: "admin:users",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, matchWildcard(tt.pattern, tt.permission))
		})
	}
}

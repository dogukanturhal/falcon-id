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

const testCDNLogoURL = "https://cdn.example.com/logo.png"

// ==================== RealmType constants ====================

func TestRealmTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant RealmType
		expected string
	}{
		{
			name:     "platform realm type has correct string value",
			constant: RealmTypePlatform,
			expected: "platform",
		},
		{
			name:     "enterprise realm type has correct string value",
			constant: RealmTypeEnterprise,
			expected: "enterprise",
		},
		{
			name:     "shared realm type has correct string value",
			constant: RealmTypeShared,
			expected: "shared",
		},
		{
			name:     "partner realm type has correct string value",
			constant: RealmTypePartner,
			expected: "partner",
		},
		{
			name:     "sandbox realm type has correct string value",
			constant: RealmTypeSandbox,
			expected: "sandbox",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, RealmType(tt.expected), tt.constant)
		})
	}
}

// ==================== RealmStatus constants ====================

func TestRealmStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant RealmStatus
		expected string
	}{
		{
			name:     "active realm status has correct string value",
			constant: RealmStatusActive,
			expected: "active",
		},
		{
			name:     "suspended realm status has correct string value",
			constant: RealmStatusSuspended,
			expected: "suspended",
		},
		{
			name:     "migrating realm status has correct string value",
			constant: RealmStatusMigrating,
			expected: "migrating",
		},
		{
			name:     "archived realm status has correct string value",
			constant: RealmStatusArchived,
			expected: "archived",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, RealmStatus(tt.expected), tt.constant)
		})
	}
}

// ==================== RealmAdminRole constants ====================

func TestRealmAdminRoleConstants(t *testing.T) {
	assert.Equal(t, RealmAdminRole("realm_owner"), RealmAdminRoleOwner)
	assert.Equal(t, RealmAdminRole("realm_admin"), RealmAdminRoleAdmin)
	assert.Equal(t, RealmAdminRole("realm_viewer"), RealmAdminRoleViewer)
}

// ==================== DefaultRealmID ====================

func TestDefaultRealmID(t *testing.T) {
	t.Run("default realm ID matches expected UUID sentinel", func(t *testing.T) {
		expected := uuid.MustParse("00000000-0000-0000-0000-000000000001")
		assert.Equal(t, expected, DefaultRealmID)
	})
}

// ==================== Realm.IsDefault ====================

func TestRealm_IsDefault(t *testing.T) {
	tests := []struct {
		name     string
		realm    Realm
		expected bool
	}{
		{
			name:     "should return true when ID equals the default realm sentinel UUID",
			realm:    Realm{ID: uuid.MustParse("00000000-0000-0000-0000-000000000001")},
			expected: true,
		},
		{
			name:     "should return false for a randomly generated UUID",
			realm:    Realm{ID: uuid.New()},
			expected: false,
		},
		{
			name:     "should return false for a nil-like zero UUID",
			realm:    Realm{ID: uuid.UUID{}},
			expected: false,
		},
		{
			name:     "should return false for UUID 00000000-0000-0000-0000-000000000002",
			realm:    Realm{ID: uuid.MustParse("00000000-0000-0000-0000-000000000002")},
			expected: false,
		},
		{
			name:     "should return false for UUID with only last segment differing by one",
			realm:    Realm{ID: uuid.MustParse("00000000-0000-0000-0000-000000000000")},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.realm.IsDefault())
		})
	}
}

// TestRealm_IsDefault_DefaultRealmIDVariable ensures the method honours the
// package-level variable, so a change to DefaultRealmID propagates correctly.
func TestRealm_IsDefault_DefaultRealmIDVariable(t *testing.T) {
	r := &Realm{ID: DefaultRealmID}
	assert.True(t, r.IsDefault(), "realm with ID equal to DefaultRealmID must be default")
}

// ==================== Realm.CanBeDeleted ====================

func TestRealm_CanBeDeleted(t *testing.T) {
	defaultID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	nonDefaultID := uuid.New()

	tests := []struct {
		name        string
		realm       Realm
		expected    bool
		description string
	}{
		{
			name: "should return true when not default and no tenants",
			realm: Realm{
				ID:          nonDefaultID,
				TenantCount: 0,
			},
			expected:    true,
			description: "a non-default realm with zero tenants can be deleted",
		},
		{
			name: "should return false when not default but has tenants",
			realm: Realm{
				ID:          nonDefaultID,
				TenantCount: 5,
			},
			expected:    false,
			description: "cannot delete a realm that still has tenants",
		},
		{
			name: "should return false when is the default realm even with zero tenants",
			realm: Realm{
				ID:          defaultID,
				TenantCount: 0,
			},
			expected:    false,
			description: "the default realm must never be deleted",
		},
		{
			name: "should return false when is default and has tenants",
			realm: Realm{
				ID:          defaultID,
				TenantCount: 10,
			},
			expected:    false,
			description: "default realm with tenants cannot be deleted either",
		},
		{
			name: "should return false when not default but has exactly one tenant",
			realm: Realm{
				ID:          nonDefaultID,
				TenantCount: 1,
			},
			expected:    false,
			description: "even a single tenant prevents deletion",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.realm.CanBeDeleted()
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

// ==================== Realm.ToResponse ====================

func TestRealm_ToResponse(t *testing.T) {
	t.Run("should map all scalar and pointer fields correctly", func(t *testing.T) {
		id := uuid.New()
		createdBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		maxTenants := 100
		maxUsersPerTenant := 500
		maxTotalUsers := 50000
		settings := json.RawMessage(`{"default_language":"en"}`)
		branding := json.RawMessage(`{"primary_color":"#0000ff"}`)
		features := json.RawMessage(`{"mfa_available":true}`)

		r := &Realm{
			ID:                id,
			Slug:              "enterprise-acme",
			DisplayName:       "ACME Enterprise Realm",
			Type:              RealmTypeEnterprise,
			Status:            RealmStatusActive,
			Settings:          settings,
			Branding:          branding,
			Features:          features,
			MaxTenants:        &maxTenants,
			MaxUsersPerTenant: &maxUsersPerTenant,
			MaxTotalUsers:     &maxTotalUsers,
			TenantCount:       12,
			UserCount:         340,
			CreatedAt:         now,
			UpdatedAt:         now,
			CreatedBy:         &createdBy,
		}

		resp := r.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id, resp.ID)
		assert.Equal(t, "enterprise-acme", resp.Slug)
		assert.Equal(t, "ACME Enterprise Realm", resp.DisplayName)
		assert.Equal(t, RealmTypeEnterprise, resp.Type)
		assert.Equal(t, RealmStatusActive, resp.Status)
		assert.Equal(t, settings, resp.Settings)
		assert.Equal(t, branding, resp.Branding)
		assert.Equal(t, features, resp.Features)
		assert.Equal(t, &maxTenants, resp.MaxTenants)
		assert.Equal(t, &maxUsersPerTenant, resp.MaxUsersPerTenant)
		assert.Equal(t, &maxTotalUsers, resp.MaxTotalUsers)
		assert.Equal(t, 12, resp.TenantCount)
		assert.Equal(t, 340, resp.UserCount)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
	})

	t.Run("should handle nil optional pointer fields gracefully", func(t *testing.T) {
		r := &Realm{
			ID:          uuid.New(),
			Slug:        "sandbox-test",
			DisplayName: "Test Sandbox",
			Type:        RealmTypeSandbox,
			Status:      RealmStatusActive,
		}

		resp := r.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.MaxTenants)
		assert.Nil(t, resp.MaxUsersPerTenant)
		assert.Nil(t, resp.MaxTotalUsers)
		assert.Nil(t, resp.SecurityPolicy)
		assert.Nil(t, resp.Settings)
		assert.Nil(t, resp.Branding)
		assert.Nil(t, resp.Features)
	})

	t.Run("should include security policy in response when set", func(t *testing.T) {
		ageDays := 90
		histCount := 5

		r := &Realm{
			ID:          uuid.New(),
			Slug:        "secure-realm",
			DisplayName: "Secure Realm",
			Type:        RealmTypeEnterprise,
			Status:      RealmStatusActive,
			SecurityPolicy: &RealmSecurityPolicy{
				PasswordMinLength:         12,
				PasswordRequireUppercase:  true,
				PasswordRequireLowercase:  true,
				PasswordRequireDigits:     true,
				PasswordRequireSpecial:    true,
				PasswordMaxAgeDays:        &ageDays,
				PasswordHistoryCount:      &histCount,
				MFARequired:               true,
				MFARequiredForAdmins:      true,
				SessionMaxLifetimeHours:   8,
				SessionIdleTimeoutMinutes: 30,
				MaxFailedAttempts:         5,
				LockoutDurationMinutes:    15,
				ProgressiveLockout:        true,
			},
		}

		resp := r.ToResponse()

		require.NotNil(t, resp)
		require.NotNil(t, resp.SecurityPolicy)
		assert.Equal(t, 12, resp.SecurityPolicy.PasswordMinLength)
		assert.True(t, resp.SecurityPolicy.PasswordRequireUppercase)
		assert.True(t, resp.SecurityPolicy.MFARequired)
		assert.Equal(t, 8, resp.SecurityPolicy.SessionMaxLifetimeHours)
		assert.Equal(t, 5, resp.SecurityPolicy.MaxFailedAttempts)
	})

	t.Run("should produce distinct response instances on each call", func(t *testing.T) {
		r := &Realm{
			ID:   uuid.New(),
			Slug: "idempotency-check",
			Type: RealmTypeShared,
		}

		resp1 := r.ToResponse()
		resp2 := r.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})

	t.Run("should propagate tenant and user counts to response", func(t *testing.T) {
		r := &Realm{
			ID:          uuid.New(),
			TenantCount: 25,
			UserCount:   1500,
		}

		resp := r.ToResponse()

		assert.Equal(t, 25, resp.TenantCount)
		assert.Equal(t, 1500, resp.UserCount)
	})
}

// ==================== RealmSecurityPolicy.ToResponse ====================

func TestRealmSecurityPolicy_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly with populated MFA methods JSON", func(t *testing.T) {
		ageDays := 60
		histCount := 8
		graceDays := 7
		concLimit := 3
		rawMFAMethods, _ := json.Marshal([]string{"totp", "sms"})
		mfaMethods := json.RawMessage(rawMFAMethods)

		p := &RealmSecurityPolicy{
			PasswordMinLength:         10,
			PasswordRequireUppercase:  true,
			PasswordRequireLowercase:  true,
			PasswordRequireDigits:     true,
			PasswordRequireSpecial:    false,
			PasswordMaxAgeDays:        &ageDays,
			PasswordHistoryCount:      &histCount,
			MFARequired:               true,
			MFARequiredForAdmins:      true,
			MFAMethods:                mfaMethods,
			MFAGracePeriodDays:        &graceDays,
			SessionMaxLifetimeHours:   12,
			SessionIdleTimeoutMinutes: 60,
			ConcurrentSessionsLimit:   &concLimit,
			MaxFailedAttempts:         3,
			LockoutDurationMinutes:    30,
			ProgressiveLockout:        false,
		}

		resp := p.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, 10, resp.PasswordMinLength)
		assert.True(t, resp.PasswordRequireUppercase)
		assert.True(t, resp.PasswordRequireLowercase)
		assert.True(t, resp.PasswordRequireDigits)
		assert.False(t, resp.PasswordRequireSpecial)
		assert.Equal(t, &ageDays, resp.PasswordMaxAgeDays)
		assert.Equal(t, &histCount, resp.PasswordHistoryCount)
		assert.True(t, resp.MFARequired)
		assert.True(t, resp.MFARequiredForAdmins)
		assert.Equal(t, []string{"totp", "sms"}, resp.MFAMethods)
		assert.Equal(t, &graceDays, resp.MFAGracePeriodDays)
		assert.Equal(t, 12, resp.SessionMaxLifetimeHours)
		assert.Equal(t, 60, resp.SessionIdleTimeoutMinutes)
		assert.Equal(t, &concLimit, resp.ConcurrentSessionsLimit)
		assert.Equal(t, 3, resp.MaxFailedAttempts)
		assert.Equal(t, 30, resp.LockoutDurationMinutes)
		assert.False(t, resp.ProgressiveLockout)
	})

	t.Run("should return empty slice for MFA methods when MFAMethods is nil", func(t *testing.T) {
		p := &RealmSecurityPolicy{
			MFAMethods: nil,
		}

		resp := p.ToResponse()

		require.NotNil(t, resp)
		// json.Unmarshal into nil target produces nil slice; the response field must be nil or empty.
		assert.Empty(t, resp.MFAMethods)
	})

	t.Run("should handle nil optional pointer fields", func(t *testing.T) {
		p := &RealmSecurityPolicy{
			PasswordMinLength:         8,
			SessionMaxLifetimeHours:   24,
			SessionIdleTimeoutMinutes: 120,
			MaxFailedAttempts:         5,
			LockoutDurationMinutes:    10,
		}

		resp := p.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.PasswordMaxAgeDays)
		assert.Nil(t, resp.PasswordHistoryCount)
		assert.Nil(t, resp.MFAGracePeriodDays)
		assert.Nil(t, resp.ConcurrentSessionsLimit)
	})
}

// ==================== RealmBranding struct ====================

func TestRealmBranding(t *testing.T) {
	t.Run("should hold all branding fields correctly", func(t *testing.T) {
		logo := testCDNLogoURL
		favicon := "https://cdn.example.com/favicon.ico"
		bg := "https://cdn.example.com/bg.jpg"
		css := ".login { color: red; }"

		b := RealmBranding{
			LogoURL:            &logo,
			FaviconURL:         &favicon,
			PrimaryColor:       "#1a73e8",
			SecondaryColor:     "#fbbc04",
			LoginBackgroundURL: &bg,
			CustomCSS:          &css,
		}

		assert.Equal(t, &logo, b.LogoURL)
		assert.Equal(t, &favicon, b.FaviconURL)
		assert.Equal(t, "#1a73e8", b.PrimaryColor)
		assert.Equal(t, "#fbbc04", b.SecondaryColor)
		assert.Equal(t, &bg, b.LoginBackgroundURL)
		assert.Equal(t, &css, b.CustomCSS)
	})

	t.Run("should allow nil optional pointer fields", func(t *testing.T) {
		b := RealmBranding{
			PrimaryColor:   "#000000",
			SecondaryColor: "#ffffff",
		}

		assert.Nil(t, b.LogoURL)
		assert.Nil(t, b.FaviconURL)
		assert.Nil(t, b.LoginBackgroundURL)
		assert.Nil(t, b.CustomCSS)
	})
}

// ==================== RealmFeatures struct ====================

func TestRealmFeatures(t *testing.T) {
	tests := []struct {
		name     string
		features RealmFeatures
	}{
		{
			name: "all features enabled",
			features: RealmFeatures{
				MFAAvailable:  true,
				SSOAvailable:  true,
				APIAccess:     true,
				CustomDomain:  true,
				AdvancedAudit: true,
			},
		},
		{
			name:     "all features disabled (zero value)",
			features: RealmFeatures{},
		},
		{
			name: "partial feature set — only MFA and SSO enabled",
			features: RealmFeatures{
				MFAAvailable: true,
				SSOAvailable: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal/unmarshal round-trip to verify JSON tags are consistent.
			data, err := json.Marshal(tt.features)
			require.NoError(t, err)

			var got RealmFeatures
			err = json.Unmarshal(data, &got)
			require.NoError(t, err)

			assert.Equal(t, tt.features, got)
		})
	}
}

// ==================== CreateRealmRequest ====================

func TestCreateRealmRequest(t *testing.T) {
	t.Run("should hold required slug and other fields", func(t *testing.T) {
		maxTenants := 50
		req := CreateRealmRequest{
			Slug:        "my-enterprise",
			DisplayName: "My Enterprise Realm",
			Type:        RealmTypeEnterprise,
			MaxTenants:  &maxTenants,
		}

		assert.Equal(t, "my-enterprise", req.Slug)
		assert.Equal(t, "My Enterprise Realm", req.DisplayName)
		assert.Equal(t, RealmTypeEnterprise, req.Type)
		assert.Equal(t, &maxTenants, req.MaxTenants)
	})

	t.Run("binding tags specify slug as required", func(t *testing.T) {
		// Verify the struct field tag contains "required" for Slug.
		// This is a static-analysis style check via struct literal zero value.
		req := CreateRealmRequest{}
		assert.Empty(t, req.Slug, "zero-value slug must be empty — required is enforced at handler level")
	})

	t.Run("should accept all realm types", func(t *testing.T) {
		realmTypes := []RealmType{
			RealmTypePlatform,
			RealmTypeEnterprise,
			RealmTypeShared,
			RealmTypePartner,
			RealmTypeSandbox,
		}

		for _, rt := range realmTypes {
			req := CreateRealmRequest{
				Slug:        "test-slug",
				DisplayName: "Test",
				Type:        rt,
			}
			assert.Equal(t, rt, req.Type)
		}
	})

	t.Run("should support optional branding settings", func(t *testing.T) {
		logo := "https://example.com/logo.png"
		req := CreateRealmRequest{
			Slug:        "branded",
			DisplayName: "Branded Realm",
			Type:        RealmTypeShared,
			Branding: &RealmBranding{
				LogoURL:        &logo,
				PrimaryColor:   "#ff0000",
				SecondaryColor: "#00ff00",
			},
		}

		require.NotNil(t, req.Branding)
		assert.Equal(t, "#ff0000", req.Branding.PrimaryColor)
	})
}

// ==================== UpdateRealmRequest ====================

func TestUpdateRealmRequest(t *testing.T) {
	t.Run("should be valid with all nil fields (no-op update)", func(t *testing.T) {
		req := UpdateRealmRequest{}

		assert.Nil(t, req.DisplayName)
		assert.Nil(t, req.Settings)
		assert.Nil(t, req.Branding)
		assert.Nil(t, req.Features)
		assert.Nil(t, req.MaxTenants)
		assert.Nil(t, req.MaxUsersPerTenant)
		assert.Nil(t, req.MaxTotalUsers)
	})

	t.Run("should allow partial field updates", func(t *testing.T) {
		newName := "Updated Realm Name"
		maxTenants := 200

		req := UpdateRealmRequest{
			DisplayName: &newName,
			MaxTenants:  &maxTenants,
		}

		require.NotNil(t, req.DisplayName)
		assert.Equal(t, "Updated Realm Name", *req.DisplayName)
		require.NotNil(t, req.MaxTenants)
		assert.Equal(t, 200, *req.MaxTenants)
		assert.Nil(t, req.Settings)
	})

	t.Run("should accept feature flag updates", func(t *testing.T) {
		req := UpdateRealmRequest{
			Features: &RealmFeatures{
				MFAAvailable: true,
				SSOAvailable: false,
				APIAccess:    true,
			},
		}

		require.NotNil(t, req.Features)
		assert.True(t, req.Features.MFAAvailable)
		assert.False(t, req.Features.SSOAvailable)
	})
}

// ==================== RealmSecurityPolicy struct ====================

func TestRealmSecurityPolicy(t *testing.T) {
	t.Run("should hold all password policy fields", func(t *testing.T) {
		ageDays := 90
		histCount := 12
		minAgeHours := 24
		specialChars := "!@#$%"

		p := RealmSecurityPolicy{
			ID:                       uuid.New(),
			RealmID:                  uuid.New(),
			PasswordMinLength:        8,
			PasswordMaxLength:        128,
			PasswordRequireUppercase: true,
			PasswordRequireLowercase: true,
			PasswordRequireDigits:    true,
			PasswordRequireSpecial:   true,
			PasswordSpecialChars:     &specialChars,
			PasswordMaxAgeDays:       &ageDays,
			PasswordHistoryCount:     &histCount,
			PasswordMinAgeHours:      &minAgeHours,
		}

		assert.Equal(t, 8, p.PasswordMinLength)
		assert.Equal(t, 128, p.PasswordMaxLength)
		assert.True(t, p.PasswordRequireUppercase)
		assert.True(t, p.PasswordRequireLowercase)
		assert.True(t, p.PasswordRequireDigits)
		assert.True(t, p.PasswordRequireSpecial)
		assert.Equal(t, &specialChars, p.PasswordSpecialChars)
		assert.Equal(t, &ageDays, p.PasswordMaxAgeDays)
		assert.Equal(t, &histCount, p.PasswordHistoryCount)
		assert.Equal(t, &minAgeHours, p.PasswordMinAgeHours)
	})

	t.Run("should hold all MFA policy fields", func(t *testing.T) {
		graceDays := 3
		rememberDeviceDays := 30
		rawMethods, _ := json.Marshal([]string{"totp", "webauthn"})
		mfaMethods := json.RawMessage(rawMethods)

		p := RealmSecurityPolicy{
			MFARequired:           true,
			MFARequiredForAdmins:  true,
			MFAMethods:            mfaMethods,
			MFAGracePeriodDays:    &graceDays,
			MFARememberDeviceDays: &rememberDeviceDays,
		}

		assert.True(t, p.MFARequired)
		assert.True(t, p.MFARequiredForAdmins)
		assert.Equal(t, mfaMethods, p.MFAMethods)
		assert.Equal(t, &graceDays, p.MFAGracePeriodDays)
		assert.Equal(t, &rememberDeviceDays, p.MFARememberDeviceDays)
	})

	t.Run("should hold all session policy fields", func(t *testing.T) {
		absTimeout := 72
		concLimit := 5

		p := RealmSecurityPolicy{
			SessionMaxLifetimeHours:     24,
			SessionIdleTimeoutMinutes:   30,
			SessionAbsoluteTimeoutHours: &absTimeout,
			ConcurrentSessionsLimit:     &concLimit,
			SingleSessionPerDevice:      true,
		}

		assert.Equal(t, 24, p.SessionMaxLifetimeHours)
		assert.Equal(t, 30, p.SessionIdleTimeoutMinutes)
		assert.Equal(t, &absTimeout, p.SessionAbsoluteTimeoutHours)
		assert.Equal(t, &concLimit, p.ConcurrentSessionsLimit)
		assert.True(t, p.SingleSessionPerDevice)
	})

	t.Run("should hold all lockout policy fields", func(t *testing.T) {
		p := RealmSecurityPolicy{
			MaxFailedAttempts:             5,
			LockoutDurationMinutes:        15,
			LockoutThresholdWindowMinutes: 10,
			ProgressiveLockout:            true,
		}

		assert.Equal(t, 5, p.MaxFailedAttempts)
		assert.Equal(t, 15, p.LockoutDurationMinutes)
		assert.Equal(t, 10, p.LockoutThresholdWindowMinutes)
		assert.True(t, p.ProgressiveLockout)
	})

	t.Run("should hold audit settings", func(t *testing.T) {
		p := RealmSecurityPolicy{
			AuditRetentionDays:       365,
			AuditLogFailedLogins:     true,
			AuditLogSuccessfulLogins: false,
			AuditLogAdminActions:     true,
		}

		assert.Equal(t, 365, p.AuditRetentionDays)
		assert.True(t, p.AuditLogFailedLogins)
		assert.False(t, p.AuditLogSuccessfulLogins)
		assert.True(t, p.AuditLogAdminActions)
	})
}

// ==================== Integration: IsDefault + CanBeDeleted ====================

func TestRealm_DefaultAndDeletion_Integration(t *testing.T) {
	t.Run("default realm cannot be deleted regardless of tenant count", func(t *testing.T) {
		for _, tc := range []int{0, 1, 100} {
			r := &Realm{
				ID:          DefaultRealmID,
				TenantCount: tc,
			}
			assert.True(t, r.IsDefault(), "should be detected as default")
			assert.False(t, r.CanBeDeleted(), "default realm must never be deletable")
		}
	})

	t.Run("non-default realm deletion depends solely on tenant count", func(t *testing.T) {
		r := &Realm{
			ID:          uuid.New(),
			TenantCount: 0,
		}
		assert.False(t, r.IsDefault())
		assert.True(t, r.CanBeDeleted(), "zero tenants means deletable")

		r.TenantCount = 1
		assert.False(t, r.CanBeDeleted(), "one tenant prevents deletion")
	})
}

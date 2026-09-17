// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testNameAlice         = "Alice"
	testIPAddr192_168_1_1 = "192.168.1.1"
	testHTTPPOST          = "POST"
)

// ==================== PlatformAdminRole constants ====================

func TestPlatformAdminRoleConstants(t *testing.T) {
	assert.Equal(t, PlatformAdminRole("super_admin"), PlatformAdminRoleSuperAdmin)
	assert.Equal(t, PlatformAdminRole("support_admin"), PlatformAdminRoleSupportAdmin)
	assert.Equal(t, PlatformAdminRole("billing_admin"), PlatformAdminRoleBillingAdmin)
	assert.Equal(t, PlatformAdminRole("ops_admin"), PlatformAdminRoleOpsAdmin)
	assert.Equal(t, PlatformAdminRole("developer"), PlatformAdminRoleDeveloper)
}

// buildPlatformAdmin returns a fully populated PlatformAdmin for use in tests.
func buildPlatformAdmin() *PlatformAdmin {
	id := uuid.New()
	createdBy := uuid.New()
	updatedBy := uuid.New()
	now := time.Now().Truncate(time.Second)
	firstName := testNameAlice
	lastName := "Admin"
	mfaSecret := "JBSWY3DPEHPK3PXP" //nolint:gosec // test fixture value, not a real credential
	lockedUntil := now.Add(15 * time.Minute)
	lockReason := "too many failures"
	lastLoginAt := now.Add(-1 * time.Hour)
	lastLoginIP := testIPAddr192_168_1_1

	return &PlatformAdmin{ //nolint:gosec // test fixture value, not a real credential
		ID:                  id,
		Email:               "alice@example.com",
		PasswordHash:        "$2a$10$hashedpassword",
		FirstName:           &firstName,
		LastName:            &lastName,
		Role:                PlatformAdminRoleSuperAdmin,
		Permissions:         []string{"*"},
		MFAEnabled:          true,
		MFASecret:           &mfaSecret,
		MFABackupCodes:      []string{"backup1", "backup2"},
		IsActive:            true,
		IsLocked:            false,
		LockedUntil:         &lockedUntil,
		LockReason:          &lockReason,
		LastLoginAt:         &lastLoginAt,
		LastLoginIP:         &lastLoginIP,
		FailedLoginAttempts: 0,
		CreatedAt:           now,
		UpdatedAt:           now,
		CreatedBy:           &createdBy,
		UpdatedBy:           &updatedBy,
	}
}

// ==================== PlatformAdmin.HasPermission ====================

func TestPlatformAdmin_HasPermission(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		check       string
		expected    bool
	}{
		{
			name:        "should return true for global wildcard permission",
			permissions: []string{"*"},
			check:       "tenants.read",
			expected:    true,
		},
		{
			name:        "should return true for exact permission match",
			permissions: []string{"tenants.read", "users.write"},
			check:       "tenants.read",
			expected:    true,
		},
		{
			name:        "should return false when permission not in list",
			permissions: []string{"tenants.read"},
			check:       "users.write",
			expected:    false,
		},
		{
			name:        "should return true for wildcard prefix match (tenants.*)",
			permissions: []string{"tenants.*"},
			check:       "tenants.read",
			expected:    true,
		},
		{
			name:        "should return true for wildcard prefix match (tenants.*) with subpath",
			permissions: []string{"tenants.*"},
			check:       "tenants.suspend",
			expected:    true,
		},
		{
			name:        "should return false when prefix does not match",
			permissions: []string{"tenants.*"},
			check:       "users.read",
			expected:    false,
		},
		{
			name:        "should return true when one of many permissions matches exactly",
			permissions: []string{"billing.read", "users.delete", "tenants.suspend"},
			check:       "users.delete",
			expected:    true,
		},
		{
			name:        "should return false for empty permissions list",
			permissions: []string{},
			check:       "tenants.read",
			expected:    false,
		},
		{
			name:        "should return false for nil permissions list",
			permissions: nil,
			check:       "tenants.read",
			expected:    false,
		},
		{
			name:        "should return false when permission matches prefix but wildcard not set",
			permissions: []string{"tenants.read"},
			check:       "tenants.read.extra",
			expected:    false,
		},
		{
			name:        "should return true for wildcard at category level (billing.*)",
			permissions: []string{"billing.*"},
			check:       "billing.invoices",
			expected:    true,
		},
		{
			name:        "should return false for wildcard-only prefix if check is not within prefix",
			permissions: []string{"billing.*"},
			check:       "billing",
			// "billing" has length equal to prefix "billing." minus wildcard char
			// The prefix is "billing." (len=8), check is "billing" (len=7) — shorter, no match
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			admin := &PlatformAdmin{Permissions: tt.permissions}
			assert.Equal(t, tt.expected, admin.HasPermission(tt.check))
		})
	}
}

func TestPlatformAdmin_HasPermission_MultipleWildcards(t *testing.T) {
	t.Run("should match any permission with global wildcard", func(t *testing.T) {
		admin := &PlatformAdmin{Permissions: []string{"*"}}

		permissions := []string{
			"tenants.read",
			"tenants.write",
			"users.delete",
			"billing.export",
			"system.reboot",
		}

		for _, p := range permissions {
			assert.True(t, admin.HasPermission(p),
				"global wildcard should grant permission %q", p)
		}
	})
}

// ==================== PlatformAdmin.ToResponse ====================

func TestPlatformAdmin_ToResponse(t *testing.T) {
	t.Run("should map all visible fields correctly", func(t *testing.T) {
		admin := buildPlatformAdmin()

		resp := admin.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, admin.ID, resp.ID)
		assert.Equal(t, admin.Email, resp.Email)
		assert.Equal(t, admin.FirstName, resp.FirstName)
		assert.Equal(t, admin.LastName, resp.LastName)
		assert.Equal(t, admin.Role, resp.Role)
		assert.Equal(t, admin.Permissions, resp.Permissions)
		assert.Equal(t, admin.MFAEnabled, resp.MFAEnabled)
		assert.Equal(t, admin.IsActive, resp.IsActive)
		assert.Equal(t, admin.LastLoginAt, resp.LastLoginAt)
		assert.Equal(t, admin.CreatedAt, resp.CreatedAt)
	})

	t.Run("should NOT expose PasswordHash in response", func(t *testing.T) {
		admin := buildPlatformAdmin()
		admin.PasswordHash = "$2a$10$verysecretpasswordhash"

		resp := admin.ToResponse()

		// PlatformAdminResponse has no PasswordHash field — verified at compile time.
		// We verify the response type is correct.
		require.NotNil(t, resp)
		assert.Equal(t, admin.Email, resp.Email)
	})

	t.Run("should NOT expose MFASecret or MFABackupCodes in response", func(t *testing.T) {
		admin := buildPlatformAdmin()
		secret := "TOPSECRETMFASECRET"
		admin.MFASecret = &secret
		admin.MFABackupCodes = []string{"code1", "code2", "code3"}

		resp := admin.ToResponse()

		// PlatformAdminResponse has no MFASecret or MFABackupCodes field.
		require.NotNil(t, resp)
		assert.Equal(t, admin.MFAEnabled, resp.MFAEnabled)
	})

	t.Run("should handle nil optional pointer fields", func(t *testing.T) {
		admin := &PlatformAdmin{
			ID:          uuid.New(),
			Email:       "minimal@hexxlock.com",
			Role:        PlatformAdminRoleDeveloper,
			Permissions: []string{"tenants.read"},
			IsActive:    true,
			CreatedAt:   time.Now(),
		}

		resp := admin.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.FirstName)
		assert.Nil(t, resp.LastName)
		assert.Nil(t, resp.LastLoginAt)
	})

	t.Run("should produce a distinct response instance on each call", func(t *testing.T) {
		admin := buildPlatformAdmin()

		resp1 := admin.ToResponse()
		resp2 := admin.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== PlatformAdminSession ====================

func TestPlatformAdminSession_StructFields(t *testing.T) {
	t.Run("should carry all session fields correctly", func(t *testing.T) {
		id := uuid.New()
		adminID := uuid.New()
		now := time.Now().Truncate(time.Second)
		refreshHash := "refresh-token-hash"
		ip := testIPAddrTen
		ua := testUserAgentMozilla
		deviceInfo := "MacBook Pro"
		refreshExpires := now.Add(7 * 24 * time.Hour)
		revokedAt := now.Add(1 * time.Hour)
		revokedReason := "manual logout"

		session := PlatformAdminSession{
			ID:               id,
			AdminID:          adminID,
			SessionTokenHash: "session-hash-value",
			RefreshTokenHash: &refreshHash,
			IPAddress:        &ip,
			UserAgent:        &ua,
			DeviceInfo:       &deviceInfo,
			ExpiresAt:        now.Add(15 * time.Minute),
			RefreshExpiresAt: &refreshExpires,
			IsRevoked:        true,
			RevokedAt:        &revokedAt,
			RevokedReason:    &revokedReason,
			CreatedAt:        now,
		}

		assert.Equal(t, id, session.ID)
		assert.Equal(t, adminID, session.AdminID)
		assert.Equal(t, "session-hash-value", session.SessionTokenHash)
		assert.Equal(t, &refreshHash, session.RefreshTokenHash)
		assert.Equal(t, &ip, session.IPAddress)
		assert.Equal(t, &ua, session.UserAgent)
		assert.Equal(t, &deviceInfo, session.DeviceInfo)
		assert.True(t, session.IsRevoked)
		assert.Equal(t, &revokedAt, session.RevokedAt)
		assert.Equal(t, &revokedReason, session.RevokedReason)
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		session := PlatformAdminSession{
			ID:               uuid.New(),
			AdminID:          uuid.New(),
			SessionTokenHash: "hash",
			ExpiresAt:        time.Now().Add(15 * time.Minute),
		}

		assert.Nil(t, session.RefreshTokenHash)
		assert.Nil(t, session.IPAddress)
		assert.Nil(t, session.UserAgent)
		assert.Nil(t, session.DeviceInfo)
		assert.Nil(t, session.RefreshExpiresAt)
		assert.Nil(t, session.RevokedAt)
		assert.Nil(t, session.RevokedReason)
	})
}

// ==================== PlatformAdminAuditLog ====================

func TestPlatformAdminAuditLog_StructFields(t *testing.T) {
	t.Run("should carry all audit log fields", func(t *testing.T) {
		id := uuid.New()
		adminID := uuid.New()
		targetID := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		category := "auth"
		targetType := "session"
		method := testHTTPPOST
		path := "/api/v1/admin/login"
		body := `{"email":"admin@example.com"}`
		status := 200
		ip := "127.0.0.1"
		ua := "Go-test"
		details := "successful login"
		durationMs := 42

		log := PlatformAdminAuditLog{
			ID:             id,
			AdminID:        &adminID,
			AdminEmail:     "admin@example.com",
			Action:         "admin_login",
			ActionCategory: &category,
			TargetType:     &targetType,
			TargetID:       &targetID,
			TenantID:       &tenantID,
			RequestMethod:  &method,
			RequestPath:    &path,
			RequestBody:    &body,
			ResponseStatus: &status,
			IPAddress:      &ip,
			UserAgent:      &ua,
			Details:        &details,
			CreatedAt:      now,
			DurationMs:     &durationMs,
		}

		assert.Equal(t, id, log.ID)
		assert.Equal(t, &adminID, log.AdminID)
		assert.Equal(t, "admin@example.com", log.AdminEmail)
		assert.Equal(t, "admin_login", log.Action)
		assert.Equal(t, &category, log.ActionCategory)
		assert.Equal(t, &targetType, log.TargetType)
		assert.Equal(t, &targetID, log.TargetID)
		assert.Equal(t, &tenantID, log.TenantID)
		assert.Equal(t, &method, log.RequestMethod)
		assert.Equal(t, &path, log.RequestPath)
		assert.Equal(t, &body, log.RequestBody)
		assert.Equal(t, &status, log.ResponseStatus)
		assert.Equal(t, &ip, log.IPAddress)
		assert.Equal(t, &ua, log.UserAgent)
		assert.Equal(t, &details, log.Details)
		assert.Equal(t, now, log.CreatedAt)
		assert.Equal(t, &durationMs, log.DurationMs)
	})
}

// ==================== PlatformAdminImpersonation ====================

func TestPlatformAdminImpersonation_StructFields(t *testing.T) {
	t.Run("should carry all impersonation fields", func(t *testing.T) {
		id := uuid.New()
		adminID := uuid.New()
		tenantID := uuid.New()
		impersonatedUserID := uuid.New()
		now := time.Now().Truncate(time.Second)
		revokedAt := now.Add(30 * time.Minute)
		reason := "customer support ticket #12345"
		ticketID := "TICKET-12345"
		actions := "viewed user profile"

		imp := PlatformAdminImpersonation{
			ID:                     id,
			AdminID:                adminID,
			TenantID:               tenantID,
			ImpersonatedUserID:     impersonatedUserID,
			ImpersonatedUserEmail:  "user@example.com",
			ImpersonationTokenHash: "token-hash",
			ExpiresAt:              now.Add(1 * time.Hour),
			IsRevoked:              true,
			RevokedAt:              &revokedAt,
			Reason:                 &reason,
			TicketID:               &ticketID,
			CreatedAt:              now,
			ActionsPerformed:       &actions,
		}

		assert.Equal(t, id, imp.ID)
		assert.Equal(t, adminID, imp.AdminID)
		assert.Equal(t, tenantID, imp.TenantID)
		assert.Equal(t, impersonatedUserID, imp.ImpersonatedUserID)
		assert.Equal(t, "user@example.com", imp.ImpersonatedUserEmail)
		assert.Equal(t, "token-hash", imp.ImpersonationTokenHash)
		assert.True(t, imp.IsRevoked)
		assert.Equal(t, &revokedAt, imp.RevokedAt)
		assert.Equal(t, &reason, imp.Reason)
		assert.Equal(t, &ticketID, imp.TicketID)
		assert.Equal(t, &actions, imp.ActionsPerformed)
	})
}

// ==================== PlatformAdminLoginRequest ====================

func TestPlatformAdminLoginRequest_StructFields(t *testing.T) {
	t.Run("should carry email, password and MFA code", func(t *testing.T) {
		req := PlatformAdminLoginRequest{
			Email:    "admin@example.com",
			Password: "SuperSecret123!",
			MFACode:  "123456",
		}

		assert.Equal(t, "admin@example.com", req.Email)
		assert.Equal(t, "SuperSecret123!", req.Password)
		assert.Equal(t, "123456", req.MFACode)
	})

	t.Run("should allow empty MFACode (optional field)", func(t *testing.T) {
		req := PlatformAdminLoginRequest{
			Email:    "admin@example.com",
			Password: "SecurePass!",
		}

		assert.Empty(t, req.MFACode)
	})
}

// ==================== PlatformAdminLoginResponse ====================

func TestPlatformAdminLoginResponse_StructFields(t *testing.T) {
	t.Run("should carry full login response", func(t *testing.T) {
		adminResp := &PlatformAdminResponse{
			ID:    uuid.New(),
			Email: "admin@example.com",
			Role:  PlatformAdminRoleSuperAdmin,
		}

		resp := PlatformAdminLoginResponse{
			AccessToken:      "access-token-abc",
			RefreshToken:     "refresh-token-xyz",
			TokenType:        "Bearer",
			ExpiresIn:        900,
			RefreshExpiresIn: 604800,
			Admin:            adminResp,
			RequiresMFA:      false,
			SessionID:        "session-123",
		}

		assert.Equal(t, "access-token-abc", resp.AccessToken)
		assert.Equal(t, "refresh-token-xyz", resp.RefreshToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, int64(900), resp.ExpiresIn)
		assert.Equal(t, int64(604800), resp.RefreshExpiresIn)
		assert.Equal(t, adminResp, resp.Admin)
		assert.False(t, resp.RequiresMFA)
		assert.Equal(t, "session-123", resp.SessionID)
	})

	t.Run("should support MFA-required response (no tokens yet)", func(t *testing.T) {
		resp := PlatformAdminLoginResponse{
			RequiresMFA: true,
			SessionID:   "pending-session-123",
		}

		assert.True(t, resp.RequiresMFA)
		assert.Empty(t, resp.AccessToken)
		assert.Nil(t, resp.Admin)
	})
}

// ==================== ImpersonateRequest ====================

func TestImpersonateRequest_StructFields(t *testing.T) {
	t.Run("should carry TenantID, optional UserID, Reason and TicketID", func(t *testing.T) {
		tenantID := uuid.New()
		userID := uuid.New()
		ticketID := "TICKET-789"

		req := ImpersonateRequest{
			TenantID: tenantID,
			UserID:   &userID,
			Reason:   "Diagnosing login issue for customer",
			TicketID: &ticketID,
		}

		assert.Equal(t, tenantID, req.TenantID)
		require.NotNil(t, req.UserID)
		assert.Equal(t, userID, *req.UserID)
		assert.Equal(t, "Diagnosing login issue for customer", req.Reason)
		require.NotNil(t, req.TicketID)
		assert.Equal(t, ticketID, *req.TicketID)
	})

	t.Run("should allow nil UserID and TicketID", func(t *testing.T) {
		req := ImpersonateRequest{
			TenantID: uuid.New(),
			Reason:   "General investigation",
		}

		assert.Nil(t, req.UserID)
		assert.Nil(t, req.TicketID)
	})
}

// ==================== ImpersonateResponse ====================

func TestImpersonateResponse_StructFields(t *testing.T) {
	t.Run("should carry all impersonation response fields", func(t *testing.T) {
		expiresAt := time.Now().Add(1 * time.Hour)

		resp := ImpersonateResponse{
			ImpersonationToken: "impersonation-token-abc",
			TenantID:           uuid.New().String(),
			UserID:             uuid.New().String(),
			UserEmail:          "user@example.com",
			ExpiresIn:          3600,
			ExpiresAt:          expiresAt,
		}

		assert.Equal(t, "impersonation-token-abc", resp.ImpersonationToken)
		assert.NotEmpty(t, resp.TenantID)
		assert.NotEmpty(t, resp.UserID)
		assert.Equal(t, "user@example.com", resp.UserEmail)
		assert.Equal(t, int64(3600), resp.ExpiresIn)
		assert.Equal(t, expiresAt, resp.ExpiresAt)
	})
}

// ==================== PlatformAdminClaims ====================

func TestPlatformAdminClaims_StructFields(t *testing.T) {
	t.Run("should carry all JWT claim fields", func(t *testing.T) {
		adminID := uuid.New()
		sessionID := uuid.New()

		claims := PlatformAdminClaims{
			AdminID:     adminID,
			Email:       "admin@example.com",
			Role:        PlatformAdminRoleSuperAdmin,
			Permissions: []string{"*"},
			SessionID:   sessionID,
			Scope:       "platform",
		}

		assert.Equal(t, adminID, claims.AdminID)
		assert.Equal(t, "admin@example.com", claims.Email)
		assert.Equal(t, PlatformAdminRoleSuperAdmin, claims.Role)
		assert.Equal(t, []string{"*"}, claims.Permissions)
		assert.Equal(t, sessionID, claims.SessionID)
		assert.Equal(t, "platform", claims.Scope)
	})
}

// ==================== ImpersonationClaims ====================

func TestImpersonationClaims_StructFields(t *testing.T) {
	t.Run("should carry admin and impersonated user info", func(t *testing.T) {
		adminID := uuid.New()
		userID := uuid.New()
		tenantID := uuid.New()

		claims := ImpersonationClaims{
			AdminID:         adminID,
			AdminEmail:      "admin@example.com",
			UserID:          userID,
			TenantID:        tenantID,
			IsImpersonation: true,
			Scope:           "impersonation",
		}

		assert.Equal(t, adminID, claims.AdminID)
		assert.Equal(t, "admin@example.com", claims.AdminEmail)
		assert.Equal(t, userID, claims.UserID)
		assert.Equal(t, tenantID, claims.TenantID)
		assert.True(t, claims.IsImpersonation)
		assert.Equal(t, "impersonation", claims.Scope)
	})
}

// ==================== PlatformAdminResponse ====================

func TestPlatformAdminResponse_StructFields(t *testing.T) {
	t.Run("should carry all response fields", func(t *testing.T) {
		id := uuid.New()
		now := time.Now().Truncate(time.Second)
		firstName := "Bob"
		lastName := "Builder"
		lastLogin := now.Add(-2 * time.Hour)

		resp := PlatformAdminResponse{
			ID:          id,
			Email:       "bob@example.com",
			FirstName:   &firstName,
			LastName:    &lastName,
			Role:        PlatformAdminRoleBillingAdmin,
			Permissions: []string{"billing.*"},
			MFAEnabled:  false,
			IsActive:    true,
			LastLoginAt: &lastLogin,
			CreatedAt:   now,
		}

		assert.Equal(t, id, resp.ID)
		assert.Equal(t, "bob@example.com", resp.Email)
		assert.Equal(t, &firstName, resp.FirstName)
		assert.Equal(t, &lastName, resp.LastName)
		assert.Equal(t, PlatformAdminRoleBillingAdmin, resp.Role)
		assert.Equal(t, []string{"billing.*"}, resp.Permissions)
		assert.False(t, resp.MFAEnabled)
		assert.True(t, resp.IsActive)
		assert.Equal(t, &lastLogin, resp.LastLoginAt)
		assert.Equal(t, now, resp.CreatedAt)
	})
}

// ==================== PlatformAdminRefreshRequest ====================

func TestPlatformAdminRefreshRequest_StructFields(t *testing.T) {
	t.Run("should carry RefreshToken", func(t *testing.T) {
		req := PlatformAdminRefreshRequest{ //nolint:gosec // test fixture value, not a real credential
			RefreshToken: "eyJhbGciOiJIUzI1NiJ9.refresh", // gitleaks:allow — JWT-shaped test fixture
		}

		assert.Equal(t, "eyJhbGciOiJIUzI1NiJ9.refresh", req.RefreshToken)
	})
}

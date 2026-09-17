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

// ==================== IAMSettings struct ====================

func buildIAMSettings() *IAMSettings {
	id := uuid.New()
	tenantID := uuid.New()
	updatedBy := uuid.New()
	now := time.Now().Truncate(time.Second)

	return &IAMSettings{
		ID:       id,
		TenantID: tenantID,

		HRLDAPEnabled:      true,
		HRLDAPServer:       "ldap.corp.com",
		HRLDAPPort:         636,
		HRLDAPUseTLS:       true,
		HRLDAPBindDN:       "cn=svc,dc=corp,dc=com",
		HRLDAPBindPassword: "super-secret",
		HRLDAPBaseDN:       "dc=corp,dc=com",
		HRLDAPUserFilter:   "(&(objectClass=user)(sAMAccountName=%s))",
		HRLDAPGroupBaseDN:  "ou=groups,dc=corp,dc=com",
		HRLDAPGroupFilter:  "(&(objectClass=group)(member=%s))",

		ABACEnabled:           true,
		ABACFallbackRBAC:      true,
		RoleExpirationEnabled: true,

		CreatedAt: now,
		UpdatedAt: now,
		UpdatedBy: &updatedBy,
	}
}

func TestIAMSettings_Instantiation(t *testing.T) {
	t.Run("should create a fully populated IAMSettings", func(t *testing.T) {
		s := buildIAMSettings()

		assert.NotEqual(t, uuid.Nil, s.ID)
		assert.NotEqual(t, uuid.Nil, s.TenantID)
		assert.True(t, s.HRLDAPEnabled)
		assert.Equal(t, "ldap.corp.com", s.HRLDAPServer)
		assert.Equal(t, 636, s.HRLDAPPort)
		assert.True(t, s.HRLDAPUseTLS)
		assert.Equal(t, "cn=svc,dc=corp,dc=com", s.HRLDAPBindDN)
		assert.Equal(t, "super-secret", s.HRLDAPBindPassword)
		assert.Equal(t, "dc=corp,dc=com", s.HRLDAPBaseDN)
		assert.NotEmpty(t, s.HRLDAPUserFilter)
		assert.NotEmpty(t, s.HRLDAPGroupBaseDN)
		assert.NotEmpty(t, s.HRLDAPGroupFilter)
		assert.True(t, s.ABACEnabled)
		assert.True(t, s.ABACFallbackRBAC)
		assert.True(t, s.RoleExpirationEnabled)
		require.NotNil(t, s.UpdatedBy)
	})

	t.Run("should create a minimal IAMSettings with LDAP disabled", func(t *testing.T) {
		s := &IAMSettings{
			ID:                    uuid.New(),
			TenantID:              uuid.New(),
			HRLDAPEnabled:         false,
			ABACEnabled:           false,
			ABACFallbackRBAC:      false,
			RoleExpirationEnabled: false,
		}

		assert.False(t, s.HRLDAPEnabled)
		assert.False(t, s.ABACEnabled)
		assert.False(t, s.ABACFallbackRBAC)
		assert.False(t, s.RoleExpirationEnabled)
		assert.Empty(t, s.HRLDAPServer)
		assert.Empty(t, s.HRLDAPBindPassword)
		assert.Nil(t, s.UpdatedBy)
	})

	t.Run("should use standard LDAP port 389 when TLS is not enabled", func(t *testing.T) {
		s := &IAMSettings{
			ID:            uuid.New(),
			TenantID:      uuid.New(),
			HRLDAPEnabled: true,
			HRLDAPServer:  "ldap.corp.com",
			HRLDAPPort:    389,
			HRLDAPUseTLS:  false,
		}

		assert.Equal(t, 389, s.HRLDAPPort)
		assert.False(t, s.HRLDAPUseTLS)
	})

	t.Run("bind password should be stored but not serialized to JSON", func(t *testing.T) {
		s := &IAMSettings{
			ID:                 uuid.New(),
			TenantID:           uuid.New(),
			HRLDAPBindPassword: "my-secret-password",
		}

		data, err := json.Marshal(s)
		require.NoError(t, err)

		// The bind password has json:"-" tag — it MUST NOT appear in JSON output.
		jsonStr := string(data)
		assert.NotContains(t, jsonStr, "my-secret-password",
			"HRLDAPBindPassword must not appear in JSON output due to json:\"-\" tag")
		assert.NotContains(t, jsonStr, "hr_ldap_bind_password",
			"HRLDAPBindPassword field name must not appear in JSON output")
	})
}

// ==================== IAMSettings.ToResponse ====================

func TestIAMSettings_ToResponse(t *testing.T) {
	t.Run("should map all non-sensitive fields correctly", func(t *testing.T) {
		s := buildIAMSettings()
		now := s.CreatedAt

		resp := s.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, s.ID, resp.ID)
		assert.Equal(t, s.TenantID, resp.TenantID)
		assert.Equal(t, s.HRLDAPEnabled, resp.HRLDAPEnabled)
		assert.Equal(t, s.HRLDAPServer, resp.HRLDAPServer)
		assert.Equal(t, s.HRLDAPPort, resp.HRLDAPPort)
		assert.Equal(t, s.HRLDAPUseTLS, resp.HRLDAPUseTLS)
		assert.Equal(t, s.HRLDAPBindDN, resp.HRLDAPBindDN)
		assert.Equal(t, s.HRLDAPBaseDN, resp.HRLDAPBaseDN)
		assert.Equal(t, s.HRLDAPUserFilter, resp.HRLDAPUserFilter)
		assert.Equal(t, s.HRLDAPGroupBaseDN, resp.HRLDAPGroupBaseDN)
		assert.Equal(t, s.HRLDAPGroupFilter, resp.HRLDAPGroupFilter)
		assert.Equal(t, s.ABACEnabled, resp.ABACEnabled)
		assert.Equal(t, s.ABACFallbackRBAC, resp.ABACFallbackRBAC)
		assert.Equal(t, s.RoleExpirationEnabled, resp.RoleExpirationEnabled)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
	})

	t.Run("should NOT expose bind password in response", func(t *testing.T) {
		s := buildIAMSettings()
		s.HRLDAPBindPassword = "ultra-secret-password"

		resp := s.ToResponse()

		require.NotNil(t, resp)
		// GetIAMSettingsResponse has no BindPassword field.
		// Compile-time guarantee. We verify the secret-adjacent HasBindPassword flag instead.
		assert.True(t, resp.HasBindPassword,
			"HasBindPassword should be true when BindPassword is set")
	})

	t.Run("should set HasBindPassword to true when bind password is non-empty", func(t *testing.T) {
		s := &IAMSettings{
			ID:                 uuid.New(),
			TenantID:           uuid.New(),
			HRLDAPBindPassword: "any-password",
		}

		resp := s.ToResponse()

		require.NotNil(t, resp)
		assert.True(t, resp.HasBindPassword)
	})

	t.Run("should set HasBindPassword to false when bind password is empty", func(t *testing.T) {
		s := &IAMSettings{
			ID:                 uuid.New(),
			TenantID:           uuid.New(),
			HRLDAPBindPassword: "",
		}

		resp := s.ToResponse()

		require.NotNil(t, resp)
		assert.False(t, resp.HasBindPassword)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		s := buildIAMSettings()

		resp1 := s.ToResponse()
		resp2 := s.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})

	t.Run("should handle disabled LDAP settings correctly", func(t *testing.T) {
		s := &IAMSettings{
			ID:            uuid.New(),
			TenantID:      uuid.New(),
			HRLDAPEnabled: false,
			ABACEnabled:   false,
		}

		resp := s.ToResponse()

		require.NotNil(t, resp)
		assert.False(t, resp.HRLDAPEnabled)
		assert.False(t, resp.ABACEnabled)
		assert.False(t, resp.HasBindPassword)
	})
}

// ==================== HasBindPassword boundary tests ====================

func TestIAMSettings_HasBindPassword_Boundary(t *testing.T) {
	tests := []struct {
		name            string
		bindPassword    string
		wantHasPassword bool
	}{
		{
			name:            "should report false for empty string",
			bindPassword:    "",
			wantHasPassword: false,
		},
		{
			name:            "should report true for single character password",
			bindPassword:    "x",
			wantHasPassword: true,
		},
		{
			name:            "should report true for minimal realistic password",
			bindPassword:    "pass1234",
			wantHasPassword: true,
		},
		{ //nolint:gosec // test fixture value, not a real credential
			name:            "should report true for long complex password",
			bindPassword:    "Tr0ub4dor&3#SuperSecure!LDAPPassword2026",
			wantHasPassword: true,
		},
		{
			name:            "should report true for password with special characters",
			bindPassword:    "!@#$%^&*()",
			wantHasPassword: true,
		},
		{
			name:            "should report true for password with spaces",
			bindPassword:    "has spaces in it",
			wantHasPassword: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &IAMSettings{
				ID:                 uuid.New(),
				TenantID:           uuid.New(),
				HRLDAPBindPassword: tt.bindPassword,
			}

			resp := s.ToResponse()

			require.NotNil(t, resp)
			assert.Equal(t, tt.wantHasPassword, resp.HasBindPassword)
		})
	}
}

// ==================== GetIAMSettingsResponse struct ====================

func TestGetIAMSettingsResponse_Instantiation(t *testing.T) {
	t.Run("should create a fully populated GetIAMSettingsResponse", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)

		resp := &GetIAMSettingsResponse{
			ID:       uuid.New(),
			TenantID: uuid.New(),

			HRLDAPEnabled:     true,
			HRLDAPServer:      "ldap.corp.com",
			HRLDAPPort:        636,
			HRLDAPUseTLS:      true,
			HRLDAPBindDN:      "cn=svc,dc=corp,dc=com",
			HRLDAPBaseDN:      "dc=corp,dc=com",
			HRLDAPUserFilter:  "(sAMAccountName=%s)",
			HRLDAPGroupBaseDN: "ou=groups,dc=corp,dc=com",
			HRLDAPGroupFilter: "(objectClass=group)",
			HasBindPassword:   true,

			ABACEnabled:           true,
			ABACFallbackRBAC:      false,
			RoleExpirationEnabled: true,

			CreatedAt: now,
			UpdatedAt: now,
		}

		assert.NotEqual(t, uuid.Nil, resp.ID)
		assert.True(t, resp.HRLDAPEnabled)
		assert.Equal(t, "ldap.corp.com", resp.HRLDAPServer)
		assert.Equal(t, 636, resp.HRLDAPPort)
		assert.True(t, resp.HRLDAPUseTLS)
		assert.Equal(t, "cn=svc,dc=corp,dc=com", resp.HRLDAPBindDN)
		assert.True(t, resp.HasBindPassword)
		assert.True(t, resp.ABACEnabled)
		assert.False(t, resp.ABACFallbackRBAC)
		assert.True(t, resp.RoleExpirationEnabled)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
	})

	t.Run("response should not have a raw BindPassword field", func(t *testing.T) {
		// The GetIAMSettingsResponse struct deliberately has no BindPassword field.
		// It only has the safe "has_bind_password" boolean sentinel.
		// We verify that no raw password value leaks into the JSON output.
		resp := &GetIAMSettingsResponse{
			ID:              uuid.New(),
			HasBindPassword: true,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		jsonStr := string(data)
		// The struct has "has_bind_password" (the sentinel) which is allowed.
		// There must NOT be a standalone "hr_ldap_bind_password" key.
		assert.NotContains(t, jsonStr, "\"hr_ldap_bind_password\"",
			"serialized response must not contain an hr_ldap_bind_password field")
		// Also verify that "has_bind_password" IS present (proving the sentinel works).
		assert.Contains(t, jsonStr, "has_bind_password",
			"has_bind_password sentinel should be present in JSON output")
	})
}

// ==================== UpdateIAMSettingsRequest ====================

func TestUpdateIAMSettingsRequest_Fields(t *testing.T) {
	t.Run("should set all LDAP fields for a full update", func(t *testing.T) {
		enabled := true
		server := "newldap.corp.com"
		port := 389
		useTLS := false
		bindDN := "cn=new-svc,dc=corp,dc=com"
		bindPassword := "new-secret"
		baseDN := "dc=corp,dc=com"
		userFilter := "(uid=%s)"
		groupBaseDN := "ou=groups,dc=corp,dc=com"
		groupFilter := "(objectClass=groupOfNames)"

		req := &UpdateIAMSettingsRequest{
			HRLDAPEnabled:      &enabled,
			HRLDAPServer:       &server,
			HRLDAPPort:         &port,
			HRLDAPUseTLS:       &useTLS,
			HRLDAPBindDN:       &bindDN,
			HRLDAPBindPassword: &bindPassword,
			HRLDAPBaseDN:       &baseDN,
			HRLDAPUserFilter:   &userFilter,
			HRLDAPGroupBaseDN:  &groupBaseDN,
			HRLDAPGroupFilter:  &groupFilter,
		}

		require.NotNil(t, req.HRLDAPEnabled)
		assert.True(t, *req.HRLDAPEnabled)
		require.NotNil(t, req.HRLDAPServer)
		assert.Equal(t, "newldap.corp.com", *req.HRLDAPServer)
		require.NotNil(t, req.HRLDAPPort)
		assert.Equal(t, 389, *req.HRLDAPPort)
		require.NotNil(t, req.HRLDAPUseTLS)
		assert.False(t, *req.HRLDAPUseTLS)
		require.NotNil(t, req.HRLDAPBindDN)
		assert.Equal(t, "cn=new-svc,dc=corp,dc=com", *req.HRLDAPBindDN)
		require.NotNil(t, req.HRLDAPBindPassword)
		assert.Equal(t, "new-secret", *req.HRLDAPBindPassword)
		require.NotNil(t, req.HRLDAPBaseDN)
		assert.Equal(t, "dc=corp,dc=com", *req.HRLDAPBaseDN)
		require.NotNil(t, req.HRLDAPUserFilter)
		assert.Equal(t, "(uid=%s)", *req.HRLDAPUserFilter)
		require.NotNil(t, req.HRLDAPGroupBaseDN)
		assert.Equal(t, "ou=groups,dc=corp,dc=com", *req.HRLDAPGroupBaseDN)
		require.NotNil(t, req.HRLDAPGroupFilter)
		assert.Equal(t, "(objectClass=groupOfNames)", *req.HRLDAPGroupFilter)
	})

	t.Run("should set ABAC configuration flags", func(t *testing.T) {
		abacEnabled := true
		abacFallback := false
		roleExpiration := true

		req := &UpdateIAMSettingsRequest{
			ABACEnabled:           &abacEnabled,
			ABACFallbackRBAC:      &abacFallback,
			RoleExpirationEnabled: &roleExpiration,
		}

		require.NotNil(t, req.ABACEnabled)
		assert.True(t, *req.ABACEnabled)
		require.NotNil(t, req.ABACFallbackRBAC)
		assert.False(t, *req.ABACFallbackRBAC)
		require.NotNil(t, req.RoleExpirationEnabled)
		assert.True(t, *req.RoleExpirationEnabled)
	})

	t.Run("should allow a fully nil request (noop patch)", func(t *testing.T) {
		req := &UpdateIAMSettingsRequest{}

		assert.Nil(t, req.HRLDAPEnabled)
		assert.Nil(t, req.HRLDAPServer)
		assert.Nil(t, req.HRLDAPPort)
		assert.Nil(t, req.HRLDAPUseTLS)
		assert.Nil(t, req.HRLDAPBindDN)
		assert.Nil(t, req.HRLDAPBindPassword)
		assert.Nil(t, req.HRLDAPBaseDN)
		assert.Nil(t, req.HRLDAPUserFilter)
		assert.Nil(t, req.HRLDAPGroupBaseDN)
		assert.Nil(t, req.HRLDAPGroupFilter)
		assert.Nil(t, req.ABACEnabled)
		assert.Nil(t, req.ABACFallbackRBAC)
		assert.Nil(t, req.RoleExpirationEnabled)
	})

	t.Run("should disable LDAP with partial update", func(t *testing.T) {
		disabled := false
		req := &UpdateIAMSettingsRequest{
			HRLDAPEnabled: &disabled,
		}

		require.NotNil(t, req.HRLDAPEnabled)
		assert.False(t, *req.HRLDAPEnabled)
		// All other fields remain nil.
		assert.Nil(t, req.HRLDAPServer)
		assert.Nil(t, req.ABACEnabled)
	})

	t.Run("should enable role expiration only", func(t *testing.T) {
		roleExp := true
		req := &UpdateIAMSettingsRequest{
			RoleExpirationEnabled: &roleExp,
		}

		require.NotNil(t, req.RoleExpirationEnabled)
		assert.True(t, *req.RoleExpirationEnabled)
		assert.Nil(t, req.ABACEnabled)
		assert.Nil(t, req.HRLDAPEnabled)
	})
}

// ==================== IAMSettings JSON tag for BindPassword ====================

func TestIAMSettings_BindPassword_JSONTag(t *testing.T) {
	t.Run("HRLDAPBindPassword json dash tag hides value from output", func(t *testing.T) {
		s := &IAMSettings{
			ID:                 uuid.New(),
			TenantID:           uuid.New(),
			HRLDAPEnabled:      true,
			HRLDAPServer:       "ldap.corp.com",
			HRLDAPBindPassword: "this-must-not-appear-in-json",
		}

		data, err := json.Marshal(s)
		require.NoError(t, err)

		jsonStr := string(data)
		assert.Contains(t, jsonStr, "ldap.corp.com",
			"other fields should be present in JSON")
		assert.NotContains(t, jsonStr, "this-must-not-appear-in-json",
			"bind password value must not appear in JSON output")
		assert.NotContains(t, jsonStr, "hr_ldap_bind_password",
			"bind password key must not appear in JSON output (json:\"-\" tag)")
	})

	t.Run("ToResponse HasBindPassword reflects presence without exposing value", func(t *testing.T) {
		// With password set.
		withPassword := &IAMSettings{
			ID:                 uuid.New(),
			HRLDAPBindPassword: "secret123",
		}
		withResp := withPassword.ToResponse()
		assert.True(t, withResp.HasBindPassword)

		// Without password.
		withoutPassword := &IAMSettings{
			ID:                 uuid.New(),
			HRLDAPBindPassword: "",
		}
		withoutResp := withoutPassword.ToResponse()
		assert.False(t, withoutResp.HasBindPassword)
	})
}

// ==================== IAMSettings ABAC configuration ====================

func TestIAMSettings_ABACConfiguration(t *testing.T) {
	tests := []struct {
		name                  string
		abacEnabled           bool
		abacFallbackRBAC      bool
		roleExpirationEnabled bool
	}{
		{
			name:                  "full ABAC with RBAC fallback and role expiration",
			abacEnabled:           true,
			abacFallbackRBAC:      true,
			roleExpirationEnabled: true,
		},
		{
			name:                  "ABAC only without RBAC fallback",
			abacEnabled:           true,
			abacFallbackRBAC:      false,
			roleExpirationEnabled: false,
		},
		{
			name:                  "RBAC only (ABAC disabled)",
			abacEnabled:           false,
			abacFallbackRBAC:      false,
			roleExpirationEnabled: false,
		},
		{
			name:                  "role expiration enabled without ABAC",
			abacEnabled:           false,
			abacFallbackRBAC:      false,
			roleExpirationEnabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &IAMSettings{
				ID:                    uuid.New(),
				TenantID:              uuid.New(),
				ABACEnabled:           tt.abacEnabled,
				ABACFallbackRBAC:      tt.abacFallbackRBAC,
				RoleExpirationEnabled: tt.roleExpirationEnabled,
			}

			resp := s.ToResponse()

			require.NotNil(t, resp)
			assert.Equal(t, tt.abacEnabled, resp.ABACEnabled)
			assert.Equal(t, tt.abacFallbackRBAC, resp.ABACFallbackRBAC)
			assert.Equal(t, tt.roleExpirationEnabled, resp.RoleExpirationEnabled)
		})
	}
}

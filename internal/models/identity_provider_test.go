// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== IdentityProvider type constants ====================

func TestIdentityProviderTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{name: "ldap type string", value: "ldap", expected: "ldap"},
		{name: "saml type string", value: "saml", expected: "saml"},
		{name: "oauth type string", value: "oauth", expected: "oauth"},
		{name: "oidc type string", value: "oidc", expected: "oidc"},
		{name: "google type string", value: "google", expected: "google"},
		{name: "microsoft type string", value: "microsoft", expected: "microsoft"},
		{name: "github type string", value: "github", expected: "github"},
		{name: "apple type string", value: "apple", expected: "apple"},
	}

	// The model uses bare string constants for the type field; we verify that
	// the expected values are what the binding:"oneof=..." tag lists.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := &IdentityProvider{Type: tt.value}
			assert.Equal(t, tt.expected, ip.Type)
		})
	}
}

// ==================== IdentityProvider struct ====================

func buildIdentityProvider() *IdentityProvider {
	id := uuid.New()
	tenantID := uuid.New()
	createdBy := uuid.New()
	clientID := "client-abc"
	secretEnc := "encrypted-secret"
	authURL := "https://idp.example.com/auth"
	tokenURL := "https://idp.example.com/token" //nolint:gosec // test fixture value, not a real credential
	userInfoURL := "https://idp.example.com/userinfo"
	now := time.Now().Truncate(time.Second)

	return &IdentityProvider{
		ID:                    id,
		TenantID:              tenantID,
		Type:                  "oidc",
		Name:                  "company-oidc",
		DisplayName:           "Company SSO",
		IsEnabled:             true,
		Priority:              10,
		ClientID:              &clientID,
		ClientSecretEncrypted: &secretEnc,
		AuthorizationURL:      &authURL,
		TokenURL:              &tokenURL,
		UserInfoURL:           &userInfoURL,
		Scopes:                []string{"openid", "profile", "email"},
		AttributeMapping: map[string]string{
			"email":       "email",
			"given_name":  "first_name",
			"family_name": "last_name",
		},
		AutoProvisionUsers: true,
		DefaultRoleIDs:     []uuid.UUID{uuid.New()},
		CreatedAt:          now,
		UpdatedAt:          now,
		CreatedBy:          &createdBy,
	}
}

func TestIdentityProvider_Instantiation(t *testing.T) {
	t.Run("should create a fully populated IdentityProvider", func(t *testing.T) {
		ip := buildIdentityProvider()

		assert.NotEqual(t, uuid.Nil, ip.ID)
		assert.NotEqual(t, uuid.Nil, ip.TenantID)
		assert.Equal(t, "oidc", ip.Type)
		assert.Equal(t, "company-oidc", ip.Name)
		assert.Equal(t, "Company SSO", ip.DisplayName)
		assert.True(t, ip.IsEnabled)
		assert.Equal(t, 10, ip.Priority)
		require.NotNil(t, ip.ClientID)
		assert.Equal(t, "client-abc", *ip.ClientID)
		require.NotNil(t, ip.ClientSecretEncrypted)
		assert.NotEmpty(t, *ip.ClientSecretEncrypted)
		require.NotNil(t, ip.AuthorizationURL)
		assert.Equal(t, "https://idp.example.com/auth", *ip.AuthorizationURL)
		assert.Equal(t, []string{"openid", "profile", "email"}, ip.Scopes)
		assert.True(t, ip.AutoProvisionUsers)
		assert.NotEmpty(t, ip.DefaultRoleIDs)
		require.NotNil(t, ip.CreatedBy)
	})

	t.Run("should create a minimal LDAP IdentityProvider", func(t *testing.T) {
		ip := &IdentityProvider{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			Type:        "ldap",
			Name:        "corp-ldap",
			DisplayName: "Corporate LDAP",
			IsEnabled:   true,
			Priority:    1,
			LDAPConfig: &LDAPConfig{
				Host:         "ldap.corp.com",
				Port:         389,
				BindDN:       "cn=svc,dc=corp,dc=com",
				BindPassword: "secret",
				BaseDN:       "dc=corp,dc=com",
				UserFilter:   "(sAMAccountName=%s)",
				UsernameAttr: "sAMAccountName",
				EmailAttr:    "mail",
			},
		}

		assert.Equal(t, "ldap", ip.Type)
		require.NotNil(t, ip.LDAPConfig)
		assert.Equal(t, "ldap.corp.com", ip.LDAPConfig.Host)
		assert.Equal(t, 389, ip.LDAPConfig.Port)
		assert.Nil(t, ip.ClientID)
		assert.Nil(t, ip.ClientSecretEncrypted)
	})

	t.Run("should create a SAML SP IdentityProvider with SAMLSPConfig", func(t *testing.T) {
		ip := &IdentityProvider{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			Type:     "saml",
			Name:     "okta-saml",
			SAMLSPConfig: &SAMLSPConfig{
				IDPEntityID: "https://okta.example.com",
				IDPSSOURL:   "https://okta.example.com/sso",
				SPEntityID:  "https://sp.example.com",
				SPACSURL:    "https://sp.example.com/acs",
			},
		}

		assert.Equal(t, "saml", ip.Type)
		require.NotNil(t, ip.SAMLSPConfig)
		assert.Equal(t, "https://okta.example.com", ip.SAMLSPConfig.IDPEntityID)
	})

	t.Run("should allow priority zero (lowest)", func(t *testing.T) {
		ip := &IdentityProvider{Priority: 0}
		assert.Equal(t, 0, ip.Priority)
	})

	t.Run("should allow maximum priority value", func(t *testing.T) {
		ip := &IdentityProvider{Priority: 1000}
		assert.Equal(t, 1000, ip.Priority)
	})
}

// ==================== IdentityProvider.ToResponse ====================

func TestIdentityProvider_ToResponse(t *testing.T) {
	t.Run("should map all scalar fields correctly", func(t *testing.T) {
		ip := buildIdentityProvider()

		resp := ip.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, ip.ID, resp.ID)
		assert.Equal(t, ip.TenantID, resp.TenantID)
		assert.Equal(t, ip.Type, resp.Type)
		assert.Equal(t, ip.Name, resp.Name)
		assert.Equal(t, ip.DisplayName, resp.DisplayName)
		assert.Equal(t, ip.IsEnabled, resp.IsEnabled)
		assert.Equal(t, ip.Priority, resp.Priority)
		assert.Equal(t, ip.AutoProvisionUsers, resp.AutoProvisionUsers)
		assert.Equal(t, ip.AttributeMapping, resp.AttributeMapping)
		assert.Equal(t, ip.CreatedAt, resp.CreatedAt)
		assert.Equal(t, ip.UpdatedAt, resp.UpdatedAt)
	})

	t.Run("should not include client secret in response", func(t *testing.T) {
		ip := buildIdentityProvider()

		resp := ip.ToResponse()

		require.NotNil(t, resp)
		// IdentityProviderResponse has no ClientSecret or ClientSecretEncrypted field.
		// Verify that sensitive OAuth fields are absent from the response type by
		// checking they are not present on the struct.
		// (Compile-time guarantee; this test documents intent.)
		assert.Nil(t, resp.LDAPConfig, "no LDAP config for OIDC provider")
	})

	t.Run("should sanitize LDAP config removing bind password", func(t *testing.T) {
		ip := &IdentityProvider{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			Type:     "ldap",
			Name:     "ldap-provider",
			LDAPConfig: &LDAPConfig{
				Host:                  "ldap.corp.com",
				Port:                  636,
				UseTLS:                true,
				UseStartTLS:           false,
				BindDN:                "cn=svc,dc=corp,dc=com",
				BindPassword:          "super-secret-password",
				BindPasswordEncrypted: "encrypted-version",
				BaseDN:                "dc=corp,dc=com",
				UserFilter:            "(sAMAccountName=%s)",
				UserSearchBase:        "ou=users,dc=corp,dc=com",
				GroupFilter:           "(objectClass=group)",
				GroupSearchBase:       "ou=groups,dc=corp,dc=com",
				UsernameAttr:          "sAMAccountName",
				EmailAttr:             "mail",
				SyncEnabled:           true,
				SyncInterval:          60,
				GroupMappings:         map[string]string{"Admins": "admin"},
			},
		}

		resp := ip.ToResponse()

		require.NotNil(t, resp)
		require.NotNil(t, resp.LDAPConfig)
		assert.Equal(t, "ldap.corp.com", resp.LDAPConfig.Host)
		assert.Equal(t, 636, resp.LDAPConfig.Port)
		assert.True(t, resp.LDAPConfig.UseTLS)
		assert.False(t, resp.LDAPConfig.UseStartTLS)
		assert.Equal(t, "dc=corp,dc=com", resp.LDAPConfig.BaseDN)
		assert.Equal(t, "(sAMAccountName=%s)", resp.LDAPConfig.UserFilter)
		assert.Equal(t, "ou=users,dc=corp,dc=com", resp.LDAPConfig.UserSearchBase)
		assert.Equal(t, "(objectClass=group)", resp.LDAPConfig.GroupFilter)
		assert.Equal(t, "ou=groups,dc=corp,dc=com", resp.LDAPConfig.GroupSearchBase)
		assert.Equal(t, "sAMAccountName", resp.LDAPConfig.UsernameAttr)
		assert.Equal(t, "mail", resp.LDAPConfig.EmailAttr)
		assert.True(t, resp.LDAPConfig.SyncEnabled)
		assert.Equal(t, 60, resp.LDAPConfig.SyncInterval)
		assert.Equal(t, map[string]string{"Admins": "admin"}, resp.LDAPConfig.GroupMappings)
	})

	t.Run("should return nil LDAPConfig in response when model has no LDAPConfig", func(t *testing.T) {
		ip := buildIdentityProvider() // OIDC type, no LDAPConfig

		resp := ip.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.LDAPConfig)
	})

	t.Run("should handle nil AttributeMapping", func(t *testing.T) {
		ip := &IdentityProvider{
			ID:               uuid.New(),
			TenantID:         uuid.New(),
			Type:             "google",
			AttributeMapping: nil,
		}

		resp := ip.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.AttributeMapping)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		ip := buildIdentityProvider()

		resp1 := ip.ToResponse()
		resp2 := ip.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== LDAPConfig struct ====================

func TestLDAPConfig_Instantiation(t *testing.T) {
	t.Run("should create a fully populated LDAPConfig", func(t *testing.T) {
		cfg := &LDAPConfig{
			Host:                  "ad.corp.com",
			Port:                  636,
			UseTLS:                true,
			UseStartTLS:           false,
			SkipTLSVerify:         false,
			BindDN:                "cn=svc-account,dc=corp,dc=com",
			BindPassword:          "plaintext-secret",
			BindPasswordEncrypted: "encrypted-blob",
			ServerName:            "ad.corp.com",
			BaseDN:                "dc=corp,dc=com",
			UserFilter:            "(&(objectClass=user)(sAMAccountName=%s))",
			UserSearchBase:        "ou=users,dc=corp,dc=com",
			GroupFilter:           "(&(objectClass=group)(member=%s))",
			GroupSearchBase:       "ou=groups,dc=corp,dc=com",
			UsernameAttr:          "sAMAccountName",
			EmailAttr:             "mail",
			FirstNameAttr:         "givenName",
			LastNameAttr:          "sn",
			DisplayNameAttr:       "displayName",
			PhoneAttr:             "telephoneNumber",
			DepartmentAttr:        "department",
			TitleAttr:             "title",
			GroupAttr:             "memberOf",
			SyncEnabled:           true,
			SyncInterval:          30,
			SyncGroups:            true,
			GroupMappings:         map[string]string{"Domain Admins": "admin"},
			CreateUsers:           true,
			UpdateUsers:           true,
			DisableLocalAuth:      false,
		}

		assert.Equal(t, "ad.corp.com", cfg.Host)
		assert.Equal(t, 636, cfg.Port)
		assert.True(t, cfg.UseTLS)
		assert.False(t, cfg.UseStartTLS)
		assert.False(t, cfg.SkipTLSVerify)
		assert.Equal(t, "cn=svc-account,dc=corp,dc=com", cfg.BindDN)
		assert.Equal(t, "plaintext-secret", cfg.BindPassword)
		assert.Equal(t, "encrypted-blob", cfg.BindPasswordEncrypted)
		assert.Equal(t, "ad.corp.com", cfg.ServerName)
		assert.Equal(t, "dc=corp,dc=com", cfg.BaseDN)
		assert.Equal(t, "(&(objectClass=user)(sAMAccountName=%s))", cfg.UserFilter)
		assert.Equal(t, "sAMAccountName", cfg.UsernameAttr)
		assert.Equal(t, "mail", cfg.EmailAttr)
		assert.Equal(t, "givenName", cfg.FirstNameAttr)
		assert.Equal(t, "sn", cfg.LastNameAttr)
		assert.Equal(t, "displayName", cfg.DisplayNameAttr)
		assert.Equal(t, "telephoneNumber", cfg.PhoneAttr)
		assert.Equal(t, "department", cfg.DepartmentAttr)
		assert.Equal(t, "title", cfg.TitleAttr)
		assert.Equal(t, "memberOf", cfg.GroupAttr)
		assert.True(t, cfg.SyncEnabled)
		assert.Equal(t, 30, cfg.SyncInterval)
		assert.True(t, cfg.SyncGroups)
		assert.Equal(t, map[string]string{"Domain Admins": "admin"}, cfg.GroupMappings)
		assert.True(t, cfg.CreateUsers)
		assert.True(t, cfg.UpdateUsers)
		assert.False(t, cfg.DisableLocalAuth)
	})

	t.Run("should default SkipTLSVerify to false (secure by default)", func(t *testing.T) {
		cfg := &LDAPConfig{}
		assert.False(t, cfg.SkipTLSVerify)
	})

	t.Run("should support standard LDAP port 389", func(t *testing.T) {
		cfg := &LDAPConfig{
			Host: "ldap.corp.com",
			Port: 389,
		}
		assert.Equal(t, 389, cfg.Port)
		assert.False(t, cfg.UseTLS)
	})

	t.Run("should support LDAPS port 636 with TLS", func(t *testing.T) {
		cfg := &LDAPConfig{
			Host:   "ldap.corp.com",
			Port:   636,
			UseTLS: true,
		}
		assert.Equal(t, 636, cfg.Port)
		assert.True(t, cfg.UseTLS)
	})
}

// ==================== OAuth2Config struct ====================

func TestOAuth2Config_Instantiation(t *testing.T) {
	t.Run("should create a fully populated OAuth2Config", func(t *testing.T) {
		cfg := &OAuth2Config{ //nolint:gosec // test fixture value, not a real credential
			ClientID:        "client-123",
			ClientSecret:    "secret-abc",
			AuthURL:         "https://accounts.google.com/o/oauth2/auth",
			TokenURL:        "https://oauth2.googleapis.com/token",
			UserInfoURL:     "https://www.googleapis.com/oauth2/v1/userinfo",
			RedirectURI:     "https://app.example.com/callback",
			Scopes:          []string{"openid", "profile", "email"},
			ProviderName:    "google",
			UserIDAttr:      "sub",
			EmailAttr:       "email",
			FirstNameAttr:   "given_name",
			LastNameAttr:    "family_name",
			DisplayNameAttr: "name",
			AvatarAttr:      "picture",
			CreateUsers:     true,
			UpdateUsers:     true,
		}

		assert.Equal(t, "client-123", cfg.ClientID)
		assert.Equal(t, "secret-abc", cfg.ClientSecret)
		assert.Equal(t, "https://accounts.google.com/o/oauth2/auth", cfg.AuthURL)
		assert.Equal(t, "https://oauth2.googleapis.com/token", cfg.TokenURL)
		assert.Equal(t, "https://www.googleapis.com/oauth2/v1/userinfo", cfg.UserInfoURL)
		assert.Equal(t, "https://app.example.com/callback", cfg.RedirectURI)
		assert.Equal(t, []string{"openid", "profile", "email"}, cfg.Scopes)
		assert.Equal(t, "google", cfg.ProviderName)
		assert.Equal(t, "sub", cfg.UserIDAttr)
		assert.Equal(t, "email", cfg.EmailAttr)
		assert.Equal(t, "given_name", cfg.FirstNameAttr)
		assert.Equal(t, "family_name", cfg.LastNameAttr)
		assert.Equal(t, "name", cfg.DisplayNameAttr)
		assert.Equal(t, "picture", cfg.AvatarAttr)
		assert.True(t, cfg.CreateUsers)
		assert.True(t, cfg.UpdateUsers)
	})

	t.Run("should support GitHub provider configuration", func(t *testing.T) {
		cfg := &OAuth2Config{ //nolint:gosec // test fixture value, not a real credential
			ProviderName: "github",
			UserIDAttr:   "id",
			EmailAttr:    "email",
			AuthURL:      "https://github.com/login/oauth/authorize",
			TokenURL:     "https://github.com/login/oauth/access_token",
			UserInfoURL:  "https://api.github.com/user",
		}

		assert.Equal(t, "github", cfg.ProviderName)
		assert.Equal(t, "id", cfg.UserIDAttr)
	})
}

// ==================== LDAPSyncResult struct ====================

func TestLDAPSyncResult_Instantiation(t *testing.T) {
	t.Run("should create a successful LDAPSyncResult", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		completed := now.Add(30 * time.Second)

		result := &LDAPSyncResult{
			Success:       true,
			StartedAt:     now,
			CompletedAt:   completed,
			Duration:      "30s",
			UsersFound:    100,
			UsersCreated:  5,
			UsersUpdated:  20,
			UsersDisabled: 2,
			GroupsFound:   10,
			GroupsCreated: 1,
			GroupsUpdated: 3,
			Message:       "Sync completed successfully",
		}

		assert.True(t, result.Success)
		assert.Equal(t, now, result.StartedAt)
		assert.Equal(t, completed, result.CompletedAt)
		assert.Equal(t, "30s", result.Duration)
		assert.Equal(t, 100, result.UsersFound)
		assert.Equal(t, 5, result.UsersCreated)
		assert.Equal(t, 20, result.UsersUpdated)
		assert.Equal(t, 2, result.UsersDisabled)
		assert.Equal(t, 10, result.GroupsFound)
		assert.Equal(t, 1, result.GroupsCreated)
		assert.Equal(t, 3, result.GroupsUpdated)
		assert.Empty(t, result.Errors)
		assert.Equal(t, "Sync completed successfully", result.Message)
	})

	t.Run("should create a failed LDAPSyncResult with errors", func(t *testing.T) {
		result := &LDAPSyncResult{
			Success: false,
			Errors: []string{
				"connection timeout",
				"failed to process user: uid=bad,dc=corp,dc=com",
			},
			Message: "Sync failed with 2 errors",
		}

		assert.False(t, result.Success)
		assert.Len(t, result.Errors, 2)
		assert.Equal(t, "connection timeout", result.Errors[0])
	})
}

// ==================== LDAPSyncHistory struct ====================

func TestLDAPSyncHistory_Instantiation(t *testing.T) {
	t.Run("should create a fully populated LDAPSyncHistory", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		providerID := uuid.New()
		triggeredBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		completed := now.Add(45 * time.Second)

		h := &LDAPSyncHistory{
			ID:            id,
			TenantID:      tenantID,
			ProviderID:    providerID,
			ProviderName:  "corp-ldap",
			SyncType:      "scheduled",
			Status:        "completed",
			StartedAt:     now,
			CompletedAt:   &completed,
			DurationMs:    45000,
			UsersFound:    50,
			UsersCreated:  3,
			UsersUpdated:  10,
			UsersDisabled: 1,
			GroupsFound:   5,
			Errors:        []string{"minor warning: user skipped"},
			Message:       "Sync completed with warnings",
			TriggeredBy:   &triggeredBy,
			CreatedAt:     now,
		}

		assert.Equal(t, id, h.ID)
		assert.Equal(t, tenantID, h.TenantID)
		assert.Equal(t, providerID, h.ProviderID)
		assert.Equal(t, "corp-ldap", h.ProviderName)
		assert.Equal(t, "scheduled", h.SyncType)
		assert.Equal(t, "completed", h.Status)
		assert.Equal(t, now, h.StartedAt)
		require.NotNil(t, h.CompletedAt)
		assert.Equal(t, completed, *h.CompletedAt)
		assert.Equal(t, int64(45000), h.DurationMs)
		assert.Equal(t, 50, h.UsersFound)
		assert.Len(t, h.Errors, 1)
		require.NotNil(t, h.TriggeredBy)
		assert.Equal(t, triggeredBy, *h.TriggeredBy)
	})

	t.Run("should create a running LDAPSyncHistory without CompletedAt", func(t *testing.T) {
		h := &LDAPSyncHistory{
			ID:         uuid.New(),
			TenantID:   uuid.New(),
			ProviderID: uuid.New(),
			SyncType:   "manual",
			Status:     "running",
			StartedAt:  time.Now(),
		}

		assert.Equal(t, "running", h.Status)
		assert.Nil(t, h.CompletedAt)
		assert.Nil(t, h.TriggeredBy)
	})

	t.Run("sync types should be valid known values", func(t *testing.T) {
		validTypes := []string{"manual", "scheduled", "full"}
		for _, syncType := range validTypes {
			h := &LDAPSyncHistory{SyncType: syncType}
			assert.Equal(t, syncType, h.SyncType)
		}
	})

	t.Run("sync status should be valid known values", func(t *testing.T) {
		validStatuses := []string{"running", "completed", "failed"}
		for _, status := range validStatuses {
			h := &LDAPSyncHistory{Status: status}
			assert.Equal(t, status, h.Status)
		}
	})
}

// ==================== CreateIdentityProviderRequest ====================

func TestCreateIdentityProviderRequest_Fields(t *testing.T) {
	t.Run("should set all fields for an OAuth OIDC provider", func(t *testing.T) {
		tenantID := uuid.New()
		clientID := "client-abc"
		clientSecret := "secret-xyz"
		authURL := "https://idp.example.com/auth"
		tokenURL := "https://idp.example.com/token" //nolint:gosec // test fixture value, not a real credential
		userInfoURL := "https://idp.example.com/userinfo"
		roleID := uuid.New()

		req := &CreateIdentityProviderRequest{
			TenantID:           tenantID,
			Type:               "oidc",
			Name:               "company-oidc",
			DisplayName:        "Company OIDC",
			IsEnabled:          true,
			Priority:           5,
			ClientID:           &clientID,
			ClientSecret:       &clientSecret,
			AuthorizationURL:   &authURL,
			TokenURL:           &tokenURL,
			UserInfoURL:        &userInfoURL,
			Scopes:             []string{"openid", "profile", "email"},
			AttributeMapping:   map[string]string{"email": "email"},
			AutoProvisionUsers: true,
			DefaultRoleIDs:     []uuid.UUID{roleID},
		}

		assert.Equal(t, tenantID, req.TenantID)
		assert.Equal(t, "oidc", req.Type)
		assert.Equal(t, "company-oidc", req.Name)
		assert.Equal(t, "Company OIDC", req.DisplayName)
		assert.True(t, req.IsEnabled)
		assert.Equal(t, 5, req.Priority)
		require.NotNil(t, req.ClientID)
		assert.Equal(t, "client-abc", *req.ClientID)
		require.NotNil(t, req.ClientSecret)
		assert.Equal(t, "secret-xyz", *req.ClientSecret)
		assert.Equal(t, []string{"openid", "profile", "email"}, req.Scopes)
		assert.True(t, req.AutoProvisionUsers)
		assert.Len(t, req.DefaultRoleIDs, 1)
		assert.Equal(t, roleID, req.DefaultRoleIDs[0])
	})

	t.Run("should create an LDAP provider request with LDAPConfig", func(t *testing.T) {
		req := &CreateIdentityProviderRequest{
			TenantID:    uuid.New(),
			Type:        "ldap",
			Name:        "corp-ldap",
			DisplayName: "Corporate LDAP",
			LDAPConfig: &LDAPConfig{
				Host:         "ldap.corp.com",
				Port:         389,
				BaseDN:       "dc=corp,dc=com",
				UserFilter:   "(sAMAccountName=%s)",
				UsernameAttr: "sAMAccountName",
				EmailAttr:    "mail",
			},
		}

		assert.Equal(t, "ldap", req.Type)
		require.NotNil(t, req.LDAPConfig)
		assert.Equal(t, "ldap.corp.com", req.LDAPConfig.Host)
	})

	t.Run("should allow nil optional fields for minimal request", func(t *testing.T) {
		req := &CreateIdentityProviderRequest{
			TenantID:    uuid.New(),
			Type:        "google",
			Name:        "google-sso",
			DisplayName: "Google SSO",
		}

		assert.Nil(t, req.ClientID)
		assert.Nil(t, req.ClientSecret)
		assert.Nil(t, req.AuthorizationURL)
		assert.Nil(t, req.TokenURL)
		assert.Nil(t, req.UserInfoURL)
		assert.Nil(t, req.LDAPConfig)
		assert.Empty(t, req.Scopes)
		assert.Empty(t, req.DefaultRoleIDs)
	})
}

// ==================== UpdateIdentityProviderRequest ====================

func TestUpdateIdentityProviderRequest_Fields(t *testing.T) {
	t.Run("should patch specific fields leaving others nil", func(t *testing.T) {
		displayName := "Updated Display Name"
		isEnabled := false
		priority := 20

		req := &UpdateIdentityProviderRequest{
			DisplayName: &displayName,
			IsEnabled:   &isEnabled,
			Priority:    &priority,
		}

		require.NotNil(t, req.DisplayName)
		assert.Equal(t, "Updated Display Name", *req.DisplayName)
		require.NotNil(t, req.IsEnabled)
		assert.False(t, *req.IsEnabled)
		require.NotNil(t, req.Priority)
		assert.Equal(t, 20, *req.Priority)

		// Unset fields are nil (partial patch semantics).
		assert.Nil(t, req.ClientID)
		assert.Nil(t, req.ClientSecret)
		assert.Nil(t, req.LDAPConfig)
		assert.Nil(t, req.AutoProvisionUsers)
	})

	t.Run("should allow a fully nil update request (noop)", func(t *testing.T) {
		req := &UpdateIdentityProviderRequest{}

		assert.Nil(t, req.DisplayName)
		assert.Nil(t, req.IsEnabled)
		assert.Nil(t, req.Priority)
		assert.Nil(t, req.ClientID)
		assert.Nil(t, req.ClientSecret)
		assert.Nil(t, req.AuthorizationURL)
		assert.Nil(t, req.TokenURL)
		assert.Nil(t, req.UserInfoURL)
		assert.Nil(t, req.LDAPConfig)
		assert.Nil(t, req.AutoProvisionUsers)
	})

	t.Run("should update AutoProvisionUsers", func(t *testing.T) {
		provision := true
		req := &UpdateIdentityProviderRequest{
			AutoProvisionUsers: &provision,
		}

		require.NotNil(t, req.AutoProvisionUsers)
		assert.True(t, *req.AutoProvisionUsers)
	})
}

// ==================== IdentityProviderResponse / LDAPConfigResponse ====================

func TestIdentityProviderResponse_Instantiation(t *testing.T) {
	t.Run("should create a response with all fields", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)

		resp := &IdentityProviderResponse{
			ID:                 uuid.New(),
			TenantID:           uuid.New(),
			Type:               "ldap",
			Name:               "corp-ldap",
			DisplayName:        "Corporate LDAP",
			IsEnabled:          true,
			Priority:           1,
			AutoProvisionUsers: true,
			LDAPConfig: &LDAPConfigResponse{
				Host:         "ldap.corp.com",
				Port:         389,
				UseTLS:       false,
				UseStartTLS:  true,
				BaseDN:       "dc=corp,dc=com",
				UserFilter:   "(sAMAccountName=%s)",
				UsernameAttr: "sAMAccountName",
				EmailAttr:    "mail",
				SyncEnabled:  true,
				SyncInterval: 30,
			},
			AttributeMapping: map[string]string{"email": "mail"},
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		assert.Equal(t, "ldap", resp.Type)
		require.NotNil(t, resp.LDAPConfig)
		assert.Equal(t, "ldap.corp.com", resp.LDAPConfig.Host)
		// BindPassword must never appear in LDAPConfigResponse.
		// Compile-time check: the struct has no BindPassword field.
		assert.Equal(t, 30, resp.LDAPConfig.SyncInterval)
	})
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildServiceAccount returns a fully populated ServiceAccount for use in tests.
func buildServiceAccount() *ServiceAccount {
	id := uuid.New()
	tenantID := uuid.New()
	createdBy := uuid.New()
	now := time.Now().Truncate(time.Second)
	lastUsed := now.Add(-15 * time.Minute)
	lastIP := "10.0.1.50"
	desc := "CI/CD deployment account"

	return &ServiceAccount{ //nolint:gosec // test fixture value, not a real credential
		ID:                   id,
		TenantID:             tenantID,
		Name:                 "ci-deploy",
		Description:          &desc,
		ClientID:             "sa_abcdef1234567890",
		ClientSecretHash:     "$argon2id$v=19$m=65536,t=3,p=4$secretHash",
		RoleIDs:              pq.StringArray{"role-deploy", "role-readonly"},
		AllowedIPs:           pq.StringArray{"10.0.0.0/8", "192.168.0.0/16"},
		AllowedEndpoints:     pq.StringArray{"/api/v1/deploy"},
		IsActive:             true,
		LastUsedAt:           &lastUsed,
		LastUsedIP:           &lastIP,
		TokenLifetimeMinutes: 60,
		CreatedAt:            now,
		UpdatedAt:            now,
		CreatedBy:            &createdBy,
	}
}

// ==================== ServiceAccount struct field mapping ====================

func TestServiceAccount_StructFields(t *testing.T) {
	t.Run("should hold all field values correctly", func(t *testing.T) {
		sa := buildServiceAccount()

		assert.NotEqual(t, uuid.Nil, sa.ID)
		assert.NotEqual(t, uuid.Nil, sa.TenantID)
		assert.NotEmpty(t, sa.Name)
		assert.NotNil(t, sa.Description)
		assert.NotEmpty(t, sa.ClientID)
		assert.NotEmpty(t, sa.ClientSecretHash)
		assert.NotEmpty(t, sa.RoleIDs)
		assert.NotEmpty(t, sa.AllowedIPs)
		assert.NotEmpty(t, sa.AllowedEndpoints)
		assert.True(t, sa.IsActive)
		assert.NotNil(t, sa.LastUsedAt)
		assert.NotNil(t, sa.LastUsedIP)
		assert.Greater(t, sa.TokenLifetimeMinutes, 0)
		assert.False(t, sa.CreatedAt.IsZero())
		assert.False(t, sa.UpdatedAt.IsZero())
		assert.NotNil(t, sa.CreatedBy)
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		sa := &ServiceAccount{ //nolint:gosec // test fixture value, not a real credential
			ID:                   uuid.New(),
			TenantID:             uuid.New(),
			Name:                 "minimal-sa",
			ClientID:             "sa_minimal",
			ClientSecretHash:     "$argon2id$minimalhash",
			RoleIDs:              pq.StringArray{"role-basic"},
			IsActive:             true,
			TokenLifetimeMinutes: 30,
		}

		assert.Nil(t, sa.Description)
		assert.Nil(t, sa.LastUsedAt)
		assert.Nil(t, sa.LastUsedIP)
		assert.Nil(t, sa.CreatedBy)
	})
}

// ==================== ClientSecretHash json:"-" tag ====================

func TestServiceAccount_ClientSecretHash_JSONDashTag(t *testing.T) {
	t.Run("ClientSecretHash must not appear in JSON serialization of ServiceAccount", func(t *testing.T) {
		sa := &ServiceAccount{ //nolint:gosec // test fixture value, not a real credential
			ID:               uuid.New(),
			TenantID:         uuid.New(),
			Name:             "test-sa",
			ClientID:         "sa_test",
			ClientSecretHash: "$argon2id$this-must-not-leak",
			RoleIDs:          pq.StringArray{"role-1"},
			IsActive:         true,
		}

		data, err := json.Marshal(sa)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.NotContains(t, out, "client_secret_hash",
			"ClientSecretHash must be excluded from JSON output via json:\"-\" tag")
		assert.NotContains(t, string(data), "this-must-not-leak")
	})

	t.Run("ToResponse output must not contain client_secret_hash", func(t *testing.T) {
		sa := buildServiceAccount()
		resp := sa.ToResponse()

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		assert.NotContains(t, string(data), "client_secret_hash")
	})
}

// ==================== ServiceAccount.ToResponse ====================

func TestServiceAccount_ToResponse(t *testing.T) {
	t.Run("should map all scalar fields correctly", func(t *testing.T) {
		sa := buildServiceAccount()

		resp := sa.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, sa.ID, resp.ID)
		assert.Equal(t, sa.TenantID, resp.TenantID)
		assert.Equal(t, sa.Name, resp.Name)
		assert.Equal(t, sa.Description, resp.Description)
		assert.Equal(t, sa.ClientID, resp.ClientID)
		assert.ElementsMatch(t, sa.RoleIDs, resp.RoleIDs)
		assert.ElementsMatch(t, sa.AllowedIPs, resp.AllowedIPs)
		assert.ElementsMatch(t, sa.AllowedEndpoints, resp.AllowedEndpoints)
		assert.Equal(t, sa.IsActive, resp.IsActive)
		assert.Equal(t, sa.LastUsedAt, resp.LastUsedAt)
		assert.Equal(t, sa.LastUsedIP, resp.LastUsedIP)
		assert.Equal(t, sa.TokenLifetimeMinutes, resp.TokenLifetimeMinutes)
		assert.Equal(t, sa.CreatedAt, resp.CreatedAt)
		assert.Equal(t, sa.UpdatedAt, resp.UpdatedAt)
	})

	t.Run("should NOT include ClientSecretHash in response", func(t *testing.T) {
		sa := buildServiceAccount()
		sa.ClientSecretHash = "$argon2id$supersecret-do-not-leak"

		resp := sa.ToResponse()

		require.NotNil(t, resp)
		// ServiceAccountResponse has no ClientSecretHash field.
		// Verify via JSON serialization.
		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))
		assert.NotContains(t, out, "client_secret_hash")
		assert.NotContains(t, string(data), "supersecret-do-not-leak")
	})

	t.Run("should NOT include CreatedBy in response (not in ServiceAccountResponse)", func(t *testing.T) {
		sa := buildServiceAccount()
		resp := sa.ToResponse()

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		// ServiceAccountResponse does not carry CreatedBy.
		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))
		assert.NotContains(t, out, "created_by")
	})

	t.Run("should handle nil optional fields", func(t *testing.T) {
		sa := &ServiceAccount{ //nolint:gosec // test fixture value, not a real credential
			ID:                   uuid.New(),
			TenantID:             uuid.New(),
			Name:                 "minimal-sa",
			ClientID:             "sa_minimal",
			ClientSecretHash:     "$argon2id$hash",
			RoleIDs:              pq.StringArray{"role-1"},
			IsActive:             true,
			TokenLifetimeMinutes: 30,
		}

		resp := sa.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.Description)
		assert.Nil(t, resp.LastUsedAt)
		assert.Nil(t, resp.LastUsedIP)
	})

	t.Run("should produce distinct instances on each call", func(t *testing.T) {
		sa := buildServiceAccount()

		resp1 := sa.ToResponse()
		resp2 := sa.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})

	t.Run("inactive service account should reflect in response", func(t *testing.T) {
		sa := buildServiceAccount()
		sa.IsActive = false

		resp := sa.ToResponse()

		require.NotNil(t, resp)
		assert.False(t, resp.IsActive)
	})
}

// ==================== ServiceAccountCreatedResponse ====================

func TestServiceAccountCreatedResponse_Fields(t *testing.T) {
	t.Run("should include the plain-text client secret in response", func(t *testing.T) {
		sa := buildServiceAccount()
		base := sa.ToResponse()

		createdResp := ServiceAccountCreatedResponse{ //nolint:gosec // test fixture value, not a real credential
			ServiceAccountResponse: *base,
			ClientSecret:           "plain-text-secret-abc123XYZ",
		}

		assert.Equal(t, sa.ID, createdResp.ID)
		assert.Equal(t, "plain-text-secret-abc123XYZ", createdResp.ClientSecret)
	})

	t.Run("ClientSecret should appear in JSON output", func(t *testing.T) {
		sa := buildServiceAccount()
		createdResp := ServiceAccountCreatedResponse{
			ServiceAccountResponse: *sa.ToResponse(),
			ClientSecret:           "super-secret-value",
		}

		data, err := json.Marshal(createdResp) //nolint:gosec // test struct with secret field, not real credentials
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Equal(t, "super-secret-value", out["client_secret"])
		assert.NotContains(t, out, "client_secret_hash")
	})

	t.Run("base response fields should be identical to ToResponse", func(t *testing.T) {
		sa := buildServiceAccount()
		base := sa.ToResponse()
		createdResp := ServiceAccountCreatedResponse{
			ServiceAccountResponse: *sa.ToResponse(),
			ClientSecret:           "secret",
		}

		assert.Equal(t, base.ID, createdResp.ID)
		assert.Equal(t, base.ClientID, createdResp.ClientID)
		assert.Equal(t, base.TenantID, createdResp.TenantID)
		assert.Equal(t, base.Name, createdResp.Name)
		assert.Equal(t, base.IsActive, createdResp.IsActive)
	})
}

// ==================== CreateServiceAccountRequest field tags ====================

func TestCreateServiceAccountRequest_FieldTags(t *testing.T) {
	t.Run("should accept a valid request with all fields", func(t *testing.T) {
		lifetime := 120
		desc := "Deployment account"

		req := CreateServiceAccountRequest{
			Name:                 "deploy-sa",
			Description:          &desc,
			RoleIDs:              []string{"role-deploy", "role-read"},
			AllowedIPs:           []string{"10.0.0.0/8"},
			AllowedEndpoints:     []string{"/api/v1/deploy"},
			TokenLifetimeMinutes: &lifetime,
		}

		assert.Equal(t, "deploy-sa", req.Name)
		assert.Equal(t, &desc, req.Description)
		assert.ElementsMatch(t, []string{"role-deploy", "role-read"}, req.RoleIDs)
		assert.Equal(t, []string{"10.0.0.0/8"}, req.AllowedIPs)
		assert.Equal(t, &lifetime, req.TokenLifetimeMinutes)
	})

	t.Run("should allow omission of optional fields", func(t *testing.T) {
		req := CreateServiceAccountRequest{
			Name:    "minimal-sa",
			RoleIDs: []string{"role-1"},
		}

		assert.Equal(t, "minimal-sa", req.Name)
		assert.Nil(t, req.Description)
		assert.Empty(t, req.AllowedIPs)
		assert.Empty(t, req.AllowedEndpoints)
		assert.Nil(t, req.TokenLifetimeMinutes)
	})

	t.Run("max name length constraint is 100 characters", func(t *testing.T) {
		longName := "a"
		for i := 0; i < 99; i++ {
			longName += "b"
		}
		// 100 chars — should be accepted by the validate tag.
		req := CreateServiceAccountRequest{
			Name:    longName,
			RoleIDs: []string{"role-1"},
		}
		assert.Len(t, req.Name, 100)
	})

	t.Run("token lifetime min=1 max=1440 minutes", func(t *testing.T) {
		lifetime := 1440
		req := CreateServiceAccountRequest{
			Name:                 "sa",
			RoleIDs:              []string{"role-1"},
			TokenLifetimeMinutes: &lifetime,
		}
		assert.Equal(t, 1440, *req.TokenLifetimeMinutes)
	})
}

// ==================== UpdateServiceAccountRequest field tags ====================

func TestUpdateServiceAccountRequest_FieldTags(t *testing.T) {
	t.Run("all fields are optional (pointer types)", func(t *testing.T) {
		req := UpdateServiceAccountRequest{}

		assert.Nil(t, req.Name)
		assert.Nil(t, req.Description)
		assert.Empty(t, req.RoleIDs)
		assert.Empty(t, req.AllowedIPs)
		assert.Empty(t, req.AllowedEndpoints)
		assert.Nil(t, req.IsActive)
		assert.Nil(t, req.TokenLifetimeMinutes)
	})

	t.Run("should carry all populated fields correctly", func(t *testing.T) {
		name := "updated-sa"
		desc := "Updated description"
		isActive := false
		lifetime := 90

		req := UpdateServiceAccountRequest{
			Name:                 &name,
			Description:          &desc,
			RoleIDs:              []string{"role-updated"},
			AllowedIPs:           []string{"192.168.0.0/16"},
			AllowedEndpoints:     []string{"/api/v1/users"},
			IsActive:             &isActive,
			TokenLifetimeMinutes: &lifetime,
		}

		assert.Equal(t, &name, req.Name)
		assert.Equal(t, &desc, req.Description)
		assert.ElementsMatch(t, []string{"role-updated"}, req.RoleIDs)
		assert.Equal(t, &isActive, req.IsActive)
		assert.Equal(t, &lifetime, req.TokenLifetimeMinutes)
	})
}

// ==================== ServiceAccountTokenRequest ====================

func TestServiceAccountTokenRequest_FieldTags(t *testing.T) {
	t.Run("should hold a valid client_credentials grant request", func(t *testing.T) {
		req := ServiceAccountTokenRequest{ //nolint:gosec // test fixture value, not a real credential
			GrantType:    "client_credentials",
			ClientID:     "sa_abcdef1234567890",
			ClientSecret: "plain-text-secret",
			Scope:        "users:read roles:read",
		}

		assert.Equal(t, "client_credentials", req.GrantType)
		assert.Equal(t, "sa_abcdef1234567890", req.ClientID)
		assert.Equal(t, "plain-text-secret", req.ClientSecret)
		assert.Equal(t, "users:read roles:read", req.Scope)
	})

	t.Run("scope is optional", func(t *testing.T) {
		req := ServiceAccountTokenRequest{
			GrantType:    "client_credentials",
			ClientID:     "sa_abc",
			ClientSecret: "secret",
		}
		assert.Empty(t, req.Scope)
	})
}

// ==================== ServiceAccountTokenResponse ====================

func TestServiceAccountTokenResponse_Fields(t *testing.T) {
	t.Run("should hold token response fields", func(t *testing.T) {
		resp := ServiceAccountTokenResponse{ //nolint:gosec // test fixture value, not a real credential
			AccessToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.payload",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "users:read",
		}

		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, 3600, resp.ExpiresIn)
		assert.Equal(t, "users:read", resp.Scope)
	})

	t.Run("scope omitempty should be absent when empty", func(t *testing.T) {
		resp := ServiceAccountTokenResponse{
			AccessToken: "token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		data, err := json.Marshal(resp) //nolint:gosec // test struct with token field, not real credentials
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.NotContains(t, out, "scope")
	})
}

// ==================== ServiceAccountToken struct ====================

func TestServiceAccountToken_JSONDashTag(t *testing.T) {
	t.Run("TokenHash must not appear in JSON serialization", func(t *testing.T) {
		now := time.Now()
		tok := &ServiceAccountToken{
			ID:               uuid.New(),
			ServiceAccountID: uuid.New(),
			TokenHash:        "$argon2id$secret-token-hash-must-not-leak",
			CreatedAt:        now,
			ExpiresAt:        now.Add(1 * time.Hour),
		}

		data, err := json.Marshal(tok)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.NotContains(t, out, "token_hash",
			"TokenHash must be excluded from JSON output via json:\"-\" tag")
		assert.NotContains(t, string(data), "secret-token-hash-must-not-leak")
	})
}

// ==================== ServiceAccountResponse JSON marshaling ====================

func TestServiceAccountResponse_JSONMarshaling(t *testing.T) {
	t.Run("should omit nil optional fields", func(t *testing.T) {
		resp := &ServiceAccountResponse{
			ID:                   uuid.New(),
			TenantID:             uuid.New(),
			Name:                 "sa",
			ClientID:             "sa_abc",
			RoleIDs:              []string{"role-1"},
			IsActive:             true,
			TokenLifetimeMinutes: 60,
			CreatedAt:            time.Now(),
			UpdatedAt:            time.Now(),
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.NotContains(t, out, "description")
		assert.NotContains(t, out, "last_used_at")
		assert.NotContains(t, out, "last_used_ip")
	})

	t.Run("populated optional fields should appear in output", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		desc := "test"
		lastIP := "10.0.0.1"

		resp := &ServiceAccountResponse{
			ID:                   uuid.New(),
			TenantID:             uuid.New(),
			Name:                 "sa",
			Description:          &desc,
			ClientID:             "sa_abc",
			RoleIDs:              []string{"role-1"},
			IsActive:             true,
			LastUsedAt:           &now,
			LastUsedIP:           &lastIP,
			TokenLifetimeMinutes: 60,
			CreatedAt:            now,
			UpdatedAt:            now,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Contains(t, out, "description")
		assert.Contains(t, out, "last_used_at")
		assert.Contains(t, out, "last_used_ip")
	})
}

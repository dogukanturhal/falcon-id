// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildFederatedAccount constructs a fully populated FederatedAccount for use in tests.
func buildFederatedAccount() *FederatedAccount {
	id := uuid.New()
	userID := uuid.New()
	providerID := uuid.New()
	now := time.Now().Truncate(time.Second)
	lastUsed := now.Add(-1 * time.Hour)
	tokenExpires := now.Add(1 * time.Hour)
	username := "alice.google"
	email := "alice@gmail.com"
	accessToken := "access-token-encrypted"
	refreshToken := "refresh-token-encrypted"

	return &FederatedAccount{
		ID:               id,
		UserID:           userID,
		ProviderID:       providerID,
		ProviderUserID:   "google-sub-12345",
		ProviderUsername: &username,
		ProviderEmail:    &email,
		AccessToken:      &accessToken,
		RefreshToken:     &refreshToken,
		TokenExpiresAt:   &tokenExpires,
		ProfileData:      map[string]interface{}{"locale": "en-US", "picture": "https://example.com/photo.jpg"},
		FirstLinkedAt:    now,
		LastUsedAt:       &lastUsed,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

// ==================== FederatedAccount struct ====================

func TestFederatedAccount_StructFields(t *testing.T) {
	t.Run("should carry all fields correctly", func(t *testing.T) {
		fa := buildFederatedAccount()

		assert.NotEqual(t, uuid.Nil, fa.ID)
		assert.NotEqual(t, uuid.Nil, fa.UserID)
		assert.NotEqual(t, uuid.Nil, fa.ProviderID)
		assert.Equal(t, "google-sub-12345", fa.ProviderUserID)
		require.NotNil(t, fa.ProviderUsername)
		assert.Equal(t, "alice.google", *fa.ProviderUsername)
		require.NotNil(t, fa.ProviderEmail)
		assert.Equal(t, "alice@gmail.com", *fa.ProviderEmail)
		require.NotNil(t, fa.AccessToken)
		assert.Equal(t, "access-token-encrypted", *fa.AccessToken)
		require.NotNil(t, fa.RefreshToken)
		assert.Equal(t, "refresh-token-encrypted", *fa.RefreshToken)
		require.NotNil(t, fa.TokenExpiresAt)
		require.NotNil(t, fa.LastUsedAt)
		assert.Equal(t, map[string]interface{}{"locale": "en-US", "picture": "https://example.com/photo.jpg"}, fa.ProfileData)
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		fa := FederatedAccount{
			ID:             uuid.New(),
			UserID:         uuid.New(),
			ProviderID:     uuid.New(),
			ProviderUserID: "github-user-789",
			FirstLinkedAt:  time.Now(),
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}

		assert.Nil(t, fa.ProviderUsername)
		assert.Nil(t, fa.ProviderEmail)
		assert.Nil(t, fa.AccessToken)
		assert.Nil(t, fa.RefreshToken)
		assert.Nil(t, fa.TokenExpiresAt)
		assert.Nil(t, fa.ProfileData)
		assert.Nil(t, fa.LastUsedAt)
		assert.Nil(t, fa.Provider)
	})
}

// ==================== FederatedAccount.ToResponse ====================

func TestFederatedAccount_ToResponse(t *testing.T) {
	t.Run("should map all visible fields correctly", func(t *testing.T) {
		fa := buildFederatedAccount()

		resp := fa.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, fa.ID, resp.ID)
		assert.Equal(t, fa.UserID, resp.UserID)
		assert.Equal(t, fa.ProviderID, resp.ProviderID)
		assert.Equal(t, fa.ProviderUserID, resp.ProviderUserID)
		assert.Equal(t, fa.ProviderUsername, resp.ProviderUsername)
		assert.Equal(t, fa.ProviderEmail, resp.ProviderEmail)
		assert.Equal(t, fa.ProfileData, resp.ProfileData)
		assert.Equal(t, fa.FirstLinkedAt, resp.FirstLinkedAt)
		assert.Equal(t, fa.LastUsedAt, resp.LastUsedAt)
	})

	t.Run("should NOT expose AccessToken in response", func(t *testing.T) {
		fa := buildFederatedAccount()

		resp := fa.ToResponse()

		// FederatedAccountResponse has no AccessToken field (json:"-" on source).
		// We verify the response struct is correct and doesn't carry the token.
		require.NotNil(t, resp)
		// Indirect verification: the response type has no AccessToken field (compile-time).
		assert.Equal(t, fa.ProviderUserID, resp.ProviderUserID)
	})

	t.Run("should NOT expose RefreshToken in response", func(t *testing.T) {
		fa := buildFederatedAccount()

		resp := fa.ToResponse()

		// FederatedAccountResponse has no RefreshToken field.
		require.NotNil(t, resp)
		assert.Equal(t, fa.ProviderUserID, resp.ProviderUserID)
	})

	t.Run("should set Provider response when Provider is set", func(t *testing.T) {
		fa := buildFederatedAccount()
		fa.Provider = &IdentityProvider{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			Type:        "google",
			Name:        "google-sso",
			DisplayName: "Google",
			IsEnabled:   true,
			Priority:    1,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		resp := fa.ToResponse()

		require.NotNil(t, resp)
		require.NotNil(t, resp.Provider, "Provider should be populated in response")
		assert.Equal(t, fa.Provider.ID, resp.Provider.ID)
		assert.Equal(t, "google", resp.Provider.Type)
		assert.Equal(t, "Google", resp.Provider.DisplayName)
	})

	t.Run("should set nil Provider response when Provider is nil", func(t *testing.T) {
		fa := buildFederatedAccount()
		fa.Provider = nil

		resp := fa.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.Provider)
	})

	t.Run("should handle nil optional fields in response", func(t *testing.T) {
		fa := &FederatedAccount{
			ID:             uuid.New(),
			UserID:         uuid.New(),
			ProviderID:     uuid.New(),
			ProviderUserID: "minimal-user",
			FirstLinkedAt:  time.Now(),
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}

		resp := fa.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.ProviderUsername)
		assert.Nil(t, resp.ProviderEmail)
		assert.Nil(t, resp.ProfileData)
		assert.Nil(t, resp.LastUsedAt)
		assert.Nil(t, resp.Provider)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		fa := buildFederatedAccount()

		resp1 := fa.ToResponse()
		resp2 := fa.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== FederatedAccountResponse struct ====================

func TestFederatedAccountResponse_StructFields(t *testing.T) {
	t.Run("should carry all response fields", func(t *testing.T) {
		id := uuid.New()
		userID := uuid.New()
		providerID := uuid.New()
		now := time.Now().Truncate(time.Second)
		lastUsed := now.Add(-30 * time.Minute)
		username := "alice.github"
		email := "alice@github.com"

		providerResp := &IdentityProviderResponse{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			Type:        "github",
			Name:        "github-sso",
			DisplayName: "GitHub",
			IsEnabled:   true,
		}

		resp := FederatedAccountResponse{
			ID:               id,
			UserID:           userID,
			ProviderID:       providerID,
			ProviderUserID:   "gh-user-123",
			ProviderUsername: &username,
			ProviderEmail:    &email,
			ProfileData:      map[string]interface{}{"bio": "Developer"},
			FirstLinkedAt:    now,
			LastUsedAt:       &lastUsed,
			Provider:         providerResp,
		}

		assert.Equal(t, id, resp.ID)
		assert.Equal(t, userID, resp.UserID)
		assert.Equal(t, providerID, resp.ProviderID)
		assert.Equal(t, "gh-user-123", resp.ProviderUserID)
		assert.Equal(t, &username, resp.ProviderUsername)
		assert.Equal(t, &email, resp.ProviderEmail)
		assert.Equal(t, map[string]interface{}{"bio": "Developer"}, resp.ProfileData)
		assert.Equal(t, now, resp.FirstLinkedAt)
		assert.Equal(t, &lastUsed, resp.LastUsedAt)
		assert.Equal(t, providerResp, resp.Provider)
	})
}

// ==================== Provider type coverage ====================

func TestFederatedAccount_ProviderTypes(t *testing.T) {
	providerTypes := []string{
		"google",
		"microsoft",
		"github",
		"apple",
		"ldap",
		"saml",
		"oauth",
		"oidc",
	}

	for _, providerType := range providerTypes {
		providerType := providerType
		t.Run(providerType, func(t *testing.T) {
			provider := &IdentityProvider{
				ID:          uuid.New(),
				TenantID:    uuid.New(),
				Type:        providerType,
				Name:        providerType + "-sso",
				DisplayName: providerType,
				IsEnabled:   true,
			}

			fa := &FederatedAccount{
				ID:             uuid.New(),
				UserID:         uuid.New(),
				ProviderID:     provider.ID,
				ProviderUserID: "user-in-" + providerType,
				FirstLinkedAt:  time.Now(),
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
				Provider:       provider,
			}

			resp := fa.ToResponse()

			require.NotNil(t, resp.Provider)
			assert.Equal(t, providerType, resp.Provider.Type)
		})
	}
}

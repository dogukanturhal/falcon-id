// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func TestClientCredentialsGrant_RejectsPublicClient(t *testing.T) {
	client := newServiceClient("public-cc", uuid.New())
	client.IsPublic = true
	_, err := newTestOAuthService(t).ClientCredentialsGrant(context.Background(), client, nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized_client")
}

func TestCreateClient_RejectsPublicClientCredentials(t *testing.T) {
	svc := newTestOAuthProviderService(t, new(MockOAuthClientRepo), new(MockOAuthUserRepo))
	_, _, err := svc.CreateClient(context.Background(), uuid.New(), &models.CreateOAuthClientRequest{
		Name: "x", GrantTypes: []string{"client_credentials"}, Scopes: []string{"openid"}, IsPublic: true,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_client_metadata")
}

func TestUpdateClient_RejectsPublicWithClientCredentials(t *testing.T) {
	repo := new(MockOAuthClientRepo)
	svc := newTestOAuthProviderService(t, repo, new(MockOAuthUserRepo))
	c := newServiceClient("cc", uuid.New())
	repo.On("GetByID", mock.Anything, c.ID).Return(c, nil)
	pub := true
	_, err := svc.UpdateClient(context.Background(), c.ID, &models.UpdateOAuthClientRequest{IsPublic: &pub}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_client_metadata")
}

func TestValidateTenantClientScopes(t *testing.T) {
	assert.NoError(t, ValidateTenantClientScopes([]string{"openid", "profile", "email", "offline_access", "roles", "read:orders"}))
	for _, bad := range []string{"service:register", "tenant:act-as", "iam:members:read", "authz:check", "iam-devices:enroll", "quota:usage:update", "platform:tenants:read", "admin:oauth-clients"} {
		err := ValidateTenantClientScopes([]string{"openid", bad})
		require.Error(t, err, bad)
		assert.Contains(t, err.Error(), "invalid_scope")
	}
}

func TestRefreshTokens_DeletedUserRejected(t *testing.T) {
	f := newSessionBindingFixture(t, &models.Session{ID: uuid.New(), IsActive: true})
	f.svc.userRepo = &bindingUserRepo{user: nil}
	resp, err := f.refresh()
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid_grant")
}

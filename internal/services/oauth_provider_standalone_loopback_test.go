// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

type fixedTypeLookup struct{ tt models.TenantType }

func (f fixedTypeLookup) GetByID(_ context.Context, id uuid.UUID) (*models.Tenant, error) {
	return &models.Tenant{ID: id, Type: f.tt}, nil
}

func TestValidateRedirectURIMode_StandaloneLoopback(t *testing.T) {
	prod := models.TenantType("internal")
	for _, u := range []string{"http://localhost/cb", "http://localhost:3000/cb", "http://127.0.0.1:8080/cb", "http://[::1]:5173/cb"} {
		assert.NoError(t, validateRedirectURIMode(prod, u, false, nil, true), u)
		assert.Error(t, validateRedirectURIMode(prod, u, false, nil, false), u+" outside standalone")
	}
	// https enforcement is not relaxed for non-loopback hosts.
	assert.Error(t, validateRedirectURIMode(prod, "http://app.example.com/cb", false, nil, true))
	assert.NoError(t, validateRedirectURIMode(prod, "https://app.example.com/cb", false, nil, true))
}

func TestCreateClient_StandaloneLoopbackRedirect(t *testing.T) {
	newReq := func(uri string) *models.CreateOAuthClientRequest {
		return &models.CreateOAuthClientRequest{
			Name: "web", GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
			RedirectURIs: []string{uri}, Scopes: []string{"openid"},
		}
	}
	newSvc := func(standalone bool) *OAuthProviderService {
		svc := newTestOAuthProviderService(t, new(MockOAuthClientRepo), new(MockOAuthUserRepo))
		svc.SetTenantTypeLookup(fixedTypeLookup{tt: models.TenantType("customer")})
		svc.SetStandaloneMode(standalone)
		return svc
	}

	// Outside standalone: production tier rejects http://localhost with a typed error.
	_, _, err := newSvc(false).CreateClient(context.Background(), uuid.New(), newReq("http://localhost:3000/cb"), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRedirectURI))
	code, desc, ok := ClientValidationDescription(err)
	assert.True(t, ok)
	assert.Equal(t, "invalid_redirect_uri", code)
	assert.Contains(t, desc, "https scheme")

	// Standalone: non-loopback http is still rejected.
	_, _, err = newSvc(true).CreateClient(context.Background(), uuid.New(), newReq("http://app.example.com/cb"), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRedirectURI))

	// Standalone: loopback passes the redirect check (the nil-repo mock later
	// fails on persistence, which must not be a validation error).
	func() {
		defer func() { _ = recover() }()
		_, _, err = newSvc(true).CreateClient(context.Background(), uuid.New(), newReq("http://localhost:3000/cb"), nil)
		assert.False(t, errors.Is(err, ErrInvalidRedirectURI))
	}()
}

func TestCreateClient_InvalidMetadataIsTyped(t *testing.T) {
	svc := newTestOAuthProviderService(t, new(MockOAuthClientRepo), new(MockOAuthUserRepo))
	_, _, err := svc.CreateClient(context.Background(), uuid.New(), &models.CreateOAuthClientRequest{
		Name: "x", GrantTypes: []string{"authorization_code"}, Scopes: []string{"openid"}, LogoURL: strPtr("http://x.example.com/l.png"),
	}, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidClientMetadata))
}

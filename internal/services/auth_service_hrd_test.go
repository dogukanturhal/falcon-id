// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	testTenantSlugAcme = "acme-corp"
)

// --- Mock ---

type mockLoginDiscoverer struct {
	resp *models.DiscoverResponse
	err  error
}

func (m *mockLoginDiscoverer) Discover(_ context.Context, _ *models.DiscoverRequest) (*models.DiscoverResponse, error) {
	return m.resp, m.err
}

// --- Tests ---

func TestResolveTenantContext_EmailDiscovery_FindsTenant(t *testing.T) {
	tenantID := uuid.New().String()
	tenantSlug := testTenantSlugAcme

	discoverer := &mockLoginDiscoverer{
		resp: &models.DiscoverResponse{
			Email:      "user@acme.com",
			EmailKnown: true,
			AuthMethod: "password",
			TenantID:   &tenantID,
			TenantSlug: &tenantSlug,
		},
	}

	svc := &AuthService{}
	svc.SetLoginDiscoverer(discoverer)

	ctx := context.Background()
	tenantCtx, err := svc.resolveTenantContext(ctx, &models.LoginRequest{
		Username: "user@acme.com",
		// No TenantSlug or TenantID — should trigger email discovery
	})

	assert.NoError(t, err)
	assert.NotNil(t, tenantCtx)
	parsedID, _ := uuid.Parse(tenantID)
	assert.Equal(t, parsedID, tenantCtx.TenantID)
	assert.Equal(t, tenantSlug, tenantCtx.TenantSlug)
}

func TestResolveTenantContext_EmailDiscovery_SSO_ReturnsError(t *testing.T) {
	tenantID := uuid.New().String()
	ssoProviderID := uuid.New().String()

	discoverer := &mockLoginDiscoverer{
		resp: &models.DiscoverResponse{
			Email:         "user@sso-corp.com",
			AuthMethod:    "sso",
			TenantID:      &tenantID,
			SSOProviderID: &ssoProviderID,
		},
	}

	svc := &AuthService{}
	svc.SetLoginDiscoverer(discoverer)

	_, err := svc.resolveTenantContext(context.Background(), &models.LoginRequest{
		Username: "user@sso-corp.com",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SSO")
}

func TestResolveTenantContext_EmailDiscovery_NoTenant_ReturnsError(t *testing.T) {
	discoverer := &mockLoginDiscoverer{
		resp: &models.DiscoverResponse{
			Email:      "unknown@example.com",
			AuthMethod: "signup",
		},
	}

	svc := &AuthService{}
	svc.SetLoginDiscoverer(discoverer)

	_, err := svc.resolveTenantContext(context.Background(), &models.LoginRequest{
		Username: "unknown@example.com",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant")
}

func TestResolveTenantContext_NilDiscoverer_FallsBackToError(t *testing.T) {
	svc := &AuthService{}
	// No discoverer set

	_, err := svc.resolveTenantContext(context.Background(), &models.LoginRequest{
		Username: "user@example.com",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant context required")
}

func TestResolveTenantContext_NonEmail_FallsBackToError(t *testing.T) {
	discoverer := &mockLoginDiscoverer{
		resp: &models.DiscoverResponse{},
	}

	svc := &AuthService{}
	svc.SetLoginDiscoverer(discoverer)

	// Username without @ should not trigger HRD
	_, err := svc.resolveTenantContext(context.Background(), &models.LoginRequest{
		Username: "admin",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant context required")
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ─── mock implementations ─────────────────────────────────────────────────────

type mockDiscoverDomainRepo struct{ mock.Mock }

func (m *mockDiscoverDomainRepo) GetVerifiedByDomain(ctx context.Context, domain string) (*models.EmailDomainRegistry, error) {
	args := m.Called(ctx, domain)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.EmailDomainRegistry), args.Error(1)
}

type mockDiscoverTenantRepo struct{ mock.Mock }

func (m *mockDiscoverTenantRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Tenant), args.Error(1)
}

type mockDiscoverUserRepo struct{ mock.Mock }

func (m *mockDiscoverUserRepo) GetByEmailGlobal(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

type mockDiscoverIDPRepo struct{ mock.Mock }

func (m *mockDiscoverIDPRepo) GetEnabledLoginProviders(ctx context.Context, tenantID uuid.UUID, realmID uuid.UUID) ([]*models.IdentityProvider, error) {
	args := m.Called(ctx, tenantID, realmID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.IdentityProvider), args.Error(1)
}

type mockDiscoverBrandingRepo struct{ mock.Mock }

func (m *mockDiscoverBrandingRepo) GetByTenantID(ctx context.Context, tenantID uuid.UUID) (*models.TenantBranding, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TenantBranding), args.Error(1)
}

// ─── test fixtures ────────────────────────────────────────────────────────────

func newDiscoverService(
	domainRepo *mockDiscoverDomainRepo,
	tenantRepo *mockDiscoverTenantRepo,
	userRepo *mockDiscoverUserRepo,
	idpRepo *mockDiscoverIDPRepo,
	brandingRepo *mockDiscoverBrandingRepo,
) *DiscoverService {
	return NewDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo, nil)
}

func testTenant() *models.Tenant {
	return &models.Tenant{
		ID:          uuid.New(),
		Name:        "acme-corp",
		Slug:        "acme-corp",
		DisplayName: "Acme Corporation",
		Status:      "active",
		Type:        models.TenantTypeCustomer,
		Plan:        "enterprise",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
}

func testDomainEntry(tenantID uuid.UUID) *models.EmailDomainRegistry {
	token := "tok-abc"
	now := time.Now().UTC()
	return &models.EmailDomainRegistry{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Domain:             "acme.com",
		IsVerified:         true,
		VerificationToken:  &token,
		VerificationMethod: "dns_txt",
		VerifiedAt:         &now,
		AutoEnroll:         false,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

func testUser(tenantID uuid.UUID, email string) *models.User {
	return &models.User{
		ID:       uuid.New(),
		TenantID: tenantID,
		RealmID:  uuid.New(),
		Username: "testuser",
		Email:    email,
		IsActive: true,
	}
}

func testSAMLProvider(tenantID uuid.UUID, priority int) *models.IdentityProvider {
	return &models.IdentityProvider{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Type:        "saml",
		Name:        "acme-saml",
		DisplayName: "Acme SSO",
		IsEnabled:   true,
		Priority:    priority,
	}
}

func testOIDCProvider(tenantID uuid.UUID, priority int) *models.IdentityProvider {
	return &models.IdentityProvider{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Type:        "oidc",
		Name:        "acme-oidc",
		DisplayName: "Acme OIDC",
		IsEnabled:   true,
		Priority:    priority,
	}
}

func testGoogleProvider(tenantID uuid.UUID) *models.IdentityProvider {
	return &models.IdentityProvider{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Type:        "google",
		Name:        "google",
		DisplayName: "Google",
		IsEnabled:   true,
		Priority:    0,
	}
}

func testBranding(tenantID uuid.UUID) *models.TenantBranding {
	logo := "https://cdn.acme.com/logo.png"
	title := "Acme Login"
	now := time.Now().UTC()
	return &models.TenantBranding{
		ID:              uuid.New(),
		TenantID:        tenantID,
		LogoURL:         &logo,
		PrimaryColor:    "#CC0000",
		BackgroundColor: "#F5F5F5",
		LoginTitle:      &title,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// ─── test cases ───────────────────────────────────────────────────────────────

func TestDiscoverService_Discover(t *testing.T) {
	ctx := context.Background()

	t.Run("known domain with SSO enforced returns sso auth method", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		entry := testDomainEntry(tenant.ID)
		saml := testSAMLProvider(tenant.ID, 10)
		google := testGoogleProvider(tenant.ID)

		domainRepo.On("GetVerifiedByDomain", ctx, "acme.com").Return(entry, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(tenant, nil)
		brandingRepo.On("GetByTenantID", ctx, tenant.ID).Return(nil, nil)
		idpRepo.On("GetEnabledLoginProviders", ctx, tenant.ID, mock.Anything).Return([]*models.IdentityProvider{saml, google}, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "jane@acme.com"})

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "jane@acme.com", resp.Email)
		assert.Equal(t, "sso", resp.AuthMethod)
		require.NotNil(t, resp.SSOProviderID)
		assert.Equal(t, saml.ID.String(), *resp.SSOProviderID)
		require.NotNil(t, resp.SSOProviderType)
		assert.Equal(t, "saml", *resp.SSOProviderType)
		require.NotNil(t, resp.SSOProviderName)
		assert.Equal(t, "Acme SSO", *resp.SSOProviderName)
		assert.Len(t, resp.AvailableProviders, 2)
		assert.Equal(t, tenant.ID.String(), *resp.TenantID)
		assert.Nil(t, resp.Branding)

		domainRepo.AssertExpectations(t)
		tenantRepo.AssertExpectations(t)
		idpRepo.AssertExpectations(t)
		brandingRepo.AssertExpectations(t)
		userRepo.AssertNotCalled(t, "GetByEmailGlobal")
	})

	t.Run("known domain with OIDC provider and priority enforced returns sso", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		entry := testDomainEntry(tenant.ID)
		oidc := testOIDCProvider(tenant.ID, 5)

		domainRepo.On("GetVerifiedByDomain", ctx, "acme.com").Return(entry, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(tenant, nil)
		brandingRepo.On("GetByTenantID", ctx, tenant.ID).Return(nil, nil)
		idpRepo.On("GetEnabledLoginProviders", ctx, tenant.ID, mock.Anything).Return([]*models.IdentityProvider{oidc}, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "bob@acme.com"})

		require.NoError(t, err)
		assert.Equal(t, "sso", resp.AuthMethod)
		assert.Equal(t, "oidc", *resp.SSOProviderType)
		userRepo.AssertNotCalled(t, "GetByEmailGlobal")
	})

	t.Run("known domain, user exists, no SSO returns password auth method", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		entry := testDomainEntry(tenant.ID)
		user := testUser(tenant.ID, "alice@acme.com")
		google := testGoogleProvider(tenant.ID)

		// SAML with priority 0 should NOT enforce SSO
		samlNoSSO := testSAMLProvider(tenant.ID, 0)

		domainRepo.On("GetVerifiedByDomain", ctx, "acme.com").Return(entry, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(tenant, nil)
		brandingRepo.On("GetByTenantID", ctx, tenant.ID).Return(nil, nil)
		idpRepo.On("GetEnabledLoginProviders", ctx, tenant.ID, mock.Anything).Return([]*models.IdentityProvider{samlNoSSO, google}, nil)
		userRepo.On("GetByEmailGlobal", ctx, "alice@acme.com").Return(user, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "alice@acme.com"})

		require.NoError(t, err)
		assert.Equal(t, "password", resp.AuthMethod)
		assert.True(t, resp.EmailKnown)
		assert.Equal(t, tenant.ID.String(), *resp.TenantID)
		assert.Len(t, resp.AvailableProviders, 2)
		assert.Nil(t, resp.SSOProviderID)

		domainRepo.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})

	t.Run("known domain, no SSO, inactive user returns contact_admin", func(t *testing.T) {
		// An is_active=false user (typically pending email verification or
		// admin-disabled) must NOT be routed to the password form (login
		// would fail with "invalid credentials" with no recovery hint) NOR
		// to the signup flow (misleads the user into thinking their email
		// is unrecognised when in fact their account just isn't activated).
		// The contact_admin path renders an explicit "your account is not
		// active, contact your administrator" screen.
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		entry := testDomainEntry(tenant.ID)
		user := testUser(tenant.ID, "alice@acme.com")
		user.IsActive = false

		domainRepo.On("GetVerifiedByDomain", ctx, "acme.com").Return(entry, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(tenant, nil)
		brandingRepo.On("GetByTenantID", ctx, tenant.ID).Return(nil, nil)
		idpRepo.On("GetEnabledLoginProviders", ctx, tenant.ID, mock.Anything).Return([]*models.IdentityProvider{}, nil)
		userRepo.On("GetByEmailGlobal", ctx, "alice@acme.com").Return(user, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "alice@acme.com"})

		require.NoError(t, err)
		assert.Equal(t, "contact_admin", resp.AuthMethod)
		assert.True(t, resp.EmailKnown, "inactive user still exists — UI must not show signup flow")
		assert.False(t, resp.SignupAllowed)

		domainRepo.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})

	t.Run("known domain, user does not exist, auto_enroll false returns contact_admin", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		entry := testDomainEntry(tenant.ID)
		entry.AutoEnroll = false

		domainRepo.On("GetVerifiedByDomain", ctx, "acme.com").Return(entry, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(tenant, nil)
		brandingRepo.On("GetByTenantID", ctx, tenant.ID).Return(nil, nil)
		idpRepo.On("GetEnabledLoginProviders", ctx, tenant.ID, mock.Anything).Return([]*models.IdentityProvider{}, nil)
		userRepo.On("GetByEmailGlobal", ctx, "newbie@acme.com").Return(nil, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "newbie@acme.com"})

		require.NoError(t, err)
		assert.Equal(t, "contact_admin", resp.AuthMethod)
		assert.False(t, resp.EmailKnown)
		assert.False(t, resp.SignupAllowed)
		assert.Equal(t, tenant.ID.String(), *resp.TenantID)

		domainRepo.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})

	t.Run("known domain, user does not exist, auto_enroll true returns signup business", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		entry := testDomainEntry(tenant.ID)
		entry.AutoEnroll = true

		domainRepo.On("GetVerifiedByDomain", ctx, "acme.com").Return(entry, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(tenant, nil)
		brandingRepo.On("GetByTenantID", ctx, tenant.ID).Return(nil, nil)
		idpRepo.On("GetEnabledLoginProviders", ctx, tenant.ID, mock.Anything).Return([]*models.IdentityProvider{}, nil)
		userRepo.On("GetByEmailGlobal", ctx, "newenroll@acme.com").Return(nil, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "newenroll@acme.com"})

		require.NoError(t, err)
		assert.Equal(t, "signup", resp.AuthMethod)
		assert.False(t, resp.EmailKnown)
		assert.True(t, resp.SignupAllowed)
		require.NotNil(t, resp.AccountType)
		assert.Equal(t, "business", *resp.AccountType)

		domainRepo.AssertExpectations(t)
	})

	t.Run("unknown domain, user exists returns password with tenant branding", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		user := testUser(tenant.ID, "john@personal.io")
		branding := testBranding(tenant.ID)
		google := testGoogleProvider(tenant.ID)

		domainRepo.On("GetVerifiedByDomain", ctx, "personal.io").Return(nil, nil)
		userRepo.On("GetByEmailGlobal", ctx, "john@personal.io").Return(user, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(tenant, nil)
		brandingRepo.On("GetByTenantID", ctx, tenant.ID).Return(branding, nil)
		idpRepo.On("GetEnabledLoginProviders", ctx, tenant.ID, mock.Anything).Return([]*models.IdentityProvider{google}, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "john@personal.io"})

		require.NoError(t, err)
		assert.Equal(t, "password", resp.AuthMethod)
		assert.True(t, resp.EmailKnown)
		assert.Equal(t, tenant.ID.String(), *resp.TenantID)
		require.NotNil(t, resp.Branding)
		assert.Equal(t, "#CC0000", resp.Branding.PrimaryColor)
		assert.Len(t, resp.AvailableProviders, 1)

		domainRepo.AssertExpectations(t)
		tenantRepo.AssertExpectations(t)
		brandingRepo.AssertExpectations(t)
	})

	t.Run("unknown domain, inactive user returns contact_admin (not signup)", func(t *testing.T) {
		// Companion to "known domain, no SSO, inactive user returns
		// contact_admin" — same routing applies on the no-domain-match
		// path. Without this branch the inactive user would be told their
		// email is unknown and offered self-service signup, which leaks no
		// useful information and prevents account recovery.
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		user := testUser(tenant.ID, "john@personal.io")
		user.IsActive = false

		domainRepo.On("GetVerifiedByDomain", ctx, "personal.io").Return(nil, nil)
		userRepo.On("GetByEmailGlobal", ctx, "john@personal.io").Return(user, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(tenant, nil)
		brandingRepo.On("GetByTenantID", ctx, tenant.ID).Return(nil, nil)
		idpRepo.On("GetEnabledLoginProviders", ctx, tenant.ID, mock.Anything).Return([]*models.IdentityProvider{}, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "john@personal.io"})

		require.NoError(t, err)
		assert.Equal(t, "contact_admin", resp.AuthMethod)
		assert.True(t, resp.EmailKnown)
		assert.False(t, resp.SignupAllowed)

		domainRepo.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})

	t.Run("unknown domain, unknown user returns signup personal", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		domainRepo.On("GetVerifiedByDomain", ctx, "gmail.com").Return(nil, nil)
		userRepo.On("GetByEmailGlobal", ctx, "stranger@gmail.com").Return(nil, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "stranger@gmail.com"})

		require.NoError(t, err)
		assert.Equal(t, "signup", resp.AuthMethod)
		assert.False(t, resp.EmailKnown)
		assert.True(t, resp.SignupAllowed)
		require.NotNil(t, resp.AccountType)
		assert.Equal(t, "personal", *resp.AccountType)
		assert.Nil(t, resp.TenantID)
		assert.Nil(t, resp.Branding)

		domainRepo.AssertExpectations(t)
		userRepo.AssertExpectations(t)
		tenantRepo.AssertNotCalled(t, "GetByID")
		brandingRepo.AssertNotCalled(t, "GetByTenantID")
	})

	t.Run("invalid email format returns error", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		_, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "not-an-email"})

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDiscoverInvalidEmail)

		domainRepo.AssertNotCalled(t, "GetVerifiedByDomain")
	})

	t.Run("email normalised to lowercase before lookup", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		// Expectations use lowercase — the service must normalise before calling.
		domainRepo.On("GetVerifiedByDomain", ctx, "example.com").Return(nil, nil)
		userRepo.On("GetByEmailGlobal", ctx, "user@example.com").Return(nil, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "USER@EXAMPLE.COM"})

		require.NoError(t, err)
		assert.Equal(t, "user@example.com", resp.Email)

		domainRepo.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})

	t.Run("branding returned when available for domain user", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		entry := testDomainEntry(tenant.ID)
		branding := testBranding(tenant.ID)
		user := testUser(tenant.ID, "branded@acme.com")

		domainRepo.On("GetVerifiedByDomain", ctx, "acme.com").Return(entry, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(tenant, nil)
		brandingRepo.On("GetByTenantID", ctx, tenant.ID).Return(branding, nil)
		idpRepo.On("GetEnabledLoginProviders", ctx, tenant.ID, mock.Anything).Return([]*models.IdentityProvider{}, nil)
		userRepo.On("GetByEmailGlobal", ctx, "branded@acme.com").Return(user, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "branded@acme.com"})

		require.NoError(t, err)
		require.NotNil(t, resp.Branding)
		assert.Equal(t, "#CC0000", resp.Branding.PrimaryColor)
		assert.Equal(t, "#F5F5F5", resp.Branding.BackgroundColor)
		require.NotNil(t, resp.Branding.LogoURL)
		assert.Equal(t, "https://cdn.acme.com/logo.png", *resp.Branding.LogoURL)
		require.NotNil(t, resp.Branding.LoginTitle)
		assert.Equal(t, "Acme Login", *resp.Branding.LoginTitle)
	})

	t.Run("no branding when not configured for tenant", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		entry := testDomainEntry(tenant.ID)

		domainRepo.On("GetVerifiedByDomain", ctx, "acme.com").Return(entry, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(tenant, nil)
		brandingRepo.On("GetByTenantID", ctx, tenant.ID).Return(nil, nil)
		idpRepo.On("GetEnabledLoginProviders", ctx, tenant.ID, mock.Anything).Return([]*models.IdentityProvider{}, nil)
		userRepo.On("GetByEmailGlobal", ctx, "nob@acme.com").Return(nil, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "nob@acme.com"})

		require.NoError(t, err)
		assert.Nil(t, resp.Branding)
		assert.Equal(t, "contact_admin", resp.AuthMethod)
	})

	t.Run("domain registry error returns wrapped error", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		domainRepo.On("GetVerifiedByDomain", ctx, "acme.com").Return(nil, errors.New("connection refused"))

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		_, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "user@acme.com"})

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDiscoverDomainLookup)
		assert.Contains(t, err.Error(), "connection refused")
	})

	t.Run("tenant lookup failure after domain match returns error", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		entry := testDomainEntry(tenant.ID)

		domainRepo.On("GetVerifiedByDomain", ctx, "acme.com").Return(entry, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(nil, errors.New("tenant not found"))

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		_, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "user@acme.com"})

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDiscoverTenantLookup)
		assert.Contains(t, err.Error(), "tenant not found")
	})

	t.Run("unknown domain with user having nil TenantID returns password without branding", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		// User exists but is not assigned to any tenant (edge case)
		user := &models.User{
			ID:       uuid.New(),
			TenantID: uuid.Nil,
			Email:    "floating@test.io",
			IsActive: true,
		}

		domainRepo.On("GetVerifiedByDomain", ctx, "test.io").Return(nil, nil)
		userRepo.On("GetByEmailGlobal", ctx, "floating@test.io").Return(user, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "floating@test.io"})

		require.NoError(t, err)
		assert.Equal(t, "password", resp.AuthMethod)
		assert.True(t, resp.EmailKnown)
		assert.Nil(t, resp.TenantID)
		assert.Nil(t, resp.Branding)

		tenantRepo.AssertNotCalled(t, "GetByID")
		brandingRepo.AssertNotCalled(t, "GetByTenantID")
	})

	t.Run("SSO not triggered when SAML priority is zero", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		entry := testDomainEntry(tenant.ID)
		samlZero := testSAMLProvider(tenant.ID, 0) // priority = 0, should NOT enforce SSO
		user := testUser(tenant.ID, "user@acme.com")

		domainRepo.On("GetVerifiedByDomain", ctx, "acme.com").Return(entry, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(tenant, nil)
		brandingRepo.On("GetByTenantID", ctx, tenant.ID).Return(nil, nil)
		idpRepo.On("GetEnabledLoginProviders", ctx, tenant.ID, mock.Anything).Return([]*models.IdentityProvider{samlZero}, nil)
		userRepo.On("GetByEmailGlobal", ctx, "user@acme.com").Return(user, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "user@acme.com"})

		require.NoError(t, err)
		// Should fall through to password, not SSO
		assert.Equal(t, "password", resp.AuthMethod)
		assert.Nil(t, resp.SSOProviderID)
	})

	t.Run("whitespace in email is trimmed", func(t *testing.T) {
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		domainRepo.On("GetVerifiedByDomain", ctx, "example.com").Return(nil, nil)
		userRepo.On("GetByEmailGlobal", ctx, "user@example.com").Return(nil, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{Email: "  user@example.com  "})

		require.NoError(t, err)
		assert.Equal(t, "user@example.com", resp.Email)

		domainRepo.AssertExpectations(t)
	})

	t.Run("realm-scoped IDP surfaces when request carries realm", func(t *testing.T) {
		// Verifies G3: a realm-scoped IDP must reach the response when
		// the request carries a non-Nil RealmID. Pre-fix, the service
		// hard-coded uuid.Nil and the repo's `scope='realm'` branch
		// never matched, hiding every realm-scoped provider from
		// /discover.
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		entry := testDomainEntry(tenant.ID)
		realmID := uuid.New()
		realmScopedOIDC := &models.IdentityProvider{
			ID:          uuid.New(),
			TenantID:    tenant.ID,
			RealmID:     &realmID,
			Type:        "oidc",
			Name:        "realm-oidc",
			DisplayName: "Realm OIDC",
			IsEnabled:   true,
			Priority:    7,
		}

		domainRepo.On("GetVerifiedByDomain", ctx, "acme.com").Return(entry, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(tenant, nil)
		brandingRepo.On("GetByTenantID", ctx, tenant.ID).Return(nil, nil)
		// Tight expectation: the realmID passed by the caller MUST be
		// the one used in the repo call. Using mock.Anything would
		// silently re-introduce the uuid.Nil bug.
		idpRepo.On("GetEnabledLoginProviders", ctx, tenant.ID, realmID).
			Return([]*models.IdentityProvider{realmScopedOIDC}, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{
			Email:   "jane@acme.com",
			RealmID: realmID,
		})

		require.NoError(t, err)
		require.NotNil(t, resp)
		// Realm-scoped OIDC at Priority>0 enforces SSO.
		assert.Equal(t, "sso", resp.AuthMethod)
		require.NotNil(t, resp.SSOProviderID)
		assert.Equal(t, realmScopedOIDC.ID.String(), *resp.SSOProviderID)
		assert.Len(t, resp.AvailableProviders, 1)

		idpRepo.AssertExpectations(t)
	})

	t.Run("unknown email served from negative cache on second probe", func(t *testing.T) {
		// G4: the truly-unknown path (no domain match, no global user)
		// must memoise so repeated probes for the same email do NOT
		// re-hit the domain or user repo. Cuts DB load under
		// enumeration attempts AND reduces the timing skew between
		// known and unknown branches (the second hit on this path is
		// now sub-millisecond).
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		// EXACTLY one repo call expected: the cache must absorb the second probe.
		domainRepo.On("GetVerifiedByDomain", ctx, "stranger.io").Return(nil, nil).Once()
		userRepo.On("GetByEmailGlobal", ctx, "ghost@stranger.io").Return(nil, nil).Once()

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		req := &models.DiscoverRequest{Email: "ghost@stranger.io"}

		first, err := svc.Discover(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, "signup", first.AuthMethod)
		assert.False(t, first.EmailKnown)

		// Second call — must NOT hit repos. mock.AssertExpectations
		// below will fail if it does (Times: 1 declared via .Once()).
		second, err := svc.Discover(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, "signup", second.AuthMethod)
		assert.False(t, second.EmailKnown)
		assert.Equal(t, first.Email, second.Email)

		// Caller mutating the returned response must not poison the
		// cache (we return defensive copies on both Add and Get).
		mutAccount := "business"
		second.AccountType = &mutAccount
		third, err := svc.Discover(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, third.AccountType)
		assert.Equal(t, "personal", *third.AccountType, "cache must not be poisoned by caller mutation")

		domainRepo.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})

	t.Run("realm threaded through unknown-domain enrichment path", func(t *testing.T) {
		// The unknown-domain branch enriches with tenant + IDPs via
		// enrichWithTenant. realmID must propagate there too — pre-fix
		// only the resolveForTenant branch was checked.
		domainRepo := &mockDiscoverDomainRepo{}
		tenantRepo := &mockDiscoverTenantRepo{}
		userRepo := &mockDiscoverUserRepo{}
		idpRepo := &mockDiscoverIDPRepo{}
		brandingRepo := &mockDiscoverBrandingRepo{}

		tenant := testTenant()
		user := testUser(tenant.ID, "john@personal.io")
		realmID := uuid.New()

		domainRepo.On("GetVerifiedByDomain", ctx, "personal.io").Return(nil, nil)
		userRepo.On("GetByEmailGlobal", ctx, "john@personal.io").Return(user, nil)
		tenantRepo.On("GetByID", ctx, tenant.ID).Return(tenant, nil)
		brandingRepo.On("GetByTenantID", ctx, tenant.ID).Return(nil, nil)
		idpRepo.On("GetEnabledLoginProviders", ctx, tenant.ID, realmID).
			Return([]*models.IdentityProvider{}, nil)

		svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
		resp, err := svc.Discover(ctx, &models.DiscoverRequest{
			Email:   "john@personal.io",
			RealmID: realmID,
		})

		require.NoError(t, err)
		assert.Equal(t, "password", resp.AuthMethod)
		idpRepo.AssertExpectations(t)
	})
}

// ─── benchmark ────────────────────────────────────────────────────────────────

func BenchmarkDiscoverService_Discover_UnknownUser(b *testing.B) {
	ctx := context.Background()

	domainRepo := &mockDiscoverDomainRepo{}
	tenantRepo := &mockDiscoverTenantRepo{}
	userRepo := &mockDiscoverUserRepo{}
	idpRepo := &mockDiscoverIDPRepo{}
	brandingRepo := &mockDiscoverBrandingRepo{}

	domainRepo.On("GetVerifiedByDomain", mock.Anything, "gmail.com").Return(nil, nil)
	userRepo.On("GetByEmailGlobal", mock.Anything, "bench@gmail.com").Return(nil, nil)

	svc := newDiscoverService(domainRepo, tenantRepo, userRepo, idpRepo, brandingRepo)
	req := &models.DiscoverRequest{Email: "bench@gmail.com"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.Discover(ctx, req)
	}
}

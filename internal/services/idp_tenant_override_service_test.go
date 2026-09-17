// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// --- In-process fakes ---

// fakeIDPTenantOverrideRepo implements a minimal in-memory stub for unit tests.
// It is NOT meant to mirror the pgx repository; its only purpose is to drive the
// service layer without a database.
type fakeIDPTenantOverrideRepo struct {
	overrides []*models.IDPTenantOverride
}

func (f *fakeIDPTenantOverrideRepo) Upsert(_ context.Context, o *models.IDPTenantOverride) error {
	for i, existing := range f.overrides {
		if existing.TenantID == o.TenantID && existing.ProviderID == o.ProviderID {
			f.overrides[i] = o
			return nil
		}
	}
	if o.ID == uuid.Nil {
		o.ID = uuid.New()
	}
	f.overrides = append(f.overrides, o)
	return nil
}

func (f *fakeIDPTenantOverrideRepo) GetByID(_ context.Context, id uuid.UUID) (*models.IDPTenantOverride, error) {
	for _, o := range f.overrides {
		if o.ID == id {
			return o, nil
		}
	}
	return nil, nil
}

func (f *fakeIDPTenantOverrideRepo) GetByTenantAndProvider(_ context.Context, tenantID, providerID uuid.UUID) (*models.IDPTenantOverride, error) {
	for _, o := range f.overrides {
		if o.TenantID == tenantID && o.ProviderID == providerID {
			return o, nil
		}
	}
	return nil, nil
}

func (f *fakeIDPTenantOverrideRepo) List(_ context.Context, tenantID uuid.UUID) ([]*models.IDPTenantOverride, error) {
	var result []*models.IDPTenantOverride
	for _, o := range f.overrides {
		if o.TenantID == tenantID {
			result = append(result, o)
		}
	}
	return result, nil
}

func (f *fakeIDPTenantOverrideRepo) Delete(_ context.Context, id uuid.UUID) error {
	for i, o := range f.overrides {
		if o.ID == id {
			f.overrides = append(f.overrides[:i], f.overrides[i+1:]...)
			return nil
		}
	}
	return nil
}

func (f *fakeIDPTenantOverrideRepo) GetOverrideMapByTenant(_ context.Context, tenantID uuid.UUID) (map[uuid.UUID]*models.IDPTenantOverride, error) {
	m := make(map[uuid.UUID]*models.IDPTenantOverride)
	for _, o := range f.overrides {
		if o.TenantID == tenantID {
			m[o.ProviderID] = o
		}
	}
	return m, nil
}

// fakeIDPRepo stores providers and satisfies the minimal interface needed by
// IDPTenantOverrideService.
type fakeIDPRepo struct {
	providers []*models.IdentityProvider
}

func (f *fakeIDPRepo) GetByID(_ context.Context, id uuid.UUID) (*models.IdentityProvider, error) {
	for _, p := range f.providers {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, nil
}

func (f *fakeIDPRepo) List(_ context.Context, _ uuid.UUID) ([]*models.IdentityProvider, error) {
	return f.providers, nil
}

// --- Service tests ---

func makeProvider(providerType string) *models.IdentityProvider {
	return &models.IdentityProvider{
		ID:                 uuid.New(),
		Type:               providerType,
		Name:               providerType + "-provider",
		DisplayName:        providerType + " Login",
		IsEnabled:          true,
		AutoProvisionUsers: false,
	}
}

// newTestService wires up in-memory fakes and returns the service + fake repos.
func newTestService(providers []*models.IdentityProvider, overrides []*models.IDPTenantOverride) *IDPTenantOverrideService {
	idpRepo := &fakeIDPRepo{providers: providers}
	overrideRepo := &fakeIDPTenantOverrideRepo{overrides: overrides}
	return newIDPTenantOverrideServiceWithRepos(overrideRepo, idpRepo)
}

// newIDPTenantOverrideServiceWithRepos constructs the service from fake repos.
// We use interface wrapping here rather than restructuring the real service.
func newIDPTenantOverrideServiceWithRepos(
	overrideRepo idpOverrideRepoIface,
	idpRepo idpRepoIface,
) *IDPTenantOverrideService {
	return &IDPTenantOverrideService{
		overrideRepo: overrideRepo,
		idpRepo:      idpRepo,
	}
}

// TestGetEnabledLoginProvidersWithOverrides_ShowButtonFilter verifies that when
// showButtonOnly=true, only providers with EffectiveShowAsButton()==true are
// returned.
func TestGetEnabledLoginProvidersWithOverrides_ShowButtonFilter(t *testing.T) {
	t.Parallel()

	tenantID := uuid.New()

	googleP := makeProvider("google") // social → show by default
	ldapP := makeProvider("ldap")     // enterprise → hidden by default
	samlP := makeProvider("saml")     // enterprise → hidden by default, but overridden to show
	githubP := makeProvider("github") // social → show, but overridden to hide

	// Override: show SAML as a button
	showTrue := true
	showFalse := false
	overrides := []*models.IDPTenantOverride{
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			ProviderID:   samlP.ID,
			IsEnabled:    true,
			ShowAsButton: &showTrue,
		},
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			ProviderID:   githubP.ID,
			IsEnabled:    true,
			ShowAsButton: &showFalse,
		},
	}

	svc := newTestService(
		[]*models.IdentityProvider{googleP, ldapP, samlP, githubP},
		overrides,
	)

	ctx := context.Background()

	t.Run("showButtonOnly=true filters to visible providers", func(t *testing.T) {
		result, err := svc.GetEnabledLoginProvidersWithOverrides(ctx, tenantID, true)
		require.NoError(t, err)

		ids := make(map[uuid.UUID]bool, len(result))
		for _, combo := range result {
			ids[combo.Provider.ID] = true
		}

		assert.True(t, ids[googleP.ID], "google (social, no override) should be visible")
		assert.True(t, ids[samlP.ID], "saml (enterprise, override=true) should be visible")
		assert.False(t, ids[ldapP.ID], "ldap (enterprise, no override) should be hidden")
		assert.False(t, ids[githubP.ID], "github (social, override=false) should be hidden")
	})

	t.Run("showButtonOnly=false returns all enabled", func(t *testing.T) {
		result, err := svc.GetEnabledLoginProvidersWithOverrides(ctx, tenantID, false)
		require.NoError(t, err)
		// All four providers are enabled (no is_enabled=false override)
		assert.Len(t, result, 4)
	})
}

// TestGetEnabledLoginProvidersWithOverrides_DisabledExclusion verifies that a
// provider disabled via its override is excluded from all listings.
func TestGetEnabledLoginProvidersWithOverrides_DisabledExclusion(t *testing.T) {
	t.Parallel()

	tenantID := uuid.New()
	googleP := makeProvider("google")
	msP := makeProvider("microsoft")

	// Disable Microsoft for this tenant via override
	overrides := []*models.IDPTenantOverride{
		{
			ID:         uuid.New(),
			TenantID:   tenantID,
			ProviderID: msP.ID,
			IsEnabled:  false,
		},
	}

	svc := newTestService([]*models.IdentityProvider{googleP, msP}, overrides)

	result, err := svc.GetEnabledLoginProvidersWithOverrides(context.Background(), tenantID, false)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, googleP.ID, result[0].Provider.ID)
}

// TestDiscoverService_GetDiscoverResponse verifies that the discover response
// respects show_as_button filtering and populates signup_enabled correctly.
func TestDiscoverService_GetDiscoverResponse(t *testing.T) {
	t.Parallel()

	tenantID := uuid.New()

	googleP := makeProvider("google")
	googleP.AutoProvisionUsers = true

	ldapP := makeProvider("ldap")

	showTrue := true
	signupFalse := false

	overrides := []*models.IDPTenantOverride{
		// LDAP gets a button but signup is explicitly disabled
		{
			ID:              uuid.New(),
			TenantID:        tenantID,
			ProviderID:      ldapP.ID,
			IsEnabled:       true,
			ShowAsButton:    &showTrue,
			IsSignupEnabled: &signupFalse,
		},
	}

	overrideRepo := &fakeIDPTenantOverrideRepo{overrides: overrides}
	idpRepo := &fakeIDPRepo{providers: []*models.IdentityProvider{googleP, ldapP}}
	svc := NewDiscoverService(nil, nil, nil, nil, nil, newIDPTenantOverrideServiceWithRepos(overrideRepo, idpRepo))

	resp, err := svc.GetDiscoverResponse(context.Background(), tenantID)
	require.NoError(t, err)

	// Both providers are enabled; google by type default shows a button, ldap is forced
	assert.Equal(t, 2, resp.TotalEnabled)
	assert.Len(t, resp.AvailableProviders, 2)

	// Find each provider in the response
	byType := make(map[string]DiscoverProvider)
	for _, p := range resp.AvailableProviders {
		byType[p.Type] = p
	}

	require.Contains(t, byType, "google")
	assert.True(t, byType["google"].SignupEnabled, "google inherits AutoProvisionUsers=true")
	assert.True(t, byType["google"].AssignMembership)

	require.Contains(t, byType, "ldap")
	assert.False(t, byType["ldap"].SignupEnabled, "ldap has explicit is_signup_enabled=false override")
}

// TestIDPTenantOverrideService_Upsert_NewRecord verifies that Upsert creates a
// new record when none exists for the (tenant, provider) pair.
func TestIDPTenantOverrideService_Upsert_NewRecord(t *testing.T) {
	t.Parallel()

	tenantID := uuid.New()
	googleP := makeProvider("google")

	svc := newTestService([]*models.IdentityProvider{googleP}, nil)

	showFalse := false
	req := &models.UpsertIDPTenantOverrideRequest{
		ProviderID:   googleP.ID,
		IsEnabled:    true,
		ShowAsButton: &showFalse,
	}

	result, err := svc.Upsert(context.Background(), tenantID, req)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, tenantID, result.TenantID)
	assert.Equal(t, googleP.ID, result.ProviderID)
	assert.NotNil(t, result.ShowAsButton)
	assert.False(t, *result.ShowAsButton)
}

// TestIDPTenantOverrideService_Upsert_UpdatesExisting verifies that Upsert
// replaces an existing override when (tenant, provider) already has a record.
func TestIDPTenantOverrideService_Upsert_UpdatesExisting(t *testing.T) {
	t.Parallel()

	tenantID := uuid.New()
	googleP := makeProvider("google")
	showTrue := true
	showFalse := false

	existing := &models.IDPTenantOverride{
		ID:           uuid.New(),
		TenantID:     tenantID,
		ProviderID:   googleP.ID,
		IsEnabled:    true,
		ShowAsButton: &showTrue,
	}

	svc := newTestService([]*models.IdentityProvider{googleP}, []*models.IDPTenantOverride{existing})

	req := &models.UpsertIDPTenantOverrideRequest{
		ProviderID:   googleP.ID,
		IsEnabled:    false, // changing this
		ShowAsButton: &showFalse,
	}

	result, err := svc.Upsert(context.Background(), tenantID, req)
	require.NoError(t, err)
	assert.False(t, result.IsEnabled)
	assert.NotNil(t, result.ShowAsButton)
	assert.False(t, *result.ShowAsButton)
}

// TestIDPTenantOverrideService_Upsert_UnknownProvider verifies that Upsert
// returns an error when the specified provider does not exist.
func TestIDPTenantOverrideService_Upsert_UnknownProvider(t *testing.T) {
	t.Parallel()

	svc := newTestService(nil, nil)

	req := &models.UpsertIDPTenantOverrideRequest{
		ProviderID: uuid.New(),
		IsEnabled:  true,
	}

	_, err := svc.Upsert(context.Background(), uuid.New(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestIDPTenantOverrideService_DeleteOverride_WrongTenant verifies that
// deleting an override that belongs to a different tenant returns an error.
func TestIDPTenantOverrideService_DeleteOverride_WrongTenant(t *testing.T) {
	t.Parallel()

	tenantA := uuid.New()
	tenantB := uuid.New()

	oid := uuid.New()
	overrides := []*models.IDPTenantOverride{
		{ID: oid, TenantID: tenantA, ProviderID: uuid.New(), IsEnabled: true},
	}

	svc := newTestService(nil, overrides)

	err := svc.DeleteOverride(context.Background(), tenantB, oid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong to tenant")
}

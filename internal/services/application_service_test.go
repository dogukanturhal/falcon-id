// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mock: mockApplicationRepo
// ---------------------------------------------------------------------------

type mockApplicationRepo struct {
	mock.Mock
}

func (m *mockApplicationRepo) Create(ctx context.Context, app *models.Application) error {
	args := m.Called(ctx, app)
	return args.Error(0)
}

func (m *mockApplicationRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Application, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Application), args.Error(1)
}

func (m *mockApplicationRepo) GetBySlug(ctx context.Context, slug string) (*models.Application, error) {
	args := m.Called(ctx, slug)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Application), args.Error(1)
}

func (m *mockApplicationRepo) List(ctx context.Context, page, pageSize int, status, publisherType string, isPlatformApp *bool) ([]models.Application, int64, error) {
	args := m.Called(ctx, page, pageSize, status, publisherType, isPlatformApp)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.Application), args.Get(1).(int64), args.Error(2)
}

func (m *mockApplicationRepo) Update(ctx context.Context, id uuid.UUID, req *models.UpdateApplicationRequest) (*models.Application, error) {
	args := m.Called(ctx, id, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Application), args.Error(1)
}

func (m *mockApplicationRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockApplicationRepo) GetPreauthorized(ctx context.Context) ([]models.Application, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Application), args.Error(1)
}

func (m *mockApplicationRepo) CountServicePrincipals(ctx context.Context, appID uuid.UUID) (int64, error) {
	args := m.Called(ctx, appID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockApplicationRepo) UpdatePublisherVerification(ctx context.Context, id uuid.UUID, verified bool, domain *string) error {
	args := m.Called(ctx, id, verified, domain)
	return args.Error(0)
}

func (m *mockApplicationRepo) GetByIDIncludeDeleted(ctx context.Context, id uuid.UUID) (*models.Application, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Application), args.Error(1)
}

func (m *mockApplicationRepo) SoftDelete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockApplicationRepo) Restore(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockApplicationRepo) PurgeExpired(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockApplicationRepo) ListDeleted(ctx context.Context) ([]models.Application, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Application), args.Error(1)
}

func (m *mockApplicationRepo) SoftDeleteSP(ctx context.Context, spID uuid.UUID) error {
	args := m.Called(ctx, spID)
	return args.Error(0)
}

func (m *mockApplicationRepo) RestoreSP(ctx context.Context, spID uuid.UUID) error {
	args := m.Called(ctx, spID)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Mock: mockApplicationSPRepo
// ---------------------------------------------------------------------------

type mockApplicationSPRepo struct {
	mock.Mock
}

func (m *mockApplicationSPRepo) Create(ctx context.Context, sp *models.ServicePrincipal) error {
	args := m.Called(ctx, sp)
	return args.Error(0)
}

func (m *mockApplicationSPRepo) GetByApplicationAndTenant(ctx context.Context, appID, tenantID uuid.UUID) (*models.ServicePrincipal, error) {
	args := m.Called(ctx, appID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ServicePrincipal), args.Error(1)
}

func (m *mockApplicationSPRepo) ListByApplication(ctx context.Context, appID uuid.UUID) ([]models.ServicePrincipal, error) {
	args := m.Called(ctx, appID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.ServicePrincipal), args.Error(1)
}

func (m *mockApplicationSPRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.ServicePrincipal, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ServicePrincipal), args.Error(1)
}

func (m *mockApplicationSPRepo) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ServicePrincipal, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.ServicePrincipal), args.Error(1)
}

func (m *mockApplicationSPRepo) Update(ctx context.Context, sp *models.ServicePrincipal) error {
	args := m.Called(ctx, sp)
	return args.Error(0)
}

func (m *mockApplicationSPRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newApplicationService(appRepo *mockApplicationRepo, spRepo *mockApplicationSPRepo) *ApplicationService {
	return NewApplicationService(appRepo, spRepo)
}

func activeApplication(id uuid.UUID, slug string) *models.Application {
	return &models.Application{
		ID:                   id,
		DisplayName:          "Test Application",
		Slug:                 slug,
		Description:          "A test application",
		AppType:              models.ApplicationAppTypeWeb,
		PublisherType:        models.ApplicationPublisherThirdParty,
		SignInAudience:       "single_tenant",
		AllowedGrantTypes:    []string{"authorization_code", "refresh_token"},
		DefaultScopes:        []string{"openid", "profile", "email"},
		RedirectURIs:         []string{},
		PostLogoutURIs:       []string{},
		Tags:                 []string{},
		AccessTokenLifetime:  3600,
		RefreshTokenLifetime: 86400,
		IDTokenLifetime:      3600,
		Status:               models.ApplicationStatusActive,
		Metadata:             []byte("{}"),
	}
}

func minimalCreateRequest() *models.CreateApplicationRequest {
	return &models.CreateApplicationRequest{
		DisplayName: "Minimal App",
		Slug:        "minimal-app",
		AppType:     models.ApplicationAppTypeWeb,
	}
}

// ---------------------------------------------------------------------------
// Tests: Create
// ---------------------------------------------------------------------------

func TestApplicationService_Create_Success(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	createdBy := uuid.New()
	req := &models.CreateApplicationRequest{
		DisplayName:       "My Web App",
		Slug:              "my-web-app",
		Description:       "A web application",
		AppType:           models.ApplicationAppTypeWeb,
		PublisherType:     models.ApplicationPublisherFirstParty,
		SignInAudience:    appAudienceMultiTenant,
		AllowedGrantTypes: []string{"client_credentials"},
		DefaultScopes:     []string{"openid", "email"},
		RedirectURIs:      []string{"https://example.com/callback"},
		Tags:              []string{"internal"},
	}

	appRepo.On("Create", ctx, mock.AnythingOfType("*models.Application")).Return(nil)

	app, err := svc.Create(ctx, req, &createdBy)

	require.NoError(t, err)
	require.NotNil(t, app)
	assert.NotEqual(t, uuid.Nil, app.ID)
	assert.Equal(t, "My Web App", app.DisplayName)
	assert.Equal(t, "my-web-app", app.Slug)
	assert.Equal(t, models.ApplicationStatusActive, app.Status)
	assert.Equal(t, models.ApplicationPublisherFirstParty, app.PublisherType)
	assert.Equal(t, appAudienceMultiTenant, app.SignInAudience)
	assert.Equal(t, []string{"client_credentials"}, app.AllowedGrantTypes)
	assert.Equal(t, []string{"openid", "email"}, app.DefaultScopes)
	assert.Equal(t, []string{"https://example.com/callback"}, app.RedirectURIs)
	assert.Equal(t, []byte("{}"), app.Metadata)
	assert.Equal(t, &createdBy, app.CreatedBy)

	appRepo.AssertExpectations(t)
}

func TestApplicationService_Create_Defaults(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	// Submit a bare-minimum request — omit all optional fields to trigger defaults.
	req := minimalCreateRequest()
	appRepo.On("Create", ctx, mock.AnythingOfType("*models.Application")).Return(nil)

	app, err := svc.Create(ctx, req, nil)

	require.NoError(t, err)
	require.NotNil(t, app)

	// publisher_type defaults to third_party
	assert.Equal(t, models.ApplicationPublisherThirdParty, app.PublisherType)

	// sign_in_audience defaults to single_tenant
	assert.Equal(t, "single_tenant", app.SignInAudience)

	// allowed_grant_types defaults to authorization_code + refresh_token
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, app.AllowedGrantTypes)

	// default_scopes defaults to openid, profile, email
	assert.Equal(t, []string{"openid", "profile", "email"}, app.DefaultScopes)

	// slices that are nil become empty slices, not nil
	assert.NotNil(t, app.RedirectURIs)
	assert.NotNil(t, app.PostLogoutURIs)
	assert.NotNil(t, app.Tags)

	// token lifetime defaults
	assert.Equal(t, 3600, app.AccessTokenLifetime)
	assert.Equal(t, 86400, app.RefreshTokenLifetime)
	assert.Equal(t, 3600, app.IDTokenLifetime)

	appRepo.AssertExpectations(t)
}

func TestApplicationService_Create_CustomTokenLifetimes(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	access := 1800
	refresh := 43200
	id := 900
	req := &models.CreateApplicationRequest{
		DisplayName:          "Lifetime App",
		Slug:                 "lifetime-app",
		AppType:              models.ApplicationAppTypeService,
		AccessTokenLifetime:  &access,
		RefreshTokenLifetime: &refresh,
		IDTokenLifetime:      &id,
	}

	appRepo.On("Create", ctx, mock.AnythingOfType("*models.Application")).Return(nil)

	app, err := svc.Create(ctx, req, nil)

	require.NoError(t, err)
	assert.Equal(t, 1800, app.AccessTokenLifetime)
	assert.Equal(t, 43200, app.RefreshTokenLifetime)
	assert.Equal(t, 900, app.IDTokenLifetime)

	appRepo.AssertExpectations(t)
}

func TestApplicationService_Create_RepoError(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appRepo.On("Create", ctx, mock.AnythingOfType("*models.Application")).
		Return(errors.New("unique constraint violation"))

	app, err := svc.Create(ctx, minimalCreateRequest(), nil)

	assert.Error(t, err)
	assert.Nil(t, app)
	assert.Contains(t, err.Error(), "ApplicationService.Create")

	appRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetByID
// ---------------------------------------------------------------------------

func TestApplicationService_GetByID_Success(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	id := uuid.New()
	expected := activeApplication(id, "my-app")
	appRepo.On("GetByID", ctx, id).Return(expected, nil)

	app, err := svc.GetByID(ctx, id)

	require.NoError(t, err)
	require.NotNil(t, app)
	assert.Equal(t, id, app.ID)
	assert.Equal(t, "my-app", app.Slug)

	appRepo.AssertExpectations(t)
}

func TestApplicationService_GetByID_NotFound(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	id := uuid.New()
	appRepo.On("GetByID", ctx, id).Return(nil, errors.New("not found"))

	app, err := svc.GetByID(ctx, id)

	assert.Error(t, err)
	assert.Nil(t, app)
	assert.Contains(t, err.Error(), "ApplicationService.GetByID")

	appRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetBySlug
// ---------------------------------------------------------------------------

func TestApplicationService_GetBySlug_Success(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	id := uuid.New()
	slug := "my-web-app"
	expected := activeApplication(id, slug)
	appRepo.On("GetBySlug", ctx, slug).Return(expected, nil)

	app, err := svc.GetBySlug(ctx, slug)

	require.NoError(t, err)
	require.NotNil(t, app)
	assert.Equal(t, slug, app.Slug)
	assert.Equal(t, id, app.ID)

	appRepo.AssertExpectations(t)
}

func TestApplicationService_GetBySlug_NotFound(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appRepo.On("GetBySlug", ctx, "unknown-slug").Return(nil, errors.New("not found"))

	app, err := svc.GetBySlug(ctx, "unknown-slug")

	assert.Error(t, err)
	assert.Nil(t, app)
	assert.Contains(t, err.Error(), "ApplicationService.GetBySlug")

	appRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: List
// ---------------------------------------------------------------------------

func TestApplicationService_List_AllFilters(t *testing.T) {
	tests := []struct {
		name          string
		page          int
		pageSize      int
		status        string
		publisherType string
		isPlatformApp *bool
		returnCount   int64
	}{
		{
			name:          "no filters returns all",
			page:          1,
			pageSize:      20,
			status:        "",
			publisherType: "",
			isPlatformApp: nil,
			returnCount:   5,
		},
		{
			name:          "filter by active status",
			page:          1,
			pageSize:      10,
			status:        "active",
			publisherType: "",
			isPlatformApp: nil,
			returnCount:   3,
		},
		{
			name:          "filter by publisher type",
			page:          1,
			pageSize:      10,
			status:        "",
			publisherType: "first_party",
			isPlatformApp: nil,
			returnCount:   2,
		},
		{
			name:          "filter platform apps only",
			page:          1,
			pageSize:      10,
			status:        "active",
			publisherType: "first_party",
			isPlatformApp: boolPtr(true),
			returnCount:   1,
		},
		{
			name:          "empty result set",
			page:          2,
			pageSize:      50,
			status:        "archived",
			publisherType: "",
			isPlatformApp: nil,
			returnCount:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			appRepo := new(mockApplicationRepo)
			spRepo := new(mockApplicationSPRepo)
			svc := newApplicationService(appRepo, spRepo)

			apps := make([]models.Application, tt.returnCount)
			for i := range apps {
				apps[i] = *activeApplication(uuid.New(), "app-"+uuid.New().String()[:8])
			}

			appRepo.On("List", ctx, tt.page, tt.pageSize, tt.status, tt.publisherType, tt.isPlatformApp).
				Return(apps, tt.returnCount, nil)

			result, total, err := svc.List(ctx, tt.page, tt.pageSize, tt.status, tt.publisherType, tt.isPlatformApp)

			require.NoError(t, err)
			assert.Equal(t, tt.returnCount, total)
			assert.Len(t, result, int(tt.returnCount))

			appRepo.AssertExpectations(t)
		})
	}
}

func TestApplicationService_List_RepoError(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appRepo.On("List", ctx, 1, 20, "", "", (*bool)(nil)).
		Return(nil, int64(0), errors.New("db connection lost"))

	result, total, err := svc.List(ctx, 1, 20, "", "", nil)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Zero(t, total)
	assert.Contains(t, err.Error(), "ApplicationService.List")

	appRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: Update
// ---------------------------------------------------------------------------

func TestApplicationService_Update_Success(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	id := uuid.New()
	existing := activeApplication(id, "my-app")

	newName := "Updated Name"
	req := &models.UpdateApplicationRequest{
		DisplayName: &newName,
	}
	updated := *existing
	updated.DisplayName = newName

	appRepo.On("GetByID", ctx, id).Return(existing, nil)
	appRepo.On("Update", ctx, id, req).Return(&updated, nil)

	app, err := svc.Update(ctx, id, req)

	require.NoError(t, err)
	require.NotNil(t, app)
	assert.Equal(t, "Updated Name", app.DisplayName)

	appRepo.AssertExpectations(t)
}

func TestApplicationService_Update_NotFound(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	id := uuid.New()
	appRepo.On("GetByID", ctx, id).Return(nil, errors.New("not found"))

	app, err := svc.Update(ctx, id, &models.UpdateApplicationRequest{})

	assert.Error(t, err)
	assert.Nil(t, app)
	assert.Contains(t, err.Error(), "application not found")

	appRepo.AssertExpectations(t)
}

func TestApplicationService_Update_RepoError(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	id := uuid.New()
	existing := activeApplication(id, "my-app")
	req := &models.UpdateApplicationRequest{}

	appRepo.On("GetByID", ctx, id).Return(existing, nil)
	appRepo.On("Update", ctx, id, req).Return(nil, errors.New("update failed"))

	app, err := svc.Update(ctx, id, req)

	assert.Error(t, err)
	assert.Nil(t, app)
	assert.Contains(t, err.Error(), "ApplicationService.Update")

	appRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: Delete
// ---------------------------------------------------------------------------

func TestApplicationService_Delete_Success(t *testing.T) {
	// Delete on a non-soft-deleted app initiates a soft-delete (first call).
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	id := uuid.New()
	existing := activeApplication(id, "app-to-delete")
	// DeletedAt is nil → Delete() will route to SoftDelete()
	appRepo.On("GetByIDIncludeDeleted", ctx, id).Return(existing, nil)
	appRepo.On("GetByID", ctx, id).Return(existing, nil)
	appRepo.On("SoftDelete", ctx, id).Return(nil)

	err := svc.Delete(ctx, id)

	require.NoError(t, err)
	appRepo.AssertExpectations(t)
}

func TestApplicationService_Delete_NotFound(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	id := uuid.New()
	appRepo.On("GetByIDIncludeDeleted", ctx, id).Return(nil, errors.New("not found"))

	err := svc.Delete(ctx, id)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "application not found")

	appRepo.AssertExpectations(t)
}

func TestApplicationService_Delete_RepoError(t *testing.T) {
	// When the app is already soft-deleted, Delete() hard-deletes it.
	// Test that a repo error on hard-delete is surfaced.
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	id := uuid.New()
	existing := activeApplication(id, "my-app")
	now := time.Now()
	existing.DeletedAt = &now // already soft-deleted

	appRepo.On("GetByIDIncludeDeleted", ctx, id).Return(existing, nil)
	appRepo.On("Delete", ctx, id).Return(errors.New("foreign key constraint"))

	err := svc.Delete(ctx, id)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ApplicationService.Delete")

	appRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ProvisionServicePrincipal
// ---------------------------------------------------------------------------

func TestApplicationService_ProvisionServicePrincipal_New(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	tenantID := uuid.New()
	app := activeApplication(appID, "my-saas-app")
	app.SignInAudience = appAudienceMultiTenant // ensure audience check passes

	// No existing SP for this (app, tenant) pair.
	spRepo.On("GetByApplicationAndTenant", ctx, appID, tenantID).
		Return(nil, errors.New("not found"))
	appRepo.On("GetByID", ctx, appID).Return(app, nil)
	spRepo.On("Create", ctx, mock.AnythingOfType("*models.ServicePrincipal")).Return(nil)

	resp, err := svc.ProvisionServicePrincipal(ctx, appID, tenantID, nil)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.ServicePrincipal)
	sp := resp.ServicePrincipal
	assert.NotEmpty(t, sp.ID)
	assert.Equal(t, models.SPTypeApplication, sp.Type)
	assert.Equal(t, models.SPInstallStatusEnabled, sp.InstallationStatus)
	assert.Equal(t, "active", sp.Status)

	// Name must include application display name
	assert.Contains(t, sp.Name, app.DisplayName)

	// Slug must incorporate the app slug and the beginning of the tenant ID
	assert.True(t, strings.HasPrefix(sp.Slug, app.Slug+"-"),
		"SP slug %q should start with app slug %q followed by a dash", sp.Slug, app.Slug+"-")
	assert.Contains(t, sp.Slug, tenantID.String()[:8])

	spRepo.AssertExpectations(t)
	appRepo.AssertExpectations(t)
}

func TestApplicationService_ProvisionServicePrincipal_Idempotent(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	tenantID := uuid.New()

	existingSP := &models.ServicePrincipal{
		ID:                 uuid.New(),
		Name:               "Existing SP",
		Slug:               "existing-sp",
		Type:               models.SPTypeApplication,
		ApplicationID:      &appID,
		TenantID:           &tenantID,
		InstallationStatus: models.SPInstallStatusEnabled,
		Status:             "active",
	}

	// Existing SP found — no further calls should be made.
	spRepo.On("GetByApplicationAndTenant", ctx, appID, tenantID).Return(existingSP, nil)

	resp, err := svc.ProvisionServicePrincipal(ctx, appID, tenantID, nil)

	require.NoError(t, err)
	require.NotNil(t, resp)
	// Must return the existing SP without creating a new one.
	assert.Equal(t, existingSP.ID, resp.ServicePrincipal.ID)
	assert.Equal(t, existingSP.Name, resp.ServicePrincipal.Name)

	// appRepo.GetByID and spRepo.Create must NOT be called.
	appRepo.AssertNotCalled(t, "GetByID")
	spRepo.AssertNotCalled(t, "Create")

	spRepo.AssertExpectations(t)
	appRepo.AssertExpectations(t)
}

func TestApplicationService_ProvisionServicePrincipal_InactiveApp_Fails(t *testing.T) {
	tests := []struct {
		name   string
		status models.ApplicationStatus
	}{
		{name: "disabled application", status: models.ApplicationStatusDisabled},
		{name: "archived application", status: models.ApplicationStatusArchived},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			appRepo := new(mockApplicationRepo)
			spRepo := new(mockApplicationSPRepo)
			svc := newApplicationService(appRepo, spRepo)

			appID := uuid.New()
			tenantID := uuid.New()

			inactiveApp := activeApplication(appID, "inactive-app")
			inactiveApp.Status = tt.status

			spRepo.On("GetByApplicationAndTenant", ctx, appID, tenantID).
				Return(nil, errors.New("not found"))
			appRepo.On("GetByID", ctx, appID).Return(inactiveApp, nil)

			resp, err := svc.ProvisionServicePrincipal(ctx, appID, tenantID, nil)

			assert.Nil(t, resp)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not active")
			assert.Contains(t, err.Error(), string(tt.status))

			// spRepo.Create must NOT be called for an inactive application.
			spRepo.AssertNotCalled(t, "Create")

			spRepo.AssertExpectations(t)
			appRepo.AssertExpectations(t)
		})
	}
}

func TestApplicationService_ProvisionServicePrincipal_AppNotFound(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	tenantID := uuid.New()

	spRepo.On("GetByApplicationAndTenant", ctx, appID, tenantID).
		Return(nil, errors.New("not found"))
	appRepo.On("GetByID", ctx, appID).Return(nil, errors.New("record not found"))

	resp, err := svc.ProvisionServicePrincipal(ctx, appID, tenantID, nil)

	assert.Nil(t, resp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "app not found")

	spRepo.AssertNotCalled(t, "Create")

	spRepo.AssertExpectations(t)
	appRepo.AssertExpectations(t)
}

func TestApplicationService_ProvisionServicePrincipal_CreateFails(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	tenantID := uuid.New()
	app := activeApplication(appID, "my-app")
	app.SignInAudience = appAudienceMultiTenant // ensure audience check passes

	spRepo.On("GetByApplicationAndTenant", ctx, appID, tenantID).
		Return(nil, errors.New("not found"))
	appRepo.On("GetByID", ctx, appID).Return(app, nil)
	spRepo.On("Create", ctx, mock.AnythingOfType("*models.ServicePrincipal")).
		Return(errors.New("db error"))

	resp, err := svc.ProvisionServicePrincipal(ctx, appID, tenantID, nil)

	assert.Nil(t, resp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ApplicationService.ProvisionServicePrincipal")

	spRepo.AssertExpectations(t)
	appRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ListServicePrincipals
// ---------------------------------------------------------------------------

func TestApplicationService_ListServicePrincipals_Success(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	t1 := uuid.New()
	t2 := uuid.New()

	expectedSPs := []models.ServicePrincipal{
		{
			ID:            uuid.New(),
			Name:          "SP for Tenant 1",
			Slug:          "sp-tenant-1",
			ApplicationID: &appID,
			TenantID:      &t1,
			Type:          models.SPTypeApplication,
			Status:        "active",
		},
		{
			ID:            uuid.New(),
			Name:          "SP for Tenant 2",
			Slug:          "sp-tenant-2",
			ApplicationID: &appID,
			TenantID:      &t2,
			Type:          models.SPTypeApplication,
			Status:        "active",
		},
	}

	spRepo.On("ListByApplication", ctx, appID).Return(expectedSPs, nil)

	sps, err := svc.ListServicePrincipals(ctx, appID)

	require.NoError(t, err)
	assert.Len(t, sps, 2)
	assert.Equal(t, &appID, sps[0].ApplicationID)
	assert.Equal(t, &appID, sps[1].ApplicationID)

	spRepo.AssertExpectations(t)
}

func TestApplicationService_ListServicePrincipals_Empty(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	spRepo.On("ListByApplication", ctx, appID).Return([]models.ServicePrincipal{}, nil)

	sps, err := svc.ListServicePrincipals(ctx, appID)

	require.NoError(t, err)
	assert.Empty(t, sps)

	spRepo.AssertExpectations(t)
}

func TestApplicationService_ListServicePrincipals_RepoError(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	spRepo.On("ListByApplication", ctx, appID).Return(nil, errors.New("db error"))

	sps, err := svc.ListServicePrincipals(ctx, appID)

	assert.Error(t, err)
	assert.Nil(t, sps)
	assert.Contains(t, err.Error(), "ApplicationService.ListServicePrincipals")

	spRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetServicePrincipalCount
// ---------------------------------------------------------------------------

func TestApplicationService_GetServicePrincipalCount_Success(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	appRepo.On("CountServicePrincipals", ctx, appID).Return(int64(7), nil)

	count, err := svc.GetServicePrincipalCount(ctx, appID)

	require.NoError(t, err)
	assert.Equal(t, int64(7), count)

	appRepo.AssertExpectations(t)
}

func TestApplicationService_GetServicePrincipalCount_Zero(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	appRepo.On("CountServicePrincipals", ctx, appID).Return(int64(0), nil)

	count, err := svc.GetServicePrincipalCount(ctx, appID)

	require.NoError(t, err)
	assert.Zero(t, count)

	appRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Mock: mockAppConsentChecker
// ---------------------------------------------------------------------------

type mockAppConsentChecker struct {
	mock.Mock
}

func (m *mockAppConsentChecker) HasConsent(ctx context.Context, appID, tenantID uuid.UUID) (bool, error) {
	args := m.Called(ctx, appID, tenantID)
	return args.Bool(0), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// boolPtr returns a pointer to b, used for optional bool filter parameters.
func boolPtr(b bool) *bool {
	return &b
}

// ---------------------------------------------------------------------------
// Phase 2 Tests: State machine transitions
// ---------------------------------------------------------------------------

func TestValidateStatusTransition(t *testing.T) {
	tests := []struct {
		name    string
		from    models.ServicePrincipalInstallStatus
		to      models.ServicePrincipalInstallStatus
		wantErr bool
	}{
		{"installed→enabled", models.SPInstallStatusInstalled, models.SPInstallStatusEnabled, false},
		{"enabled→disabled", models.SPInstallStatusEnabled, models.SPInstallStatusDisabled, false},
		{"disabled→enabled", models.SPInstallStatusDisabled, models.SPInstallStatusEnabled, false},
		{"disabled→uninstalled", models.SPInstallStatusDisabled, models.SPInstallStatusUninstalled, false},
		{"enabled→uninstalled (must go through disabled)", models.SPInstallStatusEnabled, models.SPInstallStatusUninstalled, true},
		{"installed→disabled", models.SPInstallStatusInstalled, models.SPInstallStatusDisabled, true},
		{"installed→uninstalled", models.SPInstallStatusInstalled, models.SPInstallStatusUninstalled, true},
		{"uninstalled→enabled", models.SPInstallStatusUninstalled, models.SPInstallStatusEnabled, true},
		{"enabled→installed", models.SPInstallStatusEnabled, models.SPInstallStatusInstalled, true},
		{"same state", models.SPInstallStatusEnabled, models.SPInstallStatusEnabled, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStatusTransition(tt.from, tt.to)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Phase 2 Tests: EnableSP / DisableSP
// ---------------------------------------------------------------------------

func TestApplicationService_EnableSP(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	spID := uuid.New()
	tenantID := uuid.New()

	sp := &models.ServicePrincipal{
		ID:                 spID,
		Name:               "Test SP",
		Slug:               "test-sp",
		ApplicationID:      &appID,
		TenantID:           &tenantID,
		Type:               models.SPTypeApplication,
		InstallationStatus: models.SPInstallStatusInstalled,
		Status:             "active",
	}

	spRepo.On("GetByID", ctx, spID).Return(sp, nil)
	spRepo.On("Update", ctx, mock.AnythingOfType("*models.ServicePrincipal")).Return(nil)

	result, err := svc.EnableSP(ctx, appID, spID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, models.SPInstallStatusEnabled, result.InstallationStatus)

	spRepo.AssertExpectations(t)
}

func TestApplicationService_DisableSP(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	spID := uuid.New()
	tenantID := uuid.New()

	sp := &models.ServicePrincipal{
		ID:                 spID,
		Name:               "Test SP",
		Slug:               "test-sp",
		ApplicationID:      &appID,
		TenantID:           &tenantID,
		Type:               models.SPTypeApplication,
		InstallationStatus: models.SPInstallStatusEnabled,
		Status:             "active",
	}

	spRepo.On("GetByID", ctx, spID).Return(sp, nil)
	spRepo.On("Update", ctx, mock.AnythingOfType("*models.ServicePrincipal")).Return(nil)

	result, err := svc.DisableSP(ctx, appID, spID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, models.SPInstallStatusDisabled, result.InstallationStatus)

	spRepo.AssertExpectations(t)
}

func TestApplicationService_EnableSP_WrongApp(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	otherAppID := uuid.New()
	spID := uuid.New()

	sp := &models.ServicePrincipal{
		ID:            spID,
		ApplicationID: &otherAppID,
	}

	spRepo.On("GetByID", ctx, spID).Return(sp, nil)

	result, err := svc.EnableSP(ctx, appID, spID)

	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong to application")
}

// ---------------------------------------------------------------------------
// Phase 2 Tests: DeleteSP
// ---------------------------------------------------------------------------

func TestApplicationService_DeleteSP(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	spID := uuid.New()
	tenantID := uuid.New()

	sp := &models.ServicePrincipal{
		ID:            spID,
		ApplicationID: &appID,
		TenantID:      &tenantID,
	}

	spRepo.On("GetByID", ctx, spID).Return(sp, nil)
	spRepo.On("Delete", ctx, spID).Return(nil)

	err := svc.DeleteSP(ctx, appID, spID)

	require.NoError(t, err)
	spRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Phase 2 Tests: GetSP
// ---------------------------------------------------------------------------

func TestApplicationService_GetSP(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	spID := uuid.New()

	sp := &models.ServicePrincipal{
		ID:            spID,
		Name:          "My SP",
		ApplicationID: &appID,
	}

	spRepo.On("GetByID", ctx, spID).Return(sp, nil)

	result, err := svc.GetSP(ctx, appID, spID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, spID, result.ID)

	spRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Phase 2 Tests: ListSPsByTenant
// ---------------------------------------------------------------------------

func TestApplicationService_ListSPsByTenant(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	tenantID := uuid.New()
	appID := uuid.New()

	expectedSPs := []models.ServicePrincipal{
		{ID: uuid.New(), ApplicationID: &appID, TenantID: &tenantID, Name: "SP1"},
		{ID: uuid.New(), ApplicationID: &appID, TenantID: &tenantID, Name: "SP2"},
	}

	spRepo.On("ListByTenant", ctx, tenantID).Return(expectedSPs, nil)

	sps, err := svc.ListSPsByTenant(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, sps, 2)

	spRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Phase 2 Tests: VerifyPublisher / RevokeVerification
// ---------------------------------------------------------------------------

func TestApplicationService_VerifyPublisher(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	app := activeApplication(appID, "my-app")
	domain := "example.com"

	appRepo.On("GetByID", ctx, appID).Return(app, nil)
	appRepo.On("UpdatePublisherVerification", ctx, appID, true, &domain).Return(nil)

	result, err := svc.VerifyPublisher(ctx, appID, domain)

	require.NoError(t, err)
	require.NotNil(t, result)
	appRepo.AssertExpectations(t)
}

func TestApplicationService_RevokeVerification(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	app := activeApplication(appID, "my-app")

	appRepo.On("GetByID", ctx, appID).Return(app, nil)
	appRepo.On("UpdatePublisherVerification", ctx, appID, false, (*string)(nil)).Return(nil)

	result, err := svc.RevokeVerification(ctx, appID)

	require.NoError(t, err)
	require.NotNil(t, result)
	appRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Phase 2 Tests: Audience enforcement
// ---------------------------------------------------------------------------

func TestApplicationService_ProvisionServicePrincipal_SingleTenantBlocked(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	ownerTenant := uuid.New()
	otherTenant := uuid.New()

	app := activeApplication(appID, "single-tenant-app")
	app.SignInAudience = "single_tenant"
	app.CreatedBy = &ownerTenant

	spRepo.On("GetByApplicationAndTenant", ctx, appID, otherTenant).
		Return(nil, errors.New("not found"))
	appRepo.On("GetByID", ctx, appID).Return(app, nil)

	resp, err := svc.ProvisionServicePrincipal(ctx, appID, otherTenant, nil)

	assert.Nil(t, resp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "single_tenant")

	spRepo.AssertNotCalled(t, "Create")
}

// ---------------------------------------------------------------------------
// Phase 2 Tests: BulkProvision
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tests: ProvisionServicePrincipal — consent-gating (C6)
// ---------------------------------------------------------------------------

// TestProvisionServicePrincipal_ConsentRequired verifies that a multi-tenant,
// non-first-party, non-preauthorized application cannot provision a service
// principal in a tenant that has not yet granted admin consent.
func TestProvisionServicePrincipal_ConsentRequired(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	consentChecker := new(mockAppConsentChecker)
	svc := newApplicationService(appRepo, spRepo)
	svc.SetAppConsentService(consentChecker)

	appID := uuid.New()
	tenantID := uuid.New()

	app := activeApplication(appID, "third-party-app")
	app.SignInAudience = appAudienceMultiTenant
	app.PublisherType = models.ApplicationPublisherThirdParty
	app.Preauthorized = false

	spRepo.On("GetByApplicationAndTenant", ctx, appID, tenantID).
		Return(nil, errors.New("not found"))
	appRepo.On("GetByID", ctx, appID).Return(app, nil)
	// Tenant has NOT granted consent.
	consentChecker.On("HasConsent", ctx, appID, tenantID).Return(false, nil)

	resp, err := svc.ProvisionServicePrincipal(ctx, appID, tenantID, nil)

	assert.Nil(t, resp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has not granted admin consent")
	assert.Contains(t, err.Error(), tenantID.String())
	assert.Contains(t, err.Error(), appID.String())

	spRepo.AssertNotCalled(t, "Create")
	consentChecker.AssertExpectations(t)
	appRepo.AssertExpectations(t)
	spRepo.AssertExpectations(t)
}

// TestProvisionServicePrincipal_ConsentGranted verifies that a multi-tenant
// third-party application with active admin consent provisions successfully.
func TestProvisionServicePrincipal_ConsentGranted(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	consentChecker := new(mockAppConsentChecker)
	svc := newApplicationService(appRepo, spRepo)
	svc.SetAppConsentService(consentChecker)

	appID := uuid.New()
	tenantID := uuid.New()

	app := activeApplication(appID, "third-party-app")
	app.SignInAudience = appAudienceMultiTenant
	app.PublisherType = models.ApplicationPublisherThirdParty
	app.Preauthorized = false

	spRepo.On("GetByApplicationAndTenant", ctx, appID, tenantID).
		Return(nil, errors.New("not found"))
	appRepo.On("GetByID", ctx, appID).Return(app, nil)
	// Tenant HAS granted consent.
	consentChecker.On("HasConsent", ctx, appID, tenantID).Return(true, nil)
	spRepo.On("Create", ctx, mock.AnythingOfType("*models.ServicePrincipal")).Return(nil)

	resp, err := svc.ProvisionServicePrincipal(ctx, appID, tenantID, nil)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.ServicePrincipal)
	assert.Equal(t, models.SPInstallStatusEnabled, resp.ServicePrincipal.InstallationStatus)

	consentChecker.AssertExpectations(t)
	appRepo.AssertExpectations(t)
	spRepo.AssertExpectations(t)
}

// TestProvisionServicePrincipal_FirstPartySkipsConsent verifies that first-party
// applications bypass the consent check entirely.
func TestProvisionServicePrincipal_FirstPartySkipsConsent(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	consentChecker := new(mockAppConsentChecker)
	svc := newApplicationService(appRepo, spRepo)
	svc.SetAppConsentService(consentChecker)

	appID := uuid.New()
	tenantID := uuid.New()

	app := activeApplication(appID, "platform-app")
	app.SignInAudience = appAudienceMultiTenant
	app.PublisherType = models.ApplicationPublisherFirstParty
	app.Preauthorized = false

	spRepo.On("GetByApplicationAndTenant", ctx, appID, tenantID).
		Return(nil, errors.New("not found"))
	appRepo.On("GetByID", ctx, appID).Return(app, nil)
	spRepo.On("Create", ctx, mock.AnythingOfType("*models.ServicePrincipal")).Return(nil)

	resp, err := svc.ProvisionServicePrincipal(ctx, appID, tenantID, nil)

	require.NoError(t, err)
	require.NotNil(t, resp)

	// HasConsent must NEVER be called for first-party apps.
	consentChecker.AssertNotCalled(t, "HasConsent")
	appRepo.AssertExpectations(t)
	spRepo.AssertExpectations(t)
}

// TestProvisionServicePrincipal_PreauthorizedSkipsConsent verifies that
// preauthorized applications bypass the consent check entirely.
func TestProvisionServicePrincipal_PreauthorizedSkipsConsent(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	consentChecker := new(mockAppConsentChecker)
	svc := newApplicationService(appRepo, spRepo)
	svc.SetAppConsentService(consentChecker)

	appID := uuid.New()
	tenantID := uuid.New()

	app := activeApplication(appID, "preauth-app")
	app.SignInAudience = appAudienceMultiTenant
	app.PublisherType = models.ApplicationPublisherThirdParty
	app.Preauthorized = true // preauthorized flag bypasses consent

	spRepo.On("GetByApplicationAndTenant", ctx, appID, tenantID).
		Return(nil, errors.New("not found"))
	appRepo.On("GetByID", ctx, appID).Return(app, nil)
	spRepo.On("Create", ctx, mock.AnythingOfType("*models.ServicePrincipal")).Return(nil)

	resp, err := svc.ProvisionServicePrincipal(ctx, appID, tenantID, nil)

	require.NoError(t, err)
	require.NotNil(t, resp)

	// HasConsent must NEVER be called for preauthorized apps.
	consentChecker.AssertNotCalled(t, "HasConsent")
	appRepo.AssertExpectations(t)
	spRepo.AssertExpectations(t)
}

func TestApplicationService_BulkProvisionServicePrincipals(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	t1 := uuid.New()
	t2 := uuid.New()
	app := activeApplication(appID, "bulk-app")
	app.SignInAudience = appAudienceMultiTenant

	// Tenant 1: successful provision
	spRepo.On("GetByApplicationAndTenant", ctx, appID, t1).
		Return(nil, errors.New("not found"))
	appRepo.On("GetByID", ctx, appID).Return(app, nil)
	spRepo.On("Create", ctx, mock.AnythingOfType("*models.ServicePrincipal")).Return(nil)

	// Tenant 2: successful provision
	spRepo.On("GetByApplicationAndTenant", ctx, appID, t2).
		Return(nil, errors.New("not found"))

	results := svc.BulkProvisionServicePrincipals(ctx, appID, []uuid.UUID{t1, t2})

	assert.Len(t, results, 2)
	// At least one should succeed (both should since mocks allow multiple calls)
	successCount := 0
	for _, r := range results {
		if r.Error == "" {
			successCount++
		}
	}
	assert.GreaterOrEqual(t, successCount, 1)
}

// ---------------------------------------------------------------------------
// Tests: SoftDelete, Restore, PurgeExpired
// ---------------------------------------------------------------------------

func TestApplicationService_SoftDelete_Success(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	app := activeApplication(appID, "delete-me")

	appRepo.On("GetByID", ctx, appID).Return(app, nil)
	appRepo.On("SoftDelete", ctx, appID).Return(nil)

	err := svc.SoftDelete(ctx, appID)

	require.NoError(t, err)
	appRepo.AssertExpectations(t)
}

func TestApplicationService_SoftDelete_NotFound(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	appRepo.On("GetByID", ctx, appID).Return(nil, errors.New("no rows in result set"))

	err := svc.SoftDelete(ctx, appID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	appRepo.AssertExpectations(t)
}

func TestApplicationService_Delete_SoftDeletesFirst(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	// GetByIDIncludeDeleted returns a non-deleted app (DeletedAt == nil)
	app := activeApplication(appID, "delete-first-call")
	appRepo.On("GetByIDIncludeDeleted", ctx, appID).Return(app, nil)
	// Since app.DeletedAt is nil, Delete() calls SoftDelete() which calls GetByID then repo.SoftDelete
	appRepo.On("GetByID", ctx, appID).Return(app, nil)
	appRepo.On("SoftDelete", ctx, appID).Return(nil)

	err := svc.Delete(ctx, appID)

	require.NoError(t, err)
	appRepo.AssertExpectations(t)
}

func TestApplicationService_Delete_HardDeleteWhenAlreadySoftDeleted(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	// Simulate app that is already soft-deleted
	now := time.Now()
	app := activeApplication(appID, "delete-second-call")
	app.DeletedAt = &now

	appRepo.On("GetByIDIncludeDeleted", ctx, appID).Return(app, nil)
	appRepo.On("Delete", ctx, appID).Return(nil)

	err := svc.Delete(ctx, appID)

	require.NoError(t, err)
	// SoftDelete repo method must NOT have been called
	appRepo.AssertNotCalled(t, "SoftDelete", ctx, appID)
	appRepo.AssertExpectations(t)
}

func TestApplicationService_Restore_Success(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	app := activeApplication(appID, "restore-me")

	appRepo.On("Restore", ctx, appID).Return(nil)
	appRepo.On("GetByID", ctx, appID).Return(app, nil)

	restored, err := svc.Restore(ctx, appID)

	require.NoError(t, err)
	require.NotNil(t, restored)
	assert.Equal(t, appID, restored.ID)
	appRepo.AssertExpectations(t)
}

func TestApplicationService_Restore_AfterPurge(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appID := uuid.New()
	// Simulate that the 30-day window has elapsed — repo returns the canonical error
	appRepo.On("Restore", ctx, appID).Return(
		errors.New("ApplicationRepository.Restore: application not found, already restored, or purge window has elapsed"),
	)

	restored, err := svc.Restore(ctx, appID)

	require.Error(t, err)
	assert.Nil(t, restored)
	assert.Contains(t, err.Error(), "cannot be restored")
	appRepo.AssertExpectations(t)
}

func TestApplicationService_PurgeExpired(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appRepo.On("PurgeExpired", ctx).Return(int64(3), nil)

	count, err := svc.PurgeExpired(ctx)

	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
	appRepo.AssertExpectations(t)
}

func TestApplicationService_PurgeExpired_NoRecords(t *testing.T) {
	ctx := context.Background()
	appRepo := new(mockApplicationRepo)
	spRepo := new(mockApplicationSPRepo)
	svc := newApplicationService(appRepo, spRepo)

	appRepo.On("PurgeExpired", ctx).Return(int64(0), nil)

	count, err := svc.PurgeExpired(ctx)

	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
	appRepo.AssertExpectations(t)
}

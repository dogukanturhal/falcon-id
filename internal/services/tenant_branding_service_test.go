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

// ---------------------------------------------------------------------------
// Mock: tenantBrandingRepo
// ---------------------------------------------------------------------------

type MockTenantBrandingRepo struct {
	mock.Mock
}

func (m *MockTenantBrandingRepo) GetByTenantID(ctx context.Context, tenantID uuid.UUID) (*models.TenantBranding, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TenantBranding), args.Error(1)
}

func (m *MockTenantBrandingRepo) Upsert(ctx context.Context, branding *models.TenantBranding) error {
	args := m.Called(ctx, branding)
	return args.Error(0)
}

func (m *MockTenantBrandingRepo) Delete(ctx context.Context, tenantID uuid.UUID) error {
	args := m.Called(ctx, tenantID)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTenantBrandingService(repo *MockTenantBrandingRepo) *TenantBrandingService {
	return NewTenantBrandingService(repo)
}

func sampleBranding(tenantID uuid.UUID) *models.TenantBranding {
	logo := "https://cdn.acme.io/logo.png"
	primary := "#ff5733"
	bg := "#f0f0f0"
	now := time.Now()
	return &models.TenantBranding{
		ID:              uuid.New(),
		TenantID:        tenantID,
		LogoURL:         &logo,
		PrimaryColor:    primary,
		BackgroundColor: bg,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

func brandingStrPtr(s string) *string { return &s }
func brandingBoolPtr(b bool) *bool    { return &b }

// ---------------------------------------------------------------------------
// Tests: GetBranding
// ---------------------------------------------------------------------------

func TestTenantBrandingService_GetBranding_ReturnsExisting(t *testing.T) {
	ctx := context.Background()
	repo := new(MockTenantBrandingRepo)
	svc := newTenantBrandingService(repo)

	tenantID := uuid.New()
	existing := sampleBranding(tenantID)

	repo.On("GetByTenantID", ctx, tenantID).Return(existing, nil)

	result, err := svc.GetBranding(ctx, tenantID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, existing.ID, result.ID)
	assert.Equal(t, "#ff5733", result.PrimaryColor)
	repo.AssertExpectations(t)
}

func TestTenantBrandingService_GetBranding_ReturnsDefaultsWhenNil(t *testing.T) {
	ctx := context.Background()
	repo := new(MockTenantBrandingRepo)
	svc := newTenantBrandingService(repo)

	tenantID := uuid.New()
	repo.On("GetByTenantID", ctx, tenantID).Return((*models.TenantBranding)(nil), nil)

	result, err := svc.GetBranding(ctx, tenantID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, tenantID, result.TenantID)
	assert.Equal(t, defaultPrimaryColor, result.PrimaryColor)
	assert.Equal(t, defaultBackgroundColor, result.BackgroundColor)
	// No ID is set on a default-only value object.
	assert.Equal(t, uuid.Nil, result.ID)
	repo.AssertExpectations(t)
}

func TestTenantBrandingService_GetBranding_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(MockTenantBrandingRepo)
	svc := newTenantBrandingService(repo)

	tenantID := uuid.New()
	repo.On("GetByTenantID", ctx, tenantID).Return((*models.TenantBranding)(nil), errors.New("db error"))

	result, err := svc.GetBranding(ctx, tenantID)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "get branding")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: UpdateBranding – create new
// ---------------------------------------------------------------------------

func TestTenantBrandingService_UpdateBranding_CreatesNewBranding(t *testing.T) {
	ctx := context.Background()
	repo := new(MockTenantBrandingRepo)
	svc := newTenantBrandingService(repo)

	tenantID := uuid.New()
	// No existing record.
	repo.On("GetByTenantID", ctx, tenantID).Return((*models.TenantBranding)(nil), nil)
	repo.On("Upsert", ctx, mock.AnythingOfType("*models.TenantBranding")).Return(nil)

	req := &models.UpdateTenantBrandingRequest{
		PrimaryColor: brandingStrPtr("#123456"),
	}

	result, err := svc.UpdateBranding(ctx, tenantID, req)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "#123456", result.PrimaryColor)
	// Fields not in request retain their defaults.
	assert.Equal(t, defaultBackgroundColor, result.BackgroundColor)
	assert.Equal(t, tenantID, result.TenantID)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: UpdateBranding – partial update of existing record
// ---------------------------------------------------------------------------

func TestTenantBrandingService_UpdateBranding_PartialUpdate(t *testing.T) {
	ctx := context.Background()
	repo := new(MockTenantBrandingRepo)
	svc := newTenantBrandingService(repo)

	tenantID := uuid.New()
	existing := sampleBranding(tenantID)
	originalBg := existing.BackgroundColor // "#f0f0f0"

	repo.On("GetByTenantID", ctx, tenantID).Return(existing, nil)
	repo.On("Upsert", ctx, mock.AnythingOfType("*models.TenantBranding")).Return(nil)

	// Only update PrimaryColor; BackgroundColor should be preserved.
	req := &models.UpdateTenantBrandingRequest{
		PrimaryColor: brandingStrPtr("#aabbcc"),
	}

	result, err := svc.UpdateBranding(ctx, tenantID, req)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "#aabbcc", result.PrimaryColor)
	assert.Equal(t, originalBg, result.BackgroundColor, "unchanged field must be preserved")
	repo.AssertExpectations(t)
}

func TestTenantBrandingService_UpdateBranding_AllOptionalFields(t *testing.T) {
	ctx := context.Background()
	repo := new(MockTenantBrandingRepo)
	svc := newTenantBrandingService(repo)

	tenantID := uuid.New()
	repo.On("GetByTenantID", ctx, tenantID).Return((*models.TenantBranding)(nil), nil)
	repo.On("Upsert", ctx, mock.AnythingOfType("*models.TenantBranding")).Return(nil)

	req := &models.UpdateTenantBrandingRequest{
		LogoURL:              brandingStrPtr("https://cdn.example.com/logo.png"),
		FaviconURL:           brandingStrPtr("https://cdn.example.com/fav.ico"),
		PrimaryColor:         brandingStrPtr("#111111"),
		BackgroundColor:      brandingStrPtr("#222222"),
		AccentColor:          brandingStrPtr("#333333"),
		CustomCSS:            brandingStrPtr("body { font-size: 16px; }"),
		LoginTitle:           brandingStrPtr("Welcome to Acme"),
		LoginSubtitle:        brandingStrPtr("Sign in to continue"),
		LoginMessage:         brandingStrPtr("For support contact it@acme.io"),
		SupportEmail:         brandingStrPtr("support@acme.io"),
		SupportURL:           brandingStrPtr("https://support.acme.io"),
		PrivacyPolicyURL:     brandingStrPtr("https://acme.io/privacy"),
		TermsOfServiceURL:    brandingStrPtr("https://acme.io/terms"),
		HideHexxlockBranding: brandingBoolPtr(true),
	}

	result, err := svc.UpdateBranding(ctx, tenantID, req)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "#111111", result.PrimaryColor)
	assert.Equal(t, "#222222", result.BackgroundColor)
	assert.Equal(t, "https://cdn.example.com/logo.png", *result.LogoURL)
	assert.Equal(t, "https://cdn.example.com/fav.ico", *result.FaviconURL)
	assert.Equal(t, "#333333", *result.AccentColor)
	assert.Equal(t, "body { font-size: 16px; }", *result.CustomCSS)
	assert.Equal(t, "Welcome to Acme", *result.LoginTitle)
	assert.Equal(t, "Sign in to continue", *result.LoginSubtitle)
	assert.Equal(t, "For support contact it@acme.io", *result.LoginMessage)
	assert.Equal(t, "support@acme.io", *result.SupportEmail)
	assert.Equal(t, "https://support.acme.io", *result.SupportURL)
	assert.Equal(t, "https://acme.io/privacy", *result.PrivacyPolicyURL)
	assert.Equal(t, "https://acme.io/terms", *result.TermsOfServiceURL)
	assert.True(t, result.HideHexxlockBranding)
	repo.AssertExpectations(t)
}

func TestTenantBrandingService_UpdateBranding_UpsertError(t *testing.T) {
	ctx := context.Background()
	repo := new(MockTenantBrandingRepo)
	svc := newTenantBrandingService(repo)

	tenantID := uuid.New()
	repo.On("GetByTenantID", ctx, tenantID).Return((*models.TenantBranding)(nil), nil)
	repo.On("Upsert", ctx, mock.AnythingOfType("*models.TenantBranding")).Return(errors.New("db write error"))

	req := &models.UpdateTenantBrandingRequest{PrimaryColor: brandingStrPtr("#000000")}
	result, err := svc.UpdateBranding(ctx, tenantID, req)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "update branding")
	repo.AssertExpectations(t)
}

// GetByTenantID repo error should be treated as "no existing record" and fall
// through to create a new one, provided Upsert succeeds.
func TestTenantBrandingService_UpdateBranding_GetErrorFallsThroughToCreate(t *testing.T) {
	ctx := context.Background()
	repo := new(MockTenantBrandingRepo)
	svc := newTenantBrandingService(repo)

	tenantID := uuid.New()
	repo.On("GetByTenantID", ctx, tenantID).Return((*models.TenantBranding)(nil), errors.New("db timeout"))
	repo.On("Upsert", ctx, mock.AnythingOfType("*models.TenantBranding")).Return(nil)

	req := &models.UpdateTenantBrandingRequest{PrimaryColor: brandingStrPtr("#abcdef")}
	result, err := svc.UpdateBranding(ctx, tenantID, req)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "#abcdef", result.PrimaryColor)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: DeleteBranding
// ---------------------------------------------------------------------------

func TestTenantBrandingService_DeleteBranding_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockTenantBrandingRepo)
	svc := newTenantBrandingService(repo)

	tenantID := uuid.New()
	repo.On("Delete", ctx, tenantID).Return(nil)

	err := svc.DeleteBranding(ctx, tenantID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestTenantBrandingService_DeleteBranding_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(MockTenantBrandingRepo)
	svc := newTenantBrandingService(repo)

	tenantID := uuid.New()
	repo.On("Delete", ctx, tenantID).Return(errors.New("db error"))

	err := svc.DeleteBranding(ctx, tenantID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delete branding")
	repo.AssertExpectations(t)
}

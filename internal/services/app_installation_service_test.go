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

// ==================== Mock: appInstallRepo ====================

type mockAppInstallRepo struct {
	mock.Mock
}

func (m *mockAppInstallRepo) Create(ctx context.Context, inst *models.AppInstallation) error {
	args := m.Called(ctx, inst)
	return args.Error(0)
}

func (m *mockAppInstallRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.AppInstallation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AppInstallation), args.Error(1)
}

func (m *mockAppInstallRepo) GetByTenantAndProduct(ctx context.Context, tenantID, productID uuid.UUID) (*models.AppInstallation, error) {
	args := m.Called(ctx, tenantID, productID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AppInstallation), args.Error(1)
}

func (m *mockAppInstallRepo) List(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]models.AppInstallation, int64, error) {
	args := m.Called(ctx, tenantID, status, page, pageSize)
	return args.Get(0).([]models.AppInstallation), args.Get(1).(int64), args.Error(2)
}

func (m *mockAppInstallRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status models.AppInstallationStatus) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *mockAppInstallRepo) SetUninstalledAt(ctx context.Context, id uuid.UUID, t time.Time) error {
	args := m.Called(ctx, id, t)
	return args.Error(0)
}

// ==================== Mock: appInstallProductRepo ====================

type mockAppInstallProductRepo struct {
	mock.Mock
}

func (m *mockAppInstallProductRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Product, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Product), args.Error(1)
}

// ==================== Helpers ====================

func activeProduct(id uuid.UUID) *models.Product {
	return &models.Product{
		ID:     id,
		Name:   "Test Product",
		Slug:   "test-product",
		Type:   models.ProductTypeSaaS,
		Status: models.ProductStatusActive,
	}
}

func activeInstallation(tenantID, productID uuid.UUID) *models.AppInstallation {
	return &models.AppInstallation{
		ID:          uuid.New(),
		TenantID:    tenantID,
		ProductID:   productID,
		InstalledBy: uuid.New(),
		Status:      models.AppInstallationStatusActive,
		InstalledAt: time.Now(),
	}
}

// ==================== TestInstall_Success ====================

func TestInstall_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	productID := uuid.New()
	installedBy := uuid.New()
	scopes := []string{"read:users", "write:users"}

	installRepo := new(mockAppInstallRepo)
	productRepo := new(mockAppInstallProductRepo)

	productRepo.On("GetByID", ctx, productID).Return(activeProduct(productID), nil)
	// No existing installation.
	installRepo.On("GetByTenantAndProduct", ctx, tenantID, productID).Return(nil, errors.New("not found"))
	installRepo.On("Create", ctx, mock.AnythingOfType("*models.AppInstallation")).Return(nil)

	svc := NewAppInstallationService(installRepo, productRepo)
	inst, err := svc.Install(ctx, tenantID, productID, installedBy, scopes)

	require.NoError(t, err)
	require.NotNil(t, inst)
	assert.Equal(t, tenantID, inst.TenantID)
	assert.Equal(t, productID, inst.ProductID)
	assert.Equal(t, installedBy, inst.InstalledBy)
	assert.Equal(t, models.AppInstallationStatusActive, inst.Status)
	assert.Equal(t, scopes, inst.ConsentScopes)

	installRepo.AssertExpectations(t)
	productRepo.AssertExpectations(t)
}

// ==================== TestInstall_DuplicateInstall_ReturnsError ====================

func TestInstall_DuplicateInstall_ReturnsError(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	productID := uuid.New()

	installRepo := new(mockAppInstallRepo)
	productRepo := new(mockAppInstallProductRepo)

	productRepo.On("GetByID", ctx, productID).Return(activeProduct(productID), nil)
	// Existing active installation.
	installRepo.On("GetByTenantAndProduct", ctx, tenantID, productID).
		Return(activeInstallation(tenantID, productID), nil)

	svc := NewAppInstallationService(installRepo, productRepo)
	inst, err := svc.Install(ctx, tenantID, productID, uuid.New(), nil)

	assert.Nil(t, inst)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAlreadyInstalled)

	installRepo.AssertExpectations(t)
	productRepo.AssertExpectations(t)
}

// ==================== TestInstall_InactiveProduct_ReturnsError ====================

func TestInstall_InactiveProduct_ReturnsError(t *testing.T) {
	tests := []struct {
		name   string
		status models.ProductStatus
	}{
		{name: "deprecated product", status: models.ProductStatusDeprecated},
		{name: "archived product", status: models.ProductStatusArchived},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			productID := uuid.New()

			product := &models.Product{
				ID:     productID,
				Status: tt.status,
			}

			installRepo := new(mockAppInstallRepo)
			productRepo := new(mockAppInstallProductRepo)
			productRepo.On("GetByID", ctx, productID).Return(product, nil)

			svc := NewAppInstallationService(installRepo, productRepo)
			inst, err := svc.Install(ctx, uuid.New(), productID, uuid.New(), nil)

			assert.Nil(t, inst)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrProductInactive)
		})
	}
}

// ==================== TestUninstall_Success ====================

func TestUninstall_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	productID := uuid.New()
	inst := activeInstallation(tenantID, productID)

	installRepo := new(mockAppInstallRepo)
	productRepo := new(mockAppInstallProductRepo)

	installRepo.On("GetByTenantAndProduct", ctx, tenantID, productID).Return(inst, nil)
	installRepo.On("UpdateStatus", ctx, inst.ID, models.AppInstallationStatusUninstalled).Return(nil)
	installRepo.On("SetUninstalledAt", ctx, inst.ID, mock.AnythingOfType("time.Time")).Return(nil)

	svc := NewAppInstallationService(installRepo, productRepo)
	err := svc.Uninstall(ctx, tenantID, productID)

	require.NoError(t, err)
	installRepo.AssertExpectations(t)
}

// ==================== TestListInstallations_Success ====================

func TestListInstallations_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	expected := []models.AppInstallation{
		*activeInstallation(tenantID, uuid.New()),
		*activeInstallation(tenantID, uuid.New()),
	}

	installRepo := new(mockAppInstallRepo)
	productRepo := new(mockAppInstallProductRepo)
	installRepo.On("List", ctx, tenantID, "active", 1, 20).Return(expected, int64(2), nil)

	svc := NewAppInstallationService(installRepo, productRepo)
	result, total, err := svc.ListInstallations(ctx, tenantID, "active", 1, 20)

	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, result, 2)
	installRepo.AssertExpectations(t)
}

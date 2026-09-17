// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// --- Mocks ---

type mockPermissionAutoRegistrar struct {
	called bool
	module string
	perms  []models.PermissionDefinition
	err    error
}

func (m *mockPermissionAutoRegistrar) RegisterModule(_ context.Context, req *models.RegisterModuleRequest) (*models.RegisterModuleResponse, error) {
	m.called = true
	m.module = req.Module
	m.perms = req.Permissions
	if m.err != nil {
		return nil, m.err
	}
	return &models.RegisterModuleResponse{
		Module:     req.Module,
		Registered: len(req.Permissions),
	}, nil
}

type mockProductServiceRepo struct {
	product *models.Product
	err     error
}

func (m *mockProductServiceRepo) GetBySlug(_ context.Context, _ string) (*models.Product, error) {
	return nil, nil // not found
}

func (m *mockProductServiceRepo) Create(_ context.Context, product *models.Product) error {
	product.ID = uuid.New()
	m.product = product
	return m.err
}

func (m *mockProductServiceRepo) GetByID(_ context.Context, _ uuid.UUID) (*models.Product, error) {
	if m.product != nil {
		return m.product, nil
	}
	return nil, m.err
}

func (m *mockProductServiceRepo) List(_ context.Context, _, _ int, _, _, _ string) ([]models.Product, int64, error) {
	return nil, 0, nil
}

func (m *mockProductServiceRepo) Update(_ context.Context, _ uuid.UUID, _ *models.UpdateProductRequest) (*models.Product, error) {
	return m.product, nil
}
func (m *mockProductServiceRepo) Delete(_ context.Context, _ uuid.UUID) error { return nil }
func (m *mockProductServiceRepo) CreateVersion(_ context.Context, _ *models.ProductVersion) error {
	return nil
}

func (m *mockProductServiceRepo) ListVersions(_ context.Context, _ uuid.UUID) ([]models.ProductVersion, error) {
	return nil, nil
}

// --- Tests ---

func TestProductService_Create_CallsPermissionRegistrar(t *testing.T) {
	registrar := &mockPermissionAutoRegistrar{}
	repo := &mockProductServiceRepo{}
	svc := NewProductService(repo, nil)
	svc.SetPermissionRegistrar(registrar)

	manifest := &models.ProductManifest{
		Permissions: []models.PermissionSpec{
			{Resource: "contacts", Actions: []string{"read", "write"}},
		},
	}
	manifestBytes, _ := json.Marshal(manifest)

	// Simulate how the handler sets CapabilityManifest on the Product
	repo.err = nil
	product, err := svc.Create(context.Background(), &models.CreateProductRequest{
		Name: "Test CRM",
		Slug: "test-crm",
		Type: "saas",
	}, uuid.New())
	assert.NoError(t, err)

	// Now simulate manifest being set and trigger auto-registration
	product.CapabilityManifest = manifestBytes
	svc.autoRegisterPermissions(context.Background(), product)

	assert.True(t, registrar.called, "registrar should be called")
	assert.Equal(t, "test-crm", registrar.module)
	assert.Len(t, registrar.perms, 1)
	assert.Equal(t, "contacts", registrar.perms[0].Resource)
	assert.Equal(t, []string{"read", "write"}, registrar.perms[0].Actions)
}

func TestProductService_NilRegistrar_NoError(_ *testing.T) {
	repo := &mockProductServiceRepo{}
	svc := NewProductService(repo, nil)
	// No registrar set — autoRegisterPermissions should be a no-op

	product := &models.Product{Slug: "test"}
	manifest := &models.ProductManifest{
		Permissions: []models.PermissionSpec{
			{Resource: "items", Actions: []string{"read"}},
		},
	}
	b, _ := json.Marshal(manifest)
	product.CapabilityManifest = b

	// Should not panic
	svc.autoRegisterPermissions(context.Background(), product)
}

func TestProductService_RegistrarError_NonFatal(t *testing.T) {
	registrar := &mockPermissionAutoRegistrar{err: assert.AnError}
	repo := &mockProductServiceRepo{}
	svc := NewProductService(repo, nil)
	svc.SetPermissionRegistrar(registrar)

	product := &models.Product{Slug: "test-product"}
	manifest := &models.ProductManifest{
		Permissions: []models.PermissionSpec{
			{Resource: "items", Actions: []string{"read"}},
		},
	}
	b, _ := json.Marshal(manifest)
	product.CapabilityManifest = b

	// Should not panic or return error
	svc.autoRegisterPermissions(context.Background(), product)
	assert.True(t, registrar.called)
}

func TestProductService_EmptyManifest_SkipsRegistrar(t *testing.T) {
	registrar := &mockPermissionAutoRegistrar{}
	repo := &mockProductServiceRepo{}
	svc := NewProductService(repo, nil)
	svc.SetPermissionRegistrar(registrar)

	product := &models.Product{Slug: "test-empty"}
	// No manifest

	svc.autoRegisterPermissions(context.Background(), product)
	assert.False(t, registrar.called, "registrar should not be called for empty manifest")
}

func TestProductService_ManifestWithNoPermissions_SkipsRegistrar(t *testing.T) {
	registrar := &mockPermissionAutoRegistrar{}
	repo := &mockProductServiceRepo{}
	svc := NewProductService(repo, nil)
	svc.SetPermissionRegistrar(registrar)

	product := &models.Product{Slug: "test-no-perms"}
	manifest := &models.ProductManifest{
		Permissions: []models.PermissionSpec{}, // empty
	}
	b, _ := json.Marshal(manifest)
	product.CapabilityManifest = b

	svc.autoRegisterPermissions(context.Background(), product)
	assert.False(t, registrar.called, "registrar should not be called for empty permissions")
}

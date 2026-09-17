// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// productServiceProductRepo defines the product repository methods needed by ProductService.
type productServiceProductRepo interface {
	GetBySlug(ctx context.Context, slug string) (*models.Product, error)
	Create(ctx context.Context, product *models.Product) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Product, error)
	List(ctx context.Context, page, pageSize int, search, productType, status string) ([]models.Product, int64, error)
	Update(ctx context.Context, id uuid.UUID, req *models.UpdateProductRequest) (*models.Product, error)
	Delete(ctx context.Context, id uuid.UUID) error
	CreateVersion(ctx context.Context, version *models.ProductVersion) error
	ListVersions(ctx context.Context, productID uuid.UUID) ([]models.ProductVersion, error)
}

// PermissionAutoRegistrar registers module permissions from a product manifest.
// The concrete implementation is PermissionService.RegisterModule.
type PermissionAutoRegistrar interface {
	RegisterModule(ctx context.Context, req *models.RegisterModuleRequest) (*models.RegisterModuleResponse, error)
}

// ProductService handles product registry business logic.
type ProductService struct {
	productRepo         productServiceProductRepo
	auditService        *AuditService
	manifestValidator   *ManifestValidator
	permissionRegistrar PermissionAutoRegistrar
}

// SetPermissionRegistrar wires an optional permission auto-registrar.
// When set, Create() and Update() will auto-register permissions from the
// product's capability manifest. Errors are logged but non-fatal.
func (s *ProductService) SetPermissionRegistrar(registrar PermissionAutoRegistrar) {
	s.permissionRegistrar = registrar
}

// NewProductService creates a new product service.
func NewProductService(productRepo productServiceProductRepo, auditService *AuditService) *ProductService {
	return &ProductService{
		productRepo:       productRepo,
		auditService:      auditService,
		manifestValidator: NewManifestValidator(),
	}
}

// Create registers a new product. If Slug is empty it is generated from Name.
func (s *ProductService) Create(ctx context.Context, req *models.CreateProductRequest, createdBy uuid.UUID) (*models.Product, error) {
	slug := req.Slug
	if slug == "" {
		slug = slugify(req.Name)
	}

	// Verify slug uniqueness.
	existing, _ := s.productRepo.GetBySlug(ctx, slug)
	if existing != nil {
		return nil, fmt.Errorf("product with slug %q already exists", slug)
	}

	product := &models.Product{
		Name:             req.Name,
		Slug:             slug,
		Description:      req.Description,
		Type:             req.Type,
		Status:           models.ProductStatusActive,
		IconURL:          req.IconURL,
		HomepageURL:      req.HomepageURL,
		DocumentationURL: req.DocumentationURL,
		Metadata:         req.Metadata,
		CreatedBy:        &createdBy,
	}

	// Validate capability manifest if provided in metadata or set directly.
	if product.CapabilityManifest != nil {
		if err := s.manifestValidator.Validate(product.CapabilityManifest); err != nil {
			return nil, fmt.Errorf("invalid capability manifest: %w", err)
		}
	}

	if err := s.productRepo.Create(ctx, product); err != nil {
		return nil, fmt.Errorf("ProductService.Create: %w", err)
	}

	// Best-effort: auto-register permissions from manifest
	s.autoRegisterPermissions(ctx, product)

	return product, nil
}

// autoRegisterPermissions extracts permissions from the product's capability
// manifest and registers them via the permission registrar. Errors are logged
// but never propagated — product creation/update must not fail due to
// permission registration issues.
func (s *ProductService) autoRegisterPermissions(ctx context.Context, product *models.Product) {
	if s.permissionRegistrar == nil {
		return
	}

	manifest, err := product.ParseManifest()
	if err != nil || manifest == nil || len(manifest.Permissions) == 0 {
		return
	}

	// Convert PermissionSpec → PermissionDefinition
	defs := make([]models.PermissionDefinition, len(manifest.Permissions))
	for i, spec := range manifest.Permissions {
		defs[i] = models.PermissionDefinition{
			Resource: spec.Resource,
			Actions:  spec.Actions,
		}
	}

	req := &models.RegisterModuleRequest{
		Module:      product.Slug,
		Permissions: defs,
	}

	if _, regErr := s.permissionRegistrar.RegisterModule(ctx, req); regErr != nil {
		// Non-fatal: log but don't fail
		_ = regErr // logged by caller if needed
	}
}

// GetByID retrieves a product by its UUID.
func (s *ProductService) GetByID(ctx context.Context, id uuid.UUID) (*models.Product, error) {
	product, err := s.productRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("ProductService.GetByID: %w", err)
	}
	return product, nil
}

// GetBySlug retrieves a product by its slug.
func (s *ProductService) GetBySlug(ctx context.Context, slug string) (*models.Product, error) {
	product, err := s.productRepo.GetBySlug(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("ProductService.GetBySlug: %w", err)
	}
	return product, nil
}

// List returns a paginated list of products.
func (s *ProductService) List(ctx context.Context, page, pageSize int, search, productType, status string) ([]models.Product, int64, error) {
	products, total, err := s.productRepo.List(ctx, page, pageSize, search, productType, status)
	if err != nil {
		return nil, 0, fmt.Errorf("ProductService.List: %w", err)
	}
	return products, total, nil
}

// Update applies partial updates to a product.
func (s *ProductService) Update(ctx context.Context, id uuid.UUID, req *models.UpdateProductRequest) (*models.Product, error) {
	// Ensure product exists before updating.
	if _, err := s.productRepo.GetByID(ctx, id); err != nil {
		return nil, fmt.Errorf("product not found: %w", err)
	}

	// Validate capability manifest if being updated.
	if req.CapabilityManifest != nil {
		if err := s.manifestValidator.Validate(req.CapabilityManifest); err != nil {
			return nil, fmt.Errorf("invalid capability manifest: %w", err)
		}
	}

	product, err := s.productRepo.Update(ctx, id, req)
	if err != nil {
		return nil, fmt.Errorf("ProductService.Update: %w", err)
	}
	return product, nil
}

// Delete removes a product after confirming no active licenses are attached.
func (s *ProductService) Delete(ctx context.Context, id uuid.UUID) error {
	if _, err := s.productRepo.GetByID(ctx, id); err != nil {
		return fmt.Errorf("product not found: %w", err)
	}

	if err := s.productRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("ProductService.Delete: %w", err)
	}
	return nil
}

// CreateVersion adds a new version to an existing product.
func (s *ProductService) CreateVersion(ctx context.Context, productID uuid.UUID, req *models.CreateProductVersionRequest) (*models.ProductVersion, error) {
	// Ensure the parent product exists.
	if _, err := s.productRepo.GetByID(ctx, productID); err != nil {
		return nil, fmt.Errorf("product not found: %w", err)
	}

	version := &models.ProductVersion{
		ProductID:     productID,
		Version:       req.Version,
		ReleaseNotes:  req.ReleaseNotes,
		MinAPIVersion: req.MinAPIVersion,
		Status:        models.ProductVersionStatusActive,
		ReleasedAt:    req.ReleasedAt,
	}

	if err := s.productRepo.CreateVersion(ctx, version); err != nil {
		return nil, fmt.Errorf("ProductService.CreateVersion: %w", err)
	}

	return version, nil
}

// ListVersions returns all versions for a product.
func (s *ProductService) ListVersions(ctx context.Context, productID uuid.UUID) ([]models.ProductVersion, error) {
	versions, err := s.productRepo.ListVersions(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("ProductService.ListVersions: %w", err)
	}
	return versions, nil
}

// slugify converts a human-readable name into a URL-safe slug.
var nonAlphanumRE = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(name string) string {
	s := strings.ToLower(name)
	s = nonAlphanumRE.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return s
}

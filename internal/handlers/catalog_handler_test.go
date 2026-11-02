// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ============================================================================
// Mock: catalogProductRepo
// ============================================================================

type mockCatalogProductRepo struct {
	mock.Mock
}

func (m *mockCatalogProductRepo) ListActive(ctx context.Context, page, pageSize int) ([]models.Product, int64, error) {
	args := m.Called(ctx, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.Product), args.Get(1).(int64), args.Error(2)
}

func (m *mockCatalogProductRepo) GetBySlug(ctx context.Context, slug string) (*models.Product, error) {
	args := m.Called(ctx, slug)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Product), args.Error(1)
}

// ============================================================================
// Helpers
// ============================================================================

// newCatalogTestRouter returns a test-mode Gin engine wired to the supplied handler.
func newCatalogTestRouter(h *CatalogHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v1/catalog/products", h.ListProducts)
	r.GET("/api/v1/catalog/products/:slug", h.GetProduct)
	return r
}

// sampleProduct returns a deterministic active Product for use in tests.
func sampleProduct(name, slug string) models.Product {
	desc := fmt.Sprintf("%s description", name)
	iconURL := fmt.Sprintf("https://cdn.example.com/%s.png", slug)
	homepageURL := fmt.Sprintf("https://example.com/products/%s", slug)
	return models.Product{
		ID:          uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		Name:        name,
		Slug:        slug,
		Description: &desc,
		Type:        models.ProductTypeSaaS,
		Status:      models.ProductStatusActive,
		IconURL:     &iconURL,
		HomepageURL: &homepageURL,
		CreatedBy:   nil, // internal — must NOT appear in catalog response
		Metadata: map[string]interface{}{
			"billing_plan_id": "plan_xxx", // sensitive — must NOT appear in catalog response
			"public_tagline":  "The best ERP",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// newTestCatalogLogger returns a no-op zap logger for handler tests.
func newTestCatalogLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

// ============================================================================
// TestListProducts_ReturnsActiveOnly
// ============================================================================

func TestListProducts_ReturnsActiveOnly(t *testing.T) {
	repo := new(mockCatalogProductRepo)
	h := NewCatalogHandler(repo, newTestCatalogLogger())
	router := newCatalogTestRouter(h)

	product1 := sampleProduct("Example Suite", "examplesuite")
	product2 := sampleProduct("HexxLock Example PMS", "example-pms")
	product2.ID = uuid.MustParse("00000000-0000-0000-0000-000000000002")

	repo.On("ListActive", mock.Anything, 1, 20).
		Return([]models.Product{product1, product2}, int64(2), nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/catalog/products", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CatalogListResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	assert.Equal(t, int64(2), resp.Total)
	assert.Equal(t, 1, resp.Page)
	assert.Equal(t, 20, resp.PageSize)
	assert.Equal(t, 1, resp.TotalPages)
	require.Len(t, resp.Products, 2)

	// Verify public-safe fields are present.
	assert.Equal(t, "examplesuite", resp.Products[0].Slug)
	assert.Equal(t, models.ProductTypeSaaS, resp.Products[0].Type)
	assert.Equal(t, models.ProductStatusActive, resp.Products[0].Status)
	assert.NotNil(t, resp.Products[0].Description)
	assert.NotNil(t, resp.Products[0].IconURL)

	repo.AssertExpectations(t)
}

// ============================================================================
// TestListProducts_Pagination
// ============================================================================

func TestListProducts_Pagination(t *testing.T) {
	repo := new(mockCatalogProductRepo)
	h := NewCatalogHandler(repo, newTestCatalogLogger())
	router := newCatalogTestRouter(h)

	repo.On("ListActive", mock.Anything, 2, 5).
		Return([]models.Product{sampleProduct("Product A", "product-a")}, int64(6), nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/catalog/products?page=2&page_size=5", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CatalogListResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	assert.Equal(t, 2, resp.Page)
	assert.Equal(t, 5, resp.PageSize)
	assert.Equal(t, int64(6), resp.Total)
	assert.Equal(t, 2, resp.TotalPages) // ceil(6/5) = 2
}

// ============================================================================
// TestListProducts_InvalidPageDefaults
// ============================================================================

func TestListProducts_InvalidPageDefaults(t *testing.T) {
	repo := new(mockCatalogProductRepo)
	h := NewCatalogHandler(repo, newTestCatalogLogger())
	router := newCatalogTestRouter(h)

	// page=0 and page_size=999 should be clamped to 1 and 20.
	repo.On("ListActive", mock.Anything, 1, 20).
		Return([]models.Product{}, int64(0), nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/catalog/products?page=0&page_size=999", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	repo.AssertExpectations(t)
}

// ============================================================================
// TestListProducts_RepoError_Returns500
// ============================================================================

func TestListProducts_RepoError_Returns500(t *testing.T) {
	repo := new(mockCatalogProductRepo)
	h := NewCatalogHandler(repo, newTestCatalogLogger())
	router := newCatalogTestRouter(h)

	repo.On("ListActive", mock.Anything, 1, 20).
		Return(nil, int64(0), errors.New("db connection error"))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/catalog/products", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var body map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Contains(t, body["error"], "Failed to list products")
}

// ============================================================================
// TestGetProduct_BySlug_Success
// ============================================================================

func TestGetProduct_BySlug_Success(t *testing.T) {
	repo := new(mockCatalogProductRepo)
	h := NewCatalogHandler(repo, newTestCatalogLogger())
	router := newCatalogTestRouter(h)

	product := sampleProduct("Example Suite", "examplesuite")
	repo.On("GetBySlug", mock.Anything, "examplesuite").
		Return(&product, nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/catalog/products/examplesuite", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CatalogProductResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	assert.Equal(t, "examplesuite", resp.Slug)
	assert.Equal(t, "Example Suite", resp.Name)
	assert.Equal(t, models.ProductTypeSaaS, resp.Type)
	assert.Equal(t, models.ProductStatusActive, resp.Status)
	assert.NotNil(t, resp.Description)
	assert.NotNil(t, resp.IconURL)
	assert.NotNil(t, resp.HomepageURL)

	repo.AssertExpectations(t)
}

// ============================================================================
// TestGetProduct_DoesNotExposeInternalFields
// ============================================================================

// TestGetProduct_DoesNotExposeInternalFields verifies that the catalog
// response body never includes created_by or sensitive metadata keys.
func TestGetProduct_DoesNotExposeInternalFields(t *testing.T) {
	repo := new(mockCatalogProductRepo)
	h := NewCatalogHandler(repo, newTestCatalogLogger())
	router := newCatalogTestRouter(h)

	createdBy := uuid.New()
	product := sampleProduct("Example Suite", "examplesuite")
	product.CreatedBy = &createdBy
	product.Metadata = map[string]interface{}{
		"billing_plan_id":   "plan_secret_123",
		"stripe_product_id": "prod_xyz",
	}

	repo.On("GetBySlug", mock.Anything, "examplesuite").
		Return(&product, nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/catalog/products/examplesuite", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	// Deserialise into a raw map to check for the presence of forbidden keys.
	var raw map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&raw))

	assert.NotContains(t, raw, "created_by",
		"created_by must not be present in the public catalog response")
	assert.NotContains(t, raw, "metadata",
		"metadata must not be present in the public catalog response")
}

// ============================================================================
// TestGetProduct_NotFound_Returns404
// ============================================================================

func TestGetProduct_NotFound_Returns404(t *testing.T) {
	repo := new(mockCatalogProductRepo)
	h := NewCatalogHandler(repo, newTestCatalogLogger())
	router := newCatalogTestRouter(h)

	repo.On("GetBySlug", mock.Anything, "nonexistent-slug").
		Return(nil, errors.New("product not found"))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/catalog/products/nonexistent-slug", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var body map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Contains(t, body["error"], "not found")
}

// ============================================================================
// TestGetProduct_NoRows_Returns404
// ============================================================================

// TestGetProduct_NoRows_Returns404 verifies that sql.ErrNoRows-style errors
// (the string "no rows") are also mapped to 404, not 500.
func TestGetProduct_NoRows_Returns404(t *testing.T) {
	repo := new(mockCatalogProductRepo)
	h := NewCatalogHandler(repo, newTestCatalogLogger())
	router := newCatalogTestRouter(h)

	repo.On("GetBySlug", mock.Anything, "missing-slug").
		Return(nil, errors.New("sql: no rows in result set"))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/catalog/products/missing-slug", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ============================================================================
// TestGetProduct_RepoError_Returns500
// ============================================================================

func TestGetProduct_RepoError_Returns500(t *testing.T) {
	repo := new(mockCatalogProductRepo)
	h := NewCatalogHandler(repo, newTestCatalogLogger())
	router := newCatalogTestRouter(h)

	repo.On("GetBySlug", mock.Anything, "examplesuite").
		Return(nil, errors.New("connection timeout"))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/catalog/products/examplesuite", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var body map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Contains(t, body["error"], "Failed to retrieve product")
}

// ============================================================================
// TestListProducts_EmptyResult
// ============================================================================

func TestListProducts_EmptyResult(t *testing.T) {
	repo := new(mockCatalogProductRepo)
	h := NewCatalogHandler(repo, newTestCatalogLogger())
	router := newCatalogTestRouter(h)

	repo.On("ListActive", mock.Anything, 1, 20).
		Return([]models.Product{}, int64(0), nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/catalog/products", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CatalogListResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	assert.Equal(t, int64(0), resp.Total)
	assert.Equal(t, 0, resp.TotalPages)
	assert.Empty(t, resp.Products)
}

// ============================================================================
// TestToPublicResponse_StripsSensitiveFields
// ============================================================================

func TestToPublicResponse_StripsSensitiveFields(t *testing.T) {
	createdBy := uuid.New()
	desc := "A great product"
	p := &models.Product{
		ID:          uuid.New(),
		Name:        "Example Suite",
		Slug:        "examplesuite",
		Description: &desc,
		Type:        models.ProductTypeSaaS,
		Status:      models.ProductStatusActive,
		CreatedBy:   &createdBy,
		Metadata: map[string]interface{}{
			"billing_plan_id": "plan_secret",
			"public_tagline":  "Best ERP",
		},
	}

	resp := toPublicResponse(p)

	assert.Equal(t, p.ID, resp.ID)
	assert.Equal(t, p.Name, resp.Name)
	assert.Equal(t, p.Slug, resp.Slug)
	assert.Equal(t, p.Type, resp.Type)
	assert.Equal(t, p.Status, resp.Status)
	assert.Equal(t, p.Description, resp.Description)
	// CatalogProductResponse has no CreatedBy or Metadata field — compile-time guarantee.
}

// ============================================================================
// TestIsNotFound
// ============================================================================

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"not found string", errors.New("product not found"), true},
		{"no rows string", errors.New("sql: no rows in result set"), true},
		{"no_rows underscore", errors.New("no_rows error"), true},
		{"generic error", errors.New("connection timeout"), false},
		{"uppercase Not Found", errors.New("Resource Not Found"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isNotFound(tt.err))
		})
	}
}

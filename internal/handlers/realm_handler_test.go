// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ─────────────────────────────────────────────────────────────
// Mock implementation of realmServiceRepo (the private interface
// used internally by services.RealmService).
// Defined here as a struct satisfying all required methods.
// ─────────────────────────────────────────────────────────────

type mockRealmRepo struct {
	slugExistsFn             func(ctx context.Context, slug string) (bool, error)
	createFn                 func(ctx context.Context, realm *models.Realm) error
	createSecurityPolicyFn   func(ctx context.Context, policy *models.RealmSecurityPolicy) error
	getByIDFn                func(ctx context.Context, id uuid.UUID) (*models.Realm, error)
	getBySlugFn              func(ctx context.Context, slug string) (*models.Realm, error)
	getRealmByDomainFn       func(ctx context.Context, domainName string) (*models.Realm, error)
	updateFn                 func(ctx context.Context, realm *models.Realm) error
	updateStatusFn           func(ctx context.Context, id uuid.UUID, status models.RealmStatus) error
	listFn                   func(ctx context.Context, filters repositories.RealmFilters) ([]models.Realm, int64, error)
	getSecurityPolicyFn      func(ctx context.Context, realmID uuid.UUID) (*models.RealmSecurityPolicy, error)
	updateSecurityPolicyFn   func(ctx context.Context, policy *models.RealmSecurityPolicy) error
	createIdentityProviderFn func(ctx context.Context, idp *models.RealmIdentityProvider) error
	listIdentityProvidersFn  func(ctx context.Context, realmID uuid.UUID) ([]models.RealmIdentityProvider, error)
	deleteIdentityProviderFn func(ctx context.Context, id uuid.UUID) error
	getIdentityProviderFn    func(ctx context.Context, id uuid.UUID) (*models.RealmIdentityProvider, error)
	updateIdentityProviderFn func(ctx context.Context, idp *models.RealmIdentityProvider) error
	countTenantsInRealmFn    func(ctx context.Context, realmID uuid.UUID) (int, error)
	assignTenantFn           func(ctx context.Context, realmID, tenantID uuid.UUID, assignedBy *uuid.UUID) error
	getTenantRealmFn         func(ctx context.Context, tenantID uuid.UUID) (*models.Realm, error)
	listRealmTenantsFn       func(ctx context.Context, realmID uuid.UUID) ([]models.RealmTenant, error)
	assignAdminFn            func(ctx context.Context, assignment *models.RealmAdminAssignment) error
	listRealmAdminsFn        func(ctx context.Context, realmID uuid.UUID) ([]models.RealmAdminAssignment, error)
	removeAdminFn            func(ctx context.Context, realmID, adminID uuid.UUID) error
	logAuditFn               func(ctx context.Context, log *models.RealmAuditLog) error
	listAuditLogsFn          func(ctx context.Context, realmID uuid.UUID, filters repositories.AuditLogFilters) ([]models.RealmAuditLog, int64, error)
	listDomainsFn            func(ctx context.Context, realmID uuid.UUID) ([]models.RealmDomain, error)
	getDomainByNameFn        func(ctx context.Context, domainName string) (*models.RealmDomain, error)
	createDomainFn           func(ctx context.Context, domain *models.RealmDomain) error
	setPrimaryDomainFn       func(ctx context.Context, realmID, domainID uuid.UUID) error
	getDomainByIDFn          func(ctx context.Context, domainID uuid.UUID) (*models.RealmDomain, error)
	deleteDomainFn           func(ctx context.Context, domainID uuid.UUID) error
	updateDomainFn           func(ctx context.Context, domain *models.RealmDomain) error
	getDefaultRealmFn        func(ctx context.Context) (*models.Realm, error)
	getUserAvailableRealmsFn func(ctx context.Context, userID uuid.UUID) ([]*models.Realm, error)
	userHasRealmAccessFn     func(ctx context.Context, userID, realmID uuid.UUID) (bool, error)
}

func (m *mockRealmRepo) SlugExists(ctx context.Context, slug string) (bool, error) {
	if m.slugExistsFn != nil {
		return m.slugExistsFn(ctx, slug)
	}
	return false, nil
}

func (m *mockRealmRepo) Create(ctx context.Context, realm *models.Realm) error {
	if m.createFn != nil {
		return m.createFn(ctx, realm)
	}
	return nil
}

func (m *mockRealmRepo) CreateSecurityPolicy(ctx context.Context, policy *models.RealmSecurityPolicy) error {
	if m.createSecurityPolicyFn != nil {
		return m.createSecurityPolicyFn(ctx, policy)
	}
	return nil
}

func (m *mockRealmRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Realm, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return nil, errors.New("not found")
}

func (m *mockRealmRepo) GetBySlug(ctx context.Context, slug string) (*models.Realm, error) {
	if m.getBySlugFn != nil {
		return m.getBySlugFn(ctx, slug)
	}
	return nil, errors.New("not found")
}

func (m *mockRealmRepo) GetRealmByDomain(ctx context.Context, domainName string) (*models.Realm, error) {
	if m.getRealmByDomainFn != nil {
		return m.getRealmByDomainFn(ctx, domainName)
	}
	return nil, errors.New("not found")
}

func (m *mockRealmRepo) Update(ctx context.Context, realm *models.Realm) error {
	if m.updateFn != nil {
		return m.updateFn(ctx, realm)
	}
	return nil
}

func (m *mockRealmRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status models.RealmStatus) error {
	if m.updateStatusFn != nil {
		return m.updateStatusFn(ctx, id, status)
	}
	return nil
}

func (m *mockRealmRepo) List(ctx context.Context, filters repositories.RealmFilters) ([]models.Realm, int64, error) {
	if m.listFn != nil {
		return m.listFn(ctx, filters)
	}
	return []models.Realm{}, 0, nil
}

func (m *mockRealmRepo) GetSecurityPolicy(ctx context.Context, realmID uuid.UUID) (*models.RealmSecurityPolicy, error) {
	if m.getSecurityPolicyFn != nil {
		return m.getSecurityPolicyFn(ctx, realmID)
	}
	return nil, errors.New("not found")
}

func (m *mockRealmRepo) UpdateSecurityPolicy(ctx context.Context, policy *models.RealmSecurityPolicy) error {
	if m.updateSecurityPolicyFn != nil {
		return m.updateSecurityPolicyFn(ctx, policy)
	}
	return nil
}

func (m *mockRealmRepo) CreateIdentityProvider(ctx context.Context, idp *models.RealmIdentityProvider) error {
	if m.createIdentityProviderFn != nil {
		return m.createIdentityProviderFn(ctx, idp)
	}
	return nil
}

func (m *mockRealmRepo) ListIdentityProviders(ctx context.Context, realmID uuid.UUID) ([]models.RealmIdentityProvider, error) {
	if m.listIdentityProvidersFn != nil {
		return m.listIdentityProvidersFn(ctx, realmID)
	}
	return []models.RealmIdentityProvider{}, nil
}

func (m *mockRealmRepo) DeleteIdentityProvider(ctx context.Context, id uuid.UUID) error {
	if m.deleteIdentityProviderFn != nil {
		return m.deleteIdentityProviderFn(ctx, id)
	}
	return nil
}

func (m *mockRealmRepo) GetIdentityProvider(ctx context.Context, id uuid.UUID) (*models.RealmIdentityProvider, error) {
	if m.getIdentityProviderFn != nil {
		return m.getIdentityProviderFn(ctx, id)
	}
	return nil, errors.New("not found")
}

func (m *mockRealmRepo) UpdateIdentityProvider(ctx context.Context, idp *models.RealmIdentityProvider) error {
	if m.updateIdentityProviderFn != nil {
		return m.updateIdentityProviderFn(ctx, idp)
	}
	return nil
}

func (m *mockRealmRepo) CountTenantsInRealm(ctx context.Context, realmID uuid.UUID) (int, error) {
	if m.countTenantsInRealmFn != nil {
		return m.countTenantsInRealmFn(ctx, realmID)
	}
	return 0, nil
}

func (m *mockRealmRepo) AssignTenant(ctx context.Context, realmID, tenantID uuid.UUID, assignedBy *uuid.UUID) error {
	if m.assignTenantFn != nil {
		return m.assignTenantFn(ctx, realmID, tenantID, assignedBy)
	}
	return nil
}

func (m *mockRealmRepo) GetTenantRealm(ctx context.Context, tenantID uuid.UUID) (*models.Realm, error) {
	if m.getTenantRealmFn != nil {
		return m.getTenantRealmFn(ctx, tenantID)
	}
	return nil, errors.New("not found")
}

func (m *mockRealmRepo) ListRealmTenants(ctx context.Context, realmID uuid.UUID) ([]models.RealmTenant, error) {
	if m.listRealmTenantsFn != nil {
		return m.listRealmTenantsFn(ctx, realmID)
	}
	return []models.RealmTenant{}, nil
}

func (m *mockRealmRepo) AssignAdmin(ctx context.Context, assignment *models.RealmAdminAssignment) error {
	if m.assignAdminFn != nil {
		return m.assignAdminFn(ctx, assignment)
	}
	return nil
}

func (m *mockRealmRepo) ListRealmAdmins(ctx context.Context, realmID uuid.UUID) ([]models.RealmAdminAssignment, error) {
	if m.listRealmAdminsFn != nil {
		return m.listRealmAdminsFn(ctx, realmID)
	}
	return []models.RealmAdminAssignment{}, nil
}

func (m *mockRealmRepo) RemoveAdmin(ctx context.Context, realmID, adminID uuid.UUID) error {
	if m.removeAdminFn != nil {
		return m.removeAdminFn(ctx, realmID, adminID)
	}
	return nil
}

func (m *mockRealmRepo) LogAudit(ctx context.Context, log *models.RealmAuditLog) error {
	if m.logAuditFn != nil {
		return m.logAuditFn(ctx, log)
	}
	return nil
}

func (m *mockRealmRepo) ListAuditLogs(ctx context.Context, realmID uuid.UUID, filters repositories.AuditLogFilters) ([]models.RealmAuditLog, int64, error) {
	if m.listAuditLogsFn != nil {
		return m.listAuditLogsFn(ctx, realmID, filters)
	}
	return []models.RealmAuditLog{}, 0, nil
}

func (m *mockRealmRepo) ListDomains(ctx context.Context, realmID uuid.UUID) ([]models.RealmDomain, error) {
	if m.listDomainsFn != nil {
		return m.listDomainsFn(ctx, realmID)
	}
	return []models.RealmDomain{}, nil
}

func (m *mockRealmRepo) GetDomainByName(ctx context.Context, domainName string) (*models.RealmDomain, error) {
	if m.getDomainByNameFn != nil {
		return m.getDomainByNameFn(ctx, domainName)
	}
	return nil, errors.New("not found")
}

func (m *mockRealmRepo) CreateDomain(ctx context.Context, domain *models.RealmDomain) error {
	if m.createDomainFn != nil {
		return m.createDomainFn(ctx, domain)
	}
	return nil
}

func (m *mockRealmRepo) SetPrimaryDomain(ctx context.Context, realmID, domainID uuid.UUID) error {
	if m.setPrimaryDomainFn != nil {
		return m.setPrimaryDomainFn(ctx, realmID, domainID)
	}
	return nil
}

func (m *mockRealmRepo) GetDomainByID(ctx context.Context, domainID uuid.UUID) (*models.RealmDomain, error) {
	if m.getDomainByIDFn != nil {
		return m.getDomainByIDFn(ctx, domainID)
	}
	return nil, errors.New("not found")
}

func (m *mockRealmRepo) DeleteDomain(ctx context.Context, domainID uuid.UUID) error {
	if m.deleteDomainFn != nil {
		return m.deleteDomainFn(ctx, domainID)
	}
	return nil
}

func (m *mockRealmRepo) UpdateDomain(ctx context.Context, domain *models.RealmDomain) error {
	if m.updateDomainFn != nil {
		return m.updateDomainFn(ctx, domain)
	}
	return nil
}

func (m *mockRealmRepo) GetDefaultRealm(ctx context.Context) (*models.Realm, error) {
	if m.getDefaultRealmFn != nil {
		return m.getDefaultRealmFn(ctx)
	}
	return nil, errors.New("not found")
}

func (m *mockRealmRepo) GetUserAvailableRealms(ctx context.Context, userID uuid.UUID, _ uuid.UUID) ([]*models.Realm, error) {
	if m.getUserAvailableRealmsFn != nil {
		return m.getUserAvailableRealmsFn(ctx, userID)
	}
	return []*models.Realm{}, nil
}

func (m *mockRealmRepo) UserHasRealmAccess(ctx context.Context, userID, realmID, _ uuid.UUID) (bool, error) {
	if m.userHasRealmAccessFn != nil {
		return m.userHasRealmAccessFn(ctx, userID, realmID)
	}
	return false, nil
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

func newTestCfg() *config.Config {
	return &config.Config{
		Environment: "test",
		JWTSecret:   "test-secret-at-least-32-characters-long",
	}
}

func newTestRealm(id uuid.UUID, slug, displayName string, realmType models.RealmType) *models.Realm {
	return &models.Realm{
		ID:          id,
		Slug:        slug,
		DisplayName: displayName,
		Type:        realmType,
		Status:      models.RealmStatusActive,
		Settings:    json.RawMessage(`{}`),
		Branding:    json.RawMessage(`{}`),
		Features:    json.RawMessage(`{}`),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func newRealmHandlerWithMock(repo *mockRealmRepo) *RealmHandler {
	svc := services.NewRealmService(repo, newTestCfg(), zap.NewNop())
	return NewRealmHandler(svc, zap.NewNop())
}

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

func TestRealmHandler_CreateRealm(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("creates realm successfully", func(t *testing.T) {
		realmID := uuid.New()
		createdAt := time.Now()

		repo := &mockRealmRepo{
			slugExistsFn: func(_ context.Context, _ string) (bool, error) {
				return false, nil
			},
			createFn: func(_ context.Context, realm *models.Realm) error {
				realm.ID = realmID
				realm.CreatedAt = createdAt
				realm.UpdatedAt = createdAt
				return nil
			},
			createSecurityPolicyFn: func(_ context.Context, _ *models.RealmSecurityPolicy) error {
				return nil
			},
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Realm, error) {
				return newTestRealm(realmID, "enterprise-realm", "Enterprise Realm", models.RealmTypeEnterprise), nil
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.POST("/realms", h.CreateRealm)

		body := `{"slug":"enterprise-realm","display_name":"Enterprise Realm","type":"enterprise"}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/realms", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp models.RealmResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "enterprise-realm", resp.Slug)
		assert.Equal(t, "Enterprise Realm", resp.DisplayName)
		assert.Equal(t, models.RealmTypeEnterprise, resp.Type)
		assert.Equal(t, models.RealmStatusActive, resp.Status)
	})

	t.Run("returns 400 on invalid request body", func(t *testing.T) {
		h := newRealmHandlerWithMock(&mockRealmRepo{})
		router := gin.New()
		router.POST("/realms", h.CreateRealm)

		// Missing required fields
		body := `{"slug":"test"}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/realms", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 when slug already exists", func(t *testing.T) {
		repo := &mockRealmRepo{
			slugExistsFn: func(_ context.Context, _ string) (bool, error) {
				return true, nil
			},
		}
		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.POST("/realms", h.CreateRealm)

		body := `{"slug":"existing","display_name":"Existing","type":"shared"}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/realms", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid slug characters", func(t *testing.T) {
		repo := &mockRealmRepo{
			slugExistsFn: func(_ context.Context, _ string) (bool, error) {
				return false, nil
			},
		}
		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.POST("/realms", h.CreateRealm)

		body := `{"slug":"Invalid Slug!","display_name":"Test","type":"shared"}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/realms", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestRealmHandler_GetRealm(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()
	realm := newTestRealm(realmID, "my-realm", "My Realm", models.RealmTypeShared)

	t.Run("returns realm by ID", func(t *testing.T) {
		repo := &mockRealmRepo{
			getByIDFn: func(_ context.Context, id uuid.UUID) (*models.Realm, error) {
				if id == realmID {
					return realm, nil
				}
				return nil, errors.New("not found")
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.GET("/realms/:id", h.GetRealm)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/realms/"+realmID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.RealmResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "my-realm", resp.Slug)
		assert.Equal(t, "My Realm", resp.DisplayName)
	})

	t.Run("returns 400 for invalid UUID", func(t *testing.T) {
		h := newRealmHandlerWithMock(&mockRealmRepo{})
		router := gin.New()
		router.GET("/realms/:id", h.GetRealm)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/realms/not-a-uuid", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 404 when realm not found", func(t *testing.T) {
		repo := &mockRealmRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Realm, error) {
				return nil, errors.New("realm not found")
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.GET("/realms/:id", h.GetRealm)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/realms/"+uuid.New().String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestRealmHandler_ListRealms(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realm1 := newTestRealm(uuid.New(), "realm-one", "Realm One", models.RealmTypeShared)
	realm2 := newTestRealm(uuid.New(), "realm-two", "Realm Two", models.RealmTypeEnterprise)

	t.Run("returns paginated list of realms", func(t *testing.T) {
		repo := &mockRealmRepo{
			listFn: func(_ context.Context, _ repositories.RealmFilters) ([]models.Realm, int64, error) {
				return []models.Realm{*realm1, *realm2}, 2, nil
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.GET("/realms", h.ListRealms)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/realms?page=1&page_size=10", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.RealmListResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Len(t, resp.Realms, 2)
		assert.Equal(t, int64(2), resp.Total)
		assert.Equal(t, 1, resp.Page)
	})

	t.Run("applies type filter from query param", func(t *testing.T) {
		var capturedFilters repositories.RealmFilters
		repo := &mockRealmRepo{
			listFn: func(_ context.Context, filters repositories.RealmFilters) ([]models.Realm, int64, error) {
				capturedFilters = filters
				return []models.Realm{*realm2}, 1, nil
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.GET("/realms", h.ListRealms)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/realms?type=enterprise", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, capturedFilters.Type)
		assert.Equal(t, models.RealmTypeEnterprise, *capturedFilters.Type)
	})

	t.Run("returns 500 on repo error", func(t *testing.T) {
		repo := &mockRealmRepo{
			listFn: func(_ context.Context, _ repositories.RealmFilters) ([]models.Realm, int64, error) {
				return nil, 0, errors.New("database error")
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.GET("/realms", h.ListRealms)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/realms", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestRealmHandler_UpdateRealm(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()
	realm := newTestRealm(realmID, "my-realm", "My Realm", models.RealmTypeShared)

	t.Run("updates realm successfully", func(t *testing.T) {
		repo := &mockRealmRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Realm, error) {
				return realm, nil
			},
			updateFn: func(_ context.Context, _ *models.Realm) error {
				return nil
			},
			logAuditFn: func(_ context.Context, _ *models.RealmAuditLog) error {
				return nil
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.PUT("/realms/:id", h.UpdateRealm)

		newName := "Updated Realm"
		body, _ := json.Marshal(models.UpdateRealmRequest{DisplayName: &newName})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/realms/"+realmID.String(), strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.RealmResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "Updated Realm", resp.DisplayName)
	})

	t.Run("returns 400 for invalid realm ID", func(t *testing.T) {
		h := newRealmHandlerWithMock(&mockRealmRepo{})
		router := gin.New()
		router.PUT("/realms/:id", h.UpdateRealm)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/realms/bad-id", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestRealmHandler_ActivateRealm(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()

	t.Run("activates realm successfully", func(t *testing.T) {
		realm := newTestRealm(realmID, "test-realm", "Test Realm", models.RealmTypeShared)
		realm.Status = models.RealmStatusSuspended

		repo := &mockRealmRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Realm, error) {
				return realm, nil
			},
			updateStatusFn: func(_ context.Context, _ uuid.UUID, _ models.RealmStatus) error {
				return nil
			},
			logAuditFn: func(_ context.Context, _ *models.RealmAuditLog) error {
				return nil
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.POST("/realms/:id/activate", h.ActivateRealm)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/realms/"+realmID.String()+"/activate", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		assert.Equal(t, "Realm activated", body["message"])
	})

	t.Run("returns 400 for invalid realm ID", func(t *testing.T) {
		h := newRealmHandlerWithMock(&mockRealmRepo{})
		router := gin.New()
		router.POST("/realms/:id/activate", h.ActivateRealm)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/realms/invalid-id/activate", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestRealmHandler_SuspendRealm(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()

	t.Run("suspends realm successfully", func(t *testing.T) {
		realm := newTestRealm(realmID, "active-realm", "Active Realm", models.RealmTypeShared)
		realm.Status = models.RealmStatusActive

		repo := &mockRealmRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Realm, error) {
				return realm, nil
			},
			updateStatusFn: func(_ context.Context, _ uuid.UUID, _ models.RealmStatus) error {
				return nil
			},
			logAuditFn: func(_ context.Context, _ *models.RealmAuditLog) error {
				return nil
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.POST("/realms/:id/suspend", h.SuspendRealm)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/realms/"+realmID.String()+"/suspend", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		assert.Equal(t, "Realm suspended", body["message"])
	})
}

func TestRealmHandler_ArchiveRealm(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()

	t.Run("archives realm successfully", func(t *testing.T) {
		realm := newTestRealm(realmID, "archive-me", "Archive Me", models.RealmTypeShared)

		repo := &mockRealmRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Realm, error) {
				return realm, nil
			},
			countTenantsInRealmFn: func(_ context.Context, _ uuid.UUID) (int, error) {
				return 0, nil
			},
			updateStatusFn: func(_ context.Context, _ uuid.UUID, _ models.RealmStatus) error {
				return nil
			},
			logAuditFn: func(_ context.Context, _ *models.RealmAuditLog) error {
				return nil
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.DELETE("/realms/:id", h.ArchiveRealm)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/realms/"+realmID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		assert.Equal(t, "Realm archived", body["message"])
	})
}

func TestRealmHandler_GetSecurityPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()

	t.Run("returns security policy for realm", func(t *testing.T) {
		policy := &models.RealmSecurityPolicy{
			ID:                realmID,
			RealmID:           realmID,
			PasswordMinLength: 12,
			MFARequired:       true,
			CreatedAt:         time.Now(),
			UpdatedAt:         time.Now(),
		}

		repo := &mockRealmRepo{
			getSecurityPolicyFn: func(_ context.Context, _ uuid.UUID) (*models.RealmSecurityPolicy, error) {
				return policy, nil
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.GET("/realms/:id/security", h.GetSecurityPolicy)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/realms/"+realmID.String()+"/security", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("returns 400 for invalid realm ID", func(t *testing.T) {
		h := newRealmHandlerWithMock(&mockRealmRepo{})
		router := gin.New()
		router.GET("/realms/:id/security", h.GetSecurityPolicy)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/realms/bad-uuid/security", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 404 when policy not found", func(t *testing.T) {
		repo := &mockRealmRepo{
			getSecurityPolicyFn: func(_ context.Context, _ uuid.UUID) (*models.RealmSecurityPolicy, error) {
				return nil, errors.New("not found")
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.GET("/realms/:id/security", h.GetSecurityPolicy)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/realms/"+realmID.String()+"/security", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestRealmHandler_UpdateSecurityPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()

	t.Run("updates security policy successfully", func(t *testing.T) {
		existingPolicy := &models.RealmSecurityPolicy{
			ID:                realmID,
			RealmID:           realmID,
			PasswordMinLength: 8,
			CreatedAt:         time.Now(),
			UpdatedAt:         time.Now(),
		}

		repo := &mockRealmRepo{
			getSecurityPolicyFn: func(_ context.Context, _ uuid.UUID) (*models.RealmSecurityPolicy, error) {
				return existingPolicy, nil
			},
			updateSecurityPolicyFn: func(_ context.Context, _ *models.RealmSecurityPolicy) error {
				return nil
			},
			logAuditFn: func(_ context.Context, _ *models.RealmAuditLog) error {
				return nil
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.PUT("/realms/:id/security", h.UpdateSecurityPolicy)

		newMin := 14
		body, _ := json.Marshal(models.UpdateRealmSecurityPolicyRequest{
			PasswordMinLength: &newMin,
		})

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/realms/"+realmID.String()+"/security", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestRealmHandler_AssignTenantToRealm(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()
	tenantID := uuid.New()

	t.Run("assigns tenant to realm", func(t *testing.T) {
		repo := &mockRealmRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Realm, error) {
				return newTestRealm(realmID, "target-realm", "Target Realm", models.RealmTypeShared), nil
			},
			assignTenantFn: func(_ context.Context, rID, tID uuid.UUID, _ *uuid.UUID) error {
				assert.Equal(t, realmID, rID)
				assert.Equal(t, tenantID, tID)
				return nil
			},
			logAuditFn: func(_ context.Context, _ *models.RealmAuditLog) error {
				return nil
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.POST("/realms/:id/tenants", h.AssignTenantToRealm)

		body, _ := json.Marshal(models.AssignTenantToRealmRequest{TenantID: tenantID})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/realms/"+realmID.String()+"/tenants", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Contains(t, resp["message"], "assigned")
	})

	t.Run("returns 400 for invalid realm ID", func(t *testing.T) {
		h := newRealmHandlerWithMock(&mockRealmRepo{})
		router := gin.New()
		router.POST("/realms/:id/tenants", h.AssignTenantToRealm)

		body, _ := json.Marshal(models.AssignTenantToRealmRequest{TenantID: tenantID})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/realms/bad-uuid/tenants", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestRealmHandler_RemoveTenantFromRealm(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()
	tenantID := uuid.New()

	t.Run("removes tenant from realm (moves to default)", func(t *testing.T) {
		sourceRealm := newTestRealm(realmID, "source-realm", "Source Realm", models.RealmTypeShared)
		repo := &mockRealmRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Realm, error) {
				// Return the default realm (target) when queried for DefaultRealmID
				return newTestRealm(models.DefaultRealmID, "default", "Default", models.RealmTypeShared), nil
			},
			getTenantRealmFn: func(_ context.Context, _ uuid.UUID) (*models.Realm, error) {
				// Return source realm so the service can log the migration "from" field
				return sourceRealm, nil
			},
			assignTenantFn: func(_ context.Context, _, _ uuid.UUID, _ *uuid.UUID) error {
				return nil
			},
			logAuditFn: func(_ context.Context, _ *models.RealmAuditLog) error {
				return nil
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.DELETE("/realms/:id/tenants/:tenant_id", h.RemoveTenantFromRealm)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/realms/"+realmID.String()+"/tenants/"+tenantID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Contains(t, resp["message"], "removed")
	})

	t.Run("returns 400 for invalid tenant ID", func(t *testing.T) {
		h := newRealmHandlerWithMock(&mockRealmRepo{})
		router := gin.New()
		router.DELETE("/realms/:id/tenants/:tenant_id", h.RemoveTenantFromRealm)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/realms/"+realmID.String()+"/tenants/bad-uuid", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestRealmHandler_ListRealmTenants(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()

	t.Run("returns list of tenants in realm", func(t *testing.T) {
		repo := &mockRealmRepo{
			listRealmTenantsFn: func(_ context.Context, _ uuid.UUID) ([]models.RealmTenant, error) {
				return []models.RealmTenant{
					{RealmID: realmID, TenantID: uuid.New(), AssignedAt: time.Now()},
					{RealmID: realmID, TenantID: uuid.New(), AssignedAt: time.Now()},
				}, nil
			},
		}

		h := newRealmHandlerWithMock(repo)
		router := gin.New()
		router.GET("/realms/:id/tenants", h.ListRealmTenants)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/realms/"+realmID.String()+"/tenants", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var body map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &body)
		require.NoError(t, err)
		tenants, ok := body["tenants"].([]interface{})
		require.True(t, ok)
		assert.Len(t, tenants, 2)
		assert.Equal(t, float64(2), body["total"])
	})
}

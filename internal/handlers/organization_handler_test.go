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

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ─────────────────────────────────────────────────────────────
// Mock org repo (satisfies organizationServiceOrgRepo)
// ─────────────────────────────────────────────────────────────

type mockOrgRepo struct {
	createFn                     func(ctx context.Context, org *models.Organization) error
	getByIDFn                    func(ctx context.Context, id uuid.UUID) (*models.Organization, error)
	getByNameFn                  func(ctx context.Context, tenantID uuid.UUID, name string, parentID *uuid.UUID) (*models.Organization, error)
	listFn                       func(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string, orgType string) ([]*models.Organization, int, error)
	updateFn                     func(ctx context.Context, org *models.Organization) error
	deleteFn                     func(ctx context.Context, id uuid.UUID) error
	addMemberFn                  func(ctx context.Context, orgID, userID uuid.UUID, role string, title *string, isPrimary bool, addedBy *uuid.UUID) error
	removeMemberFn               func(ctx context.Context, orgID, userID uuid.UUID) error
	updateMemberFn               func(ctx context.Context, orgID, userID uuid.UUID, role *string, title *string, isPrimary *bool) error
	getMembersFn                 func(ctx context.Context, orgID uuid.UUID, page, pageSize int) ([]*models.OrgMember, int, error)
	getUserOrganizationsFn       func(ctx context.Context, userID uuid.UUID) ([]*models.OrgMember, error)
	getUserPrimaryOrganizationFn func(ctx context.Context, userID uuid.UUID) (*models.OrgMember, error)
	getChildrenFn                func(ctx context.Context, parentID uuid.UUID) ([]*models.Organization, error)
	getRootOrganizationsFn       func(ctx context.Context, tenantID uuid.UUID) ([]*models.Organization, error)
	getDescendantsFn             func(ctx context.Context, orgID uuid.UUID) ([]*models.Organization, error)
	getAncestorsFn               func(ctx context.Context, orgID uuid.UUID) ([]*models.Organization, error)
	getOrgRoleAssignmentsFn      func(ctx context.Context, orgID uuid.UUID) ([]models.OrgRoleAssignment, error)
	assignOrgRoleFn              func(ctx context.Context, orgID, roleID uuid.UUID, inherit bool, assignedBy *uuid.UUID) error
	removeOrgRoleFn              func(ctx context.Context, orgID, roleID uuid.UUID) error
}

func (m *mockOrgRepo) Create(ctx context.Context, org *models.Organization) error {
	if m.createFn != nil {
		return m.createFn(ctx, org)
	}
	return nil
}

func (m *mockOrgRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Organization, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return nil, errors.New("not found")
}

func (m *mockOrgRepo) GetByName(ctx context.Context, tenantID uuid.UUID, name string, parentID *uuid.UUID) (*models.Organization, error) {
	if m.getByNameFn != nil {
		return m.getByNameFn(ctx, tenantID, name, parentID)
	}
	return nil, errors.New("not found")
}

func (m *mockOrgRepo) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string, orgType string) ([]*models.Organization, int, error) {
	if m.listFn != nil {
		return m.listFn(ctx, tenantID, page, pageSize, search, orgType)
	}
	return []*models.Organization{}, 0, nil
}

func (m *mockOrgRepo) Update(ctx context.Context, org *models.Organization) error {
	if m.updateFn != nil {
		return m.updateFn(ctx, org)
	}
	return nil
}

func (m *mockOrgRepo) Delete(ctx context.Context, id uuid.UUID) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id)
	}
	return nil
}

func (m *mockOrgRepo) AddMember(ctx context.Context, orgID, userID uuid.UUID, role string, title *string, isPrimary bool, addedBy *uuid.UUID) error {
	if m.addMemberFn != nil {
		return m.addMemberFn(ctx, orgID, userID, role, title, isPrimary, addedBy)
	}
	return nil
}

func (m *mockOrgRepo) RemoveMember(ctx context.Context, orgID, userID uuid.UUID) error {
	if m.removeMemberFn != nil {
		return m.removeMemberFn(ctx, orgID, userID)
	}
	return nil
}

func (m *mockOrgRepo) UpdateMember(ctx context.Context, orgID, userID uuid.UUID, role *string, title *string, isPrimary *bool) error {
	if m.updateMemberFn != nil {
		return m.updateMemberFn(ctx, orgID, userID, role, title, isPrimary)
	}
	return nil
}

func (m *mockOrgRepo) GetMembers(ctx context.Context, orgID uuid.UUID, page, pageSize int) ([]*models.OrgMember, int, error) {
	if m.getMembersFn != nil {
		return m.getMembersFn(ctx, orgID, page, pageSize)
	}
	return []*models.OrgMember{}, 0, nil
}

func (m *mockOrgRepo) GetUserOrganizations(ctx context.Context, userID uuid.UUID) ([]*models.OrgMember, error) {
	if m.getUserOrganizationsFn != nil {
		return m.getUserOrganizationsFn(ctx, userID)
	}
	return []*models.OrgMember{}, nil
}

func (m *mockOrgRepo) GetUserPrimaryOrganization(ctx context.Context, userID uuid.UUID) (*models.OrgMember, error) {
	if m.getUserPrimaryOrganizationFn != nil {
		return m.getUserPrimaryOrganizationFn(ctx, userID)
	}
	return nil, nil
}

func (m *mockOrgRepo) GetChildren(ctx context.Context, parentID uuid.UUID) ([]*models.Organization, error) {
	if m.getChildrenFn != nil {
		return m.getChildrenFn(ctx, parentID)
	}
	return []*models.Organization{}, nil
}

func (m *mockOrgRepo) GetRootOrganizations(ctx context.Context, tenantID uuid.UUID) ([]*models.Organization, error) {
	if m.getRootOrganizationsFn != nil {
		return m.getRootOrganizationsFn(ctx, tenantID)
	}
	return []*models.Organization{}, nil
}

func (m *mockOrgRepo) GetDescendants(ctx context.Context, orgID uuid.UUID) ([]*models.Organization, error) {
	if m.getDescendantsFn != nil {
		return m.getDescendantsFn(ctx, orgID)
	}
	return []*models.Organization{}, nil
}

func (m *mockOrgRepo) GetAncestors(ctx context.Context, orgID uuid.UUID) ([]*models.Organization, error) {
	if m.getAncestorsFn != nil {
		return m.getAncestorsFn(ctx, orgID)
	}
	return []*models.Organization{}, nil
}

func (m *mockOrgRepo) GetOrgRoleAssignments(ctx context.Context, orgID uuid.UUID) ([]models.OrgRoleAssignment, error) {
	if m.getOrgRoleAssignmentsFn != nil {
		return m.getOrgRoleAssignmentsFn(ctx, orgID)
	}
	return []models.OrgRoleAssignment{}, nil
}

func (m *mockOrgRepo) AssignOrgRole(ctx context.Context, orgID, roleID uuid.UUID, inherit bool, assignedBy *uuid.UUID) error {
	if m.assignOrgRoleFn != nil {
		return m.assignOrgRoleFn(ctx, orgID, roleID, inherit, assignedBy)
	}
	return nil
}

func (m *mockOrgRepo) RemoveOrgRole(ctx context.Context, orgID, roleID uuid.UUID) error {
	if m.removeOrgRoleFn != nil {
		return m.removeOrgRoleFn(ctx, orgID, roleID)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────
// Mock user repo for org service (satisfies organizationServiceUserRepo)
// ─────────────────────────────────────────────────────────────

type mockOrgUserRepo struct {
	getByIDFn func(ctx context.Context, id uuid.UUID) (*models.User, error)
}

func (m *mockOrgUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return nil, errors.New("not found")
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

func newOrgHandlerWithMock(orgRepo *mockOrgRepo, userRepo *mockOrgUserRepo) *OrganizationHandler {
	svc := services.NewOrganizationService(orgRepo, userRepo)
	return NewOrganizationHandler(svc, nil) // userService nil is fine for org-only tests
}

func newTestOrg(id, tenantID uuid.UUID, name string) *models.Organization {
	return &models.Organization{
		ID:        id,
		TenantID:  tenantID,
		Name:      name,
		OrgType:   models.OrgTypeDepartment,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

func TestOrganizationHandler_ListOrganizations(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()

	t.Run("returns paginated list of organizations", func(t *testing.T) {
		org1 := newTestOrg(uuid.New(), tenantID, "Engineering")
		org2 := newTestOrg(uuid.New(), tenantID, "Marketing")

		orgRepo := &mockOrgRepo{
			listFn: func(_ context.Context, tID uuid.UUID, _, _ int, _ string, _ string) ([]*models.Organization, int, error) {
				assert.Equal(t, tenantID, tID)
				return []*models.Organization{org1, org2}, 2, nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/organizations", h.ListOrganizations)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations?page=1&page_size=10", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.OrganizationListResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Len(t, resp.Organizations, 2)
		assert.Equal(t, 2, resp.Total)
		assert.Equal(t, 1, resp.Page)
		assert.Equal(t, "Engineering", resp.Organizations[0].Name)
	})

	t.Run("returns 400 when tenant_id not in context", func(t *testing.T) {
		h := newOrgHandlerWithMock(&mockOrgRepo{}, &mockOrgUserRepo{})
		router := gin.New()
		router.GET("/organizations", h.ListOrganizations)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("applies search and org_type filters", func(t *testing.T) {
		var capturedSearch, capturedType string

		orgRepo := &mockOrgRepo{
			listFn: func(_ context.Context, _ uuid.UUID, _, _ int, search string, orgType string) ([]*models.Organization, int, error) {
				capturedSearch = search
				capturedType = orgType
				return []*models.Organization{}, 0, nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/organizations", h.ListOrganizations)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations?search=Eng&org_type=team", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "Eng", capturedSearch)
		assert.Equal(t, "team", capturedType)
	})

	t.Run("returns 500 on repo error", func(t *testing.T) {
		orgRepo := &mockOrgRepo{
			listFn: func(_ context.Context, _ uuid.UUID, _, _ int, _ string, _ string) ([]*models.Organization, int, error) {
				return nil, 0, errors.New("database error")
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/organizations", h.ListOrganizations)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestOrganizationHandler_GetOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	orgID := uuid.New()
	org := newTestOrg(orgID, tenantID, "Engineering")

	t.Run("returns organization by ID", func(t *testing.T) {
		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, id uuid.UUID) (*models.Organization, error) {
				if id == orgID {
					return org, nil
				}
				return nil, errors.New("not found")
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/organizations/:id", h.GetOrganization)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations/"+orgID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.Organization
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, orgID, resp.ID)
		assert.Equal(t, "Engineering", resp.Name)
	})

	t.Run("returns 400 for invalid UUID", func(t *testing.T) {
		h := newOrgHandlerWithMock(&mockOrgRepo{}, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/organizations/:id", h.GetOrganization)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations/bad-uuid", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 404 for organization belonging to different tenant", func(t *testing.T) {
		otherTenantOrg := newTestOrg(orgID, uuid.New(), "Other Org")

		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				return otherTenantOrg, nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/organizations/:id", h.GetOrganization)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations/"+orgID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestOrganizationHandler_CreateOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	userID := uuid.New()

	t.Run("creates organization successfully", func(t *testing.T) {
		orgID := uuid.New()
		var capturedOrg *models.Organization

		orgRepo := &mockOrgRepo{
			getByNameFn: func(_ context.Context, _ uuid.UUID, _ string, _ *uuid.UUID) (*models.Organization, error) {
				return nil, errors.New("not found") // Name doesn't exist yet
			},
			createFn: func(_ context.Context, org *models.Organization) error {
				org.ID = orgID
				capturedOrg = org
				return nil
			},
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				if capturedOrg != nil {
					return capturedOrg, nil
				}
				return nil, errors.New("not found")
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantAndUser(tenantID, userID))
		router.POST("/organizations", h.CreateOrganization)

		body := `{"name":"Product Team","org_type":"team"}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/organizations", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp models.Organization
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, orgID, resp.ID)
		assert.Equal(t, "Product Team", resp.Name)
	})

	t.Run("returns 400 for invalid JSON body", func(t *testing.T) {
		h := newOrgHandlerWithMock(&mockOrgRepo{}, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.POST("/organizations", h.CreateOrganization)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/organizations", strings.NewReader(`{invalid}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 when name missing (binding required)", func(t *testing.T) {
		h := newOrgHandlerWithMock(&mockOrgRepo{}, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.POST("/organizations", h.CreateOrganization)

		body := `{"org_type":"team"}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/organizations", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 when name already exists at same level", func(t *testing.T) {
		orgRepo := &mockOrgRepo{
			getByNameFn: func(_ context.Context, _ uuid.UUID, name string, _ *uuid.UUID) (*models.Organization, error) {
				// Name already exists
				return newTestOrg(uuid.New(), tenantID, name), nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.POST("/organizations", h.CreateOrganization)

		body := `{"name":"Existing Dept","org_type":"department"}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/organizations", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestOrganizationHandler_UpdateOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	orgID := uuid.New()
	org := newTestOrg(orgID, tenantID, "Old Name")

	t.Run("updates organization successfully", func(t *testing.T) {
		callCount := 0
		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				callCount++
				// First call: validateOrgTenantAccess, subsequent calls: service internals
				return org, nil
			},
			getByNameFn: func(_ context.Context, _ uuid.UUID, _ string, _ *uuid.UUID) (*models.Organization, error) {
				return nil, errors.New("not found") // Name doesn't conflict
			},
			getDescendantsFn: func(_ context.Context, _ uuid.UUID) ([]*models.Organization, error) {
				return []*models.Organization{}, nil
			},
			updateFn: func(_ context.Context, _ *models.Organization) error {
				return nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.PUT("/organizations/:id", h.UpdateOrganization)

		newName := "New Name"
		body, _ := json.Marshal(models.UpdateOrganizationRequest{Name: &newName})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/organizations/"+orgID.String(), strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.Organization
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "New Name", resp.Name)
	})

	t.Run("returns 400 for invalid organization UUID", func(t *testing.T) {
		h := newOrgHandlerWithMock(&mockOrgRepo{}, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.PUT("/organizations/:id", h.UpdateOrganization)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/organizations/bad-uuid", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestOrganizationHandler_DeleteOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	orgID := uuid.New()

	t.Run("deletes organization without children or members", func(t *testing.T) {
		org := newTestOrg(orgID, tenantID, "Empty Dept")
		org.MemberCount = 0

		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				return org, nil
			},
			getChildrenFn: func(_ context.Context, _ uuid.UUID) ([]*models.Organization, error) {
				return []*models.Organization{}, nil // No children
			},
			deleteFn: func(_ context.Context, id uuid.UUID) error {
				assert.Equal(t, orgID, id)
				return nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.DELETE("/organizations/:id", h.DeleteOrganization)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/organizations/"+orgID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		assert.Contains(t, body["message"], "deleted")
	})

	t.Run("returns 400 when org has children", func(t *testing.T) {
		org := newTestOrg(orgID, tenantID, "Parent Dept")
		child := newTestOrg(uuid.New(), tenantID, "Child Dept")

		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				return org, nil
			},
			getChildrenFn: func(_ context.Context, _ uuid.UUID) ([]*models.Organization, error) {
				return []*models.Organization{child}, nil // Has children
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.DELETE("/organizations/:id", h.DeleteOrganization)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/organizations/"+orgID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 when org has members", func(t *testing.T) {
		org := newTestOrg(orgID, tenantID, "Member Dept")
		org.MemberCount = 5

		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				return org, nil
			},
			getChildrenFn: func(_ context.Context, _ uuid.UUID) ([]*models.Organization, error) {
				return []*models.Organization{}, nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.DELETE("/organizations/:id", h.DeleteOrganization)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/organizations/"+orgID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid UUID", func(t *testing.T) {
		h := newOrgHandlerWithMock(&mockOrgRepo{}, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.DELETE("/organizations/:id", h.DeleteOrganization)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/organizations/bad-uuid", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestOrganizationHandler_GetMembers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	orgID := uuid.New()
	org := newTestOrg(orgID, tenantID, "Engineering")
	userID := uuid.New()

	t.Run("returns members of organization", func(t *testing.T) {
		member := &models.OrgMember{
			ID:             uuid.New(),
			OrganizationID: orgID,
			UserID:         userID,
			Role:           models.OrgRoleMember,
			JoinedAt:       time.Now(),
		}

		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				return org, nil
			},
			getMembersFn: func(_ context.Context, _ uuid.UUID, _, _ int) ([]*models.OrgMember, int, error) {
				return []*models.OrgMember{member}, 1, nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/organizations/:id/members", h.GetMembers)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations/"+orgID.String()+"/members", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.OrgMembersResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Len(t, resp.Members, 1)
		assert.Equal(t, 1, resp.Total)
		assert.Equal(t, userID, resp.Members[0].UserID)
	})

	t.Run("returns 400 for invalid org UUID", func(t *testing.T) {
		h := newOrgHandlerWithMock(&mockOrgRepo{}, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/organizations/:id/members", h.GetMembers)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations/bad-uuid/members", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestOrganizationHandler_AddMember(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	orgID := uuid.New()
	org := newTestOrg(orgID, tenantID, "Engineering")
	memberUserID := uuid.New()
	adderUserID := uuid.New()

	t.Run("adds member to organization", func(t *testing.T) {
		memberUser := &models.User{
			ID:       memberUserID,
			TenantID: tenantID,
			Email:    "member@example.com",
		}

		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				return org, nil
			},
			addMemberFn: func(_ context.Context, oID, uID uuid.UUID, _ string, _ *string, _ bool, _ *uuid.UUID) error {
				assert.Equal(t, orgID, oID)
				assert.Equal(t, memberUserID, uID)
				return nil
			},
		}

		userRepo := &mockOrgUserRepo{
			getByIDFn: func(_ context.Context, id uuid.UUID) (*models.User, error) {
				if id == memberUserID {
					return memberUser, nil
				}
				return nil, errors.New("not found")
			},
		}

		h := newOrgHandlerWithMock(orgRepo, userRepo)
		router := gin.New()
		router.Use(injectTenantAndUser(tenantID, adderUserID))
		router.POST("/organizations/:id/members", h.AddMember)

		body, _ := json.Marshal(models.AddOrgMemberRequest{
			UserID:    memberUserID,
			Role:      models.OrgRoleMember,
			IsPrimary: false,
		})

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/organizations/"+orgID.String()+"/members", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Contains(t, resp["message"], "added")
	})

	t.Run("returns 400 for invalid organization UUID", func(t *testing.T) {
		h := newOrgHandlerWithMock(&mockOrgRepo{}, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.POST("/organizations/:id/members", h.AddMember)

		body := `{"user_id":"` + memberUserID.String() + `"}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/organizations/bad-uuid/members", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestOrganizationHandler_AddMembers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	orgID := uuid.New()
	org := newTestOrg(orgID, tenantID, "Engineering")

	t.Run("adds multiple members to organization", func(t *testing.T) {
		user1ID := uuid.New()
		user2ID := uuid.New()

		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				return org, nil
			},
			addMemberFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ *string, _ bool, _ *uuid.UUID) error {
				return nil
			},
		}

		userRepo := &mockOrgUserRepo{
			getByIDFn: func(_ context.Context, id uuid.UUID) (*models.User, error) {
				return &models.User{ID: id, TenantID: tenantID, Email: "user@example.com"}, nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, userRepo)
		router := gin.New()
		router.Use(injectTenantAndUser(tenantID, uuid.New()))
		router.POST("/organizations/:id/members/batch", h.AddMembers)

		body, _ := json.Marshal(models.AddOrgMembersRequest{
			UserIDs: []uuid.UUID{user1ID, user2ID},
			Role:    models.OrgRoleMember,
		})

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/organizations/"+orgID.String()+"/members/batch", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Contains(t, resp["message"], "added")
	})
}

func TestOrganizationHandler_RemoveMembers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	orgID := uuid.New()
	org := newTestOrg(orgID, tenantID, "Engineering")
	user1ID := uuid.New()
	user2ID := uuid.New()

	t.Run("removes members from organization", func(t *testing.T) {
		var removedPairs []uuid.UUID

		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				return org, nil
			},
			removeMemberFn: func(_ context.Context, _, uID uuid.UUID) error {
				removedPairs = append(removedPairs, uID)
				return nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.DELETE("/organizations/:id/members", h.RemoveMembers)

		body, _ := json.Marshal(models.RemoveOrgMembersRequest{
			UserIDs: []uuid.UUID{user1ID, user2ID},
		})

		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/organizations/"+orgID.String()+"/members", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Len(t, removedPairs, 2)
		assert.Contains(t, removedPairs, user1ID)
		assert.Contains(t, removedPairs, user2ID)
	})
}

func TestOrganizationHandler_GetOrganizationTree(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()

	t.Run("returns organization tree", func(t *testing.T) {
		root1ID := uuid.New()
		root2ID := uuid.New()
		child1ID := uuid.New()

		root1 := newTestOrg(root1ID, tenantID, "Engineering")
		root2 := newTestOrg(root2ID, tenantID, "Marketing")
		child1 := newTestOrg(child1ID, tenantID, "Backend")

		orgRepo := &mockOrgRepo{
			getRootOrganizationsFn: func(_ context.Context, _ uuid.UUID) ([]*models.Organization, error) {
				return []*models.Organization{root1, root2}, nil
			},
			getChildrenFn: func(_ context.Context, parentID uuid.UUID) ([]*models.Organization, error) {
				if parentID == root1ID {
					return []*models.Organization{child1}, nil
				}
				return []*models.Organization{}, nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/organizations/tree", h.GetOrganizationTree)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations/tree", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var body map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &body)
		require.NoError(t, err)

		organizations, ok := body["tree"].([]interface{})
		require.True(t, ok)
		assert.Len(t, organizations, 2) // Two root nodes
	})

	t.Run("returns 400 when tenant_id not in context", func(t *testing.T) {
		h := newOrgHandlerWithMock(&mockOrgRepo{}, &mockOrgUserRepo{})
		router := gin.New()
		router.GET("/organizations/tree", h.GetOrganizationTree)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations/tree", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestOrganizationHandler_GetAncestors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	orgID := uuid.New()
	org := newTestOrg(orgID, tenantID, "Backend Team")

	t.Run("returns ancestors of organization", func(t *testing.T) {
		parentID := uuid.New()
		grandParentID := uuid.New()
		parent := newTestOrg(parentID, tenantID, "Engineering")
		grandParent := newTestOrg(grandParentID, tenantID, "Technology")

		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				return org, nil
			},
			getAncestorsFn: func(_ context.Context, _ uuid.UUID) ([]*models.Organization, error) {
				return []*models.Organization{parent, grandParent}, nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/organizations/:id/ancestors", h.GetAncestors)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations/"+orgID.String()+"/ancestors", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var body map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &body)
		require.NoError(t, err)

		ancestors, ok := body["ancestors"].([]interface{})
		require.True(t, ok)
		assert.Len(t, ancestors, 2)
	})
}

func TestOrganizationHandler_GetDescendants(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	orgID := uuid.New()
	org := newTestOrg(orgID, tenantID, "Engineering")

	t.Run("returns descendants of organization", func(t *testing.T) {
		child1 := newTestOrg(uuid.New(), tenantID, "Backend")
		child2 := newTestOrg(uuid.New(), tenantID, "Frontend")
		grandChild := newTestOrg(uuid.New(), tenantID, "API Team")

		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				return org, nil
			},
			getDescendantsFn: func(_ context.Context, _ uuid.UUID) ([]*models.Organization, error) {
				return []*models.Organization{child1, child2, grandChild}, nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/organizations/:id/descendants", h.GetDescendants)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations/"+orgID.String()+"/descendants", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var body map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &body)
		require.NoError(t, err)

		descendants, ok := body["descendants"].([]interface{})
		require.True(t, ok)
		assert.Len(t, descendants, 3)
	})
}

func TestOrganizationHandler_GetOrgTypes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newOrgHandlerWithMock(&mockOrgRepo{}, &mockOrgUserRepo{})
	router := gin.New()
	router.GET("/organizations/types", h.GetOrgTypes)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations/types", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)

	types, ok := body["types"].([]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, types)

	// Verify expected types are present
	typeStrings := make([]string, len(types))
	for i, v := range types {
		typeStrings[i], _ = v.(string)
	}
	assert.Contains(t, typeStrings, models.OrgTypeTeam)
	assert.Contains(t, typeStrings, models.OrgTypeDepartment)
	assert.Contains(t, typeStrings, models.OrgTypeCompany)
}

func TestOrganizationHandler_GetOrgRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newOrgHandlerWithMock(&mockOrgRepo{}, &mockOrgUserRepo{})
	router := gin.New()
	router.GET("/organizations/roles", h.GetOrgRoles)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/organizations/roles", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)

	roles, ok := body["roles"].([]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, roles)
}

func TestOrganizationHandler_UpdateMember(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	orgID := uuid.New()
	userID := uuid.New()
	org := newTestOrg(orgID, tenantID, "Engineering")

	t.Run("updates member role successfully", func(t *testing.T) {
		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				return org, nil
			},
			updateMemberFn: func(_ context.Context, oID, uID uuid.UUID, _ *string, _ *string, _ *bool) error {
				assert.Equal(t, orgID, oID)
				assert.Equal(t, userID, uID)
				return nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.PUT("/organizations/:id/members/:user_id", h.UpdateMember)

		newRole := models.OrgRoleManager
		body, _ := json.Marshal(models.UpdateOrgMemberRequest{Role: &newRole})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/organizations/"+orgID.String()+"/members/"+userID.String(), strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("returns 400 for invalid user UUID", func(t *testing.T) {
		orgRepo := &mockOrgRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Organization, error) {
				return org, nil
			},
		}

		h := newOrgHandlerWithMock(orgRepo, &mockOrgUserRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.PUT("/organizations/:id/members/:user_id", h.UpdateMember)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/organizations/"+orgID.String()+"/members/bad-user-id", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

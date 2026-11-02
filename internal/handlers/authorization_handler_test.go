// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// authorization_handler_test.go exercises the REAL AuthorizationHandler
// (Authorize, AuthorizeBatch, GetEffectivePermissions) against a mock
// authorizationServiceAPI, via authorizationServiceAPI in
// authorization_handler.go. There is no more hand-written mirror handler:
// AuthorizationHandler.authorizationService is now that narrow interface
// instead of a concrete *services.AuthorizationService, so these tests run
// through the production Authorize/AuthorizeBatch/GetEffectivePermissions
// methods, including pinSubjectToSession which both Authorize and
// AuthorizeBatch call first.
//
// TestPinSubjectToSession (authorization_subject_pin_test.go) already covers
// pinSubjectToSession's decision table directly. This file additionally
// proves that decision is actually wired into the handler methods: a caller
// asking about a different subject must get a 403 from the real endpoint,
// not just from the helper in isolation.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mock authorizationServiceAPI
// ---------------------------------------------------------------------------

type mockAuthzSvc struct {
	authorizeFn          func(ctx context.Context, req *models.AuthorizeRequest) (*models.AuthorizeResponse, error)
	authorizeBatchFn     func(ctx context.Context, req *models.BatchAuthorizeRequest) (*models.BatchAuthorizeResponse, error)
	getEffectivePermsFn  func(ctx context.Context, userID, tenantID uuid.UUID) (*models.EffectivePermissionsResponse, error)
	simulateFn           func(ctx context.Context, actorID, userID, tenantID uuid.UUID, permission string) (*models.SimulateResponse, error)
}

func (m *mockAuthzSvc) Simulate(ctx context.Context, actorID, userID, tenantID uuid.UUID, permission string) (*models.SimulateResponse, error) {
	if m.simulateFn != nil {
		return m.simulateFn(ctx, actorID, userID, tenantID, permission)
	}
	return &models.SimulateResponse{UserID: userID, Permission: permission}, nil
}

func (m *mockAuthzSvc) Authorize(ctx context.Context, req *models.AuthorizeRequest) (*models.AuthorizeResponse, error) {
	if m.authorizeFn != nil {
		return m.authorizeFn(ctx, req)
	}
	return &models.AuthorizeResponse{Allowed: true}, nil
}

func (m *mockAuthzSvc) AuthorizeBatch(ctx context.Context, req *models.BatchAuthorizeRequest) (*models.BatchAuthorizeResponse, error) {
	if m.authorizeBatchFn != nil {
		return m.authorizeBatchFn(ctx, req)
	}
	return &models.BatchAuthorizeResponse{}, nil
}

func (m *mockAuthzSvc) GetEffectivePermissions(ctx context.Context, userID, tenantID uuid.UUID) (*models.EffectivePermissionsResponse, error) {
	if m.getEffectivePermsFn != nil {
		return m.getEffectivePermsFn(ctx, userID, tenantID)
	}
	return &models.EffectivePermissionsResponse{UserID: userID}, nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// mockUserLookup is a test double for userLookupAPI, used to exercise
// AuthorizationHandler.GetEffectivePermissions' cross-tenant target-user
// guard without standing up *services.UserService's own repo/cache
// dependency graph.
type mockUserLookup struct {
	getByIDFn func(ctx context.Context, id uuid.UUID) (*models.UserResponse, error)
}

func (m *mockUserLookup) GetByID(ctx context.Context, id uuid.UUID) (*models.UserResponse, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return nil, errors.New("mockUserLookup: GetByID not stubbed")
}

// newAuthzTestRouter wires the REAL AuthorizationHandler with a nil
// userService, so GetEffectivePermissions skips the cross-tenant
// target-user check. Used by tests (Authorize, AuthorizeBatch, and the
// GetEffectivePermissions cases that don't need a target-user lookup) that
// only care about the authorizationServiceAPI surface. Tests that need to
// exercise the cross-tenant guard itself use
// newAuthzTestRouterWithUserLookup below.
func newAuthzTestRouter(svc authorizationServiceAPI, current *models.CurrentUser) *gin.Engine {
	return newAuthzTestRouterWithUserLookup(svc, nil, current)
}

// newAuthzTestRouterWithUserLookup wires the REAL AuthorizationHandler with
// the given userLookupAPI double, so GetEffectivePermissions' full
// cross-tenant target-user branch runs through production code.
func newAuthzTestRouterWithUserLookup(svc authorizationServiceAPI, userSvc userLookupAPI, current *models.CurrentUser) *gin.Engine {
	gin.SetMode(gin.TestMode)
	h := NewAuthorizationHandler(svc, userSvc)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if current != nil {
			c.Set(middleware.CurrentUserKey, current)
		}
		c.Next()
	})
	r.POST("/api/authorize", h.Authorize)
	r.POST("/api/authorize/batch", h.AuthorizeBatch)
	r.GET("/api/users/:id/effective-permissions", h.GetEffectivePermissions)
	return r
}

func authzJSONBody(t *testing.T, v interface{}) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

func buildCurrentUser(userID, tenantID uuid.UUID) *models.CurrentUser {
	return &models.CurrentUser{ID: userID, TenantID: tenantID, Username: "caller"}
}

func authzDoRequest(router *gin.Engine, method, path string, body *bytes.Reader) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, body)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// Authorize
// ---------------------------------------------------------------------------

func TestAuthorizationHandler_Authorize(t *testing.T) {
	t.Run("allowed result is returned for the authenticated caller", func(t *testing.T) {
		userID, tenantID := uuid.New(), uuid.New()
		caller := buildCurrentUser(userID, tenantID)

		svc := &mockAuthzSvc{
			authorizeFn: func(_ context.Context, req *models.AuthorizeRequest) (*models.AuthorizeResponse, error) {
				assert.Equal(t, userID, req.UserID)
				assert.Equal(t, tenantID, req.TenantID)
				return &models.AuthorizeResponse{Allowed: true}, nil
			},
		}
		router := newAuthzTestRouter(svc, caller)

		body := authzJSONBody(t, models.AuthorizeRequest{
			UserID:     userID,
			TenantID:   tenantID,
			Permission: "users:read",
		})
		w := authzDoRequest(router, http.MethodPost, "/api/authorize", body)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.AuthorizeResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.True(t, resp.Allowed)
	})

	t.Run("denied result is returned as-is", func(t *testing.T) {
		userID, tenantID := uuid.New(), uuid.New()
		caller := buildCurrentUser(userID, tenantID)

		svc := &mockAuthzSvc{
			authorizeFn: func(_ context.Context, _ *models.AuthorizeRequest) (*models.AuthorizeResponse, error) {
				return &models.AuthorizeResponse{Allowed: false, Reason: "no matching role"}, nil
			},
		}
		router := newAuthzTestRouter(svc, caller)

		body := authzJSONBody(t, models.AuthorizeRequest{
			UserID:     userID,
			TenantID:   tenantID,
			Permission: "admin:delete",
		})
		w := authzDoRequest(router, http.MethodPost, "/api/authorize", body)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.AuthorizeResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.False(t, resp.Allowed)
		assert.Equal(t, "no matching role", resp.Reason)
	})

	t.Run("returns 400 for malformed JSON body", func(t *testing.T) {
		userID, tenantID := uuid.New(), uuid.New()
		caller := buildCurrentUser(userID, tenantID)
		router := newAuthzTestRouter(&mockAuthzSvc{}, caller)

		w := authzDoRequest(router, http.MethodPost, "/api/authorize", bytes.NewReader([]byte("not-json")))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 500 on service error", func(t *testing.T) {
		userID, tenantID := uuid.New(), uuid.New()
		caller := buildCurrentUser(userID, tenantID)

		svc := &mockAuthzSvc{
			authorizeFn: func(_ context.Context, _ *models.AuthorizeRequest) (*models.AuthorizeResponse, error) {
				return nil, errors.New("spicedb unavailable")
			},
		}
		router := newAuthzTestRouter(svc, caller)

		body := authzJSONBody(t, models.AuthorizeRequest{
			UserID:     userID,
			TenantID:   tenantID,
			Permission: "users:read",
		})
		w := authzDoRequest(router, http.MethodPost, "/api/authorize", body)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("returns 401 when unauthenticated", func(t *testing.T) {
		svc := &mockAuthzSvc{
			authorizeFn: func(_ context.Context, _ *models.AuthorizeRequest) (*models.AuthorizeResponse, error) {
				t.Fatal("AuthorizationService.Authorize must not be called when pinSubjectToSession rejects the request")
				return nil, nil
			},
		}
		router := newAuthzTestRouter(svc, nil)

		body := authzJSONBody(t, models.AuthorizeRequest{
			UserID:     uuid.New(),
			TenantID:   uuid.New(),
			Permission: "users:read",
		})
		w := authzDoRequest(router, http.MethodPost, "/api/authorize", body)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	// This is the case the mirror handler in the old test file could never
	// catch: it does not go through pinSubjectToSession at all, so a
	// regression there would stay green. Routed through the real handler,
	// a caller asking about a different subject must be refused with 403,
	// and AuthorizationService.Authorize must never be invoked.
	t.Run("returns 403 for a cross-subject query (BOLA)", func(t *testing.T) {
		callerID, callerTenant := uuid.New(), uuid.New()
		caller := buildCurrentUser(callerID, callerTenant)
		victimID := uuid.New()

		svc := &mockAuthzSvc{
			authorizeFn: func(_ context.Context, _ *models.AuthorizeRequest) (*models.AuthorizeResponse, error) {
				t.Fatal("AuthorizationService.Authorize must not be called for a cross-subject request")
				return nil, nil
			},
		}
		router := newAuthzTestRouter(svc, caller)

		body := authzJSONBody(t, models.AuthorizeRequest{
			UserID:     victimID,
			TenantID:   callerTenant,
			Permission: "users:read",
		})
		w := authzDoRequest(router, http.MethodPost, "/api/authorize", body)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

// ---------------------------------------------------------------------------
// AuthorizeBatch
// ---------------------------------------------------------------------------

func TestAuthorizationHandler_AuthorizeBatch(t *testing.T) {
	t.Run("results are returned for the authenticated caller", func(t *testing.T) {
		userID, tenantID := uuid.New(), uuid.New()
		caller := buildCurrentUser(userID, tenantID)

		svc := &mockAuthzSvc{
			authorizeBatchFn: func(_ context.Context, req *models.BatchAuthorizeRequest) (*models.BatchAuthorizeResponse, error) {
				assert.Equal(t, userID, req.UserID)
				assert.Equal(t, tenantID, req.TenantID)
				return &models.BatchAuthorizeResponse{
					Results: map[string]bool{"users:read": true, "users:write": false},
				}, nil
			},
		}
		router := newAuthzTestRouter(svc, caller)

		body := authzJSONBody(t, models.BatchAuthorizeRequest{
			UserID:      userID,
			TenantID:    tenantID,
			Permissions: []string{"users:read", "users:write"},
		})
		w := authzDoRequest(router, http.MethodPost, "/api/authorize/batch", body)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.BatchAuthorizeResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		require.NotNil(t, resp.Results)
		assert.True(t, resp.Results["users:read"])
		assert.False(t, resp.Results["users:write"])
	})

	t.Run("returns 400 for malformed JSON", func(t *testing.T) {
		userID, tenantID := uuid.New(), uuid.New()
		caller := buildCurrentUser(userID, tenantID)
		router := newAuthzTestRouter(&mockAuthzSvc{}, caller)

		w := authzDoRequest(router, http.MethodPost, "/api/authorize/batch", bytes.NewReader([]byte("{broken")))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 on service error", func(t *testing.T) {
		userID, tenantID := uuid.New(), uuid.New()
		caller := buildCurrentUser(userID, tenantID)

		svc := &mockAuthzSvc{
			authorizeBatchFn: func(_ context.Context, _ *models.BatchAuthorizeRequest) (*models.BatchAuthorizeResponse, error) {
				return nil, errors.New("batch authorization failed")
			},
		}
		router := newAuthzTestRouter(svc, caller)

		body := authzJSONBody(t, models.BatchAuthorizeRequest{
			UserID:      userID,
			TenantID:    tenantID,
			Permissions: []string{"users:read"},
		})
		w := authzDoRequest(router, http.MethodPost, "/api/authorize/batch", body)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 401 when unauthenticated", func(t *testing.T) {
		svc := &mockAuthzSvc{
			authorizeBatchFn: func(_ context.Context, _ *models.BatchAuthorizeRequest) (*models.BatchAuthorizeResponse, error) {
				t.Fatal("AuthorizationService.AuthorizeBatch must not be called when pinSubjectToSession rejects the request")
				return nil, nil
			},
		}
		router := newAuthzTestRouter(svc, nil)

		body := authzJSONBody(t, models.BatchAuthorizeRequest{
			UserID:      uuid.New(),
			TenantID:    uuid.New(),
			Permissions: []string{"users:read"},
		})
		w := authzDoRequest(router, http.MethodPost, "/api/authorize/batch", body)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 403 for a cross-subject batch query (BOLA)", func(t *testing.T) {
		callerID, callerTenant := uuid.New(), uuid.New()
		caller := buildCurrentUser(callerID, callerTenant)
		victimID := uuid.New()

		svc := &mockAuthzSvc{
			authorizeBatchFn: func(_ context.Context, _ *models.BatchAuthorizeRequest) (*models.BatchAuthorizeResponse, error) {
				t.Fatal("AuthorizationService.AuthorizeBatch must not be called for a cross-subject request")
				return nil, nil
			},
		}
		router := newAuthzTestRouter(svc, caller)

		body := authzJSONBody(t, models.BatchAuthorizeRequest{
			UserID:      victimID,
			TenantID:    callerTenant,
			Permissions: []string{"users:read"},
		})
		w := authzDoRequest(router, http.MethodPost, "/api/authorize/batch", body)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

// ---------------------------------------------------------------------------
// GetEffectivePermissions
//
// The tests below that use newAuthzTestRouter (userService nil) skip the
// production handler's cross-tenant target-user check and go straight to
// authorizationService.GetEffectivePermissions. The tests further down
// under "cross-tenant target-user guard" use
// newAuthzTestRouterWithUserLookup to exercise that check itself.
// ---------------------------------------------------------------------------

func TestAuthorizationHandler_GetEffectivePermissions(t *testing.T) {
	t.Run("returns effective permissions for the requested user", func(t *testing.T) {
		tenantID := uuid.New()
		targetUserID := uuid.New()
		caller := buildCurrentUser(uuid.New(), tenantID)

		svc := &mockAuthzSvc{
			getEffectivePermsFn: func(_ context.Context, userID, tID uuid.UUID) (*models.EffectivePermissionsResponse, error) {
				assert.Equal(t, targetUserID, userID)
				assert.Equal(t, tenantID, tID)
				return &models.EffectivePermissionsResponse{
					UserID: targetUserID,
					Permissions: []models.PermissionResponse{
						{Name: "users:read"},
						{Name: "users:write"},
					},
				}, nil
			},
		}
		router := newAuthzTestRouter(svc, caller)

		w := authzDoRequest(router, http.MethodGet, "/api/users/"+targetUserID.String()+"/effective-permissions", nil)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.EffectivePermissionsResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Len(t, resp.Permissions, 2)
		assert.Equal(t, "users:read", resp.Permissions[0].Name)
	})

	t.Run("returns 400 for invalid user UUID", func(t *testing.T) {
		caller := buildCurrentUser(uuid.New(), uuid.New())
		router := newAuthzTestRouter(&mockAuthzSvc{}, caller)

		w := authzDoRequest(router, http.MethodGet, "/api/users/bad-uuid/effective-permissions", nil)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 401 when no current user in context", func(t *testing.T) {
		router := newAuthzTestRouter(&mockAuthzSvc{}, nil)

		w := authzDoRequest(router, http.MethodGet, "/api/users/"+uuid.New().String()+"/effective-permissions", nil)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 500 on service error", func(t *testing.T) {
		tenantID := uuid.New()
		targetUserID := uuid.New()
		caller := buildCurrentUser(uuid.New(), tenantID)

		svc := &mockAuthzSvc{
			getEffectivePermsFn: func(_ context.Context, _, _ uuid.UUID) (*models.EffectivePermissionsResponse, error) {
				return nil, errors.New("database connection lost")
			},
		}
		router := newAuthzTestRouter(svc, caller)

		w := authzDoRequest(router, http.MethodGet, "/api/users/"+targetUserID.String()+"/effective-permissions", nil)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// GetEffectivePermissions: cross-tenant target-user guard
//
// These tests wire a real userLookupAPI double (mockUserLookup) so the
// production tenant-mismatch branch in GetEffectivePermissions actually
// runs, instead of being skipped via a nil userService.
// ---------------------------------------------------------------------------

func TestAuthorizationHandler_GetEffectivePermissions_CrossTenantGuard(t *testing.T) {
	t.Run("404s when the target user belongs to a different tenant", func(t *testing.T) {
		callerTenant := uuid.New()
		otherTenant := uuid.New()
		targetUserID := uuid.New()
		caller := buildCurrentUser(uuid.New(), callerTenant)

		userSvc := &mockUserLookup{
			getByIDFn: func(_ context.Context, id uuid.UUID) (*models.UserResponse, error) {
				assert.Equal(t, targetUserID, id)
				return &models.UserResponse{ID: targetUserID, TenantID: otherTenant}, nil
			},
		}
		authzSvc := &mockAuthzSvc{
			getEffectivePermsFn: func(context.Context, uuid.UUID, uuid.UUID) (*models.EffectivePermissionsResponse, error) {
				t.Fatal("authorizationService.GetEffectivePermissions must not be called when the target user is cross-tenant")
				return nil, nil
			},
		}
		router := newAuthzTestRouterWithUserLookup(authzSvc, userSvc, caller)

		w := authzDoRequest(router, http.MethodGet, "/api/users/"+targetUserID.String()+"/effective-permissions", nil)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("404s when the target user does not exist", func(t *testing.T) {
		caller := buildCurrentUser(uuid.New(), uuid.New())
		targetUserID := uuid.New()

		userSvc := &mockUserLookup{
			getByIDFn: func(context.Context, uuid.UUID) (*models.UserResponse, error) {
				return nil, errors.New("not found")
			},
		}
		authzSvc := &mockAuthzSvc{
			getEffectivePermsFn: func(context.Context, uuid.UUID, uuid.UUID) (*models.EffectivePermissionsResponse, error) {
				t.Fatal("authorizationService.GetEffectivePermissions must not be called when the target user lookup fails")
				return nil, nil
			},
		}
		router := newAuthzTestRouterWithUserLookup(authzSvc, userSvc, caller)

		w := authzDoRequest(router, http.MethodGet, "/api/users/"+targetUserID.String()+"/effective-permissions", nil)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("proceeds when the target user belongs to the caller's tenant", func(t *testing.T) {
		tenantID := uuid.New()
		targetUserID := uuid.New()
		caller := buildCurrentUser(uuid.New(), tenantID)

		userSvc := &mockUserLookup{
			getByIDFn: func(_ context.Context, id uuid.UUID) (*models.UserResponse, error) {
				assert.Equal(t, targetUserID, id)
				return &models.UserResponse{ID: targetUserID, TenantID: tenantID}, nil
			},
		}
		authzSvc := &mockAuthzSvc{
			getEffectivePermsFn: func(_ context.Context, userID, tID uuid.UUID) (*models.EffectivePermissionsResponse, error) {
				assert.Equal(t, targetUserID, userID)
				assert.Equal(t, tenantID, tID)
				return &models.EffectivePermissionsResponse{UserID: targetUserID}, nil
			},
		}
		router := newAuthzTestRouterWithUserLookup(authzSvc, userSvc, caller)

		w := authzDoRequest(router, http.MethodGet, "/api/users/"+targetUserID.String()+"/effective-permissions", nil)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

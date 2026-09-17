// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// Fake SCIM token repository (implements the private scimServiceSCIMRepo).
// ---------------------------------------------------------------------------

type fakeSCIMTokenRepo struct {
	createFn         func(ctx context.Context, token *models.SCIMToken) error
	getByIDFn        func(ctx context.Context, id uuid.UUID) (*models.SCIMToken, error)
	getByTenantIDFn  func(ctx context.Context, tenantID uuid.UUID) ([]*models.SCIMToken, error)
	updateFn         func(ctx context.Context, token *models.SCIMToken) error
	deleteFn         func(ctx context.Context, id uuid.UUID) error
	revokeFn         func(ctx context.Context, id uuid.UUID) error
	getByTokenHashFn func(ctx context.Context, tokenHash string) (*models.SCIMToken, error)
	updateLastUsedFn func(ctx context.Context, id uuid.UUID, ip string) error
}

func (r *fakeSCIMTokenRepo) Create(ctx context.Context, token *models.SCIMToken) error {
	if r.createFn != nil {
		return r.createFn(ctx, token)
	}
	return nil
}

func (r *fakeSCIMTokenRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.SCIMToken, error) {
	if r.getByIDFn != nil {
		return r.getByIDFn(ctx, id)
	}
	return nil, nil
}

func (r *fakeSCIMTokenRepo) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.SCIMToken, error) {
	if r.getByTenantIDFn != nil {
		return r.getByTenantIDFn(ctx, tenantID)
	}
	return nil, nil
}

func (r *fakeSCIMTokenRepo) Update(ctx context.Context, token *models.SCIMToken) error {
	if r.updateFn != nil {
		return r.updateFn(ctx, token)
	}
	return nil
}

func (r *fakeSCIMTokenRepo) Delete(ctx context.Context, id uuid.UUID) error {
	if r.deleteFn != nil {
		return r.deleteFn(ctx, id)
	}
	return nil
}

func (r *fakeSCIMTokenRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	if r.revokeFn != nil {
		return r.revokeFn(ctx, id)
	}
	return nil
}

func (r *fakeSCIMTokenRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*models.SCIMToken, error) {
	if r.getByTokenHashFn != nil {
		return r.getByTokenHashFn(ctx, tokenHash)
	}
	return nil, nil
}

func (r *fakeSCIMTokenRepo) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	if r.updateLastUsedFn != nil {
		return r.updateLastUsedFn(ctx, id, ip)
	}
	return nil
}

// Fake user repo (no-op) – SCIMService requires one at construction time.
type fakeSCIMUserRepo struct{}

func (r *fakeSCIMUserRepo) List(_ context.Context, _ uuid.UUID, _, _ int, _ string) ([]models.User, int64, error) {
	return nil, 0, nil
}

func (r *fakeSCIMUserRepo) GetByID(_ context.Context, _ uuid.UUID) (*models.User, error) {
	return nil, nil
}

func (r *fakeSCIMUserRepo) GetByEmail(_ context.Context, _ uuid.UUID, _ string) (*models.User, error) {
	return nil, nil
}
func (r *fakeSCIMUserRepo) Create(_ context.Context, _ *models.User) error { return nil }
func (r *fakeSCIMUserRepo) Update(_ context.Context, _ *models.User) error { return nil }
func (r *fakeSCIMUserRepo) Delete(_ context.Context, _ uuid.UUID) error    { return nil }
func (r *fakeSCIMUserRepo) GetUserRoles(_ context.Context, _ uuid.UUID) ([]models.Role, error) {
	return nil, nil
}

func (r *fakeSCIMUserRepo) AssignRoles(_ context.Context, _ uuid.UUID, _ []uuid.UUID, _ *uuid.UUID) error {
	return nil
}

// Fake role repo (no-op).
type fakeSCIMRoleRepo struct{}

func (r *fakeSCIMRoleRepo) List(_ context.Context, _ uuid.UUID, _, _ int, _ string) ([]models.Role, int64, error) {
	return nil, 0, nil
}

func (r *fakeSCIMRoleRepo) GetByID(_ context.Context, _ uuid.UUID) (*models.Role, error) {
	return nil, nil
}
func (r *fakeSCIMRoleRepo) Create(_ context.Context, _ *models.Role) error { return nil }
func (r *fakeSCIMRoleRepo) Update(_ context.Context, _ *models.Role) error { return nil }
func (r *fakeSCIMRoleRepo) Delete(_ context.Context, _ uuid.UUID) error    { return nil }

// ---------------------------------------------------------------------------
// Helper: build middleware backed by a fake token repo.
// ---------------------------------------------------------------------------

func newSCIMMiddleware(tokenRepo *fakeSCIMTokenRepo) *SCIMAuthMiddleware {
	svc := services.NewSCIMService(
		tokenRepo,
		&fakeSCIMUserRepo{},
		&fakeSCIMRoleRepo{},
		&config.Config{},
	)
	return NewSCIMAuthMiddleware(svc)
}

// makeSCIMToken creates a real SCIM token using the service and returns the
// plain-text bearer token plus the hashed entry stored in the repo (captured
// via createFn).
func makeSCIMToken(t *testing.T) (bearerToken string, stored *models.SCIMToken) {
	t.Helper()

	var captured *models.SCIMToken
	capturingTokenRepo := &fakeSCIMTokenRepo{
		createFn: func(_ context.Context, tok *models.SCIMToken) error {
			captured = tok
			return nil
		},
	}
	svc := services.NewSCIMService(capturingTokenRepo, &fakeSCIMUserRepo{}, &fakeSCIMRoleRepo{}, &config.Config{})

	resp, err := svc.CreateToken(context.Background(), uuid.New(), &models.CreateSCIMTokenRequest{
		Name: "test-scim-token",
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, captured)

	return resp.Token, captured
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestSCIMAuth_MissingAuthorizationHeader_Returns401(t *testing.T) {
	tokenRepo := &fakeSCIMTokenRepo{}
	m := newSCIMMiddleware(tokenRepo)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", m.RequireSCIMAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSCIMAuth_MalformedAuthorizationHeader_Returns401(t *testing.T) {
	tokenRepo := &fakeSCIMTokenRepo{}
	m := newSCIMMiddleware(tokenRepo)

	tests := []struct {
		name   string
		header string
	}{
		{"no scheme", "just-a-token"},
		{"wrong scheme", "Basic dXNlcjpwYXNz"},
		{"empty bearer", "Bearer "},
		{"bearer without space", "Bearertoken"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, router := gin.CreateTestContext(w)
			router.GET("/test", m.RequireSCIMAuth(), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", tt.header)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code, "header %q should be rejected", tt.header)
		})
	}
}

func TestSCIMAuth_ValidToken_SetsContextAndCallsNext(t *testing.T) {
	bearerToken, stored := makeSCIMToken(t)

	tokenRepo := &fakeSCIMTokenRepo{
		getByTokenHashFn: func(_ context.Context, _ string) (*models.SCIMToken, error) {
			return stored, nil
		},
		updateLastUsedFn: func(_ context.Context, _ uuid.UUID, _ string) error { return nil },
	}
	m := newSCIMMiddleware(tokenRepo)

	var scimTenantID, scimTokenID interface{}
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", m.RequireSCIMAuth(), func(c *gin.Context) {
		scimTenantID, _ = c.Get("scim_tenant_id")
		scimTokenID, _ = c.Get("scim_token_id")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, stored.TenantID, scimTenantID)
	assert.Equal(t, stored.ID, scimTokenID)
}

func TestSCIMAuth_CaseInsensitiveBearer_Passes(t *testing.T) {
	bearerToken, stored := makeSCIMToken(t)

	tokenRepo := &fakeSCIMTokenRepo{
		getByTokenHashFn: func(_ context.Context, _ string) (*models.SCIMToken, error) {
			return stored, nil
		},
		updateLastUsedFn: func(_ context.Context, _ uuid.UUID, _ string) error { return nil },
	}
	m := newSCIMMiddleware(tokenRepo)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", m.RequireSCIMAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	// The SCIM middleware uses strings.EqualFold so "bearer" should work too.
	req.Header.Set("Authorization", "bearer "+bearerToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSCIMAuth_InvalidToken_Returns401(t *testing.T) {
	tokenRepo := &fakeSCIMTokenRepo{
		getByTokenHashFn: func(_ context.Context, _ string) (*models.SCIMToken, error) {
			return nil, errors.New("not found")
		},
	}
	m := newSCIMMiddleware(tokenRepo)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", m.RequireSCIMAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer scim_invalid-token-value")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSCIMAuth_TokenNotFoundInRepo_Returns401(t *testing.T) {
	tokenRepo := &fakeSCIMTokenRepo{
		getByTokenHashFn: func(_ context.Context, _ string) (*models.SCIMToken, error) {
			return nil, nil // record not found, no error
		},
	}
	m := newSCIMMiddleware(tokenRepo)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", m.RequireSCIMAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer scim_nosuchtoken")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSCIMAuth_RevokedToken_Returns401(t *testing.T) {
	// A revoked token has IsActive = false.
	bearerToken, stored := makeSCIMToken(t)
	stored.IsActive = false

	tokenRepo := &fakeSCIMTokenRepo{
		getByTokenHashFn: func(_ context.Context, _ string) (*models.SCIMToken, error) {
			return stored, nil
		},
	}
	m := newSCIMMiddleware(tokenRepo)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", m.RequireSCIMAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSCIMAuth_ExpiredToken_Returns401(t *testing.T) {
	bearerToken, stored := makeSCIMToken(t)

	// Set an expiry in the past.
	past := time.Now().Add(-1 * time.Hour)
	stored.ExpiresAt = &past

	tokenRepo := &fakeSCIMTokenRepo{
		getByTokenHashFn: func(_ context.Context, _ string) (*models.SCIMToken, error) {
			return stored, nil
		},
	}
	m := newSCIMMiddleware(tokenRepo)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", m.RequireSCIMAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSCIMAuth_FutureExpiryToken_Passes(t *testing.T) {
	bearerToken, stored := makeSCIMToken(t)

	// Set an expiry well in the future.
	future := time.Now().Add(24 * time.Hour)
	stored.ExpiresAt = &future

	tokenRepo := &fakeSCIMTokenRepo{
		getByTokenHashFn: func(_ context.Context, _ string) (*models.SCIMToken, error) {
			return stored, nil
		},
		updateLastUsedFn: func(_ context.Context, _ uuid.UUID, _ string) error { return nil },
	}
	m := newSCIMMiddleware(tokenRepo)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", m.RequireSCIMAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSCIMAuth_ResponseBodyContainsSCIMSchema(t *testing.T) {
	// SCIM errors should include the SCIM error schema URN in the JSON body.
	tokenRepo := &fakeSCIMTokenRepo{}
	m := newSCIMMiddleware(tokenRepo)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", m.RequireSCIMAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	// No Authorization header
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "urn:ietf:params:scim:api:messages:2.0:Error")
}

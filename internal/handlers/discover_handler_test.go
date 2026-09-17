// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ─── mock ─────────────────────────────────────────────────────────────────────

type mockDiscoverService struct{ mock.Mock }

func (m *mockDiscoverService) Discover(ctx context.Context, req *models.DiscoverRequest) (*models.DiscoverResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.DiscoverResponse), args.Error(1)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func setupDiscoverRouter(svc DiscoverServiceInterface) *gin.Engine {
	router := gin.New()
	h := NewDiscoverHandler(svc, nil)
	router.POST("/api/v1/auth/discover", h.Discover)
	return router
}

func postDiscover(router *gin.Engine, body interface{}) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/auth/discover", &buf)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	return w
}

// ─── tests ────────────────────────────────────────────────────────────────────

func TestDiscoverHandler_Discover(t *testing.T) {
	t.Run("200 with valid email returns discover response", func(t *testing.T) {
		svc := &mockDiscoverService{}
		tenantID := "11111111-0000-0000-0000-000000000001"
		tenantName := "Acme Corp"
		tenantSlug := "acme-corp"
		resp := &models.DiscoverResponse{
			Email:      "user@acme.com",
			EmailKnown: true,
			AuthMethod: "password",
			TenantID:   &tenantID,
			TenantName: &tenantName,
			TenantSlug: &tenantSlug,
		}

		svc.On("Discover", mock.Anything, &models.DiscoverRequest{Email: "user@acme.com"}).
			Return(resp, nil)

		router := setupDiscoverRouter(svc)
		w := postDiscover(router, map[string]string{"email": "user@acme.com"})

		assert.Equal(t, http.StatusOK, w.Code)

		var got models.DiscoverResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
		assert.Equal(t, "user@acme.com", got.Email)
		assert.Equal(t, "password", got.AuthMethod)
		assert.True(t, got.EmailKnown)
		require.NotNil(t, got.TenantID)
		assert.Equal(t, tenantID, *got.TenantID)

		svc.AssertExpectations(t)
	})

	t.Run("200 with SSO response", func(t *testing.T) {
		svc := &mockDiscoverService{}
		providerID := "aaaaaaaa-0000-0000-0000-000000000001"
		providerType := "saml"
		providerName := "Acme SSO"

		resp := &models.DiscoverResponse{
			Email:           "jane@acme.com",
			AuthMethod:      "sso",
			SSOProviderID:   &providerID,
			SSOProviderType: &providerType,
			SSOProviderName: &providerName,
		}

		svc.On("Discover", mock.Anything, &models.DiscoverRequest{Email: "jane@acme.com"}).
			Return(resp, nil)

		router := setupDiscoverRouter(svc)
		w := postDiscover(router, map[string]string{"email": "jane@acme.com"})

		assert.Equal(t, http.StatusOK, w.Code)

		var got models.DiscoverResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
		assert.Equal(t, "sso", got.AuthMethod)
		require.NotNil(t, got.SSOProviderID)
		assert.Equal(t, providerID, *got.SSOProviderID)
		require.NotNil(t, got.SSOProviderType)
		assert.Equal(t, "saml", *got.SSOProviderType)
	})

	t.Run("200 signup response for unknown personal email", func(t *testing.T) {
		svc := &mockDiscoverService{}
		accountType := "personal"
		resp := &models.DiscoverResponse{
			Email:         "new@gmail.com",
			AuthMethod:    "signup",
			SignupAllowed: true,
			AccountType:   &accountType,
		}

		svc.On("Discover", mock.Anything, &models.DiscoverRequest{Email: "new@gmail.com"}).
			Return(resp, nil)

		router := setupDiscoverRouter(svc)
		w := postDiscover(router, map[string]string{"email": "new@gmail.com"})

		assert.Equal(t, http.StatusOK, w.Code)

		var got models.DiscoverResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
		assert.Equal(t, "signup", got.AuthMethod)
		assert.True(t, got.SignupAllowed)
		require.NotNil(t, got.AccountType)
		assert.Equal(t, "personal", *got.AccountType)
	})

	t.Run("400 on invalid JSON body", func(t *testing.T) {
		svc := &mockDiscoverService{}
		router := setupDiscoverRouter(svc)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/auth/discover",
			bytes.NewBufferString(`{not valid json`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		assert.Equal(t, "invalid_request", body["error"])
		assert.NotEmpty(t, body["details"])

		svc.AssertNotCalled(t, "Discover")
	})

	t.Run("400 on missing email field", func(t *testing.T) {
		svc := &mockDiscoverService{}
		router := setupDiscoverRouter(svc)

		// Empty email — fails binding validation (required)
		w := postDiscover(router, map[string]string{})

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		assert.Equal(t, "invalid_request", body["error"])

		svc.AssertNotCalled(t, "Discover")
	})

	t.Run("400 on empty body", func(t *testing.T) {
		svc := &mockDiscoverService{}
		router := setupDiscoverRouter(svc)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/auth/discover", bytes.NewBufferString(""))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		svc.AssertNotCalled(t, "Discover")
	})

	t.Run("500 on raw (non-sentinel) service error — fallback path", func(t *testing.T) {
		svc := &mockDiscoverService{}

		svc.On("Discover", mock.Anything, &models.DiscoverRequest{Email: "fail@example.com"}).
			Return(nil, errors.New("database connection refused"))

		router := setupDiscoverRouter(svc)
		w := postDiscover(router, map[string]string{"email": "fail@example.com"})

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		// Error message should not leak internals
		assert.Equal(t, "discovery_failed", body["error"])

		svc.AssertExpectations(t)
	})

	// Sentinel-typed errors → specific HTTP codes per
	// services.DiscoverError contract. Companion B of the
	// 2026-05-20 discovery-failed incident — these tests
	// pin the contract so a future contributor can't
	// regress it back to "everything is 500".

	// Defensive: the gin `binding:"email"` tag normally catches
	// malformed emails at JSON-bind (returns "invalid_request" 400),
	// so the service-side ErrDiscoverInvalidEmail is unreachable in
	// practice via the HTTP path. But the mapping must still be
	// pinned so future contributors who add a non-HTTP caller (CLI,
	// internal RPC) get the correct 400 + body when the service
	// returns the sentinel.
	t.Run("400 on ErrDiscoverInvalidEmail (defensive — gin-binding usually catches first)", func(t *testing.T) {
		svc := &mockDiscoverService{}

		// Use a binding-valid email so the request reaches the
		// service; mock the service to return InvalidEmail anyway.
		svc.On("Discover", mock.Anything, &models.DiscoverRequest{Email: "u@x.com"}).
			Return(nil, &services.DiscoverError{
				Step: services.DiscoverStepInvalidEmail,
				Err:  errors.New("post-bind validation failed"),
			})

		router := setupDiscoverRouter(svc)
		w := postDiscover(router, map[string]string{"email": "u@x.com"})

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		assert.Equal(t, "invalid_email", body["error"])
	})

	t.Run("502 on ErrDiscoverDomainLookup (upstream DB down — not our fault)", func(t *testing.T) {
		svc := &mockDiscoverService{}

		svc.On("Discover", mock.Anything, &models.DiscoverRequest{Email: "u@example.com"}).
			Return(nil, &services.DiscoverError{
				Step: services.DiscoverStepDomainLookup,
				Err:  errors.New("connection refused"),
			})

		router := setupDiscoverRouter(svc)
		w := postDiscover(router, map[string]string{"email": "u@example.com"})

		assert.Equal(t, http.StatusBadGateway, w.Code)
		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		assert.Equal(t, "upstream_unavailable", body["error"])
	})

	t.Run("502 on ErrDiscoverTenantLookup", func(t *testing.T) {
		svc := &mockDiscoverService{}

		svc.On("Discover", mock.Anything, &models.DiscoverRequest{Email: "u@example.com"}).
			Return(nil, &services.DiscoverError{
				Step: services.DiscoverStepTenantLookup,
				Err:  errors.New("tenant not found"),
			})

		router := setupDiscoverRouter(svc)
		w := postDiscover(router, map[string]string{"email": "u@example.com"})

		assert.Equal(t, http.StatusBadGateway, w.Code)
	})

	t.Run("502 on ErrDiscoverUserLookup", func(t *testing.T) {
		svc := &mockDiscoverService{}

		svc.On("Discover", mock.Anything, &models.DiscoverRequest{Email: "u@example.com"}).
			Return(nil, &services.DiscoverError{
				Step: services.DiscoverStepUserLookup,
				Err:  errors.New("query timeout"),
			})

		router := setupDiscoverRouter(svc)
		w := postDiscover(router, map[string]string{"email": "u@example.com"})

		assert.Equal(t, http.StatusBadGateway, w.Code)
	})

	t.Run("response includes branding when present", func(t *testing.T) {
		svc := &mockDiscoverService{}
		logo := "https://cdn.example.com/logo.png"
		title := "Welcome"
		resp := &models.DiscoverResponse{
			Email:      "user@corp.com",
			AuthMethod: "password",
			EmailKnown: true,
			Branding: &models.DiscoverBranding{
				LogoURL:         &logo,
				PrimaryColor:    "#0055CC",
				BackgroundColor: "#FFFFFF",
				LoginTitle:      &title,
			},
		}

		svc.On("Discover", mock.Anything, &models.DiscoverRequest{Email: "user@corp.com"}).
			Return(resp, nil)

		router := setupDiscoverRouter(svc)
		w := postDiscover(router, map[string]string{"email": "user@corp.com"})

		assert.Equal(t, http.StatusOK, w.Code)

		var got models.DiscoverResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
		require.NotNil(t, got.Branding)
		assert.Equal(t, "#0055CC", got.Branding.PrimaryColor)
		require.NotNil(t, got.Branding.LogoURL)
		assert.Equal(t, logo, *got.Branding.LogoURL)
	})

	t.Run("available_providers list is serialised correctly", func(t *testing.T) {
		svc := &mockDiscoverService{}
		resp := &models.DiscoverResponse{
			Email:      "user@multi.com",
			AuthMethod: "password",
			EmailKnown: true,
			AvailableProviders: []models.DiscoverProvider{
				{ID: "id-1", Type: "google", Name: "google", DisplayName: "Google"},
				{ID: "id-2", Type: "saml", Name: "corp-saml", DisplayName: "Corporate SSO"},
			},
		}

		svc.On("Discover", mock.Anything, &models.DiscoverRequest{Email: "user@multi.com"}).
			Return(resp, nil)

		router := setupDiscoverRouter(svc)
		w := postDiscover(router, map[string]string{"email": "user@multi.com"})

		assert.Equal(t, http.StatusOK, w.Code)

		var got models.DiscoverResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
		assert.Len(t, got.AvailableProviders, 2)
		assert.Equal(t, "google", got.AvailableProviders[0].Type)
		assert.Equal(t, "Corporate SSO", got.AvailableProviders[1].DisplayName)
	})
}

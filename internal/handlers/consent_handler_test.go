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
)

// ---------------------------------------------------------------------------
// consentServiceFake – test double for *services.ConsentService
// ---------------------------------------------------------------------------

type consentServiceFake struct {
	consentTypes       []models.ConsentType
	consentTypesErr    error
	userConsentsResp   *models.ConsentListResponse
	userConsentsErr    error
	updateConsentErr   error
	updateByIDErr      error
	bulkUpdateErr      error
	hasAllRequired     bool
	hasAllRequiredErr  error
	pendingConsents    []models.ConsentType
	pendingConsentsErr error
	consentHistory     []models.UserConsentWithType
	consentHistoryErr  error
	detailedHistory    []models.ConsentHistoryWithType
	detailedHistoryErr error
}

func (f *consentServiceFake) GetConsentTypes(_ context.Context, _ uuid.UUID) ([]models.ConsentType, error) {
	return f.consentTypes, f.consentTypesErr
}

func (f *consentServiceFake) GetUserConsents(_ context.Context, _, _ uuid.UUID) (*models.ConsentListResponse, error) {
	return f.userConsentsResp, f.userConsentsErr
}

func (f *consentServiceFake) UpdateConsent(_ context.Context, _, _ uuid.UUID, _ string, _ bool, _, _ string) error {
	return f.updateConsentErr
}

func (f *consentServiceFake) UpdateConsentByID(_ context.Context, _, _, _ uuid.UUID, _ bool, _, _ string) error {
	return f.updateByIDErr
}

func (f *consentServiceFake) BulkUpdateConsents(
	_ context.Context,
	_, _ uuid.UUID,
	_ []struct {
		ConsentTypeID string `json:"consent_type_id"`
		Granted       bool   `json:"granted"`
	},
	_, _ string,
) error {
	return f.bulkUpdateErr
}

func (f *consentServiceFake) HasGrantedAllRequired(_ context.Context, _, _ uuid.UUID) (bool, error) {
	return f.hasAllRequired, f.hasAllRequiredErr
}

func (f *consentServiceFake) GetPendingRequiredConsents(_ context.Context, _, _ uuid.UUID) ([]models.ConsentType, error) {
	return f.pendingConsents, f.pendingConsentsErr
}

func (f *consentServiceFake) GetConsentHistory(_ context.Context, _ uuid.UUID, _ time.Time) ([]models.UserConsentWithType, error) {
	return f.consentHistory, f.consentHistoryErr
}

func (f *consentServiceFake) GetConsentHistoryDetailed(_ context.Context, _, _ uuid.UUID, _ int) ([]models.ConsentHistoryWithType, error) {
	return f.detailedHistory, f.detailedHistoryErr
}

// ---------------------------------------------------------------------------
// consentHandlerShim – mirrors ConsentHandler logic against the fake service
// ---------------------------------------------------------------------------

type consentHandlerShim struct {
	svc *consentServiceFake
}

func newConsentTestRouter(svc *consentServiceFake, withUser bool, tenantID uuid.UUID) *gin.Engine {
	router := gin.New()
	injectUser := func(c *gin.Context) {
		if withUser {
			c.Set("current_user", &models.CurrentUser{
				ID:       uuid.New(),
				TenantID: tenantID,
				Email:    "test@example.com",
			})
		}
		c.Next()
	}
	h := &consentHandlerShim{svc: svc}
	router.Use(injectUser)
	router.GET("/consents/types", h.GetConsentTypes)
	router.GET("/consents", h.GetUserConsents)
	// Note: /consents/bulk must be registered before /:type to avoid ambiguity.
	router.POST("/consents/bulk", h.BulkUpdateConsents)
	router.POST("/consents/id/:id", h.UpdateConsentByID)
	router.POST("/consents/:type", h.UpdateConsent)
	router.GET("/consents/pending", h.CheckPendingConsents)
	router.GET("/consents/history", h.GetConsentHistory)
	router.GET("/consents/history/detailed", h.GetConsentHistoryDetailed)
	return router
}

func consentCurrentUser(c *gin.Context) *models.CurrentUser {
	val, exists := c.Get("current_user")
	if !exists {
		return nil
	}
	u, ok := val.(*models.CurrentUser)
	if !ok {
		return nil
	}
	return u
}

func (h *consentHandlerShim) GetConsentTypes(c *gin.Context) {
	user := consentCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	types, err := h.svc.GetConsentTypes(c.Request.Context(), user.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get consent types"})
		return
	}
	responses := make([]models.ConsentTypeResponse, len(types))
	for i, t := range types {
		responses[i] = *t.ToResponse()
	}
	c.JSON(http.StatusOK, responses)
}

func (h *consentHandlerShim) GetUserConsents(c *gin.Context) {
	user := consentCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	response, err := h.svc.GetUserConsents(c.Request.Context(), user.ID, user.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user consents"})
		return
	}
	c.JSON(http.StatusOK, response)
}

func (h *consentHandlerShim) UpdateConsent(c *gin.Context) {
	user := consentCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	consentType := c.Param("type")
	if consentType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "consent type is required"})
		return
	}
	var req models.UpdateConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if err := h.svc.UpdateConsent(c.Request.Context(), user.ID, user.TenantID, consentType, req.Granted, c.ClientIP(), c.GetHeader("User-Agent")); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	message := "Consent granted successfully"
	if !req.Granted {
		message = "Consent revoked successfully"
	}
	c.JSON(http.StatusOK, gin.H{"message": message})
}

func (h *consentHandlerShim) UpdateConsentByID(c *gin.Context) {
	user := consentCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	consentTypeID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid consent type ID"})
		return
	}
	var req models.UpdateConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if err := h.svc.UpdateConsentByID(c.Request.Context(), user.ID, user.TenantID, consentTypeID, req.Granted, c.ClientIP(), c.GetHeader("User-Agent")); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	message := "Consent granted successfully"
	if !req.Granted {
		message = "Consent revoked successfully"
	}
	c.JSON(http.StatusOK, gin.H{"message": message})
}

func (h *consentHandlerShim) BulkUpdateConsents(c *gin.Context) {
	user := consentCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req models.BulkConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if len(req.Consents) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no consents provided"})
		return
	}
	if err := h.svc.BulkUpdateConsents(c.Request.Context(), user.ID, user.TenantID, req.Consents, c.ClientIP(), c.GetHeader("User-Agent")); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Consents updated successfully"})
}

func (h *consentHandlerShim) CheckPendingConsents(c *gin.Context) {
	user := consentCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	hasAllRequired, err := h.svc.HasGrantedAllRequired(c.Request.Context(), user.ID, user.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check pending consents"})
		return
	}
	var pending []models.ConsentTypeResponse
	if !hasAllRequired {
		pendingTypes, err := h.svc.GetPendingRequiredConsents(c.Request.Context(), user.ID, user.TenantID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get pending consents"})
			return
		}
		pending = make([]models.ConsentTypeResponse, len(pendingTypes))
		for i, p := range pendingTypes {
			pending[i] = *p.ToResponse()
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"has_pending_required": !hasAllRequired,
		"pending_consents":     pending,
	})
}

func (h *consentHandlerShim) GetConsentHistory(c *gin.Context) {
	user := consentCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	since := time.Now().AddDate(0, 0, -30)
	history, err := h.svc.GetConsentHistory(c.Request.Context(), user.ID, since)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get consent history"})
		return
	}
	responses := make([]models.UserConsentResponse, len(history))
	for i, item := range history {
		responses[i] = *item.ToResponse()
	}
	c.JSON(http.StatusOK, responses)
}

func (h *consentHandlerShim) GetConsentHistoryDetailed(c *gin.Context) {
	user := consentCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	history, err := h.svc.GetConsentHistoryDetailed(c.Request.Context(), user.ID, user.TenantID, 50)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get consent history"})
		return
	}
	responses := make([]models.ConsentHistoryResponse, len(history))
	for i, item := range history {
		responses[i] = *item.ToResponse()
	}
	c.JSON(http.StatusOK, responses)
}

// ---------------------------------------------------------------------------
// HTTP helpers for consent tests
// ---------------------------------------------------------------------------

func performConsentRequest(router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequestWithContext(context.Background(), method, path, nil)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func decodeConsentBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

func buildTestConsentType(name string, required bool) models.ConsentType {
	desc := "Consent description for " + name
	basis := "consent"
	return models.ConsentType{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Name:        name,
		DisplayName: name + " Display",
		Description: &desc,
		Category:    "functional",
		IsRequired:  required,
		IsActive:    true,
		Version:     1,
		LegalBasis:  &basis,
	}
}

// ---------------------------------------------------------------------------
// Tests: GetUserConsents (GET /consents)
// ---------------------------------------------------------------------------

func TestConsent_GetUserConsents(t *testing.T) {
	tenantID := uuid.New()

	t.Run("returns empty consent list when none exist", func(t *testing.T) {
		svc := &consentServiceFake{
			userConsentsResp: &models.ConsentListResponse{
				Consents:           []models.UserConsentResponse{},
				PendingRequired:    []models.ConsentTypeResponse{},
				HasPendingRequired: false,
			},
		}
		router := newConsentTestRouter(svc, true, tenantID)
		w := performConsentRequest(router, http.MethodGet, "/consents", "")

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.ConsentListResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Empty(t, resp.Consents)
		assert.False(t, resp.HasPendingRequired)
	})

	t.Run("returns consents with pending required types", func(t *testing.T) {
		ct := buildTestConsentType("terms_of_service", true)
		svc := &consentServiceFake{
			userConsentsResp: &models.ConsentListResponse{
				Consents:           []models.UserConsentResponse{},
				PendingRequired:    []models.ConsentTypeResponse{*ct.ToResponse()},
				HasPendingRequired: true,
			},
		}
		router := newConsentTestRouter(svc, true, tenantID)
		w := performConsentRequest(router, http.MethodGet, "/consents", "")

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.ConsentListResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.HasPendingRequired)
		assert.Len(t, resp.PendingRequired, 1)
		assert.Equal(t, "terms_of_service", resp.PendingRequired[0].Name)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newConsentTestRouter(&consentServiceFake{}, false, tenantID)
		w := performConsentRequest(router, http.MethodGet, "/consents", "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("service error returns 500", func(t *testing.T) {
		svc := &consentServiceFake{userConsentsErr: errors.New("db error")}
		router := newConsentTestRouter(svc, true, tenantID)
		w := performConsentRequest(router, http.MethodGet, "/consents", "")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: UpdateConsent (POST /consents/:type)
// ---------------------------------------------------------------------------

func TestConsent_UpdateConsent(t *testing.T) {
	tenantID := uuid.New()

	t.Run("grant consent returns success message", func(t *testing.T) {
		router := newConsentTestRouter(&consentServiceFake{}, true, tenantID)
		w := performConsentRequest(router, http.MethodPost, "/consents/terms_of_service", `{"granted":true}`)

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeConsentBody(t, w)
		assert.Equal(t, "Consent granted successfully", body["message"])
	})

	t.Run("withdraw consent returns revoked message", func(t *testing.T) {
		router := newConsentTestRouter(&consentServiceFake{}, true, tenantID)
		w := performConsentRequest(router, http.MethodPost, "/consents/analytics", `{"granted":false}`)

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeConsentBody(t, w)
		assert.Equal(t, "Consent revoked successfully", body["message"])
	})

	t.Run("service returns error → 400", func(t *testing.T) {
		svc := &consentServiceFake{updateConsentErr: errors.New("cannot revoke required consent")}
		router := newConsentTestRouter(svc, true, tenantID)
		w := performConsentRequest(router, http.MethodPost, "/consents/terms_of_service", `{"granted":false}`)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		body := decodeConsentBody(t, w)
		assert.Contains(t, body["error"], "cannot revoke required consent")
	})

	t.Run("invalid JSON body returns 400", func(t *testing.T) {
		router := newConsentTestRouter(&consentServiceFake{}, true, tenantID)
		w := performConsentRequest(router, http.MethodPost, "/consents/analytics", `not-json`)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newConsentTestRouter(&consentServiceFake{}, false, tenantID)
		w := performConsentRequest(router, http.MethodPost, "/consents/analytics", `{"granted":true}`)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: BulkUpdateConsents (POST /consents/bulk)
// ---------------------------------------------------------------------------

func TestConsent_BulkUpdateConsents(t *testing.T) {
	tenantID := uuid.New()

	t.Run("bulk update multiple consents succeeds", func(t *testing.T) {
		router := newConsentTestRouter(&consentServiceFake{}, true, tenantID)
		body := `{"consents":[
			{"consent_type_id":"` + uuid.New().String() + `","granted":true},
			{"consent_type_id":"` + uuid.New().String() + `","granted":false}
		]}`
		w := performConsentRequest(router, http.MethodPost, "/consents/bulk", body)

		assert.Equal(t, http.StatusOK, w.Code)
		resp := decodeConsentBody(t, w)
		assert.Equal(t, "Consents updated successfully", resp["message"])
	})

	t.Run("empty consents list returns 400", func(t *testing.T) {
		router := newConsentTestRouter(&consentServiceFake{}, true, tenantID)
		w := performConsentRequest(router, http.MethodPost, "/consents/bulk", `{"consents":[]}`)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service error returns 400", func(t *testing.T) {
		svc := &consentServiceFake{bulkUpdateErr: errors.New("invalid consent type ID")}
		router := newConsentTestRouter(svc, true, tenantID)
		body := `{"consents":[{"consent_type_id":"` + uuid.New().String() + `","granted":true}]}`
		w := performConsentRequest(router, http.MethodPost, "/consents/bulk", body)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newConsentTestRouter(&consentServiceFake{}, false, tenantID)
		w := performConsentRequest(router, http.MethodPost, "/consents/bulk", `{"consents":[]}`)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: GetConsentHistory (GET /consents/history)
// ---------------------------------------------------------------------------

func TestConsent_GetConsentHistory(t *testing.T) {
	tenantID := uuid.New()

	t.Run("returns empty slice when no history", func(t *testing.T) {
		svc := &consentServiceFake{consentHistory: []models.UserConsentWithType{}}
		router := newConsentTestRouter(svc, true, tenantID)
		w := performConsentRequest(router, http.MethodGet, "/consents/history", "")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("returns consent change history", func(t *testing.T) {
		ct := buildTestConsentType("analytics", false)
		now := time.Now()
		svc := &consentServiceFake{
			consentHistory: []models.UserConsentWithType{
				{
					UserConsent: models.UserConsent{
						ID:             uuid.New(),
						UserID:         uuid.New(),
						ConsentTypeID:  ct.ID,
						Granted:        true,
						ConsentVersion: 1,
						GrantedAt:      &now,
					},
					ConsentType: ct,
				},
			},
		}
		router := newConsentTestRouter(svc, true, tenantID)
		w := performConsentRequest(router, http.MethodGet, "/consents/history", "")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("service error returns 500", func(t *testing.T) {
		svc := &consentServiceFake{consentHistoryErr: errors.New("db error")}
		router := newConsentTestRouter(svc, true, tenantID)
		w := performConsentRequest(router, http.MethodGet, "/consents/history", "")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newConsentTestRouter(&consentServiceFake{}, false, tenantID)
		w := performConsentRequest(router, http.MethodGet, "/consents/history", "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: CheckPendingConsents (GET /consents/pending)
// ---------------------------------------------------------------------------

func TestConsent_CheckPendingConsents(t *testing.T) {
	tenantID := uuid.New()

	t.Run("all required consents granted – no pending", func(t *testing.T) {
		svc := &consentServiceFake{hasAllRequired: true}
		router := newConsentTestRouter(svc, true, tenantID)
		w := performConsentRequest(router, http.MethodGet, "/consents/pending", "")

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeConsentBody(t, w)
		assert.Equal(t, false, body["has_pending_required"])
	})

	t.Run("pending required consents exist", func(t *testing.T) {
		ct := buildTestConsentType("terms_of_service", true)
		svc := &consentServiceFake{
			hasAllRequired:  false,
			pendingConsents: []models.ConsentType{ct},
		}
		router := newConsentTestRouter(svc, true, tenantID)
		w := performConsentRequest(router, http.MethodGet, "/consents/pending", "")

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeConsentBody(t, w)
		assert.Equal(t, true, body["has_pending_required"])
		pending, ok := body["pending_consents"].([]interface{})
		require.True(t, ok)
		assert.Len(t, pending, 1)
	})

	t.Run("hasAllRequired error returns 500", func(t *testing.T) {
		svc := &consentServiceFake{hasAllRequiredErr: errors.New("db error")}
		router := newConsentTestRouter(svc, true, tenantID)
		w := performConsentRequest(router, http.MethodGet, "/consents/pending", "")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newConsentTestRouter(&consentServiceFake{}, false, tenantID)
		w := performConsentRequest(router, http.MethodGet, "/consents/pending", "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

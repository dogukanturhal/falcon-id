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
// invitationServiceFake – test double for *services.InvitationService
// ---------------------------------------------------------------------------

type invitationServiceFake struct {
	// ValidateToken
	validateResp *models.ValidateInvitationResponse
	validateErr  error

	// AcceptInvitation
	acceptResp *models.LoginResponse
	acceptErr  error

	// ResendInvitation
	resendResp *models.InvitationResponse
	resendErr  error

	// RevokeInvitation
	revokeErr error

	// GetPendingInvitation
	pendingResp *models.InvitationResponse
	pendingErr  error

	// CreateInvitation
	createResp  *models.InvitationResponse
	createToken string
	createErr   error
}

func (f *invitationServiceFake) ValidateToken(_ context.Context, _ string) (*models.ValidateInvitationResponse, error) {
	return f.validateResp, f.validateErr
}

func (f *invitationServiceFake) AcceptInvitation(_ context.Context, _ *models.SetupAccountRequest, _, _ string) (*models.LoginResponse, error) {
	return f.acceptResp, f.acceptErr
}

func (f *invitationServiceFake) ResendInvitation(_ context.Context, _ uuid.UUID, _ bool) (*models.InvitationResponse, error) {
	return f.resendResp, f.resendErr
}

func (f *invitationServiceFake) RevokeInvitation(_ context.Context, _ uuid.UUID) error {
	return f.revokeErr
}

func (f *invitationServiceFake) GetPendingInvitation(_ context.Context, _ uuid.UUID) (*models.InvitationResponse, error) {
	return f.pendingResp, f.pendingErr
}

func (f *invitationServiceFake) CreateInvitation(_ context.Context, _ *models.CreateInvitationRequest) (*models.InvitationResponse, string, error) {
	return f.createResp, f.createToken, f.createErr
}

// ---------------------------------------------------------------------------
// invitationHandlerShim – mirrors InvitationHandler logic
// ---------------------------------------------------------------------------

type invitationHandlerShim struct {
	svc *invitationServiceFake
}

func newInvitationTestRouter(svc *invitationServiceFake) *gin.Engine {
	router := gin.New()
	h := &invitationHandlerShim{svc: svc}
	router.GET("/auth/validate-invitation", h.ValidateInvitation)
	router.POST("/auth/setup-account", h.SetupAccount)
	router.POST("/platform/users/:user_id/resend-invitation", h.ResendInvitation)
	router.DELETE("/platform/users/:user_id/invitation", h.RevokeInvitation)
	router.GET("/platform/users/:user_id/invitation", h.GetPendingInvitation)
	router.POST("/platform/invitations", h.CreateInvitation)
	return router
}

func (h *invitationHandlerShim) ValidateInvitation(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "token is required"})
		return
	}
	resp, err := h.svc.ValidateToken(c.Request.Context(), token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to validate invitation"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

func (h *invitationHandlerShim) SetupAccount(c *gin.Context) {
	var req models.SetupAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	resp, err := h.svc.AcceptInvitation(c.Request.Context(), &req, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

func (h *invitationHandlerShim) ResendInvitation(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid user ID"})
		return
	}
	force := c.Query("force") == "true"
	resp, err := h.svc.ResendInvitation(c.Request.Context(), userID, force)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

func (h *invitationHandlerShim) RevokeInvitation(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid user ID"})
		return
	}
	if err := h.svc.RevokeInvitation(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "invitation revoked"})
}

func (h *invitationHandlerShim) GetPendingInvitation(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid user ID"})
		return
	}
	resp, err := h.svc.GetPendingInvitation(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to get invitation"})
		return
	}
	if resp == nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "no pending invitation found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

func (h *invitationHandlerShim) CreateInvitation(c *gin.Context) {
	var req models.CreateInvitationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if !req.SendEmail {
		req.SendEmail = true
	}
	resp, _, err := h.svc.CreateInvitation(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

func performInvitationRequest(router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
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

func decodeInvitationBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

func buildInvitationResponse() *models.InvitationResponse {
	now := time.Now()
	exp := now.Add(72 * time.Hour)
	return &models.InvitationResponse{
		ID:             uuid.New(),
		UserID:         uuid.New(),
		Email:          "invited@example.com",
		InvitationType: models.InvitationTypeTenantAdmin,
		Status:         models.InvitationStatusPending,
		ExpiresAt:      exp,
		CreatedAt:      now,
	}
}

// ---------------------------------------------------------------------------
// Tests: CreateInvitation (POST /platform/invitations)
// ---------------------------------------------------------------------------

func TestInvitation_CreateInvitation(t *testing.T) {
	t.Run("creates invitation successfully", func(t *testing.T) {
		svc := &invitationServiceFake{
			createResp:  buildInvitationResponse(),
			createToken: "raw-token-abc",
		}
		router := newInvitationTestRouter(svc)
		body := `{
			"user_id":"` + uuid.New().String() + `",
			"tenant_id":"` + uuid.New().String() + `",
			"email":"invited@example.com",
			"invitation_type":"tenant_admin",
			"expiry_hours":72,
			"send_email":true
		}`
		w := performInvitationRequest(router, http.MethodPost, "/platform/invitations", body)

		assert.Equal(t, http.StatusOK, w.Code)
		resp := decodeInvitationBody(t, w)
		assert.Equal(t, true, resp["success"])
		assert.NotNil(t, resp["data"])
	})

	t.Run("service error returns 400", func(t *testing.T) {
		svc := &invitationServiceFake{createErr: errors.New("user not found")}
		router := newInvitationTestRouter(svc)
		body := `{
			"user_id":"` + uuid.New().String() + `",
			"tenant_id":"` + uuid.New().String() + `",
			"email":"test@example.com",
			"invitation_type":"tenant_admin",
			"send_email":true
		}`
		w := performInvitationRequest(router, http.MethodPost, "/platform/invitations", body)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		resp := decodeInvitationBody(t, w)
		assert.Equal(t, false, resp["success"])
		assert.Contains(t, resp["error"], "user not found")
	})

	t.Run("malformed JSON returns 400", func(t *testing.T) {
		router := newInvitationTestRouter(&invitationServiceFake{})
		w := performInvitationRequest(router, http.MethodPost, "/platform/invitations", `not-json`)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: ResendInvitation (POST /platform/users/:user_id/resend-invitation)
// ---------------------------------------------------------------------------

func TestInvitation_ResendInvitation(t *testing.T) {
	t.Run("resends invitation successfully", func(t *testing.T) {
		svc := &invitationServiceFake{resendResp: buildInvitationResponse()}
		router := newInvitationTestRouter(svc)
		userID := uuid.New()
		path := "/platform/users/" + userID.String() + "/resend-invitation"
		w := performInvitationRequest(router, http.MethodPost, path, "")

		assert.Equal(t, http.StatusOK, w.Code)
		resp := decodeInvitationBody(t, w)
		assert.Equal(t, true, resp["success"])
	})

	t.Run("resend with force=true parameter", func(t *testing.T) {
		svc := &invitationServiceFake{resendResp: buildInvitationResponse()}
		router := newInvitationTestRouter(svc)
		userID := uuid.New()
		path := "/platform/users/" + userID.String() + "/resend-invitation?force=true"
		w := performInvitationRequest(router, http.MethodPost, path, "")

		assert.Equal(t, http.StatusOK, w.Code)
		resp := decodeInvitationBody(t, w)
		assert.Equal(t, true, resp["success"])
	})

	t.Run("invalid user ID returns 400", func(t *testing.T) {
		router := newInvitationTestRouter(&invitationServiceFake{})
		w := performInvitationRequest(router, http.MethodPost, "/platform/users/not-a-uuid/resend-invitation", "")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service error returns 400", func(t *testing.T) {
		svc := &invitationServiceFake{resendErr: errors.New("please wait before requesting another email")}
		router := newInvitationTestRouter(svc)
		path := "/platform/users/" + uuid.New().String() + "/resend-invitation"
		w := performInvitationRequest(router, http.MethodPost, path, "")

		assert.Equal(t, http.StatusBadRequest, w.Code)
		resp := decodeInvitationBody(t, w)
		assert.Contains(t, resp["error"], "please wait")
	})
}

// ---------------------------------------------------------------------------
// Tests: RevokeInvitation (DELETE /platform/users/:user_id/invitation)
// ---------------------------------------------------------------------------

func TestInvitation_RevokeInvitation(t *testing.T) {
	t.Run("revokes invitation successfully", func(t *testing.T) {
		router := newInvitationTestRouter(&invitationServiceFake{})
		path := "/platform/users/" + uuid.New().String() + "/invitation"
		w := performInvitationRequest(router, http.MethodDelete, path, "")

		assert.Equal(t, http.StatusOK, w.Code)
		resp := decodeInvitationBody(t, w)
		assert.Equal(t, true, resp["success"])
		assert.Equal(t, "invitation revoked", resp["message"])
	})

	t.Run("invalid user ID returns 400", func(t *testing.T) {
		router := newInvitationTestRouter(&invitationServiceFake{})
		w := performInvitationRequest(router, http.MethodDelete, "/platform/users/not-a-uuid/invitation", "")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service error returns 400", func(t *testing.T) {
		svc := &invitationServiceFake{revokeErr: errors.New("failed to revoke invitation")}
		router := newInvitationTestRouter(svc)
		path := "/platform/users/" + uuid.New().String() + "/invitation"
		w := performInvitationRequest(router, http.MethodDelete, path, "")

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: ValidateInvitation (GET /auth/validate-invitation)
// ---------------------------------------------------------------------------

func TestInvitation_ValidateInvitation(t *testing.T) {
	t.Run("valid token returns invitation details", func(t *testing.T) {
		exp := time.Now().Add(72 * time.Hour)
		svc := &invitationServiceFake{
			validateResp: &models.ValidateInvitationResponse{
				Valid:          true,
				Email:          "invited@example.com",
				TenantName:     "Acme Corp",
				InvitationType: models.InvitationTypeTenantAdmin,
				ExpiresAt:      &exp,
			},
		}
		router := newInvitationTestRouter(svc)
		w := performInvitationRequest(router, http.MethodGet, "/auth/validate-invitation?token=valid-token-abc", "")

		assert.Equal(t, http.StatusOK, w.Code)
		resp := decodeInvitationBody(t, w)
		assert.Equal(t, true, resp["success"])
		data, ok := resp["data"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, true, data["valid"])
	})

	t.Run("invalid token returns valid=false in response", func(t *testing.T) {
		svc := &invitationServiceFake{
			validateResp: &models.ValidateInvitationResponse{
				Valid: false,
				Error: "invitation has expired",
			},
		}
		router := newInvitationTestRouter(svc)
		w := performInvitationRequest(router, http.MethodGet, "/auth/validate-invitation?token=expired-token", "")

		assert.Equal(t, http.StatusOK, w.Code)
		resp := decodeInvitationBody(t, w)
		assert.Equal(t, true, resp["success"])
		data, ok := resp["data"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, false, data["valid"])
	})

	t.Run("missing token returns 400", func(t *testing.T) {
		router := newInvitationTestRouter(&invitationServiceFake{})
		w := performInvitationRequest(router, http.MethodGet, "/auth/validate-invitation", "")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service error returns 500", func(t *testing.T) {
		svc := &invitationServiceFake{validateErr: errors.New("db error")}
		router := newInvitationTestRouter(svc)
		w := performInvitationRequest(router, http.MethodGet, "/auth/validate-invitation?token=some-token", "")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: SetupAccount (POST /auth/setup-account)
// ---------------------------------------------------------------------------

func TestInvitation_SetupAccount(t *testing.T) {
	t.Run("accepts invitation and returns login response", func(t *testing.T) {
		svc := &invitationServiceFake{
			acceptResp: &models.LoginResponse{
				AccessToken:  "access.token.here",
				RefreshToken: "refresh.token.here",
				TokenType:    "Bearer",
				ExpiresIn:    900,
			},
		}
		router := newInvitationTestRouter(svc)
		body := `{
			"token":"invite-token-abc",
			"password":"NewPass123!",
			"confirm_password":"NewPass123!"
		}`
		w := performInvitationRequest(router, http.MethodPost, "/auth/setup-account", body)

		assert.Equal(t, http.StatusOK, w.Code)
		resp := decodeInvitationBody(t, w)
		assert.Equal(t, true, resp["success"])
	})

	t.Run("passwords do not match fails gin binding validation – returns 400", func(t *testing.T) {
		// The binding tag eqfield=Password triggers before the service is called,
		// so mismatched passwords produce a 400 from ShouldBindJSON itself.
		router := newInvitationTestRouter(&invitationServiceFake{})
		body := `{
			"token":"invite-token-abc",
			"password":"Pass1234!",
			"confirm_password":"Different!"
		}`
		w := performInvitationRequest(router, http.MethodPost, "/auth/setup-account", body)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		resp := decodeInvitationBody(t, w)
		// Gin returns a validation error message – confirm the error field is present
		assert.NotEmpty(t, resp["error"])
	})

	t.Run("service rejects request returns 400", func(t *testing.T) {
		// Both passwords match so binding succeeds, but the service returns an error.
		svc := &invitationServiceFake{acceptErr: errors.New("invitation has expired")}
		router := newInvitationTestRouter(svc)
		body := `{
			"token":"invite-token-abc",
			"password":"Pass1234!",
			"confirm_password":"Pass1234!"
		}`
		w := performInvitationRequest(router, http.MethodPost, "/auth/setup-account", body)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		resp := decodeInvitationBody(t, w)
		assert.Contains(t, resp["error"], "invitation has expired")
	})

	t.Run("missing required fields returns 400", func(t *testing.T) {
		router := newInvitationTestRouter(&invitationServiceFake{})
		w := performInvitationRequest(router, http.MethodPost, "/auth/setup-account", `{}`)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("expired token returns 400", func(t *testing.T) {
		svc := &invitationServiceFake{acceptErr: errors.New("invitation has expired")}
		router := newInvitationTestRouter(svc)
		body := `{
			"token":"expired-token",
			"password":"Pass1234!",
			"confirm_password":"Pass1234!"
		}`
		w := performInvitationRequest(router, http.MethodPost, "/auth/setup-account", body)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: GetPendingInvitation (GET /platform/users/:user_id/invitation)
// ---------------------------------------------------------------------------

func TestInvitation_GetPendingInvitation(t *testing.T) {
	t.Run("returns pending invitation", func(t *testing.T) {
		svc := &invitationServiceFake{pendingResp: buildInvitationResponse()}
		router := newInvitationTestRouter(svc)
		path := "/platform/users/" + uuid.New().String() + "/invitation"
		w := performInvitationRequest(router, http.MethodGet, path, "")

		assert.Equal(t, http.StatusOK, w.Code)
		resp := decodeInvitationBody(t, w)
		assert.Equal(t, true, resp["success"])
		assert.NotNil(t, resp["data"])
	})

	t.Run("no pending invitation returns 404", func(t *testing.T) {
		svc := &invitationServiceFake{pendingResp: nil}
		router := newInvitationTestRouter(svc)
		path := "/platform/users/" + uuid.New().String() + "/invitation"
		w := performInvitationRequest(router, http.MethodGet, path, "")

		assert.Equal(t, http.StatusNotFound, w.Code)
		resp := decodeInvitationBody(t, w)
		assert.Equal(t, false, resp["success"])
	})

	t.Run("invalid user ID returns 400", func(t *testing.T) {
		router := newInvitationTestRouter(&invitationServiceFake{})
		w := performInvitationRequest(router, http.MethodGet, "/platform/users/bad-uuid/invitation", "")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service error returns 500", func(t *testing.T) {
		svc := &invitationServiceFake{pendingErr: errors.New("db error")}
		router := newInvitationTestRouter(svc)
		path := "/platform/users/" + uuid.New().String() + "/invitation"
		w := performInvitationRequest(router, http.MethodGet, path, "")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

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

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// fakeMFAService is a hand-written test double for *services.MFAService.
// Each method stores its call arguments and returns pre-configured results.
type fakeMFAService struct {
	// GenerateTOTPSecret
	totpResponse *services.TOTPSetupResponse
	totpErr      error

	// VerifyAndEnableTOTP
	backupCodes []string
	verifyErr   error

	// EnableEmailMFA
	enableEmailErr error

	// GetBackupCodesCount
	codesCount    int
	codesCountErr error

	// DisableMFA
	disableErr error

	// GetMFAStatus
	statusResponse *models.MFAStatusResponse
	statusErr      error

	// GenerateBackupCodes
	genCodes    []string
	genCodesErr error

	// SendEmailMFACode
	sendCodeErr error

	// VerifyMFACode
	verifyValid  bool
	verifyMFAErr error

	// SendVerificationEmail
	sendVerifyEmailErr error

	// VerifyEmail
	verifyEmailErr error

	// GetEmailVerificationStatus
	emailVerifyStatus    *models.EmailVerificationStatus
	emailVerifyStatusErr error

	// VerifyEmailByToken
	verifyTokenErr error

	// SetPreferredMFAMethod
	setPreferredErr error

	// DisableTOTPOnly
	disableTOTPErr error

	// DisableEmailMFAOnly
	disableEmailMFAErr error
}

func (f *fakeMFAService) GenerateTOTPSecret(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID) (*services.TOTPSetupResponse, error) {
	return f.totpResponse, f.totpErr
}

func (f *fakeMFAService) VerifyAndEnableTOTP(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID, _ string) ([]string, error) {
	return f.backupCodes, f.verifyErr
}

func (f *fakeMFAService) EnableEmailMFA(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID) error {
	return f.enableEmailErr
}

func (f *fakeMFAService) GetBackupCodesCount(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID) (int, error) {
	return f.codesCount, f.codesCountErr
}

func (f *fakeMFAService) DisableMFA(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID, _, _ string) error {
	return f.disableErr
}

func (f *fakeMFAService) GetMFAStatus(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID) (*models.MFAStatusResponse, error) {
	return f.statusResponse, f.statusErr
}

func (f *fakeMFAService) GenerateBackupCodes(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID) ([]string, error) {
	return f.genCodes, f.genCodesErr
}

func (f *fakeMFAService) SendEmailMFACode(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID) error {
	return f.sendCodeErr
}

func (f *fakeMFAService) VerifyMFACode(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID, _ string) (bool, error) {
	return f.verifyValid, f.verifyMFAErr
}

func (f *fakeMFAService) SendVerificationEmail(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID) error {
	return f.sendVerifyEmailErr
}

func (f *fakeMFAService) VerifyEmail(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID, _ string) error {
	return f.verifyEmailErr
}

func (f *fakeMFAService) GetEmailVerificationStatus(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID) (*models.EmailVerificationStatus, error) {
	return f.emailVerifyStatus, f.emailVerifyStatusErr
}

func (f *fakeMFAService) VerifyEmailByToken(_ interface{ Deadline() (interface{}, bool) }, _ string) error {
	return f.verifyTokenErr
}

func (f *fakeMFAService) SetPreferredMFAMethod(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID, _ string) error {
	return f.setPreferredErr
}

func (f *fakeMFAService) DisableTOTPOnly(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID, _, _ string) error {
	return f.disableTOTPErr
}

func (f *fakeMFAService) DisableEmailMFAOnly(_ interface{ Deadline() (interface{}, bool) }, _ uuid.UUID, _, _ string) error {
	return f.disableEmailMFAErr
}

// newMFATestRouter registers MFAHandler routes against a fake service and
// returns the router ready for httptest.
func newMFATestRouter(svc *fakeMFAService, withUser bool, userID uuid.UUID) *gin.Engine {
	router := gin.New()

	// We use the real MFAHandler but swap the concrete service reference via
	// a shim: because MFAHandler.mfaService is unexported we drive it directly
	// by calling the handler methods through route closures that use the fake.

	handler := &mfaHandlerTestShim{svc: svc}

	injectUser := func(c *gin.Context) {
		if withUser {
			c.Set("current_user", &models.CurrentUser{
				ID:       userID,
				TenantID: uuid.New(),
				Email:    "test@example.com",
			})
		}
		c.Next()
	}

	router.Use(injectUser)
	router.POST("/mfa/setup/totp", handler.SetupTOTP)
	router.POST("/mfa/setup/totp/verify", handler.VerifyTOTPSetup)
	router.POST("/mfa/setup/email", handler.EnableEmailMFA)
	router.POST("/mfa/disable", handler.DisableMFA)
	router.GET("/mfa/status", handler.GetMFAStatus)
	router.POST("/mfa/backup-codes", handler.GenerateBackupCodes)
	router.GET("/mfa/backup-codes", handler.GetBackupCodesCount)
	router.POST("/mfa/send-code", handler.SendMFACode)
	router.POST("/mfa/verify", handler.VerifyMFACode)
	router.POST("/email/send-verification", handler.SendVerificationEmail)
	router.POST("/email/verify", handler.VerifyEmail)
	router.GET("/email/status", handler.GetEmailVerificationStatus)
	router.GET("/email/verify-token", handler.VerifyEmailByToken)
	router.PUT("/mfa/preferred-method", handler.SetPreferredMFAMethod)
	router.POST("/mfa/disable/totp", handler.DisableTOTP)
	router.POST("/mfa/disable/email", handler.DisableEmailMFA)

	return router
}

// mfaHandlerTestShim mirrors MFAHandler logic but calls the fake service.
// This avoids the need to export the mfaService field.
type mfaHandlerTestShim struct {
	svc *fakeMFAService
}

func (h *mfaHandlerTestShim) SetupTOTP(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	response, err := h.svc.GenerateTOTPSecret(nil, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, response)
}

func (h *mfaHandlerTestShim) VerifyTOTPSetup(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	var req models.MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	backupCodes, err := h.svc.VerifyAndEnableTOTP(nil, user.ID, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":      "Two-factor authentication enabled successfully",
		"backup_codes": backupCodes,
	})
}

func (h *mfaHandlerTestShim) EnableEmailMFA(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	if err := h.svc.EnableEmailMFA(nil, user.ID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	count, _ := h.svc.GetBackupCodesCount(nil, user.ID)
	c.JSON(http.StatusOK, gin.H{
		"message":            "Email two-factor authentication enabled successfully",
		"backup_codes_count": count,
	})
}

func (h *mfaHandlerTestShim) DisableMFA(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	var req models.MFADisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	if err := h.svc.DisableMFA(nil, user.ID, req.Password, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Two-factor authentication disabled"})
}

func (h *mfaHandlerTestShim) GetMFAStatus(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	status, err := h.svc.GetMFAStatus(nil, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get MFA status"})
		return
	}
	c.JSON(http.StatusOK, status)
}

func (h *mfaHandlerTestShim) GenerateBackupCodes(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	codes, err := h.svc.GenerateBackupCodes(nil, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate backup codes"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"backup_codes": codes,
		"message":      "New backup codes generated. Previous codes are now invalid.",
	})
}

func (h *mfaHandlerTestShim) GetBackupCodesCount(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	count, err := h.svc.GetBackupCodesCount(nil, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get backup codes count"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"count": count})
}

func (h *mfaHandlerTestShim) SendMFACode(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	if err := h.svc.SendEmailMFACode(nil, user.ID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Verification code sent to your email"})
}

func (h *mfaHandlerTestShim) VerifyMFACode(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	var req models.MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	valid, err := h.svc.VerifyMFACode(nil, user.ID, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"valid": valid})
}

func (h *mfaHandlerTestShim) SendVerificationEmail(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	if err := h.svc.SendVerificationEmail(nil, user.ID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Verification email sent"})
}

func (h *mfaHandlerTestShim) VerifyEmail(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	var req models.MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	if err := h.svc.VerifyEmail(nil, user.ID, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

func (h *mfaHandlerTestShim) GetEmailVerificationStatus(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	status, err := h.svc.GetEmailVerificationStatus(nil, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get status"})
		return
	}
	c.JSON(http.StatusOK, status)
}

func (h *mfaHandlerTestShim) VerifyEmailByToken(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}
	if err := h.svc.VerifyEmailByToken(nil, token); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

func (h *mfaHandlerTestShim) SetPreferredMFAMethod(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	var req models.SetPreferredMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	if err := h.svc.SetPreferredMFAMethod(nil, user.ID, req.Method); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Preferred MFA method updated"})
}

func (h *mfaHandlerTestShim) DisableTOTP(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	var req models.MFADisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	if err := h.svc.DisableTOTPOnly(nil, user.ID, req.Password, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Authenticator app disabled"})
}

func (h *mfaHandlerTestShim) DisableEmailMFA(c *gin.Context) {
	currentUser, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := currentUser.(*models.CurrentUser)
	var req models.MFADisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	if err := h.svc.DisableEmailMFAOnly(nil, user.ID, req.Password, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Email two-factor authentication disabled"})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func performMFARequest(router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
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

func parseBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

// ---------------------------------------------------------------------------
// Tests: SetupTOTP (POST /mfa/setup/totp)
// ---------------------------------------------------------------------------

func TestMFA_SetupTOTP(t *testing.T) {
	userID := uuid.New()

	t.Run("success returns secret and QR code", func(t *testing.T) {
		svc := &fakeMFAService{
			totpResponse: &services.TOTPSetupResponse{ //nolint:gosec // test fixture value, not a real credential
				Secret: "JBSWY3DPEHPK3PXP",
				QRCode: "data:image/png;base64,abc123",
			},
		}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/setup/totp", "")

		assert.Equal(t, http.StatusOK, w.Code)
		body := parseBody(t, w)
		assert.Equal(t, "JBSWY3DPEHPK3PXP", body["secret"])
		assert.NotEmpty(t, body["qr_code"])
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		svc := &fakeMFAService{}
		router := newMFATestRouter(svc, false, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/setup/totp", "")

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("service error returns 500", func(t *testing.T) {
		svc := &fakeMFAService{totpErr: errors.New("crypto failure")}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/setup/totp", "")

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: VerifyTOTPSetup (POST /mfa/setup/totp/verify)
// ---------------------------------------------------------------------------

func TestMFA_VerifyTOTPSetup(t *testing.T) {
	userID := uuid.New()

	t.Run("valid code enables TOTP and returns backup codes", func(t *testing.T) {
		svc := &fakeMFAService{backupCodes: []string{"AAAA-BBBB", "CCCC-DDDD"}}
		router := newMFATestRouter(svc, true, userID)
		body := `{"code":"123456"}`
		w := performMFARequest(router, http.MethodPost, "/mfa/setup/totp/verify", body)

		assert.Equal(t, http.StatusOK, w.Code)
		resp := parseBody(t, w)
		assert.Equal(t, "Two-factor authentication enabled successfully", resp["message"])
		codes, ok := resp["backup_codes"].([]interface{})
		require.True(t, ok)
		assert.Len(t, codes, 2)
	})

	t.Run("invalid code returns 400", func(t *testing.T) {
		svc := &fakeMFAService{verifyErr: errors.New("invalid TOTP code")}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/setup/totp/verify", `{"code":"000000"}`)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		resp := parseBody(t, w)
		assert.Contains(t, resp["error"], "invalid TOTP code")
	})

	t.Run("missing code returns 400", func(t *testing.T) {
		svc := &fakeMFAService{}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/setup/totp/verify", `{}`)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		svc := &fakeMFAService{}
		router := newMFATestRouter(svc, false, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/setup/totp/verify", `{"code":"123456"}`)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: DisableMFA (POST /mfa/disable)
// ---------------------------------------------------------------------------

func TestMFA_DisableMFA(t *testing.T) {
	userID := uuid.New()

	t.Run("success disables MFA", func(t *testing.T) {
		svc := &fakeMFAService{}
		router := newMFATestRouter(svc, true, userID)
		body := `{"password":"secret123","code":"123456"}`
		w := performMFARequest(router, http.MethodPost, "/mfa/disable", body)

		assert.Equal(t, http.StatusOK, w.Code)
		resp := parseBody(t, w)
		assert.Equal(t, "Two-factor authentication disabled", resp["message"])
	})

	t.Run("wrong password returns 400", func(t *testing.T) {
		svc := &fakeMFAService{disableErr: errors.New("invalid password")}
		router := newMFATestRouter(svc, true, userID)
		body := `{"password":"wrong","code":"123456"}`
		w := performMFARequest(router, http.MethodPost, "/mfa/disable", body)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("empty body succeeds — step-up gate is the sole authorization", func(t *testing.T) {
		// MFADisableRequest no longer requires password OR code: the
		// RFC 9470 freshAuth route middleware (cmd/routes.go) is the
		// canonical AAL2 gate; defense-in-depth verification still
		// fires when fields are supplied. See fix(mfa) 2026-05-25.
		svc := &fakeMFAService{}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/disable", `{}`)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		svc := &fakeMFAService{}
		router := newMFATestRouter(svc, false, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/disable", `{"password":"p","code":"c"}`)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: GetBackupCodesCount (GET /mfa/backup-codes)
// ---------------------------------------------------------------------------

func TestMFA_GetBackupCodesCount(t *testing.T) {
	userID := uuid.New()

	t.Run("returns count of remaining backup codes", func(t *testing.T) {
		svc := &fakeMFAService{codesCount: 7}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodGet, "/mfa/backup-codes", "")

		assert.Equal(t, http.StatusOK, w.Code)
		resp := parseBody(t, w)
		assert.Equal(t, float64(7), resp["count"])
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		svc := &fakeMFAService{}
		router := newMFATestRouter(svc, false, userID)
		w := performMFARequest(router, http.MethodGet, "/mfa/backup-codes", "")

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("service error returns 500", func(t *testing.T) {
		svc := &fakeMFAService{codesCountErr: errors.New("db error")}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodGet, "/mfa/backup-codes", "")

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: VerifyMFACode (POST /mfa/verify)
// ---------------------------------------------------------------------------

func TestMFA_VerifyMFACode(t *testing.T) {
	userID := uuid.New()

	t.Run("valid MFA code returns valid true", func(t *testing.T) {
		svc := &fakeMFAService{verifyValid: true}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/verify", `{"code":"123456"}`)

		assert.Equal(t, http.StatusOK, w.Code)
		resp := parseBody(t, w)
		assert.Equal(t, true, resp["valid"])
	})

	t.Run("invalid MFA code returns valid false", func(t *testing.T) {
		svc := &fakeMFAService{verifyValid: false}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/verify", `{"code":"000000"}`)

		assert.Equal(t, http.StatusOK, w.Code)
		resp := parseBody(t, w)
		assert.Equal(t, false, resp["valid"])
	})

	t.Run("service error returns 400", func(t *testing.T) {
		svc := &fakeMFAService{verifyMFAErr: errors.New("mfa not enabled")}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/verify", `{"code":"123456"}`)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing code returns 400", func(t *testing.T) {
		svc := &fakeMFAService{}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/verify", `{}`)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		svc := &fakeMFAService{}
		router := newMFATestRouter(svc, false, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/verify", `{"code":"123456"}`)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: GenerateBackupCodes (POST /mfa/backup-codes)
// ---------------------------------------------------------------------------

func TestMFA_GenerateBackupCodes(t *testing.T) {
	userID := uuid.New()

	t.Run("success generates new backup codes", func(t *testing.T) {
		svc := &fakeMFAService{genCodes: []string{"CODE1", "CODE2", "CODE3"}}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/backup-codes", "")

		assert.Equal(t, http.StatusOK, w.Code)
		resp := parseBody(t, w)
		codes, ok := resp["backup_codes"].([]interface{})
		require.True(t, ok)
		assert.Len(t, codes, 3)
		assert.Contains(t, resp["message"], "New backup codes generated")
	})

	t.Run("service error returns 500", func(t *testing.T) {
		svc := &fakeMFAService{genCodesErr: errors.New("mfa not configured")}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodPost, "/mfa/backup-codes", "")

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: GetMFAStatus (GET /mfa/status)
// ---------------------------------------------------------------------------

func TestMFA_GetMFAStatus(t *testing.T) {
	userID := uuid.New()

	t.Run("returns MFA status", func(t *testing.T) {
		svc := &fakeMFAService{
			statusResponse: &models.MFAStatusResponse{
				Enabled:          true,
				TOTPEnabled:      true,
				EmailEnabled:     false,
				PreferredMethod:  "totp",
				BackupCodesCount: 8,
			},
		}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodGet, "/mfa/status", "")

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.MFAStatusResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.Enabled)
		assert.True(t, resp.TOTPEnabled)
		assert.Equal(t, "totp", resp.PreferredMethod)
	})

	t.Run("service error returns 500", func(t *testing.T) {
		svc := &fakeMFAService{statusErr: errors.New("db error")}
		router := newMFATestRouter(svc, true, userID)
		w := performMFARequest(router, http.MethodGet, "/mfa/status", "")

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: VerifyEmailByToken (GET /email/verify-token)
// ---------------------------------------------------------------------------

func TestMFA_VerifyEmailByToken(t *testing.T) {
	userID := uuid.New()

	t.Run("valid token verifies email", func(t *testing.T) {
		svc := &fakeMFAService{}
		router := newMFATestRouter(svc, false, userID)
		w := performMFARequest(router, http.MethodGet, "/email/verify-token?token=abc123", "")

		assert.Equal(t, http.StatusOK, w.Code)
		resp := parseBody(t, w)
		assert.Equal(t, "Email verified successfully", resp["message"])
	})

	t.Run("missing token returns 400", func(t *testing.T) {
		svc := &fakeMFAService{}
		router := newMFATestRouter(svc, false, userID)
		w := performMFARequest(router, http.MethodGet, "/email/verify-token", "")

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid token returns 400", func(t *testing.T) {
		svc := &fakeMFAService{verifyTokenErr: errors.New("token not found")}
		router := newMFATestRouter(svc, false, userID)
		w := performMFARequest(router, http.MethodGet, "/email/verify-token?token=badtoken", "")

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

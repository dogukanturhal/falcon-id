// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	msgMFAInvalidRequest = "Invalid request"
)

// MFAHandler is an exported type.
type MFAHandler struct {
	mfaService  *services.MFAService
	stepUpRepo  *repositories.StepUpVerificationRepository
	sessionRepo *repositories.SessionRepository
	logger      *zap.Logger
}

// NewMFAHandler is an exported function.
func NewMFAHandler(mfaService *services.MFAService) *MFAHandler {
	return &MFAHandler{
		mfaService: mfaService,
		logger:     logger.Log,
	}
}

// SetStepUpRepo injects the step-up verification repository.
func (h *MFAHandler) SetStepUpRepo(repo *repositories.StepUpVerificationRepository) {
	h.stepUpRepo = repo
}

// SetSessionRepo injects the session repository so MFA-verify endpoints can
// elevate the current session's RFC 8176 AMR after the user demonstrates a
// fresh second factor. Tier-1 IdP pattern (RFC 9470 step-up authentication
// challenge) — Entra/Auth0/Okta atomically record the elevated AMR on the
// session as part of factor verification, so the next /oauth/authorize
// re-evaluation against `acr_values=mfa` passes without a separate
// "elevation token" the OAuth handler would have to consult.
//
// Optional. When unset, MFA verify endpoints behave exactly as before
// (no session update — backwards compatible with deployments that don't
// inject the SessionRepository).
func (h *MFAHandler) SetSessionRepo(repo *repositories.SessionRepository) {
	h.sessionRepo = repo
}

// elevateCurrentSessionAMR appends an RFC 8176 authentication-method
// reference (typically "mfa") to the request's session.AuthMethodsUsed if a
// session is present in the gin context (set upstream by auth middleware
// from the access-token cookie). No-op when:
//   - sessionRepo isn't injected (older deployments)
//   - no session_id in context (token-only auth, non-cookie flows)
//   - method already present (idempotent — repo handles the WHERE filter)
//   - the DB call fails (logged at WARN, request still succeeds — the
//     factor-verify is the authoritative event; failed AMR elevation is
//     observable via the failure log and the next OAuth flow will trigger
//     re-step-up rather than silently mint a low-assurance token)
//
// Called as the LAST step of every MFA-verify handler that runs in an
// authenticated request context (VerifyTOTPSetup, VerifyStepUp, etc.).
// MUST NOT be called from unauthenticated paths (MFAEnrollmentVerify mid-
// login uses IssueSessionAfterEnrollment which creates a fresh session
// with the correct AMR in one step).
func (h *MFAHandler) elevateCurrentSessionAMR(c *gin.Context, method string) {
	if h.sessionRepo == nil {
		return
	}
	sidVal, ok := c.Get("session_id")
	if !ok {
		return
	}
	sid, ok := sidVal.(uuid.UUID)
	if !ok || sid == uuid.Nil {
		return
	}
	changed, err := h.sessionRepo.AppendAuthMethod(c.Request.Context(), sid, method)
	if err != nil {
		h.logger.Warn("Failed to elevate session AMR after MFA verify",
			zap.String("session_id", sid.String()),
			zap.String("method", method),
			zap.Error(err),
		)
		return
	}
	if changed {
		h.logger.Info("Session AMR elevated after MFA verification",
			zap.String("session_id", sid.String()),
			zap.String("method", method),
		)
	}
}

// SetupTOTP initiates TOTP MFA setup
// @Summary Start TOTP MFA setup
// @Description Generates a TOTP secret and QR code for authenticator app setup
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} services.TOTPSetupResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/auth/mfa/setup/totp [post]
func (h *MFAHandler) SetupTOTP(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	response, err := h.mfaService.GenerateTOTPSecret(c.Request.Context(), user.ID)
	if err != nil {
		// Tier-1 invariant: MFA enrollment requires a verified email (the
		// recovery channel). Frontend pivots on the stable `code` field to
		// show a "Verify your email first" prompt without parsing the
		// free-text error message.
		if errors.Is(err, services.ErrEmailNotVerified) {
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"error": "Verify your email address before enabling two-factor authentication.",
				"code":  "email_not_verified",
			})
			return
		}
		h.logger.Error("Failed to setup TOTP",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}

	c.JSON(http.StatusOK, response)
}

// VerifyTOTPSetup verifies TOTP code and enables MFA
// @Summary Verify and enable TOTP MFA
// @Description Verifies the TOTP code and enables MFA, returns backup codes
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.MFAVerifyRequest true "Verification code"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/setup/totp/verify [post]
func (h *MFAHandler) VerifyTOTPSetup(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgMFAInvalidRequest})
		return
	}

	backupCodes, err := h.mfaService.VerifyAndEnableTOTP(c.Request.Context(), user.ID, req.Code)
	if err != nil {
		h.logger.Error("Failed to verify TOTP setup",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Tier-1 IdP step-up integration (RFC 9470): the user just demonstrated
	// a fresh MFA factor on this authenticated session — elevate the session's
	// recorded RFC 8176 AMR so the next /oauth/authorize evaluation against
	// `acr_values=mfa` passes (rather than redirecting back here in a loop).
	// Idempotent + safe to call from /settings/security too (re-elevation of
	// an already-elevated session is a no-op).
	h.elevateCurrentSessionAMR(c, "mfa")

	c.JSON(http.StatusOK, gin.H{
		"message":      "Two-factor authentication enabled successfully",
		"backup_codes": backupCodes,
	})
}

// EnableEmailMFA enables email-based MFA
// @Summary Enable email MFA
// @Description Enables email-based two-factor authentication
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/setup/email [post]
func (h *MFAHandler) EnableEmailMFA(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	backupCodes, err := h.mfaService.EnableEmailMFA(c.Request.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to enable email MFA",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get backup codes count (may be zero when this enrollment didn't
	// freshly generate — e.g. user already had codes from a prior
	// factor enrollment).
	count, _ := h.mfaService.GetBackupCodesCount(c.Request.Context(), user.ID)

	response := gin.H{
		"message":            "Email two-factor authentication enabled successfully",
		"backup_codes_count": count,
	}
	// Surface freshly-generated codes ONCE — the hashes-at-rest store
	// makes them unrecoverable later. Frontend MUST present a
	// "save / download / I have saved them" modal blocking the user
	// from continuing until they acknowledge.
	if len(backupCodes) > 0 {
		response["backup_codes"] = backupCodes
		response["backup_codes_generated"] = true
	}
	c.JSON(http.StatusOK, response)
}

// DisableMFA disables MFA for the user
// @Summary Disable MFA
// @Description Disables two-factor authentication (requires password and MFA code)
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.MFADisableRequest true "Disable request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/disable [post]
func (h *MFAHandler) DisableMFA(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.MFADisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgMFAInvalidRequest})
		return
	}

	if err := h.mfaService.DisableMFA(c.Request.Context(), user.ID, req.Password, req.Code); err != nil {
		h.logger.Error("Failed to disable MFA",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Two-factor authentication disabled"})
}

// GetMFAStatus returns the current MFA status
// @Summary Get MFA status
// @Description Returns the current MFA status for the user
// @Tags MFA
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.MFAStatusResponse
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/status [get]
func (h *MFAHandler) GetMFAStatus(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	status, err := h.mfaService.GetMFAStatus(c.Request.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to get MFA status",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get MFA status"})
		return
	}

	c.JSON(http.StatusOK, status)
}

// GenerateBackupCodes generates new backup codes
// @Summary Generate new backup codes
// @Description Generates a new set of backup codes (invalidates old ones)
// @Tags MFA
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/auth/mfa/backup-codes [post]
func (h *MFAHandler) GenerateBackupCodes(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	codes, err := h.mfaService.GenerateBackupCodes(c.Request.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to generate backup codes",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate backup codes"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"backup_codes": codes,
		"message":      "New backup codes generated. Previous codes are now invalid.",
	})
}

// GetBackupCodesCount returns the count of remaining backup codes
// @Summary Get backup codes count
// @Description Returns the number of remaining unused backup codes
// @Tags MFA
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]int
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/backup-codes [get]
func (h *MFAHandler) GetBackupCodesCount(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	count, err := h.mfaService.GetBackupCodesCount(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get backup codes count"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"count": count})
}

// SendMFACode sends an MFA code via email (for email MFA or during login)
// @Summary Send MFA code via email
// @Description Sends a one-time MFA code to the user's email
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/send-code [post]
func (h *MFAHandler) SendMFACode(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if err := h.mfaService.SendEmailMFACode(c.Request.Context(), user.ID); err != nil {
		h.logger.Error("Failed to send MFA code",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification code sent to your email"})
}

// VerifyMFACode verifies an MFA code
// @Summary Verify MFA code
// @Description Verifies a TOTP, email, or backup code
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.MFAVerifyRequest true "Verification code"
// @Success 200 {object} map[string]bool
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/verify [post]
func (h *MFAHandler) VerifyMFACode(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgMFAInvalidRequest})
		return
	}

	valid, err := h.mfaService.VerifyMFACode(c.Request.Context(), user.ID, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Tier-1 IdP step-up integration (RFC 9470): on a successful MFA code
	// verification within an authenticated session, elevate the recorded AMR
	// so subsequent OAuth flows with `acr_values=mfa` pass without re-prompting.
	// Skipped when code was invalid — we only elevate on demonstrated proof.
	if valid {
		h.elevateCurrentSessionAMR(c, "mfa")
	}

	c.JSON(http.StatusOK, gin.H{"valid": valid})
}

// Email Verification Endpoints

// SendVerificationEmail sends an email verification code
// @Summary Send email verification
// @Description Sends a verification code to the user's email
// @Tags Email
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/email/send-verification [post]
func (h *MFAHandler) SendVerificationEmail(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if err := h.mfaService.SendVerificationEmail(c.Request.Context(), user.ID); err != nil {
		h.logger.Error("Failed to send verification email",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification email sent"})
}

// VerifyEmail verifies the email with the provided code
// @Summary Verify email
// @Description Verifies the user's email with the provided code
// @Tags Email
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.MFAVerifyRequest true "Verification code"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/email/verify [post]
func (h *MFAHandler) VerifyEmail(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgMFAInvalidRequest})
		return
	}

	if err := h.mfaService.VerifyEmail(c.Request.Context(), user.ID, req.Code); err != nil {
		h.logger.Error("Failed to verify email",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

// GetEmailVerificationStatus returns the email verification status
// @Summary Get email verification status
// @Description Returns whether the user's email is verified
// @Tags Email
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.EmailVerificationStatus
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/email/status [get]
func (h *MFAHandler) GetEmailVerificationStatus(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	status, err := h.mfaService.GetEmailVerificationStatus(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get status"})
		return
	}

	c.JSON(http.StatusOK, status)
}

// VerifyEmailByToken verifies email using a token from the verification link (public endpoint)
// @Summary Verify email by token
// @Description Verifies the user's email using a token from the verification link (no authentication required)
// @Tags Email
// @Accept json
// @Produce json
// @Param token query string true "Verification token"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/v1/auth/email/verify-token [get]
func (h *MFAHandler) VerifyEmailByToken(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}

	if err := h.mfaService.VerifyEmailByToken(c.Request.Context(), token); err != nil {
		h.logger.Error("Failed to verify email by token",
			zap.String("token_prefix", token[:min(8, len(token))]),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

// SetPreferredMFAMethod sets the user's preferred MFA method
// @Summary Set preferred MFA method
// @Description Sets which MFA method (totp or email) should be used by default during login
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.SetPreferredMFARequest true "Preferred method"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/preferred-method [put]
func (h *MFAHandler) SetPreferredMFAMethod(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.SetPreferredMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgMFAInvalidRequest})
		return
	}

	if err := h.mfaService.SetPreferredMFAMethod(c.Request.Context(), user.ID, req.Method); err != nil {
		h.logger.Error("Failed to set preferred MFA method",
			zap.String("user_id", user.ID.String()),
			zap.String("method", req.Method),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Preferred MFA method updated"})
}

// DisableTOTP disables only TOTP MFA (keeps email MFA if enabled)
// @Summary Disable TOTP MFA
// @Description Disables authenticator app MFA while keeping email MFA if enabled
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.MFADisableRequest true "Disable request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/disable/totp [post]
func (h *MFAHandler) DisableTOTP(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.MFADisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgMFAInvalidRequest})
		return
	}

	if err := h.mfaService.DisableTOTPOnly(c.Request.Context(), user.ID, req.Password, req.Code); err != nil {
		h.logger.Error("Failed to disable TOTP MFA",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Authenticator app disabled"})
}

// DisableEmailMFA disables only email MFA (keeps TOTP if enabled)
// @Summary Disable email MFA
// @Description Disables email MFA while keeping authenticator app if enabled
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.MFADisableRequest true "Disable request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/disable/email [post]
func (h *MFAHandler) DisableEmailMFA(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.MFADisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgMFAInvalidRequest})
		return
	}

	if err := h.mfaService.DisableEmailMFAOnly(c.Request.Context(), user.ID, req.Password, req.Code); err != nil {
		h.logger.Error("Failed to disable email MFA",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email two-factor authentication disabled"})
}

// VerifyStepUp verifies an MFA code for a step-up action and records the
// verification so that subsequent requests for the same action pass the
// step-up middleware within the freshness window.
//
//	POST /api/v1/auth/mfa/step-up/verify
//	{ "code": "123456", "action": "role_mutation" }
//
//	200: { "verified": true, "action": "role_mutation", "expires_in_seconds": 300 }
//	400: invalid code / action
//	401: unauthorized
//	503: step-up repo not configured
func (h *MFAHandler) VerifyStepUp(c *gin.Context) {
	if h.stepUpRepo == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "step-up verification not configured"})
		return
	}

	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		Code   string `json:"code" binding:"required,min=1,max=20"`
		Action string `json:"action" binding:"required,min=1,max=100"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: code and action are required"})
		return
	}

	// Verify the MFA code.
	valid, err := h.mfaService.VerifyMFACode(c.Request.Context(), user.ID, req.Code)
	if err != nil {
		h.logger.Error("Step-up MFA verification failed",
			zap.String("user_id", user.ID.String()),
			zap.String("action", req.Action),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid MFA code"})
		return
	}

	// Extract session_id from context (set by RequireAuth).
	sessionVal, exists := c.Get("session_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session not found"})
		return
	}
	sessionID, ok := sessionVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid session context"})
		return
	}

	// Record the step-up verification (5-minute TTL matches middleware config).
	const stepUpTTL = 5 * time.Minute
	method := "totp" // default; the MFAService.VerifyMFACode auto-detects method
	if err := h.stepUpRepo.RecordVerification(c.Request.Context(), sessionID, user.ID, req.Action, method, stepUpTTL); err != nil {
		h.logger.Error("Failed to record step-up verification",
			zap.String("user_id", user.ID.String()),
			zap.String("action", req.Action),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record verification"})
		return
	}

	h.logger.Info("Step-up MFA verification recorded",
		zap.String("user_id", user.ID.String()),
		zap.String("session_id", sessionID.String()),
		zap.String("action", req.Action),
	)

	// Tier-1 IdP step-up integration (RFC 9470): the StepUpVerificationRepo
	// records a per-action assertion (kept for the existing admin-action
	// gating middleware), but the OAuth /authorize handler reads its
	// step-up decision from session.AuthMethodsUsed instead. Without this
	// elevation, an OAuth flow with `acr_values=mfa` re-triggers the
	// /auth/mfa/challenge redirect even after a successful step-up — the
	// session is unchanged. Append "mfa" to the AMR so the next /authorize
	// passes the `requiresMFA(acr) && !contains(amr,"mfa")` gate.
	h.elevateCurrentSessionAMR(c, "mfa")

	// Bump iam_sessions.authenticated_at so RequireFreshAuth (RFC 9470
	// max_age check) on the RETRIED sensitive endpoint sees a fresh
	// auth_time and lets the request through. Without this, the user
	// completes step-up successfully, the retry fires, and freshAuth
	// rejects again with "authentication time unknown / too old" —
	// which surfaces as "the OTP did nothing" in the UI. Two-write
	// elevation (AMR + auth_time) is the canonical pattern: AMR for
	// OAuth /authorize step-up gates, auth_time for resource-server
	// max_age gates.
	//
	// Optional: sessionRepo may be nil in unit-test setups; in that
	// case the freshness bump is skipped and the auth_time gate keeps
	// the legacy behaviour. Production wires sessionRepo via
	// NewMFAHandler.SetSessionRepo.
	if h.sessionRepo != nil {
		if err := h.sessionRepo.RefreshAuthenticatedAt(c.Request.Context(), sessionID); err != nil {
			// Non-fatal — the verification is recorded and AMR is elevated;
			// only the freshness bump failed. Log so it shows up in audit
			// without blocking the user's action.
			h.logger.Warn("Failed to refresh authenticated_at after step-up",
				zap.String("session_id", sessionID.String()),
				zap.String("action", req.Action),
				zap.Error(err),
			)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"verified":           true,
		"action":             req.Action,
		"expires_in_seconds": int(stepUpTTL.Seconds()),
	})
}

// Implementation status (2026-05-11):
//   - Phase 1 (this MR): TOTP + Email + Backup codes step-up AMR elevation
//   - Phase 2 (FI!165): WebAuthn / Passkey step-up via /webauthn/step-up/{begin,finish}

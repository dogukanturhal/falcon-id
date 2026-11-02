// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgSignupInvalidRequest = "invalid request"
)

// SignupServiceInterface defines the methods the handler delegates to the service layer.
type SignupServiceInterface interface {
	SignupPasswordPolicy() services.SignupPasswordPolicy
	InitiateSignup(ctx context.Context, input *models.CreateSignupRequestInput, ipAddress, userAgent string) (*models.SignupRequest, error)
	VerifyEmail(ctx context.Context, input *models.VerifySignupEmailInput) (*models.SignupRequest, error)
	CompleteSignup(ctx context.Context, input *models.CompleteSignupInput, ipAddress, userAgent string) (*services.CompleteSignupResult, error)
	CheckUsernameAvailable(ctx context.Context, username string) (bool, string, error)
	CheckSlugAvailable(ctx context.Context, slug string) (bool, error)
	SuggestSlug(ctx context.Context, name string) (string, bool)
}

// PasswordPolicy exposes only the effective local-signup requirements.
func (h *SignupHandler) PasswordPolicy(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, h.service.SignupPasswordPolicy())
}

// SignupHandler exposes the self-service signup endpoints.
type SignupHandler struct {
	service SignupServiceInterface
	logger  *zap.Logger
}

// CheckUsername handles GET /api/v1/auth/signup/check-username?username=X.
//
// Real-time availability for personal-account signup: validates the username
// format and reports whether the derived <username>@<consumer-domain> address
// is free, echoing the derived email back so the client shows exactly what the
// account will be. A format error returns 200 with available=false + reason so
// the wizard can surface it inline.
func (h *SignupHandler) CheckUsername(c *gin.Context) {
	available, email, err := h.service.CheckUsernameAvailable(c.Request.Context(), c.Query("username"))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"available": false, "reason": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"available": available, "email": email})
}

// CheckSlug handles GET /api/v1/auth/signup/check-slug?slug=X.
//
// Real-time availability for the up-front "claim your subdomain" signup
// step (business accounts): validates the slug's format, checks it
// against the reserved-word blocklist, and reports live uniqueness
// against tenant-management. A rejection (bad format, reserved, taken, or
// "cannot verify right now") always comes back as 200 available=false
// with a reason — same pattern as CheckUsername — never a distinguishable
// error status, so the wizard can surface it inline without leaking which
// specific condition fired (slug-tenant-enumeration mitigation).
func (h *SignupHandler) CheckSlug(c *gin.Context) {
	available, err := h.service.CheckSlugAvailable(c.Request.Context(), c.Query("slug"))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"available": false, "reason": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"available": available})
}

// suggestSlugMaxName caps the name read by SuggestSlug (runes, not bytes).
const suggestSlugMaxName = 255

// SuggestSlug handles GET /api/v1/auth/signup/suggest-slug?name=X.
//
// Returns the first available subdomain slug for a company name, so the
// company step can prefill it. Same discipline as CheckSlug: always 200,
// and "taken", "reserved" and "cannot verify" are not told apart (available
// is simply false), so it is no slug-enumeration oracle.
func (h *SignupHandler) SuggestSlug(c *gin.Context) {
	name := []rune(c.Query("name"))
	if len(name) > suggestSlugMaxName {
		name = name[:suggestSlugMaxName]
	}
	slug, available := h.service.SuggestSlug(c.Request.Context(), string(name))
	c.JSON(http.StatusOK, gin.H{"slug": slug, "available": available})
}

// NewSignupHandler creates a SignupHandler wired to the given service.
func NewSignupHandler(service SignupServiceInterface, logger *zap.Logger) *SignupHandler {
	return &SignupHandler{service: service, logger: logger}
}

// InitiateSignup handles POST /api/v1/auth/signup.
//
// It accepts a JSON body matching CreateSignupRequestInput, creates a pending
// signup request, and dispatches a verification email.
//
// Responses:
//
//	201 – request created, verification email sent.
//	400 – request body fails validation.
//	409 – email address already has an active account.
func (h *SignupHandler) InitiateSignup(c *gin.Context) {
	var input models.CreateSignupRequestInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   msgSignupInvalidRequest,
			"details": err.Error(),
		})
		return
	}

	ipAddress := GetClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	req, err := h.service.InitiateSignup(c.Request.Context(), &input, ipAddress, userAgent)
	if err != nil {
		var stateErr *services.SignupStateError
		if errors.As(err, &stateErr) && stateErr.Code == "invalid_continuation" {
			c.JSON(http.StatusBadRequest, gin.H{"code": stateErr.Code, "error": stateErr.Error()})
			return
		}
		if errors.As(err, &stateErr) && stateErr.Code == "resend_throttled" {
			c.JSON(http.StatusTooManyRequests, gin.H{"code": stateErr.Code, "error": stateErr.Error()})
			return
		}
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":    "Verification email sent. Please check your inbox.",
		"signup_id":  req.ID,
		"email":      req.Email,
		"expires_at": req.ExpiresAt,
	})
}

// VerifySignupEmail handles POST /api/v1/auth/signup/verify-email.
//
// It validates the one-time token included in the verification email.
//
// Responses:
//
//	200 – token valid, email verified.
//	400 – missing/invalid/expired token.
func (h *SignupHandler) VerifySignupEmail(c *gin.Context) {
	var input models.VerifySignupEmailInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSignupInvalidRequest})
		return
	}

	if strings.TrimSpace(input.Code) == "" && strings.TrimSpace(input.Token) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSignupInvalidRequest})
		return
	}

	req, err := h.service.VerifyEmail(c.Request.Context(), &input)
	if err != nil {
		var stateErr *services.SignupStateError
		if errors.As(err, &stateErr) {
			c.JSON(http.StatusBadRequest, gin.H{"code": stateErr.Code, "error": stateErr.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// completion_secret is returned only here, to the holder of the emailed
	// token, and must accompany signup/complete. Never cache it.
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"message":           "Email verified successfully.",
		"signup_id":         req.ID,
		"verified":          true,
		"completion_secret": req.CompletionSecret,
	})
}

// CompleteSignup handles POST /api/v1/auth/signup/complete.
//
// It provisions the tenant and user account after the email has been verified.
//
// Responses:
//
//	201 – account created.
//	400 – invalid body, unverified email, expired request, or already completed.
func (h *SignupHandler) CompleteSignup(c *gin.Context) {
	var input models.CompleteSignupInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   msgSignupInvalidRequest,
			"details": err.Error(),
		})
		return
	}
	if input.Password == "" {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"code": "password_policy_violation", "violations": []string{"required"}, "policy": h.service.SignupPasswordPolicy(),
		})
		return
	}

	ipAddress := GetClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	result, err := h.service.CompleteSignup(c.Request.Context(), &input, ipAddress, userAgent)
	if err != nil {
		var policyErr *services.SignupPasswordError
		if errors.As(err, &policyErr) {
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"code": "password_policy_violation", "violations": policyErr.Violations, "policy": policyErr.Policy,
			})
			return
		}
		var stateErr *services.SignupStateError
		if errors.As(err, &stateErr) {
			if stateErr.Code == "TRIAL_ALREADY_CONSUMED" {
				c.JSON(http.StatusConflict, gin.H{"code": stateErr.Code, "recovery_url": "/app/billing"})
				return
			}
			if stateErr.Code == "slug_unavailable" {
				c.JSON(http.StatusConflict, gin.H{"code": stateErr.Code})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"code": stateErr.Code})
			return
		}
		// t-604 (2026-09-11 signup outage): this 400 used to be the ONLY
		// trace of a CompleteSignup failure — the client got the raw
		// error string, but nothing was ever logged server-side, so a
		// provisioning failure (e.g. provisionTenant erroring out) was
		// invisible in falcon-id's own logs and had to be inferred
		// indirectly from a downstream service's logs instead. Log the
		// full error here so the next occurrence is diagnosable from
		// falcon-id's logs alone. signup_id identifies the affected
		// iam_signup_requests row without logging PII (email/password
		// are intentionally omitted).
		if h.logger != nil {
			h.logger.Error("signup: CompleteSignup failed",
				zap.String("signup_request_id", input.SignupRequestID.String()),
				zap.Error(err),
			)
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": "signup_provisioning_failed"})
		return
	}

	resp := gin.H{
		"message":     "Account created successfully.",
		"user_id":     result.User.ID,
		"email":       result.User.Email,
		"tenant_slug": result.TenantSlug,
	}
	if result.RedirectURL != "" {
		resp["redirect_url"] = result.RedirectURL
	}

	// Session is best-effort (see CompleteSignupResult / IssueSessionForNewUser
	// doc comments) — when it's nil (mint failed, or no session issuer wired),
	// the client falls back to the pre-existing hosted-login redirect, so the
	// message reflects that instead of implying a session was granted.
	if result.Session != nil {
		resp["access_token"] = result.Session.AccessToken
		resp["token_type"] = result.Session.TokenType
		resp["expires_in"] = result.Session.ExpiresIn
		resp["message"] = "Account created successfully."
	} else {
		resp["message"] = "Account created successfully. You can now sign in."
	}

	c.JSON(http.StatusCreated, resp)
}

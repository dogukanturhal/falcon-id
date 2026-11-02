// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// webauthn_witness_handler.go — ZTNA Path B operator enrollment witness.
//
// Flow:
//  1. POST /api/v1/auth/webauthn/witness/begin
//     Platform-admin operator POSTs { device_uuid, ek_pubkey_hash, state }.
//     Delegates to the existing BeginAuthentication ceremony (same challenge
//     shape as /step-up/begin so the frontend reuses the same passkey UI) and
//     persists {device_uuid, ek_pubkey_hash, state} server-side, keyed by the
//     ceremony's wa_session_id.
//
//  2. POST /api/v1/auth/webauthn/witness/finish?wa_session_id=<id>
//     Operator POSTs the W3C assertion response.
//     Assertion is verified via FinishAuthentication (reuses service method —
//     no duplicated WebAuthn logic).  On success, TokenService.MintWitnessJWS
//     signs a compact JWS with the existing RS256 issuer key, using the
//     device_uuid / ek_pubkey_hash stored at begin (the request body is NOT
//     trusted for them).
//     Response: { signed_jws, admin_sub, issued_at, expires_at, state }.
//
// Security posture:
//   - Both endpoints require an authenticated session (RequireAuth inherited
//     from the authProtected router group in cmd/routes.go) AND the
//     platform-admin gate (RequirePlatformAdmin, cmd/routes.go).
//   - The JWS aud is "https://jess.internal.example.com/device-attest" — not
//     accepted by any Falcon-ID resource-server gate.
//   - exp = 10 minutes — matches jess's witnessFreshnessWindow.
//   - device_uuid and ek_pubkey_hash are embedded in the JWS, defeating
//     cross-device replay; amr=["hwk"], witness_method="passkey", jti.
//   - wa_session_id reuse is defeated by WebAuthnService.FinishAuthentication
//     which deletes the challenge from the ceremony store on first use.
//   - AMR is elevated (mfa + hwk) on the current session for parity with
//     the existing FinishStepUp endpoint.
//
// ADR 0043 §3.c.0 / ZTNA Sprint 1.1 enforce-flip prerequisite.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// witnessWebAuthnService is the narrow ceremony surface the witness endpoints
// need from WebAuthnService. Extracted as an interface so unit tests can inject
// stubs without wiring the full service dependency graph.
//
// *services.WebAuthnService satisfies this interface automatically — no
// additional wiring required in production code.
type witnessWebAuthnService interface {
	BeginAuthentication(ctx context.Context, userID, tenantID uuid.UUID) (*services.AuthenticationChallenge, error)
	FinishAuthentication(ctx context.Context, userID, tenantID uuid.UUID, sessionID string, r *http.Request) (*models.WebAuthnCredential, *models.User, error)
}

// witnessStateService persists the begin-time binding between the two passkey
// witness calls. *services.WitnessService satisfies it.
type witnessStateService interface {
	SavePasskeyBinding(ctx context.Context, waSessionID string, b services.WitnessBinding) error
	TakePasskeyBinding(ctx context.Context, waSessionID string, userID uuid.UUID) (*services.WitnessBinding, error)
}

// witnessBeginRequest is the JSON body for POST /witness/begin.
type witnessBeginRequest struct {
	DeviceUUID   string `json:"device_uuid" binding:"required"`
	EKPubkeyHash string `json:"ek_pubkey_hash" binding:"required"`
	State        string `json:"state"`
}

// witnessFinishResponse is the JSON body returned on a successful /witness/finish.
type witnessFinishResponse struct {
	SignedJWS string `json:"signed_jws"`
	AdminSub  string `json:"admin_sub"`
	IssuedAt  string `json:"issued_at"`  // RFC3339
	ExpiresAt string `json:"expires_at"` // RFC3339
	State     string `json:"state,omitempty"`
}

// SetTokenService injects the TokenService so /witness/finish can mint the
// enrollment JWS after a successful passkey assertion. Optional at struct
// construction — when unset /witness/finish returns 503.
// Call in cmd/handlers.go immediately after constructing the WebAuthnHandler.
func (h *WebAuthnHandler) SetTokenService(svc *services.TokenService) {
	h.tokenService = svc
}

// SetWitnessState injects the store holding the begin-time device binding.
// When unset both witness endpoints return 503 (fail closed).
func (h *WebAuthnHandler) SetWitnessState(svc witnessStateService) {
	h.witnessState = svc
	if info, ok := svc.(witnessStatusProvider); ok {
		h.witnessInfo = info
	}
}

// witnessStatusProvider tells the witness page which methods to offer.
type witnessStatusProvider interface {
	Status(ctx context.Context, u *models.CurrentUser) services.WitnessTOTPStatus
}

// witnessUser returns the platform-admin caller or writes the refusal.
// Defense in depth on top of the RequirePlatformAdmin route middleware.
func (h *WebAuthnHandler) witnessUser(c *gin.Context) *models.CurrentUser {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return nil
	}
	if !user.IsPlatformAdmin || user.TenantID.String() != models.HexxlockInternalTenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Platform admin access required"})
		return nil
	}
	return user
}

// BeginWitnessEnroll handles POST /api/v1/auth/webauthn/witness/begin.
//
// Returns a WebAuthn assertion challenge identical to /step-up/begin and
// persists {device_uuid, ek_pubkey_hash, state} for /witness/finish.
func (h *WebAuthnHandler) BeginWitnessEnroll(c *gin.Context) {
	user := h.witnessUser(c)
	if user == nil {
		return
	}
	if h.witnessState == nil {
		h.logger.Error("WebAuthn BeginWitnessEnroll: witness state store not wired")
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "witness enrollment not configured"})
		return
	}

	var req witnessBeginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Reject malformed bindings early: they would otherwise end up inside a
	// signed JWS.
	if err := services.ValidateWitnessBinding(req.DeviceUUID, req.EKPubkeyHash, req.State); err != nil {
		var werr *services.WitnessError
		if errors.As(err, &werr) {
			c.JSON(werr.Status, gin.H{"error": werr.Message, "code": werr.Code})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Use the narrow ceremony interface when available (test path); fall
	// back to the concrete service for production paths.
	var svc witnessWebAuthnService
	if h.witnessService != nil {
		svc = h.witnessService
	} else {
		svc = h.service
	}

	challenge, err := svc.BeginAuthentication(c.Request.Context(), user.ID, user.TenantID)
	if err != nil {
		h.logger.Warn("WebAuthn BeginWitnessEnroll: BeginAuthentication failed",
			zap.String("user_id", user.ID.String()),
			zap.String("device_uuid", req.DeviceUUID),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.witnessState.SavePasskeyBinding(c.Request.Context(), challenge.SessionID, services.WitnessBinding{
		UserID: user.ID, DeviceUUID: req.DeviceUUID, EKPubkeyHash: req.EKPubkeyHash, State: req.State,
	}); err != nil {
		h.logger.Error("WebAuthn BeginWitnessEnroll: persist binding failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "witness enrollment unavailable"})
		return
	}

	h.logger.Info("WebAuthn witness enroll begin",
		zap.String("user_id", user.ID.String()),
		zap.String("device_uuid", req.DeviceUUID),
	)
	c.JSON(http.StatusOK, challenge)
}

// FinishWitnessEnroll handles POST /api/v1/auth/webauthn/witness/finish?wa_session_id=<id>.
//
// Verifies the WebAuthn assertion, then mints the enrollment witness JWS from
// the binding stored at begin. The assertion ceremony is identical to
// /step-up/finish; the difference is the artefact produced: a compact JWS
// bound to this operator's sub, device and EK hash.
//
// AMR elevation (mfa + hwk) is performed for parity with FinishStepUp — cheap
// to do and ensures session state is consistent with the completed passkey proof.
func (h *WebAuthnHandler) FinishWitnessEnroll(c *gin.Context) {
	user := h.witnessUser(c)
	if user == nil {
		return
	}

	if h.tokenService == nil || h.witnessState == nil {
		h.logger.Error("WebAuthn FinishWitnessEnroll: TokenService or witness state not wired")
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "witness enrollment not configured"})
		return
	}

	waSessionID := c.Query("wa_session_id")
	if waSessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebAuthnSessionIDRequired})
		return
	}

	// The binding is consumed (single use) BEFORE the assertion is checked, so
	// a failed assertion forces a fresh begin. Whatever device_uuid the request
	// body carries is ignored: the request body is the W3C assertion only.
	binding, err := h.witnessState.TakePasskeyBinding(c.Request.Context(), waSessionID, user.ID)
	if err != nil {
		var werr *services.WitnessError
		if errors.As(err, &werr) {
			c.JSON(werr.Status, gin.H{"error": werr.Message, "code": werr.Code})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "witness enrollment failed"})
		return
	}

	// Use the narrow ceremony interface when available (test path); fall
	// back to the concrete service for production paths.
	var svc witnessWebAuthnService
	if h.witnessService != nil {
		svc = h.witnessService
	} else {
		svc = h.service
	}

	// Verify the assertion. FinishAuthentication deletes the challenge from the
	// ceremony store on first use — wa_session_id replay is impossible at the
	// WebAuthn layer (same property FinishStepUp relies on).
	_, _, err = svc.FinishAuthentication(c.Request.Context(), user.ID, user.TenantID, waSessionID, c.Request)
	if err != nil {
		h.logger.Warn("WebAuthn FinishWitnessEnroll: assertion verification failed",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Mint the witness JWS using the existing RS256 issuer key.
	adminSub := user.ID.String()
	jws, err := h.tokenService.MintWitnessJWS(services.WitnessMintParams{
		AdminSub:     adminSub,
		DeviceUUID:   binding.DeviceUUID,
		EKPubkeyHash: binding.EKPubkeyHash,
		Method:       services.WitnessMethodPasskey,
	})
	if err != nil {
		if errors.Is(err, services.ErrNoSigningKey) {
			h.logger.Error("WebAuthn FinishWitnessEnroll: RS256 signing key unavailable",
				zap.String("user_id", adminSub),
				zap.Error(err),
			)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "signing key not available"})
			return
		}
		h.logger.Error("WebAuthn FinishWitnessEnroll: JWS mint failed",
			zap.String("user_id", adminSub),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to mint witness JWS"})
		return
	}

	// Best-effort AMR elevation — same pattern as FinishStepUp.
	// Non-fatal if sessionRepo is not wired or elevation fails.
	if h.sessionRepo != nil {
		sidVal, ok := c.Get("session_id")
		if ok {
			if sid, castOK := sidVal.(uuid.UUID); castOK && sid != uuid.Nil {
				for _, method := range []string{"mfa", "hwk"} {
					if _, elevErr := h.sessionRepo.AppendAuthMethod(c.Request.Context(), sid, method); elevErr != nil {
						h.logger.Warn("WebAuthn witness AMR elevation failed (non-fatal)",
							zap.String("session_id", sid.String()),
							zap.String("method", method),
							zap.Error(elevErr),
						)
					}
				}
			}
		}
	}

	h.logger.Info("WebAuthn witness JWS minted",
		zap.String("user_id", adminSub),
		zap.String("device_uuid", binding.DeviceUUID),
		zap.Time("expires_at", jws.ExpiresAt),
	)
	c.JSON(http.StatusOK, witnessFinishResponse{
		SignedJWS: jws.SignedJWS,
		AdminSub:  jws.AdminSub,
		IssuedAt:  jws.IssuedAt.Format(time.RFC3339),
		ExpiresAt: jws.ExpiresAt.Format(time.RFC3339),
		State:     binding.State,
	})
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// webauthn_witness_handler.go — ZTNA Path B operator enrollment witness.
//
// Flow:
//  1. POST /api/v1/auth/webauthn/witness/begin
//     Authenticated operator POSTs { device_uuid, ek_pubkey_hash }.
//     Delegates to the existing BeginAuthentication ceremony (same challenge
//     shape as /step-up/begin so the frontend reuses the same passkey UI).
//
//  2. POST /api/v1/auth/webauthn/witness/finish?wa_session_id=<id>
//     Operator POSTs the W3C assertion response.
//     Assertion is verified via FinishAuthentication (reuses service method —
//     no duplicated WebAuthn logic).  On success, TokenService.MintWitnessJWS
//     signs a compact JWS with the existing RS256 issuer key.
//     Response: { signed_jws, admin_sub, issued_at, expires_at }.
//
// Security posture:
//   - Both endpoints require an authenticated session (RequireAuth inherited
//     from the authProtected router group in cmd/routes.go).
//   - The JWS aud is "https://internal.example.com/device-attest" — not
//     accepted by any Falcon-ID resource-server gate.
//   - exp = 10 minutes — matches jess's witnessFreshnessWindow.
//   - device_uuid is embedded in the JWS, defeating cross-device replay.
//   - wa_session_id reuse is defeated by WebAuthnService.FinishAuthentication
//     which deletes the challenge from the ceremony store on first use.
//   - AMR is elevated (mfa + hwk) on the current session for parity with
//     the existing FinishStepUp endpoint.
//
// ADR 0043 §3.c.0 / ZTNA Sprint 1.1 enforce-flip prerequisite.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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

// witnessBeginRequest is the JSON body for POST /witness/begin.
type witnessBeginRequest struct {
	DeviceUUID   string `json:"device_uuid" binding:"required"`
	EKPubkeyHash string `json:"ek_pubkey_hash" binding:"required"`
}

// witnessFinishRequest is the supplemental JSON body for POST /witness/finish.
// The W3C assertion bytes are in the raw HTTP body; device_uuid must be re-
// supplied here because the WebAuthn ceremony store only holds the challenge
// bytes, not the application-level device_uuid from the begin request.
type witnessFinishRequest struct {
	DeviceUUID string `json:"device_uuid" binding:"required"`
}

// witnessFinishResponse is the JSON body returned on a successful /witness/finish.
type witnessFinishResponse struct {
	SignedJWS string `json:"signed_jws"`
	AdminSub  string `json:"admin_sub"`
	IssuedAt  string `json:"issued_at"`  // RFC3339
	ExpiresAt string `json:"expires_at"` // RFC3339
}

// SetTokenService injects the TokenService so /witness/finish can mint the
// enrollment JWS after a successful passkey assertion. Optional at struct
// construction — when unset /witness/finish returns 503.
// Call in cmd/handlers.go immediately after constructing the WebAuthnHandler.
func (h *WebAuthnHandler) SetTokenService(svc *services.TokenService) {
	h.tokenService = svc
}

// BeginWitnessEnroll handles POST /api/v1/auth/webauthn/witness/begin.
//
// Returns a WebAuthn assertion challenge identical to /step-up/begin.
// The body carries device_uuid + ek_pubkey_hash so the server can audit
// which device the operator is claiming to witness.  Both fields are
// required — absence implies a misconfigured enrollment client.
func (h *WebAuthnHandler) BeginWitnessEnroll(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req witnessBeginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate device_uuid is parseable as a UUID.  The jess verifier
	// also validates this; rejecting early produces a clear error message
	// rather than a downstream JWS with a malformed claim.
	if _, parseErr := uuid.Parse(req.DeviceUUID); parseErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_uuid must be a valid UUID"})
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

	h.logger.Info("WebAuthn witness enroll begin",
		zap.String("user_id", user.ID.String()),
		zap.String("device_uuid", req.DeviceUUID),
	)
	c.JSON(http.StatusOK, challenge)
}

// FinishWitnessEnroll handles POST /api/v1/auth/webauthn/witness/finish?wa_session_id=<id>.
//
// Verifies the WebAuthn assertion, then mints the enrollment witness JWS.
// The assertion ceremony is identical to /step-up/finish; the difference is
// the artefact produced: a compact JWS bound to this operator's sub and the
// device_uuid from the begin request, rather than an elevated session AMR.
//
// AMR elevation (mfa + hwk) is performed for parity with FinishStepUp — cheap
// to do and ensures session state is consistent with the completed passkey proof.
func (h *WebAuthnHandler) FinishWitnessEnroll(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if h.tokenService == nil {
		h.logger.Error("WebAuthn FinishWitnessEnroll: TokenService not wired")
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "witness enrollment not configured"})
		return
	}

	waSessionID := c.Query("wa_session_id")
	if waSessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebAuthnSessionIDRequired})
		return
	}

	// device_uuid must be re-supplied so we can embed it in the JWS. CRITICAL:
	// the SAME request body also carries the W3C assertion bytes that
	// FinishAuthentication (protocol.ParseCredentialRequestResponse) re-reads
	// below. c.ShouldBindJSON would consume c.Request.Body, leaving the ceremony
	// parser with an empty stream → "assertion verification failed" 401. So read
	// the body ONCE, restore it for the ceremony, and unmarshal device_uuid from
	// the captured bytes (mirrors the audit middleware's read-and-restore).
	bodyBytes, readErr := io.ReadAll(c.Request.Body)
	if readErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	var req witnessFinishRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// device_uuid is required; an empty/missing value fails uuid.Parse below.
	if _, parseErr := uuid.Parse(req.DeviceUUID); parseErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_uuid must be a valid UUID"})
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
	_, _, err := svc.FinishAuthentication(c.Request.Context(), user.ID, user.TenantID, waSessionID, c.Request)
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
	jws, err := h.tokenService.MintWitnessJWS(adminSub, req.DeviceUUID)
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
		zap.String("device_uuid", req.DeviceUUID),
		zap.Time("expires_at", jws.ExpiresAt),
	)
	c.JSON(http.StatusOK, witnessFinishResponse{
		SignedJWS: jws.SignedJWS,
		AdminSub:  jws.AdminSub,
		IssuedAt:  jws.IssuedAt.Format(time.RFC3339),
		ExpiresAt: jws.ExpiresAt.Format(time.RFC3339),
	})
}

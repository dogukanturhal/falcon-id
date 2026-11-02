// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// witness_totp_handler.go — authenticator-app (TOTP) fallback of the ZTNA
// enrollment witness, for platform admins WITHOUT a passkey.
//
//	POST /api/v1/auth/witness/totp/begin   { device_uuid, ek_pubkey_hash, state }
//	  -> { challenge_id, expires_in }
//	POST /api/v1/auth/witness/totp/finish  { challenge_id, code }
//	  -> { signed_jws, admin_sub, issued_at, expires_at, state }
//
// All policy (refusal rules, attempt caps, lockout, replay claim) lives in
// services.WitnessService; this file only maps HTTP. Both routes sit behind
// RequireAuth + RequirePlatformAdmin (cmd/routes.go).

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// witnessTOTPService is the slice of *services.WitnessService the handler uses.
type witnessTOTPService interface {
	BeginTOTP(ctx context.Context, u *models.CurrentUser, sessionID, deviceUUID, ekHash, state string) (string, time.Duration, error)
	FinishTOTP(ctx context.Context, u *models.CurrentUser, sessionID, challengeID, code, ip, ua string) (*services.FinishTOTPResult, error)
	Status(ctx context.Context, u *models.CurrentUser) services.WitnessTOTPStatus
}

// WitnessTOTPHandler serves the TOTP witness endpoints.
type WitnessTOTPHandler struct {
	svc    witnessTOTPService
	logger *zap.Logger
}

// NewWitnessTOTPHandler constructs the handler.
func NewWitnessTOTPHandler(svc witnessTOTPService, log *zap.Logger) *WitnessTOTPHandler {
	return &WitnessTOTPHandler{svc: svc, logger: log}
}

type witnessTOTPBeginRequest struct {
	DeviceUUID   string `json:"device_uuid" binding:"required"`
	EKPubkeyHash string `json:"ek_pubkey_hash" binding:"required"`
	State        string `json:"state"`
}

type witnessTOTPFinishRequest struct {
	ChallengeID string `json:"challenge_id" binding:"required"`
	Code        string `json:"code" binding:"required"`
}

func witnessSessionID(c *gin.Context) string {
	if v, ok := c.Get("session_id"); ok {
		return fmtSessionID(v)
	}
	return ""
}

func fmtSessionID(v interface{}) string {
	if s, ok := v.(interface{ String() string }); ok {
		return s.String()
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (h *WitnessTOTPHandler) writeErr(c *gin.Context, err error) {
	var werr *services.WitnessError
	if !errors.As(err, &werr) {
		h.logger.Error("witness totp: unexpected error", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "witness failed"})
		return
	}
	body := gin.H{"error": werr.Message, "code": werr.Code}
	if werr.Code == services.WitnessErrCodeInvalid {
		body["remaining_attempts"] = werr.RemainingAttempts
	}
	c.JSON(werr.Status, body)
}

// Begin handles POST /api/v1/auth/witness/totp/begin.
func (h *WitnessTOTPHandler) Begin(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	var req witnessTOTPBeginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_uuid and ek_pubkey_hash are required"})
		return
	}
	id, ttl, err := h.svc.BeginTOTP(c.Request.Context(), user, witnessSessionID(c), req.DeviceUUID, req.EKPubkeyHash, req.State)
	if err != nil {
		h.logger.Warn("witness totp begin refused", zap.String("user_id", user.ID.String()), zap.Error(err))
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"challenge_id": id, "expires_in": int(ttl.Seconds())})
}

// Finish handles POST /api/v1/auth/witness/totp/finish.
func (h *WitnessTOTPHandler) Finish(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	var req witnessTOTPFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "challenge_id and code are required"})
		return
	}
	res, err := h.svc.FinishTOTP(c.Request.Context(), user, witnessSessionID(c), req.ChallengeID, req.Code, GetClientIP(c), c.Request.UserAgent())
	if err != nil {
		h.logger.Warn("witness totp finish refused", zap.String("user_id", user.ID.String()), zap.Error(err))
		h.writeErr(c, err)
		return
	}
	h.logger.Info("witness totp JWS minted", zap.String("user_id", user.ID.String()))
	c.JSON(http.StatusOK, witnessFinishResponse{
		SignedJWS: res.JWS.SignedJWS,
		AdminSub:  res.JWS.AdminSub,
		IssuedAt:  res.JWS.IssuedAt.Format(time.RFC3339),
		ExpiresAt: res.JWS.ExpiresAt.Format(time.RFC3339),
		State:     res.State,
	})
}

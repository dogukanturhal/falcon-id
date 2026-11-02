// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/dpop"
	"github.com/redis/go-redis/v9"
)

// MFAFlowError is a stable public discriminator, never an infrastructure error.
type MFAFlowError struct {
	Code              string
	RemainingAttempts int
}

func (e *MFAFlowError) Error() string { return e.Code }

const mfaCompletionTTL = 60 * time.Second

var ErrMFAUnavailable = errors.New("MFA unavailable")

type mfaCompletion struct {
	Fingerprint string                `json:"fingerprint"`
	Response    *models.LoginResponse `json:"response"`
}

func mfaReplayFingerprint(ctx context.Context, req *models.MFACompleteRequest, ua string) string {
	// Do not bind IP: a network change is precisely the lost-response case.
	// Bind the browser and any DPoP key as well as the unguessable challenge.
	b, _ := json.Marshal([]any{req.SessionID, req.MFACode, ua, req.RememberMe, req.DeviceID, dpop.JKTFromContext(ctx)})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (s *AuthService) replayMFACompletion(ctx context.Context, req *models.MFACompleteRequest, ip, ua string) (*models.LoginResponse, error) {
	if s.sessionCache == nil {
		return nil, fmt.Errorf("session cache not available")
	}
	if _, err := uuid.Parse(req.SessionID); err != nil {
		return nil, &MFAFlowError{Code: "mfa_session_expired"}
	}
	raw, err := s.sessionCache.Client().Get(ctx, "mfa:completion:"+req.SessionID)
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read MFA completion: %w", err)
	}
	var record mfaCompletion
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return nil, fmt.Errorf("decode MFA completion: %w", err)
	}
	if record.Response == nil || record.Response.AccessToken == "" || record.Response.User == nil {
		return nil, fmt.Errorf("invalid MFA completion record")
	}
	if subtle.ConstantTimeCompare([]byte(record.Fingerprint), []byte(mfaReplayFingerprint(ctx, req, ua))) != 1 {
		return nil, &MFAFlowError{Code: "mfa_code_invalid"}
	}
	if s.tokenService == nil {
		return nil, fmt.Errorf("token validation unavailable")
	}
	claims, err := s.tokenService.ValidateAccessTokenWithContext(ctx, record.Response.AccessToken)
	if err != nil || claims == nil || record.Response.User == nil || claims.UserID != record.Response.User.ID || claims.TenantID != record.Response.User.TenantID {
		return nil, &MFAFlowError{Code: "mfa_session_expired"}
	}
	revoked, err := s.sessionCache.Client().Exists(ctx, "mfa:completion-revoked:"+claims.SessionID.String())
	if err != nil {
		return nil, fmt.Errorf("check MFA completion revocation: %w", err)
	}
	if revoked > 0 {
		return nil, &MFAFlowError{Code: "mfa_session_expired"}
	}
	return record.Response, nil
}

func (s *AuthService) saveMFACompletion(ctx context.Context, req *models.MFACompleteRequest, resp *models.LoginResponse, ip, ua string) error {
	// Roles/permissions and avatars made the old response >500 KB. They are
	// neither needed to reset cookies nor part of the completion contract.
	copyResp := *resp
	if resp.User != nil {
		copyResp.User = &models.UserResponse{ID: resp.User.ID, TenantID: resp.User.TenantID, Username: resp.User.Username, Email: resp.User.Email}
	}
	raw, err := json.Marshal(mfaCompletion{Fingerprint: mfaReplayFingerprint(ctx, req, ua), Response: &copyResp})
	if err != nil {
		return err
	}
	// Publish before deleting the challenge, so network retries never see a
	// gap between a consumed challenge and its cached successful result.
	if err := s.sessionCache.Client().Set(ctx, "mfa:completion:"+req.SessionID, string(raw), mfaCompletionTTL); err != nil {
		return err
	}
	return s.consumeMFASession(ctx, req.SessionID)
}

// A completion replay is handled before this guard. NEW challenges cannot
// reuse an already accepted TOTP, including across replicas. The claim lives
// in MFAService.ClaimTOTP so login, step-up and the device-enrollment witness
// share one replay namespace.
func (s *AuthService) claimLoginTOTP(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	if s.mfaService != nil && s.mfaService.replay != nil {
		return s.mfaService.ClaimTOTP(ctx, userID, code)
	}
	return claimTOTPCode(ctx, s.sessionCache.Client().Redis(), userID, code)
}

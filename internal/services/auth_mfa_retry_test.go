// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newMFARetryTestService(t *testing.T) (*AuthService, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client, err := redispkg.NewClient(redispkg.DefaultConfig("redis://"+mr.Addr()), zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	cfg := newAuthCfg()
	cfg.JWTHMACFallbackEnabled = true
	return &AuthService{config: cfg, tokenService: NewTokenService(cfg, nil, nil), sessionCache: redispkg.NewSessionCache(client, "auth2", time.Minute)}, mr
}

func mfaRetryToken(t *testing.T, s *AuthService, user *models.UserResponse, sid uuid.UUID) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": user.ID.String(), "tenant_id": user.TenantID.String(), "session_id": sid.String(), "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(s.config.JWTSecret))
	require.NoError(t, err)
	return token
}

func TestMFAReplay_MissIsExpiredNotInfrastructureFailure(t *testing.T) {
	s, _ := newMFARetryTestService(t)
	_, err := s.CompleteMFALogin(context.Background(), &models.MFACompleteRequest{SessionID: uuid.NewString(), MFACode: "123456"}, "1.2.3.4", "browser")
	var flow *MFAFlowError
	require.ErrorAs(t, err, &flow)
	require.Equal(t, "mfa_session_expired", flow.Code)
}

func TestMFAReplay_SameCodeWithinWindowAndAfterExpiry(t *testing.T) {
	s, mr := newMFARetryTestService(t)
	ctx := context.Background()
	req := &models.MFACompleteRequest{SessionID: uuid.NewString(), MFACode: "123456", RememberMe: true}
	resp := &models.LoginResponse{AccessToken: "test-token", ExpiresIn: 900, IsRememberMeSession: true, User: &models.UserResponse{ID: uuid.New(), TenantID: uuid.New(), Username: "test"}}
	resp.AccessToken = mfaRetryToken(t, s, resp.User, uuid.New())
	require.NoError(t, s.sessionCache.Client().Set(ctx, "mfa:session:"+req.SessionID, "{}", 5*time.Minute))
	require.NoError(t, s.saveMFACompletion(ctx, req, resp, "1.2.3.4", "browser"))
	require.False(t, mr.Exists("mfa:session:"+req.SessionID))
	// Network changed, but challenge + code + browser are still the same.
	replayed, err := s.CompleteMFALogin(ctx, req, "5.6.7.8", "browser")
	require.NoError(t, err)
	require.Equal(t, resp.AccessToken, replayed.AccessToken)
	require.Equal(t, resp.User.ID, replayed.User.ID)
	require.True(t, replayed.IsRememberMeSession)
	require.Equal(t, 60*time.Second, mr.TTL("mfa:completion:"+req.SessionID))
	mr.FastForward(61 * time.Second)
	_, err = s.CompleteMFALogin(ctx, req, "5.6.7.8", "browser")
	var flow *MFAFlowError
	require.ErrorAs(t, err, &flow)
	require.Equal(t, "mfa_session_expired", flow.Code)
}

func TestMFAReplay_DifferentCodeOrBrowserCannotReplay(t *testing.T) {
	for _, field := range []string{"code", "browser", "new-challenge"} {
		t.Run(field, func(t *testing.T) {
			s, _ := newMFARetryTestService(t)
			req := &models.MFACompleteRequest{SessionID: uuid.NewString(), MFACode: "123456"}
			user := &models.UserResponse{ID: uuid.New(), TenantID: uuid.New()}
			require.NoError(t, s.saveMFACompletion(context.Background(), req, &models.LoginResponse{User: user, AccessToken: mfaRetryToken(t, s, user, uuid.New())}, "ip", "browser"))
			ua := "browser"
			if field == "code" {
				req.MFACode = "654321"
			}
			if field == "browser" {
				ua = "other"
			}
			if field == "new-challenge" {
				req.SessionID = uuid.NewString()
			}
			_, err := s.CompleteMFALogin(context.Background(), req, "ip", ua)
			var flow *MFAFlowError
			require.ErrorAs(t, err, &flow)
			if field == "new-challenge" {
				require.Equal(t, "mfa_session_expired", flow.Code)
			} else {
				require.Equal(t, "mfa_code_invalid", flow.Code)
			}
		})
	}
}

type mfaRetryLookup struct{ user *models.User }

func (l mfaRetryLookup) GetByID(context.Context, uuid.UUID) (*models.User, error) { return l.user, nil }
func (l mfaRetryLookup) HasActiveWebAuthnCredential(context.Context, uuid.UUID) (bool, error) {
	return true, nil
}

func TestMFASwitch_AfterTwoFailuresKeepsChallengeAndAttemptBudget(t *testing.T) {
	s, mr := newMFARetryTestService(t)
	ctx := context.Background()
	user := &models.User{ID: uuid.New(), MFATOTPEnabled: true, MFAEmailEnabled: true, Email: "person@example.test"}
	s.mfaUserLookup = mfaRetryLookup{user: user}
	id := uuid.NewString()
	payload, err := json.Marshal(models.MFASessionData{UserID: user.ID.String(), TenantID: uuid.NewString()})
	require.NoError(t, err)
	require.NoError(t, s.sessionCache.Client().Set(ctx, "mfa:session:"+id, string(payload), 5*time.Minute))
	for i := 0; i < 2; i++ {
		_, exhausted, err := s.incrementMFAAttempts(ctx, id)
		require.NoError(t, err)
		require.False(t, exhausted)
	}
	mr.FastForward(30 * time.Second)
	resp, err := s.SwitchMFALoginMethod(ctx, id, "totp")
	require.NoError(t, err)
	require.Equal(t, id, resp.SessionID)
	require.Equal(t, int64(270), resp.MFAExpiresIn)
	require.Equal(t, "p***@example.test", resp.MaskedEmail)
	require.Contains(t, resp.AvailableMFAMethods, "webauthn")
	require.Equal(t, 270*time.Second, mr.TTL("mfa:session:"+id))
	count, exhausted, err := s.incrementMFAAttempts(ctx, id)
	require.NoError(t, err)
	require.False(t, exhausted)
	require.Equal(t, int64(3), count)
	mr.FastForward(271 * time.Second)
	_, err = s.SwitchMFALoginMethod(ctx, id, "email")
	var flow *MFAFlowError
	require.ErrorAs(t, err, &flow)
	require.Equal(t, "mfa_session_expired", flow.Code)
}

func TestMFAReplay_NewChallengeCannotReuseAcceptedTOTP(t *testing.T) {
	s, mr := newMFARetryTestService(t)
	userID := uuid.New()
	fresh, err := s.claimLoginTOTP(context.Background(), userID, "123456")
	require.NoError(t, err)
	require.True(t, fresh)
	fresh, err = s.claimLoginTOTP(context.Background(), userID, "123456")
	require.NoError(t, err)
	require.False(t, fresh)
	fresh, err = s.claimLoginTOTP(context.Background(), userID, "654321")
	require.NoError(t, err)
	require.True(t, fresh)
	mr.FastForward(91 * time.Second)
	fresh, err = s.claimLoginTOTP(context.Background(), userID, "123456")
	require.NoError(t, err)
	require.True(t, fresh)
}

func TestMFAReplay_ChallengePersistenceFailsClosed(t *testing.T) {
	s := &AuthService{}
	_, err := s.storeMFASession(context.Background(), &tenantContext{TenantID: uuid.New()}, &models.User{ID: uuid.New()}, "ip", "browser", "acmeapp-bff", "totp")
	require.ErrorIs(t, err, ErrMFAUnavailable)
}

func TestMFAReplay_ConcurrentCompletionDoesNotConsumeChallenge(t *testing.T) {
	s, mr := newMFARetryTestService(t)
	id := uuid.NewString()
	ctx := context.Background()
	require.NoError(t, s.sessionCache.Client().Set(ctx, "mfa:session:"+id, "{}", 5*time.Minute))
	require.NoError(t, s.sessionCache.Client().Set(ctx, "mfa:session:"+id+":completing", "other-owner", time.Minute))
	_, err := s.CompleteMFALogin(ctx, &models.MFACompleteRequest{SessionID: id, MFACode: "123456"}, "ip", "browser")
	var flow *MFAFlowError
	require.ErrorAs(t, err, &flow)
	require.Equal(t, "mfa_rate_limited", flow.Code)
	require.True(t, mr.Exists("mfa:session:"+id))
	require.False(t, mr.Exists("mfa:session:"+id+":attempts"))
}

func TestMFAReplay_LogoutCannotResurrectSessionButNewSignInStillWorks(t *testing.T) {
	s, _ := newMFARetryTestService(t)
	ctx := context.Background()
	sid := uuid.New()
	idpID := uuid.New()
	user := &models.UserResponse{ID: uuid.New(), TenantID: uuid.New()}
	resp := &models.LoginResponse{User: user, AccessToken: mfaRetryToken(t, s, user, sid)}
	req := &models.MFACompleteRequest{SessionID: uuid.NewString(), MFACode: "123456"}
	require.NoError(t, s.saveMFACompletion(ctx, req, resp, "ip", "browser"))
	require.NoError(t, s.sessionCache.SetIdpSession(ctx, idpID, &redispkg.IdpSessionData{UserID: user.ID, SessionID: sid}))
	require.NoError(t, s.sessionCache.EndIdpSession(ctx, idpID))
	_, err := s.CompleteMFALogin(ctx, req, "ip", "browser")
	var flow *MFAFlowError
	require.ErrorAs(t, err, &flow)
	require.Equal(t, "mfa_session_expired", flow.Code)
	// A fresh login has a different SQL session, so the revocation marker
	// cannot block signing back in immediately after deliberate logout.
	req.SessionID = uuid.NewString()
	resp.AccessToken = mfaRetryToken(t, s, user, uuid.New())
	require.NoError(t, s.saveMFACompletion(ctx, req, resp, "ip", "browser"))
	_, err = s.CompleteMFALogin(ctx, req, "ip", "browser")
	require.NoError(t, err)
}

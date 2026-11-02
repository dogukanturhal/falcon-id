// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	pkgcrypto "github.com/dogukanturhal/falcon-id/pkg/crypto"
)

const (
	wsDevice = "33333333-3333-3333-3333-333333333333"
	wsEKHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	wsSess   = "sess-1"
)

// wsUsers implements witnessUserReader AND mfaUserRepository.
type wsUsers struct {
	user      *models.User
	enabledAt *time.Time
}

func (u *wsUsers) GetByID(context.Context, uuid.UUID) (*models.User, error) { return u.user, nil }
func (u *wsUsers) GetMFATOTPEnabledAt(context.Context, uuid.UUID) (*time.Time, error) {
	return u.enabledAt, nil
}
func (u *wsUsers) Update(context.Context, *models.User) error { return nil }
func (u *wsUsers) HasNonPrimaryMFAFactor(context.Context, uuid.UUID) (bool, error) {
	return false, nil
}

type wsPasskeys struct{ n int }

func (p wsPasskeys) CountActiveByUser(context.Context, uuid.UUID, uuid.UUID) (int, error) {
	return p.n, nil
}

type wsPolicy struct{ allowed bool }

func (p wsPolicy) DeviceWitnessTOTPAllowed(context.Context, uuid.UUID) (bool, error) {
	return p.allowed, nil
}

type wsAudit struct{ actions []string }

func (a *wsAudit) LogUserAction(_ context.Context, _ uuid.UUID, _, _ *uuid.UUID, action string, _ bool, _ map[string]interface{}) {
	a.actions = append(a.actions, action)
}

type wsEnv struct {
	svc    *WitnessService
	mr     *miniredis.Miniredis
	users  *wsUsers
	pk     *wsPasskeys
	policy *wsPolicy
	audit  *wsAudit
	mfa    *MFAService
	cu     *models.CurrentUser
	secret string
}

func newWSEnv(t *testing.T) *wsEnv {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "t", AccountName: "ops"})
	require.NoError(t, err)
	secret := key.Secret()
	tenant := uuid.MustParse(models.HexxlockInternalTenantID)
	uid := uuid.New()
	user := &models.User{ID: uid, TenantID: tenant, Email: "ops@example.com", Username: "ops",
		MFAEnabled: true, MFATOTPEnabled: true, MFASecret: &secret}
	users := &wsUsers{user: user}
	pk := &wsPasskeys{}
	policy := &wsPolicy{allowed: true}
	audit := &wsAudit{}

	mfa := NewMFAService(&config.Config{}, users, nil, nil, nil)
	mfa.SetTOTPReplayStore(rdb)

	t.Setenv("JWT_PRIVATE_KEY", "")
	t.Setenv("JWT_PRIVATE_KEY_FILE", "")
	t.Setenv("JWT_PUBLIC_KEY", "")
	t.Setenv("JWT_PUBLIC_KEY_FILE", "")
	kp, err := pkgcrypto.NewJWTKeyProvider(nil, "test-kid")
	require.NoError(t, err)
	tok := NewTokenService(&config.Config{JWTIssuer: "https://id.example.com", JWTSigningAlgorithm: "RS256"}, nil, nil)
	tok.SetJWTKeyProvider(kp)

	env := &wsEnv{users: users, pk: pk, policy: policy, audit: audit, mfa: mfa, mr: mr, secret: secret,
		cu: &models.CurrentUser{ID: uid, TenantID: tenant, IsPlatformAdmin: true}}
	env.svc = NewWitnessService(WitnessServiceDeps{
		Redis: rdb, Users: users, Passkeys: pk, Policy: policy, MFA: mfa, Minter: tok,
		Audit: audit, TOTPEnabled: true,
	})
	return env
}

func (e *wsEnv) code(t *testing.T) string {
	t.Helper()
	c, err := totp.GenerateCode(e.secret, time.Now())
	require.NoError(t, err)
	return c
}

func (e *wsEnv) begin(t *testing.T) string {
	t.Helper()
	id, ttl, err := e.svc.BeginTOTP(context.Background(), e.cu, wsSess, wsDevice, wsEKHash, "st4te")
	require.NoError(t, err)
	assert.Equal(t, 120*time.Second, ttl)
	return id
}

func (e *wsEnv) finish(id, code string) (*FinishTOTPResult, error) {
	return e.svc.FinishTOTP(context.Background(), e.cu, wsSess, id, code, "1.2.3.4", "ua")
}

func wantWitnessErr(t *testing.T, err error, status int, code string) *WitnessError {
	t.Helper()
	var we *WitnessError
	require.True(t, errors.As(err, &we), "want WitnessError, got %v", err)
	assert.Equal(t, status, we.Status)
	assert.Equal(t, code, we.Code)
	return we
}

func TestWitnessTOTP_HappyPathMintsOTPWitness(t *testing.T) {
	e := newWSEnv(t)
	id := e.begin(t)
	res, err := e.finish(id, e.code(t))
	require.NoError(t, err)
	assert.Equal(t, "st4te", res.State)
	assert.Equal(t, WitnessMethodOTP, res.JWS.Method)
	assert.WithinDuration(t, time.Now().Add(5*time.Minute), res.JWS.ExpiresAt, 10*time.Second)

	tok, _, err := jwt.NewParser().ParseUnverified(res.JWS.SignedJWS, jwt.MapClaims{})
	require.NoError(t, err)
	assert.Equal(t, "test-kid", tok.Header["kid"])
	c := tok.Claims.(jwt.MapClaims)
	assert.Equal(t, e.cu.ID.String(), c["sub"])
	assert.Equal(t, wsDevice, c["device_uuid"])
	assert.Equal(t, wsEKHash, c["ek_pubkey_hash"])
	assert.Equal(t, "otp", c["witness_method"])
	assert.Equal(t, []interface{}{"otp"}, c["amr"])
	assert.NotEmpty(t, c["jti"])
	aud, _ := c.GetAudience()
	assert.Equal(t, jwt.ClaimStrings{"https://jess.internal.example.com/device-attest/otp"}, aud)
	assert.Equal(t, []string{"device_witness.totp.minted"}, e.audit.actions)

	// single use: the challenge is gone
	_, err = e.finish(id, e.code(t))
	wantWitnessErr(t, err, http.StatusGone, WitnessErrExpired)
}

func TestWitnessTOTP_ExpiredChallenge(t *testing.T) {
	e := newWSEnv(t)
	id := e.begin(t)
	e.mr.FastForward(121 * time.Second)
	_, err := e.finish(id, e.code(t))
	wantWitnessErr(t, err, http.StatusGone, WitnessErrExpired)
}

func TestWitnessTOTP_ChallengeBoundToUserAndSession(t *testing.T) {
	e := newWSEnv(t)
	id := e.begin(t)
	_, err := e.svc.FinishTOTP(context.Background(), e.cu, "other-session", id, e.code(t), "", "")
	wantWitnessErr(t, err, http.StatusGone, WitnessErrExpired)
}

func TestWitnessTOTP_PerChallengeAttemptCap(t *testing.T) {
	e := newWSEnv(t)
	id := e.begin(t)
	for i := 1; i <= 2; i++ {
		_, err := e.finish(id, "000000")
		we := wantWitnessErr(t, err, http.StatusUnauthorized, WitnessErrCodeInvalid)
		assert.Equal(t, 3-i, we.RemainingAttempts)
	}
	_, err := e.finish(id, "000000") // third failure burns the challenge
	wantWitnessErr(t, err, http.StatusTooManyRequests, WitnessErrExhausted)
	// even the right code can no longer use it
	_, err = e.finish(id, e.code(t))
	wantWitnessErr(t, err, http.StatusGone, WitnessErrExpired)
}

func TestWitnessTOTP_UserLockoutAfterFiveFailures(t *testing.T) {
	e := newWSEnv(t)
	// 3 + 2 failures over two challenges = 5 per user.
	id := e.begin(t)
	for i := 0; i < 3; i++ {
		_, _ = e.finish(id, "000000")
	}
	id = e.begin(t)
	_, err := e.finish(id, "000000")
	require.Error(t, err)
	_, err = e.finish(id, "000000")
	wantWitnessErr(t, err, http.StatusTooManyRequests, WitnessErrLocked)
	assert.Contains(t, e.audit.actions, "device_witness.totp.locked")

	// locked: begin refused, and a correct code on the old challenge too
	_, _, err = e.svc.BeginTOTP(context.Background(), e.cu, wsSess, wsDevice, wsEKHash, "")
	wantWitnessErr(t, err, http.StatusTooManyRequests, WitnessErrLocked)

	// lock expires after 15 minutes
	e.mr.FastForward(16 * time.Minute)
	id = e.begin(t)
	_, err = e.finish(id, e.code(t))
	require.NoError(t, err)
}

func TestWitnessTOTP_ReplayAgainstLoginClaim(t *testing.T) {
	e := newWSEnv(t)
	code := e.code(t)
	// The login path claims the code through the shared MFAService.ClaimTOTP.
	auth := &AuthService{mfaService: e.mfa}
	fresh, err := auth.claimLoginTOTP(context.Background(), e.cu.ID, code)
	require.NoError(t, err)
	require.True(t, fresh)

	id := e.begin(t)
	_, err = e.finish(id, code)
	we := wantWitnessErr(t, err, http.StatusUnauthorized, WitnessErrCodeInvalid)
	assert.Equal(t, 2, we.RemainingAttempts)
}

func TestWitnessTOTP_CodeSpentOnWitnessIsNotUsableForLogin(t *testing.T) {
	e := newWSEnv(t)
	code := e.code(t)
	id := e.begin(t)
	_, err := e.finish(id, code)
	require.NoError(t, err)
	auth := &AuthService{mfaService: e.mfa}
	fresh, err := auth.claimLoginTOTP(context.Background(), e.cu.ID, code)
	require.NoError(t, err)
	assert.False(t, fresh, "login must see the code as already used")
}

func TestWitnessTOTP_RefusesWhenUserHasPasskey(t *testing.T) {
	e := newWSEnv(t)
	e.pk.n = 1
	_, _, err := e.svc.BeginTOTP(context.Background(), e.cu, wsSess, wsDevice, wsEKHash, "")
	wantWitnessErr(t, err, http.StatusForbidden, WitnessErrHasPasskey)
}

func TestWitnessTOTP_RefusesTOTPYoungerThan24h(t *testing.T) {
	e := newWSEnv(t)
	young := time.Now().Add(-23 * time.Hour)
	e.users.enabledAt = &young
	_, _, err := e.svc.BeginTOTP(context.Background(), e.cu, wsSess, wsDevice, wsEKHash, "")
	wantWitnessErr(t, err, http.StatusForbidden, WitnessErrTOTPTooNew)

	old := time.Now().Add(-25 * time.Hour)
	e.users.enabledAt = &old
	e.begin(t)

	e.users.enabledAt = nil // legacy row: treated as old enough
	e.begin(t)
}

func TestWitnessTOTP_RefusedWhenPolicyOrKillSwitchOff(t *testing.T) {
	e := newWSEnv(t)
	e.policy.allowed = false
	_, _, err := e.svc.BeginTOTP(context.Background(), e.cu, wsSess, wsDevice, wsEKHash, "")
	wantWitnessErr(t, err, http.StatusForbidden, WitnessErrPolicyOff)

	e.policy.allowed = true
	e.svc.totpEnabled = false
	_, _, err = e.svc.BeginTOTP(context.Background(), e.cu, wsSess, wsDevice, wsEKHash, "")
	wantWitnessErr(t, err, http.StatusForbidden, WitnessErrDisabled)
}

func TestWitnessTOTP_PolicyTurnedOffBetweenBeginAndFinish(t *testing.T) {
	e := newWSEnv(t)
	id := e.begin(t)
	e.policy.allowed = false
	_, err := e.finish(id, e.code(t))
	wantWitnessErr(t, err, http.StatusForbidden, WitnessErrPolicyOff)
}

func TestWitnessTOTP_RefusesUserWithoutTOTP(t *testing.T) {
	e := newWSEnv(t)
	e.users.user.MFATOTPEnabled = false
	_, _, err := e.svc.BeginTOTP(context.Background(), e.cu, wsSess, wsDevice, wsEKHash, "")
	wantWitnessErr(t, err, http.StatusForbidden, WitnessErrNoTOTP)
}

func TestWitnessTOTP_RefusesNonPlatformAdmin(t *testing.T) {
	e := newWSEnv(t)
	e.cu.IsPlatformAdmin = false
	_, _, err := e.svc.BeginTOTP(context.Background(), e.cu, wsSess, wsDevice, wsEKHash, "")
	wantWitnessErr(t, err, http.StatusForbidden, WitnessErrNotPlatformAdmin)
}

func TestWitnessTOTP_BackupCodeNeverAccepted(t *testing.T) {
	e := newWSEnv(t) // mfaRepo is nil: touching VerifyBackupCode would panic
	id := e.begin(t)
	for _, backup := range []string{"ABCD-EFGH", "12345678", "a1b2c3d4e5"} {
		_, err := e.finish(id, backup)
		var we *WitnessError
		require.True(t, errors.As(err, &we))
		assert.Contains(t, []string{WitnessErrCodeInvalid, WitnessErrExhausted}, we.Code)
	}
}

func TestWitnessTOTP_BadBindingRejectedAtBegin(t *testing.T) {
	e := newWSEnv(t)
	for _, tc := range []struct{ dev, ek, state string }{
		{"nope", wsEKHash, ""},
		{wsDevice, "abc", ""},
		{wsDevice, wsEKHash, string(make([]byte, 65))},
	} {
		_, _, err := e.svc.BeginTOTP(context.Background(), e.cu, wsSess, tc.dev, tc.ek, tc.state)
		wantWitnessErr(t, err, http.StatusBadRequest, WitnessErrBadRequest)
	}
}

func TestWitnessPasskeyBinding_SingleUseAndUserBound(t *testing.T) {
	e := newWSEnv(t)
	ctx := context.Background()
	b := WitnessBinding{UserID: e.cu.ID, DeviceUUID: wsDevice, EKPubkeyHash: wsEKHash, State: "s"}
	require.NoError(t, e.svc.SavePasskeyBinding(ctx, "wa1", b))
	got, err := e.svc.TakePasskeyBinding(ctx, "wa1", e.cu.ID)
	require.NoError(t, err)
	assert.Equal(t, b, *got)
	_, err = e.svc.TakePasskeyBinding(ctx, "wa1", e.cu.ID)
	wantWitnessErr(t, err, http.StatusGone, WitnessErrExpired)

	require.NoError(t, e.svc.SavePasskeyBinding(ctx, "wa2", b))
	_, err = e.svc.TakePasskeyBinding(ctx, "wa2", uuid.New())
	wantWitnessErr(t, err, http.StatusGone, WitnessErrExpired)

	require.NoError(t, e.svc.SavePasskeyBinding(ctx, "wa3", b))
	e.mr.FastForward(6 * time.Minute)
	_, err = e.svc.TakePasskeyBinding(ctx, "wa3", e.cu.ID)
	wantWitnessErr(t, err, http.StatusGone, WitnessErrExpired)
}

func TestWitnessStatus(t *testing.T) {
	e := newWSEnv(t)
	st := e.svc.Status(context.Background(), e.cu)
	assert.Equal(t, WitnessTOTPStatus{HasPasskey: false, HasTOTP: true, TOTPAllowed: true}, st)
	e.pk.n = 2
	assert.True(t, e.svc.Status(context.Background(), e.cu).HasPasskey)
}

func TestMintWitnessJWS_OTPRequiresEKHash(t *testing.T) {
	tok := NewTokenService(&config.Config{JWTIssuer: "x", JWTSigningAlgorithm: "RS256"}, nil, nil)
	_, err := tok.MintWitnessJWS(WitnessMintParams{AdminSub: "s", DeviceUUID: wsDevice, Method: WitnessMethodOTP})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNoSigningKey)
	_, err = tok.MintWitnessJWS(WitnessMintParams{AdminSub: "s", DeviceUUID: wsDevice, Method: "bogus"})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNoSigningKey)
}

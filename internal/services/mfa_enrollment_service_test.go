// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// mfa_enrollment_service_test.go covers the registration-interrupt enrollment
// service: token lifecycle (create / lookup / rebind reject / consume),
// TOTP + email enrollment happy paths, and verify-failure preserving the
// session for retry. Uses lightweight in-memory fakes for the Redis cache,
// MFA service, and user repo so the suite stays fast and DB-free.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

type fakeEnrollCache struct {
	mu    sync.Mutex
	store map[string]string
	ttls  map[string]time.Time
}

func newFakeEnrollCache() *fakeEnrollCache {
	return &fakeEnrollCache{store: map[string]string{}, ttls: map[string]time.Time{}}
}

func (c *fakeEnrollCache) Get(_ context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.ttls[key]
	if ok && time.Now().After(exp) {
		delete(c.store, key)
		delete(c.ttls, key)
		return "", errors.New("expired")
	}
	v, ok := c.store[key]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func (c *fakeEnrollCache) Set(_ context.Context, key string, value interface{}, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch v := value.(type) {
	case string:
		c.store[key] = v
	default:
		return errors.New("fake cache only stores strings in this test")
	}
	c.ttls[key] = time.Now().Add(ttl)
	return nil
}

func (c *fakeEnrollCache) Del(_ context.Context, keys ...string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range keys {
		delete(c.store, k)
		delete(c.ttls, k)
	}
	return nil
}

// fakeEnrollMFA tracks calls into the underlying MFAService so tests can
// assert "no email was sent" — the central tier-1 invariant.
type fakeEnrollMFA struct {
	sendMFAEnabledNotificationCalls int
	sendMFAEnabledNotificationErr   error
	totpSetupCalls          int
	totpSetupResp           *TOTPSetupResponse
	totpSetupErr            error
	verifyAndEnableCalls    int
	verifyAndEnableBackup   []string
	verifyAndEnableErr      error
	sendEmailCodeCalls      int
	sendEmailCodeErr        error
	verifyEmailCodeCalls    int
	verifyEmailCodeValid    bool
	verifyEmailCodeErr      error
	generateBackupCallCount int
	generateBackupResp      []string
	generateBackupErr       error
}

func (f *fakeEnrollMFA) GenerateTOTPSecret(_ context.Context, _ uuid.UUID) (*TOTPSetupResponse, error) {
	f.totpSetupCalls++
	return f.totpSetupResp, f.totpSetupErr
}
func (f *fakeEnrollMFA) VerifyAndEnableTOTP(_ context.Context, _ uuid.UUID, _ string) ([]string, error) {
	f.verifyAndEnableCalls++
	return f.verifyAndEnableBackup, f.verifyAndEnableErr
}
func (f *fakeEnrollMFA) SendEmailMFACode(_ context.Context, _ uuid.UUID) error {
	f.sendEmailCodeCalls++
	return f.sendEmailCodeErr
}
func (f *fakeEnrollMFA) VerifyEmailMFACode(_ context.Context, _ uuid.UUID, _ string) (bool, error) {
	f.verifyEmailCodeCalls++
	return f.verifyEmailCodeValid, f.verifyEmailCodeErr
}
func (f *fakeEnrollMFA) GenerateBackupCodes(_ context.Context, _ uuid.UUID) ([]string, error) {
	f.generateBackupCallCount++
	return f.generateBackupResp, f.generateBackupErr
}

// sendMFAEnabledNotificationCalls counts SendMFAEnabledNotification
// invocations so tests can assert the post-enrollment notification
// fan-out — added alongside the same method on the production
// MFAService interface (feat/mfa-enrollment-success-notification-email).
func (f *fakeEnrollMFA) SendMFAEnabledNotification(_ context.Context, _ uuid.UUID, _ string) error {
	f.sendMFAEnabledNotificationCalls++
	return f.sendMFAEnabledNotificationErr
}

type fakeEnrollUserRepo struct {
	users     map[uuid.UUID]*models.User
	updateErr error
}

func newFakeEnrollUserRepo() *fakeEnrollUserRepo {
	return &fakeEnrollUserRepo{users: map[uuid.UUID]*models.User{}}
}

func (r *fakeEnrollUserRepo) GetByID(_ context.Context, id uuid.UUID) (*models.User, error) {
	u, ok := r.users[id]
	if !ok {
		return nil, nil
	}
	return u, nil
}
func (r *fakeEnrollUserRepo) Update(_ context.Context, u *models.User) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	r.users[u.ID] = u
	return nil
}
func (r *fakeEnrollUserRepo) ResetMFAEnrollmentGraceTracking(_ context.Context, userID uuid.UUID) error {
	if u, ok := r.users[userID]; ok {
		u.MFAEnrollmentSkipCount = 0
	}
	return nil
}

// newEnrollSvc returns a fresh service + dependency handles so tests can
// inject behaviour and assert call counts.
func newEnrollSvc() (*MFAEnrollmentService, *fakeEnrollCache, *fakeEnrollMFA, *fakeEnrollUserRepo) {
	cache := newFakeEnrollCache()
	mfa := &fakeEnrollMFA{}
	repo := newFakeEnrollUserRepo()
	return NewMFAEnrollmentService(cache, mfa, repo, nil), cache, mfa, repo
}

// ---------------------------------------------------------------------------
// CreateSession + LookupSession lifecycle
// ---------------------------------------------------------------------------

func TestMFAEnrollment_CreateAndLookup_HappyPath(t *testing.T) {
	svc, _, _, _ := newEnrollSvc()
	userID := uuid.New()
	tenantID := uuid.New()

	token, ttl, err := svc.CreateSession(context.Background(), userID, tenantID, "tenant-slug", "1.2.3.4", "test-ua/1.0", "client-x", 50, "medium")
	require.NoError(t, err)
	require.NotEmpty(t, token)
	assert.Equal(t, int64(600), ttl, "10-minute TTL is the tier-1 contract")

	sess, err := svc.LookupSession(context.Background(), token, "1.2.3.4", "test-ua/1.0")
	require.NoError(t, err)
	assert.Equal(t, userID.String(), sess.UserID)
	assert.Equal(t, tenantID.String(), sess.TenantID)
	assert.Equal(t, "client-x", sess.ClientID)
	assert.Equal(t, 50, sess.RiskScore)
	assert.Equal(t, "medium", sess.RiskLevel)
}

func TestMFAEnrollment_LookupSession_RejectsIPRebind(t *testing.T) {
	svc, _, _, _ := newEnrollSvc()
	userID, tenantID := uuid.New(), uuid.New()

	token, _, err := svc.CreateSession(context.Background(), userID, tenantID, "t", "1.2.3.4", "ua", "c", 50, "medium")
	require.NoError(t, err)

	_, err = svc.LookupSession(context.Background(), token, "5.6.7.8", "ua")
	require.Error(t, err, "different IP must fail closed (token-theft signal)")
	assert.Contains(t, err.Error(), "expired or invalid")
}

func TestMFAEnrollment_LookupSession_RejectsUARebind(t *testing.T) {
	svc, _, _, _ := newEnrollSvc()
	userID, tenantID := uuid.New(), uuid.New()

	token, _, err := svc.CreateSession(context.Background(), userID, tenantID, "t", "1.2.3.4", "original-ua", "c", 50, "medium")
	require.NoError(t, err)

	_, err = svc.LookupSession(context.Background(), token, "1.2.3.4", "different-ua")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired or invalid")
}

func TestMFAEnrollment_LookupSession_PreservesAfterRebindMiss(t *testing.T) {
	// Token-theft attempts must NOT invalidate the legitimate user's session;
	// only successful verify deletes it.
	svc, cache, _, _ := newEnrollSvc()
	userID, tenantID := uuid.New(), uuid.New()

	token, _, err := svc.CreateSession(context.Background(), userID, tenantID, "t", "1.2.3.4", "ua", "c", 50, "medium")
	require.NoError(t, err)

	_, _ = svc.LookupSession(context.Background(), token, "5.6.7.8", "ua")
	_, ok := cache.store[enrollmentRedisKey(token)]
	assert.True(t, ok, "session must survive token-theft attempts so the legitimate user can still complete")
}

func TestMFAEnrollment_LookupSession_RejectsMalformedToken(t *testing.T) {
	svc, _, _, _ := newEnrollSvc()
	_, err := svc.LookupSession(context.Background(), "not-a-uuid", "1.2.3.4", "ua")
	require.Error(t, err)
}

func TestMFAEnrollment_LookupSession_RejectsMissingToken(t *testing.T) {
	svc, _, _, _ := newEnrollSvc()
	_, err := svc.LookupSession(context.Background(), uuid.New().String(), "1.2.3.4", "ua")
	require.Error(t, err, "an unknown token must be rejected as expired/invalid")
}

func TestMFAEnrollment_DeleteSession_IsOneTimeUseOnSuccess(t *testing.T) {
	svc, cache, _, _ := newEnrollSvc()
	token, _, err := svc.CreateSession(context.Background(), uuid.New(), uuid.New(), "t", "1.2.3.4", "ua", "c", 50, "medium")
	require.NoError(t, err)

	svc.DeleteSession(context.Background(), token)
	_, ok := cache.store[enrollmentRedisKey(token)]
	assert.False(t, ok, "explicit DeleteSession must remove the cache row")

	_, err = svc.LookupSession(context.Background(), token, "1.2.3.4", "ua")
	require.Error(t, err, "deleted session must not look up")
}

// ---------------------------------------------------------------------------
// VerifyTOTP / VerifyEmail
// ---------------------------------------------------------------------------

func TestMFAEnrollment_VerifyTOTP_HappyPath_DeletesSession(t *testing.T) {
	svc, cache, mfa, _ := newEnrollSvc()
	mfa.verifyAndEnableBackup = []string{"AAAA-1111", "BBBB-2222"}

	token, _, err := svc.CreateSession(context.Background(), uuid.New(), uuid.New(), "t", "1.2.3.4", "ua", "c", 50, "medium")
	require.NoError(t, err)
	sess, err := svc.LookupSession(context.Background(), token, "1.2.3.4", "ua")
	require.NoError(t, err)

	codes, err := svc.VerifyTOTP(context.Background(), sess, token, "123456")
	require.NoError(t, err)
	assert.Equal(t, []string{"AAAA-1111", "BBBB-2222"}, codes)
	_, ok := cache.store[enrollmentRedisKey(token)]
	assert.False(t, ok, "successful verify must delete the enrollment session (one-time-use)")
	assert.Equal(t, 1, mfa.verifyAndEnableCalls)
}

func TestMFAEnrollment_VerifyTOTP_PreservesSessionOnInvalidCode(t *testing.T) {
	svc, cache, mfa, _ := newEnrollSvc()
	mfa.verifyAndEnableErr = errors.New("invalid verification code")

	token, _, err := svc.CreateSession(context.Background(), uuid.New(), uuid.New(), "t", "1.2.3.4", "ua", "c", 50, "medium")
	require.NoError(t, err)
	sess, err := svc.LookupSession(context.Background(), token, "1.2.3.4", "ua")
	require.NoError(t, err)

	_, err = svc.VerifyTOTP(context.Background(), sess, token, "999999")
	require.Error(t, err)
	_, ok := cache.store[enrollmentRedisKey(token)]
	assert.True(t, ok, "failed verify must preserve the session so the user can retry without restarting login")
}

func TestMFAEnrollment_VerifyEmail_HappyPath_FlipsFlagsAndMarksEmailVerified(t *testing.T) {
	svc, cache, mfa, repo := newEnrollSvc()
	mfa.verifyEmailCodeValid = true
	mfa.generateBackupResp = []string{"CCCC-3333"}

	userID := uuid.New()
	repo.users[userID] = &models.User{ID: userID, IsEmailVerified: false}

	token, _, err := svc.CreateSession(context.Background(), userID, uuid.New(), "t", "1.2.3.4", "ua", "c", 50, "medium")
	require.NoError(t, err)
	sess, err := svc.LookupSession(context.Background(), token, "1.2.3.4", "ua")
	require.NoError(t, err)

	codes, err := svc.VerifyEmail(context.Background(), sess, token, "654321")
	require.NoError(t, err)
	assert.Equal(t, []string{"CCCC-3333"}, codes)

	updated := repo.users[userID]
	assert.True(t, updated.MFAEnabled, "MFAEnabled must flip true on successful email enrollment")
	assert.True(t, updated.MFAEmailEnabled)
	assert.True(t, updated.IsEmailVerified, "successful code receipt is proof of mailbox control — mark email verified (Entra/Okta/Auth0 parity)")
	require.NotNil(t, updated.MFAType)
	assert.Equal(t, "email", *updated.MFAType)

	_, ok := cache.store[enrollmentRedisKey(token)]
	assert.False(t, ok, "successful verify must delete the enrollment session")
}

func TestMFAEnrollment_VerifyEmail_RejectsInvalidCode(t *testing.T) {
	svc, cache, mfa, repo := newEnrollSvc()
	mfa.verifyEmailCodeValid = false
	userID := uuid.New()
	repo.users[userID] = &models.User{ID: userID}

	token, _, err := svc.CreateSession(context.Background(), userID, uuid.New(), "t", "1.2.3.4", "ua", "c", 50, "medium")
	require.NoError(t, err)
	sess, err := svc.LookupSession(context.Background(), token, "1.2.3.4", "ua")
	require.NoError(t, err)

	_, err = svc.VerifyEmail(context.Background(), sess, token, "000000")
	require.Error(t, err)
	_, ok := cache.store[enrollmentRedisKey(token)]
	assert.True(t, ok, "invalid email-code verify must preserve the session for retry")
	assert.False(t, repo.users[userID].MFAEnabled, "MFA flags must NOT flip on a failed verify — protects against partial-state lockout")
}

// ---------------------------------------------------------------------------
// Init paths — verify they don't leak state to the wrong method
// ---------------------------------------------------------------------------

func TestMFAEnrollment_InitTOTP_DelegatesToMFAService(t *testing.T) {
	svc, _, mfa, _ := newEnrollSvc()
	mfa.totpSetupResp = &TOTPSetupResponse{Secret: "S", QRCode: "Q", ManualEntry: "M"}

	token, _, err := svc.CreateSession(context.Background(), uuid.New(), uuid.New(), "t", "1.2.3.4", "ua", "c", 50, "medium")
	require.NoError(t, err)
	sess, err := svc.LookupSession(context.Background(), token, "1.2.3.4", "ua")
	require.NoError(t, err)

	resp, err := svc.InitTOTP(context.Background(), sess)
	require.NoError(t, err)
	assert.Equal(t, "S", resp.Secret)
	assert.Equal(t, 0, mfa.sendEmailCodeCalls, "TOTP init must NOT trigger an email send")
}

func TestMFAEnrollment_InitEmail_DelegatesToMFAService(t *testing.T) {
	svc, _, mfa, _ := newEnrollSvc()

	token, _, err := svc.CreateSession(context.Background(), uuid.New(), uuid.New(), "t", "1.2.3.4", "ua", "c", 50, "medium")
	require.NoError(t, err)
	sess, err := svc.LookupSession(context.Background(), token, "1.2.3.4", "ua")
	require.NoError(t, err)

	require.NoError(t, svc.InitEmail(context.Background(), sess))
	assert.Equal(t, 1, mfa.sendEmailCodeCalls)
	assert.Equal(t, 0, mfa.totpSetupCalls, "Email init must NOT trigger TOTP setup")
}

// ---------------------------------------------------------------------------
// Misconfiguration guard — service must fail closed if cache is missing
// ---------------------------------------------------------------------------

func TestMFAEnrollment_NilCache_FailsClosed(t *testing.T) {
	svc := NewMFAEnrollmentService(nil, &fakeEnrollMFA{}, newFakeEnrollUserRepo(), nil)
	_, _, err := svc.CreateSession(context.Background(), uuid.New(), uuid.New(), "t", "1.2.3.4", "ua", "c", 50, "medium")
	require.Error(t, err, "missing cache must fail closed — never silently fall back to the lockout-cliff path")
}

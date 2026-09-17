// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// device_code_service_test.go covers the OAuth 2.0 Device Authorization Grant
// service (RFC 8628).
//
// DeviceCodeService depends on the deviceCodeRepo interface, which is fully
// mockable — enabling complete unit test coverage of all public methods.
//
// Test coverage:
//   - InitiateDeviceFlow: happy path, repo failure, code format validation
//   - PollDeviceCode:     not found, expired, pending, authorized
//   - AuthorizeDevice:    happy path, not found, expired
//   - DenyDevice:         happy path, not found
//   - ConsumeDeviceCode:  happy path
//   - ExpireOldCodes:     happy path
//   - Helpers:            generateDeviceCode, generateUserCode, hashDeviceCode, verificationURI

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mock: deviceCodeRepo
// ---------------------------------------------------------------------------

type MockDeviceCodeRepo struct {
	mock.Mock
}

func (m *MockDeviceCodeRepo) Create(ctx context.Context, d *models.OAuthDeviceCode) error {
	args := m.Called(ctx, d)
	return args.Error(0)
}

func (m *MockDeviceCodeRepo) GetByDeviceCode(ctx context.Context, hash string) (*models.OAuthDeviceCode, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.OAuthDeviceCode), args.Error(1)
}

func (m *MockDeviceCodeRepo) GetByUserCode(ctx context.Context, userCode string) (*models.OAuthDeviceCode, error) {
	args := m.Called(ctx, userCode)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.OAuthDeviceCode), args.Error(1)
}

func (m *MockDeviceCodeRepo) Authorize(ctx context.Context, id, userID uuid.UUID) error {
	args := m.Called(ctx, id, userID)
	return args.Error(0)
}

func (m *MockDeviceCodeRepo) Deny(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockDeviceCodeRepo) Consume(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockDeviceCodeRepo) RecordPoll(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockDeviceCodeRepo) ExpireOld(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

// compile-time interface check
var _ deviceCodeRepo = (*MockDeviceCodeRepo)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newDeviceCodeSvc(repo deviceCodeRepo) *DeviceCodeService {
	return NewDeviceCodeService(repo, "https://app.example.com")
}

func newPendingCode() *models.OAuthDeviceCode {
	future := time.Now().Add(15 * time.Minute)
	return &models.OAuthDeviceCode{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		ClientID:  uuid.New(),
		UserCode:  "BCDF-GHJK",
		Status:    models.DeviceCodeStatusPending,
		ExpiresAt: future,
	}
}

func newExpiredCode() *models.OAuthDeviceCode {
	code := newPendingCode()
	code.ExpiresAt = time.Now().Add(-1 * time.Minute) // already expired
	return code
}

func newAuthorizedCode() *models.OAuthDeviceCode {
	code := newPendingCode()
	userID := uuid.New()
	code.Status = models.DeviceCodeStatusAuthorized
	code.UserID = &userID
	return code
}

// ---------------------------------------------------------------------------
// InitiateDeviceFlow
// ---------------------------------------------------------------------------

func TestInitiateDeviceFlow_HappyPath(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	tenantID := uuid.New()
	clientID := uuid.New()
	scopes := []string{"openid", "profile"}

	repo.On("Create", mock.Anything, mock.AnythingOfType("*models.OAuthDeviceCode")).
		Return(nil)

	resp, err := svc.InitiateDeviceFlow(context.Background(), tenantID, clientID, scopes)

	require.NoError(t, err)
	require.NotNil(t, resp)

	// RFC 8628 §3.2 required fields
	assert.NotEmpty(t, resp.DeviceCode)
	assert.NotEmpty(t, resp.UserCode)
	assert.NotEmpty(t, resp.VerificationURI)
	assert.Greater(t, resp.ExpiresIn, int64(0))
	assert.Equal(t, deviceCodeInterval, resp.Interval)

	repo.AssertExpectations(t)
}

func TestInitiateDeviceFlow_DeviceCodeNotStoredRaw(t *testing.T) {
	// SECURITY: only the hash of the device code should be stored, not the raw value.
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	var storedRecord *models.OAuthDeviceCode
	repo.On("Create", mock.Anything, mock.AnythingOfType("*models.OAuthDeviceCode")).
		Run(func(args mock.Arguments) {
			storedRecord = args.Get(1).(*models.OAuthDeviceCode)
		}).
		Return(nil)

	resp, err := svc.InitiateDeviceFlow(context.Background(), uuid.New(), uuid.New(), nil)
	require.NoError(t, err)

	// The raw device code returned to the caller must NOT be stored in the DB record.
	assert.NotEqual(t, resp.DeviceCode, storedRecord.DeviceCode,
		"SECURITY: raw device code must not be stored; only its SHA-256 hash")

	// Verify the stored hash is the SHA-256 of the raw device code.
	expectedHash := hashDeviceCode(resp.DeviceCode)
	assert.Equal(t, expectedHash, storedRecord.DeviceCode,
		"stored device code must be SHA-256(raw device code)")
}

func TestInitiateDeviceFlow_UserCodeFormat(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	repo.On("Create", mock.Anything, mock.AnythingOfType("*models.OAuthDeviceCode")).
		Return(nil)

	resp, err := svc.InitiateDeviceFlow(context.Background(), uuid.New(), uuid.New(), nil)
	require.NoError(t, err)

	// RFC 8628 RECOMMENDS XXXX-XXXX format with unambiguous charset (no O, 0, I, 1)
	userCodeRegex := regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`)
	assert.True(t, userCodeRegex.MatchString(resp.UserCode),
		"user code %q must match XXXX-XXXX format using RFC 8628 charset", resp.UserCode)
}

func TestInitiateDeviceFlow_VerificationURIContainsTenantID(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	repo.On("Create", mock.Anything, mock.AnythingOfType("*models.OAuthDeviceCode")).
		Return(nil)

	resp, err := svc.InitiateDeviceFlow(context.Background(), uuid.New(), uuid.New(), nil)
	require.NoError(t, err)

	assert.Contains(t, resp.VerificationURI, "/device",
		"verification URI must point to the device authorization page")
	assert.Contains(t, resp.VerificationURIComplete, resp.UserCode,
		"verification_uri_complete must include the user_code as a query parameter")
}

func TestInitiateDeviceFlow_ExpiresInIs15Minutes(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	repo.On("Create", mock.Anything, mock.AnythingOfType("*models.OAuthDeviceCode")).
		Return(nil)

	resp, err := svc.InitiateDeviceFlow(context.Background(), uuid.New(), uuid.New(), nil)
	require.NoError(t, err)

	assert.Equal(t, int64(deviceCodeExpiry.Seconds()), resp.ExpiresIn,
		"expires_in must equal the RFC 8628 recommended device code lifetime")
}

func TestInitiateDeviceFlow_RepoError_ReturnsError(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	repo.On("Create", mock.Anything, mock.AnythingOfType("*models.OAuthDeviceCode")).
		Return(errors.New("database unavailable"))

	_, err := svc.InitiateDeviceFlow(context.Background(), uuid.New(), uuid.New(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initiate device flow",
		"DB error must produce a generic user-facing message (no internal details)")
}

func TestInitiateDeviceFlow_ScopesStoredInRecord(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	scopes := []string{"openid", "profile", "email"}
	var storedRecord *models.OAuthDeviceCode

	repo.On("Create", mock.Anything, mock.AnythingOfType("*models.OAuthDeviceCode")).
		Run(func(args mock.Arguments) {
			storedRecord = args.Get(1).(*models.OAuthDeviceCode)
		}).
		Return(nil)

	_, err := svc.InitiateDeviceFlow(context.Background(), uuid.New(), uuid.New(), scopes)
	require.NoError(t, err)
	assert.Equal(t, scopes, storedRecord.Scopes)
}

// ---------------------------------------------------------------------------
// PollDeviceCode
// ---------------------------------------------------------------------------

func TestPollDeviceCode_Pending_ReturnsPendingRecord(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	rawCode := "rawdevicecode12345"
	hash := hashDeviceCode(rawCode)
	record := newPendingCode()

	repo.On("GetByDeviceCode", mock.Anything, hash).Return(record, nil)
	repo.On("RecordPoll", mock.Anything, record.ID).Return(nil)

	got, err := svc.PollDeviceCode(context.Background(), rawCode)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, models.DeviceCodeStatusPending, got.Status)
	assert.True(t, got.IsPending())

	repo.AssertExpectations(t)
}

func TestPollDeviceCode_Authorized_ReturnsAuthorizedRecord(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	rawCode := "authorizeddevicecode"
	hash := hashDeviceCode(rawCode)
	record := newAuthorizedCode()

	repo.On("GetByDeviceCode", mock.Anything, hash).Return(record, nil)
	repo.On("RecordPoll", mock.Anything, record.ID).Return(nil)

	got, err := svc.PollDeviceCode(context.Background(), rawCode)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, models.DeviceCodeStatusAuthorized, got.Status)
	assert.True(t, got.IsAuthorized())
}

func TestPollDeviceCode_NotFound_ReturnsError(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	rawCode := "unknown-code"
	hash := hashDeviceCode(rawCode)

	repo.On("GetByDeviceCode", mock.Anything, hash).Return(nil, nil)

	_, err := svc.PollDeviceCode(context.Background(), rawCode)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "device code not found")
}

func TestPollDeviceCode_Expired_ReturnsError(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	rawCode := "expireddevicecode"
	hash := hashDeviceCode(rawCode)
	record := newExpiredCode()

	repo.On("GetByDeviceCode", mock.Anything, hash).Return(record, nil)
	repo.On("RecordPoll", mock.Anything, record.ID).Return(nil)

	_, err := svc.PollDeviceCode(context.Background(), rawCode)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestPollDeviceCode_RepoError_ReturnsWrappedError(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	rawCode := "anycode"
	hash := hashDeviceCode(rawCode)

	repo.On("GetByDeviceCode", mock.Anything, hash).
		Return(nil, errors.New("db connection lost"))

	_, err := svc.PollDeviceCode(context.Background(), rawCode)
	require.Error(t, err)
}

// TestPollDeviceCode_AlwaysRecordsPoll ensures RecordPoll is called even for
// pending records so the slow_down rate can be enforced upstream.
func TestPollDeviceCode_AlwaysRecordsPoll(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	rawCode := "testpollrecord"
	hash := hashDeviceCode(rawCode)
	record := newPendingCode()

	repo.On("GetByDeviceCode", mock.Anything, hash).Return(record, nil)
	repo.On("RecordPoll", mock.Anything, record.ID).Return(nil)

	_, err := svc.PollDeviceCode(context.Background(), rawCode)
	require.NoError(t, err)

	repo.AssertCalled(t, "RecordPoll", mock.Anything, record.ID)
}

// ---------------------------------------------------------------------------
// AuthorizeDevice
// ---------------------------------------------------------------------------

func TestAuthorizeDevice_HappyPath(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	userID := uuid.New()
	record := newPendingCode()

	repo.On("GetByUserCode", mock.Anything, record.UserCode).Return(record, nil)
	repo.On("Authorize", mock.Anything, record.ID, userID).Return(nil)

	err := svc.AuthorizeDevice(context.Background(), record.UserCode, userID)
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestAuthorizeDevice_NotFound_ReturnsError(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	repo.On("GetByUserCode", mock.Anything, "XXXX-XXXX").Return(nil, nil)

	err := svc.AuthorizeDevice(context.Background(), "XXXX-XXXX", uuid.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired user code")
}

func TestAuthorizeDevice_Expired_ReturnsError(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	record := newExpiredCode()
	repo.On("GetByUserCode", mock.Anything, record.UserCode).Return(record, nil)

	err := svc.AuthorizeDevice(context.Background(), record.UserCode, uuid.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestAuthorizeDevice_RepoAuthorizeError_ReturnsError(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	userID := uuid.New()
	record := newPendingCode()

	repo.On("GetByUserCode", mock.Anything, record.UserCode).Return(record, nil)
	repo.On("Authorize", mock.Anything, record.ID, userID).
		Return(errors.New("db error"))

	err := svc.AuthorizeDevice(context.Background(), record.UserCode, userID)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// DenyDevice
// ---------------------------------------------------------------------------

func TestDenyDevice_HappyPath(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	record := newPendingCode()
	repo.On("GetByUserCode", mock.Anything, record.UserCode).Return(record, nil)
	repo.On("Deny", mock.Anything, record.ID).Return(nil)

	err := svc.DenyDevice(context.Background(), record.UserCode)
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestDenyDevice_NotFound_ReturnsError(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	repo.On("GetByUserCode", mock.Anything, "UNKNOWN").Return(nil, nil)

	err := svc.DenyDevice(context.Background(), "UNKNOWN")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired user code")
}

// ---------------------------------------------------------------------------
// ConsumeDeviceCode
// ---------------------------------------------------------------------------

func TestConsumeDeviceCode_HappyPath(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	id := uuid.New()
	repo.On("Consume", mock.Anything, id).Return(nil)

	err := svc.ConsumeDeviceCode(context.Background(), id)
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestConsumeDeviceCode_RepoError_Propagated(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	id := uuid.New()
	repo.On("Consume", mock.Anything, id).Return(errors.New("not found"))

	err := svc.ConsumeDeviceCode(context.Background(), id)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// ExpireOldCodes
// ---------------------------------------------------------------------------

func TestExpireOldCodes_ReturnsCount(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	repo.On("ExpireOld", mock.Anything).Return(int64(42), nil)

	n, err := svc.ExpireOldCodes(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(42), n)
}

func TestExpireOldCodes_RepoError_Propagated(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := newDeviceCodeSvc(repo)

	repo.On("ExpireOld", mock.Anything).Return(int64(0), errors.New("db error"))

	_, err := svc.ExpireOldCodes(context.Background())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// generateDeviceCode — helper
// ---------------------------------------------------------------------------

func TestGenerateDeviceCode_ReturnsHexString(t *testing.T) {
	code, err := generateDeviceCode()
	require.NoError(t, err)

	// Must be a hex string of length 64 (32 bytes → 64 hex chars)
	assert.Len(t, code, 64,
		"device code must be 32 bytes (64 hex chars) for adequate entropy")
	hexRegex := regexp.MustCompile(`^[0-9a-f]+$`)
	assert.True(t, hexRegex.MatchString(code),
		"device code must be lowercase hex")
}

func TestGenerateDeviceCode_IsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, err := generateDeviceCode()
		require.NoError(t, err)
		assert.False(t, seen[code], "device code collision at i=%d", i)
		seen[code] = true
	}
}

// ---------------------------------------------------------------------------
// generateUserCode — helper
// ---------------------------------------------------------------------------

func TestGenerateUserCode_MatchesRFC8628Format(t *testing.T) {
	userCodeRegex := regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`)

	for i := 0; i < 50; i++ {
		code, err := generateUserCode()
		require.NoError(t, err)
		assert.True(t, userCodeRegex.MatchString(code),
			"user code %q must match XXXX-XXXX format", code)
	}
}

func TestGenerateUserCode_NoAmbiguousChars(t *testing.T) {
	ambiguous := []string{"O", "0", "I", "1"}

	for i := 0; i < 100; i++ {
		code, err := generateUserCode()
		require.NoError(t, err)

		for _, ch := range ambiguous {
			assert.False(t, strings.Contains(code, ch),
				"user code %q must not contain ambiguous character %q", code, ch)
		}
	}
}

// ---------------------------------------------------------------------------
// hashDeviceCode — helper
// ---------------------------------------------------------------------------

func TestHashDeviceCode_IsDeterministic(t *testing.T) {
	raw := "test-raw-device-code-abc123"
	h1 := hashDeviceCode(raw)
	h2 := hashDeviceCode(raw)
	assert.Equal(t, h1, h2, "same input must produce same SHA-256 hash")
}

func TestHashDeviceCode_DifferentInputsDifferentHashes(t *testing.T) {
	h1 := hashDeviceCode("code-a")
	h2 := hashDeviceCode("code-b")
	assert.NotEqual(t, h1, h2)
}

func TestHashDeviceCode_IsHexSHA256(t *testing.T) {
	hash := hashDeviceCode("any-raw-code")
	hexRegex := regexp.MustCompile(`^[0-9a-f]{64}$`)
	assert.True(t, hexRegex.MatchString(hash),
		"device code hash must be a 64-char lowercase hex string (SHA-256)")
}

// ---------------------------------------------------------------------------
// verificationURI — helper
// ---------------------------------------------------------------------------

func TestVerificationURI_UsesFrontendURL(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := NewDeviceCodeService(repo, "https://app.example.com")

	uri := svc.verificationURI(uuid.New())
	assert.Equal(t, "https://app.example.com/device", uri)
}

func TestVerificationURI_DefaultsToLocalhost(t *testing.T) {
	repo := new(MockDeviceCodeRepo)
	svc := NewDeviceCodeService(repo, "") // empty frontendURL

	uri := svc.verificationURI(uuid.New())
	assert.Equal(t, "http://localhost:3000/device", uri)
}

// ---------------------------------------------------------------------------
// OAuthDeviceCode model helpers
// ---------------------------------------------------------------------------

func TestOAuthDeviceCode_IsExpired(t *testing.T) {
	expired := &models.OAuthDeviceCode{ExpiresAt: time.Now().Add(-1 * time.Second)}
	assert.True(t, expired.IsExpired())

	active := &models.OAuthDeviceCode{ExpiresAt: time.Now().Add(1 * time.Hour)}
	assert.False(t, active.IsExpired())
}

func TestOAuthDeviceCode_IsPending(t *testing.T) {
	assert.True(t, (&models.OAuthDeviceCode{Status: models.DeviceCodeStatusPending}).IsPending())
	assert.False(t, (&models.OAuthDeviceCode{Status: models.DeviceCodeStatusAuthorized}).IsPending())
}

func TestOAuthDeviceCode_IsAuthorized(t *testing.T) {
	assert.True(t, (&models.OAuthDeviceCode{Status: models.DeviceCodeStatusAuthorized}).IsAuthorized())
	assert.False(t, (&models.OAuthDeviceCode{Status: models.DeviceCodeStatusPending}).IsAuthorized())
	assert.False(t, (&models.OAuthDeviceCode{Status: models.DeviceCodeStatusDenied}).IsAuthorized())
}

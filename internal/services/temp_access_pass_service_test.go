// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

type mockTAPRepo struct {
	mock.Mock
}

func (m *mockTAPRepo) Create(ctx context.Context, pass *TempAccessPass) error {
	args := m.Called(ctx, pass)
	return args.Error(0)
}

func (m *mockTAPRepo) GetByUserAndHash(ctx context.Context, userID, tenantID uuid.UUID, passHash string) (*TempAccessPass, error) {
	args := m.Called(ctx, userID, tenantID, passHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TempAccessPass), args.Error(1)
}

func (m *mockTAPRepo) DecrementUses(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockTAPRepo) DeleteExpired(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockTAPRepo) ListByUser(ctx context.Context, userID, tenantID uuid.UUID) ([]*TempAccessPass, error) {
	args := m.Called(ctx, userID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*TempAccessPass), args.Error(1)
}

func (m *mockTAPRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestTAPService constructs a TempAccessPassService backed by the provided mock.
func newTestTAPService(repo *mockTAPRepo) *TempAccessPassService {
	return NewTempAccessPassService(repo, zap.NewNop())
}

// sha256Hex returns the SHA-256 hex digest of the given string, matching the
// algorithm used internally by TempAccessPassService.hashPass.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// validTAP returns a TempAccessPass that is not expired and has uses remaining.
func validTAP(id, userID, tenantID uuid.UUID, plaintext string, usesRemaining int) *TempAccessPass {
	return &TempAccessPass{
		ID:            id,
		UserID:        userID,
		TenantID:      tenantID,
		PassHash:      sha256Hex(plaintext),
		IsOneTime:     usesRemaining == 1,
		MaxUses:       usesRemaining,
		UsesRemaining: usesRemaining,
		ExpiresAt:     time.Now().UTC().Add(30 * time.Minute),
		CreatedBy:     uuid.New(),
		CreatedAt:     time.Now().UTC(),
	}
}

// ---------------------------------------------------------------------------
// GeneratePass
// ---------------------------------------------------------------------------

func TestTAP_GeneratePass_Success(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	userID := uuid.New()
	tenantID := uuid.New()
	createdBy := uuid.New()
	ctx := context.Background()

	var capturedPass *TempAccessPass
	repo.On("Create", ctx, mock.AnythingOfType("*services.TempAccessPass")).
		Run(func(args mock.Arguments) {
			capturedPass = args.Get(1).(*TempAccessPass)
		}).
		Return(nil)

	plaintext, err := svc.GeneratePass(ctx, userID, tenantID, createdBy, false, 3, 60)
	require.NoError(t, err)
	assert.Len(t, plaintext, tapLength, "plaintext pass must be exactly %d characters", tapLength)

	require.NotNil(t, capturedPass, "repository Create must have been called")
	assert.Equal(t, sha256Hex(plaintext), capturedPass.PassHash,
		"stored hash must be SHA-256 of the returned plaintext")
	assert.Equal(t, userID, capturedPass.UserID)
	assert.Equal(t, tenantID, capturedPass.TenantID)
	assert.Equal(t, createdBy, capturedPass.CreatedBy)
	assert.Equal(t, 3, capturedPass.MaxUses)
	assert.Equal(t, 3, capturedPass.UsesRemaining)
	assert.False(t, capturedPass.IsOneTime)
	assert.WithinDuration(t, time.Now().UTC().Add(60*time.Minute), capturedPass.ExpiresAt, 5*time.Second)

	repo.AssertExpectations(t)
}

func TestTAP_GeneratePass_OneTimeForcesMaxUsesToOne(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	ctx := context.Background()

	var capturedPass *TempAccessPass
	repo.On("Create", ctx, mock.AnythingOfType("*services.TempAccessPass")).
		Run(func(args mock.Arguments) {
			capturedPass = args.Get(1).(*TempAccessPass)
		}).
		Return(nil)

	// maxUses=5 should be overridden to 1 because isOneTime=true.
	_, err := svc.GeneratePass(ctx, uuid.New(), uuid.New(), uuid.New(), true, 5, 10)
	require.NoError(t, err)
	require.NotNil(t, capturedPass)
	assert.Equal(t, 1, capturedPass.MaxUses, "one-time pass must have MaxUses=1 regardless of the provided value")
	assert.Equal(t, 1, capturedPass.UsesRemaining)
	assert.True(t, capturedPass.IsOneTime)
}

func TestTAP_GeneratePass_MaxUsesLessThanOneClampsToOne(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	ctx := context.Background()

	var capturedPass *TempAccessPass
	repo.On("Create", ctx, mock.AnythingOfType("*services.TempAccessPass")).
		Run(func(args mock.Arguments) {
			capturedPass = args.Get(1).(*TempAccessPass)
		}).
		Return(nil)

	// maxUses=0 must be clamped to 1.
	_, err := svc.GeneratePass(ctx, uuid.New(), uuid.New(), uuid.New(), false, 0, 10)
	require.NoError(t, err)
	require.NotNil(t, capturedPass)
	assert.Equal(t, 1, capturedPass.MaxUses)
}

func TestTAP_GeneratePass_ZeroDurationRejected(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	ctx := context.Background()

	_, err := svc.GeneratePass(ctx, uuid.New(), uuid.New(), uuid.New(), false, 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "durationMins must be at least 1")

	repo.AssertNotCalled(t, "Create")
}

func TestTAP_GeneratePass_NegativeDurationRejected(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	ctx := context.Background()

	_, err := svc.GeneratePass(ctx, uuid.New(), uuid.New(), uuid.New(), false, 1, -5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "durationMins must be at least 1")
}

func TestTAP_GeneratePass_RepoCreateError(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	ctx := context.Background()

	repo.On("Create", ctx, mock.AnythingOfType("*services.TempAccessPass")).
		Return(errors.New("db write error"))

	plaintext, err := svc.GeneratePass(ctx, uuid.New(), uuid.New(), uuid.New(), false, 1, 60)
	require.Error(t, err)
	assert.Empty(t, plaintext)
}

func TestTAP_GeneratePass_PlaintextNeverStored(t *testing.T) {
	// Confirm that the plaintext value itself does not appear anywhere in the
	// persisted struct — only its SHA-256 hash is stored.
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	ctx := context.Background()

	var capturedPass *TempAccessPass
	repo.On("Create", ctx, mock.AnythingOfType("*services.TempAccessPass")).
		Run(func(args mock.Arguments) {
			capturedPass = args.Get(1).(*TempAccessPass)
		}).
		Return(nil)

	plaintext, err := svc.GeneratePass(ctx, uuid.New(), uuid.New(), uuid.New(), false, 1, 60)
	require.NoError(t, err)
	require.NotNil(t, capturedPass)

	assert.NotEqual(t, plaintext, capturedPass.PassHash,
		"the raw plaintext must not equal the stored hash field")
}

// ---------------------------------------------------------------------------
// ValidatePass
// ---------------------------------------------------------------------------

func TestTAP_ValidatePass_Success(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	userID := uuid.New()
	tenantID := uuid.New()
	tapID := uuid.New()
	ctx := context.Background()
	plaintext := "SomeP4ss"

	tap := validTAP(tapID, userID, tenantID, plaintext, 3)

	repo.On("GetByUserAndHash", ctx, userID, tenantID, sha256Hex(plaintext)).Return(tap, nil)
	repo.On("DecrementUses", ctx, tapID).Return(nil)

	err := svc.ValidatePass(ctx, userID, tenantID, plaintext)
	require.NoError(t, err)

	repo.AssertExpectations(t)
}

func TestTAP_ValidatePass_WrongPass_ReturnsInvalidError(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	userID := uuid.New()
	tenantID := uuid.New()
	ctx := context.Background()

	// Hash mismatch: repository returns nil (not-found semantics used for wrong-pass too).
	repo.On("GetByUserAndHash", ctx, userID, tenantID, mock.AnythingOfType("string")).
		Return(nil, nil)

	err := svc.ValidatePass(ctx, userID, tenantID, "WrongPass")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTAPInvalidPass)

	repo.AssertNotCalled(t, "DecrementUses")
}

func TestTAP_ValidatePass_Expired_ReturnsExpiredError(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	userID := uuid.New()
	tenantID := uuid.New()
	tapID := uuid.New()
	ctx := context.Background()
	plaintext := "ExpiredP4ss"

	tap := validTAP(tapID, userID, tenantID, plaintext, 1)
	tap.ExpiresAt = time.Now().UTC().Add(-1 * time.Minute) // already expired

	repo.On("GetByUserAndHash", ctx, userID, tenantID, sha256Hex(plaintext)).Return(tap, nil)

	err := svc.ValidatePass(ctx, userID, tenantID, plaintext)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTAPExpired)

	repo.AssertNotCalled(t, "DecrementUses")
}

func TestTAP_ValidatePass_ExhaustedUses_ReturnsExhaustedError(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	userID := uuid.New()
	tenantID := uuid.New()
	tapID := uuid.New()
	ctx := context.Background()
	plaintext := "UsedUpPass"

	tap := validTAP(tapID, userID, tenantID, plaintext, 0)
	tap.UsesRemaining = 0 // exhausted

	repo.On("GetByUserAndHash", ctx, userID, tenantID, sha256Hex(plaintext)).Return(tap, nil)

	err := svc.ValidatePass(ctx, userID, tenantID, plaintext)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTAPExhausted)

	repo.AssertNotCalled(t, "DecrementUses")
}

func TestTAP_ValidatePass_RepoGetError(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	repo.On("GetByUserAndHash", ctx, userID, tenantID, mock.AnythingOfType("string")).
		Return(nil, errors.New("db read error"))

	err := svc.ValidatePass(ctx, userID, tenantID, "AnyPass1")
	require.Error(t, err)
	// Error must not be the sentinel — it should wrap the underlying db error.
	assert.NotErrorIs(t, err, ErrTAPInvalidPass)
}

func TestTAP_ValidatePass_DecrementError_PropagatesError(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	userID := uuid.New()
	tenantID := uuid.New()
	tapID := uuid.New()
	ctx := context.Background()
	plaintext := "GoodPass1"

	tap := validTAP(tapID, userID, tenantID, plaintext, 2)

	repo.On("GetByUserAndHash", ctx, userID, tenantID, sha256Hex(plaintext)).Return(tap, nil)
	repo.On("DecrementUses", ctx, tapID).Return(errors.New("decrement write error"))

	err := svc.ValidatePass(ctx, userID, tenantID, plaintext)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrement")
}

// ---------------------------------------------------------------------------
// Table-driven: ValidatePass sentinel error identity
// ---------------------------------------------------------------------------

func TestTAP_ValidatePass_SentinelErrors(t *testing.T) {
	plaintext := "SentinelP"

	tests := []struct {
		name    string
		tap     func(userID, tenantID uuid.UUID) *TempAccessPass
		wantErr error
	}{
		{
			name:    "not found",
			tap:     nil, // repository returns nil
			wantErr: ErrTAPInvalidPass,
		},
		{
			name: "expired",
			tap: func(userID, tenantID uuid.UUID) *TempAccessPass {
				t := validTAP(uuid.New(), userID, tenantID, plaintext, 1)
				t.ExpiresAt = time.Now().UTC().Add(-time.Hour)
				return t
			},
			wantErr: ErrTAPExpired,
		},
		{
			name: "exhausted",
			tap: func(userID, tenantID uuid.UUID) *TempAccessPass {
				t := validTAP(uuid.New(), userID, tenantID, plaintext, 1)
				t.UsesRemaining = 0
				return t
			},
			wantErr: ErrTAPExhausted,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := &mockTAPRepo{}
			svc := newTestTAPService(repo)
			userID := uuid.New()
			tenantID := uuid.New()
			ctx := context.Background()

			if tc.tap == nil {
				repo.On("GetByUserAndHash", ctx, userID, tenantID, sha256Hex(plaintext)).
					Return(nil, nil)
			} else {
				repo.On("GetByUserAndHash", ctx, userID, tenantID, sha256Hex(plaintext)).
					Return(tc.tap(userID, tenantID), nil)
			}

			err := svc.ValidatePass(ctx, userID, tenantID, plaintext)
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// ---------------------------------------------------------------------------
// ListPasses
// ---------------------------------------------------------------------------

func TestTAP_ListPasses_Success(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	userID := uuid.New()
	tenantID := uuid.New()
	ctx := context.Background()

	passes := []*TempAccessPass{
		validTAP(uuid.New(), userID, tenantID, "pass1", 1),
		validTAP(uuid.New(), userID, tenantID, "pass2", 3),
	}

	repo.On("ListByUser", ctx, userID, tenantID).Return(passes, nil)

	result, err := svc.ListPasses(ctx, userID, tenantID)
	require.NoError(t, err)
	assert.Len(t, result, 2)

	repo.AssertExpectations(t)
}

func TestTAP_ListPasses_NilResultBecomesEmptySlice(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	userID := uuid.New()
	tenantID := uuid.New()
	ctx := context.Background()

	repo.On("ListByUser", ctx, userID, tenantID).Return(nil, nil)

	result, err := svc.ListPasses(ctx, userID, tenantID)
	require.NoError(t, err)
	assert.NotNil(t, result, "nil from repo must be converted to an empty, non-nil slice")
	assert.Empty(t, result)
}

func TestTAP_ListPasses_RepoError(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	repo.On("ListByUser", ctx, userID, tenantID).Return(nil, errors.New("db error"))

	_, err := svc.ListPasses(ctx, userID, tenantID)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// RevokePass
// ---------------------------------------------------------------------------

func TestTAP_RevokePass_Success(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	tapID := uuid.New()
	ctx := context.Background()

	repo.On("Delete", ctx, tapID).Return(nil)

	err := svc.RevokePass(ctx, tapID)
	require.NoError(t, err)

	repo.AssertExpectations(t)
}

func TestTAP_RevokePass_NotFound_PropagatesError(t *testing.T) {
	// The service delegates directly to repo.Delete; if the row does not exist
	// the repo is expected to return an error (e.g. pgx.ErrNoRows wrapped).
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	tapID := uuid.New()
	ctx := context.Background()

	repo.On("Delete", ctx, tapID).Return(errors.New("not found"))

	err := svc.RevokePass(ctx, tapID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RevokePass")
}

// ---------------------------------------------------------------------------
// CleanupExpiredPasses
// ---------------------------------------------------------------------------

func TestTAP_CleanupExpiredPasses_Success(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	ctx := context.Background()

	repo.On("DeleteExpired", ctx).Return(int64(7), nil)

	count, err := svc.CleanupExpiredPasses(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(7), count)

	repo.AssertExpectations(t)
}

func TestTAP_CleanupExpiredPasses_NothingToDelete(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	ctx := context.Background()

	repo.On("DeleteExpired", ctx).Return(int64(0), nil)

	count, err := svc.CleanupExpiredPasses(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestTAP_CleanupExpiredPasses_RepoError(t *testing.T) {
	repo := &mockTAPRepo{}
	svc := newTestTAPService(repo)

	ctx := context.Background()

	repo.On("DeleteExpired", ctx).Return(int64(0), errors.New("cleanup failed"))

	_, err := svc.CleanupExpiredPasses(ctx)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Internal: passphrase generation properties
// ---------------------------------------------------------------------------

func TestTAP_GeneratePassPhrase_LengthAndCharset(t *testing.T) {
	svc := newTestTAPService(&mockTAPRepo{})

	for i := 0; i < 20; i++ {
		pass, err := svc.generatePassPhrase()
		require.NoError(t, err)
		assert.Len(t, pass, tapLength, "generated pass must have %d characters (iteration %d)", tapLength, i)

		for _, ch := range pass {
			assert.Contains(t, tapCharset, string(ch),
				"character %q must belong to the allowed charset", ch)
		}
	}
}

func TestTAP_HashPass_IsDeterministic(t *testing.T) {
	svc := newTestTAPService(&mockTAPRepo{})

	input := "TestInput123"
	hash1 := svc.hashPass(input)
	hash2 := svc.hashPass(input)

	assert.Equal(t, hash1, hash2, "hashPass must be deterministic for the same input")
}

func TestTAP_HashPass_DifferentInputsDifferentHashes(t *testing.T) {
	svc := newTestTAPService(&mockTAPRepo{})

	assert.NotEqual(t, svc.hashPass("pass-a"), svc.hashPass("pass-b"))
}

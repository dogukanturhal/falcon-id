// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// Focused tests for SCIMService.ValidateToken's three-state branching
// (Tier-A audit memo 2026-05-21). Pre-fix the repo filtered on
// is_active=true at the WHERE level, collapsing "revoked replay
// attempt" into "unknown hash". Post-fix the repo returns the row
// regardless and the service emits a dedicated error per state.

// ---------------------------------------------------------------------------
// mockSCIMRepo — implements scimServiceSCIMRepo
// ---------------------------------------------------------------------------

type mockSCIMRepo struct {
	mock.Mock
}

func (m *mockSCIMRepo) Create(ctx context.Context, token *models.SCIMToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}
func (m *mockSCIMRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.SCIMToken, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SCIMToken), args.Error(1)
}
func (m *mockSCIMRepo) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.SCIMToken, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SCIMToken), args.Error(1)
}
func (m *mockSCIMRepo) Update(ctx context.Context, token *models.SCIMToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}
func (m *mockSCIMRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *mockSCIMRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *mockSCIMRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*models.SCIMToken, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SCIMToken), args.Error(1)
}
func (m *mockSCIMRepo) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	args := m.Called(ctx, id, ip)
	return args.Error(0)
}

// newSCIMTestService instantiates SCIMService with the mock repo and
// nil user/role repos (ValidateToken doesn't touch them).
func newSCIMTestService(repo *mockSCIMRepo) *SCIMService {
	return &SCIMService{scimRepo: repo}
}

// hashToken computes the storage-hash for a bearer token (matches the
// service's sha256 → hex shape). Tests assert on the hash repo-side
// rather than the bearer-side so they exercise the same path as
// ValidateToken.
func hashToken(t *testing.T, plain string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

func TestSCIMService_ValidateToken_NotFound(t *testing.T) {
	repo := new(mockSCIMRepo)
	svc := newSCIMTestService(repo)

	bearer := "scim_unknown-token"
	hashed := hashToken(t, bearer)
	repo.On("GetByTokenHash", mock.Anything, hashed).
		Return(nil, errSCIMNotFound{})

	_, err := svc.ValidateToken(context.Background(), bearer)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ValidateToken")
}

func TestSCIMService_ValidateToken_Active(t *testing.T) {
	repo := new(mockSCIMRepo)
	svc := newSCIMTestService(repo)

	bearer := "scim_active-token"
	hashed := hashToken(t, bearer)
	stored := &models.SCIMToken{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		TokenHash: hashed,
		IsActive:  true,
	}
	repo.On("GetByTokenHash", mock.Anything, hashed).Return(stored, nil)

	got, err := svc.ValidateToken(context.Background(), bearer)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, stored.ID, got.ID)
}

func TestSCIMService_ValidateToken_Revoked(t *testing.T) {
	// Pre-fix this case was indistinguishable from "unknown hash" at
	// the SOC log boundary — the repo's is_active filter ate the
	// branch. Post-fix the service emits a dedicated error.
	repo := new(mockSCIMRepo)
	svc := newSCIMTestService(repo)

	bearer := "scim_revoked-token"
	hashed := hashToken(t, bearer)
	stored := &models.SCIMToken{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		TokenHash: hashed,
		IsActive:  false, // revoked
	}
	repo.On("GetByTokenHash", mock.Anything, hashed).Return(stored, nil)

	_, err := svc.ValidateToken(context.Background(), bearer)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked",
		"revoked-token replay must surface a dedicated 'revoked' error so the SOC can pivot — not collapsed into the 'unknown hash' path")
}

func TestSCIMService_ValidateToken_Expired(t *testing.T) {
	repo := new(mockSCIMRepo)
	svc := newSCIMTestService(repo)

	bearer := "scim_expired-token"
	hashed := hashToken(t, bearer)
	expiredAt := time.Now().Add(-1 * time.Hour)
	stored := &models.SCIMToken{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		TokenHash: hashed,
		IsActive:  true,
		ExpiresAt: &expiredAt,
	}
	repo.On("GetByTokenHash", mock.Anything, hashed).Return(stored, nil)

	_, err := svc.ValidateToken(context.Background(), bearer)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestSCIMService_ValidateToken_RevokedTakesPrecedenceOverExpired(t *testing.T) {
	// When both is_active=false AND expires_at < now, revocation is
	// the more security-actionable signal — the SOC cares more about
	// "someone is replaying a recently-revoked token" than "this
	// expired thing got reused". Lock the precedence in a test.
	repo := new(mockSCIMRepo)
	svc := newSCIMTestService(repo)

	bearer := "scim_both-revoked-and-expired"
	hashed := hashToken(t, bearer)
	expiredAt := time.Now().Add(-24 * time.Hour)
	stored := &models.SCIMToken{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		TokenHash: hashed,
		IsActive:  false,
		ExpiresAt: &expiredAt,
	}
	repo.On("GetByTokenHash", mock.Anything, hashed).Return(stored, nil)

	_, err := svc.ValidateToken(context.Background(), bearer)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
	assert.NotContains(t, err.Error(), "expired")
}

// errSCIMNotFound is a sentinel mimicking the repo's "not found"
// error shape so the test can satisfy GetByTokenHash's signature
// without depending on the repo's internal message format.
type errSCIMNotFound struct{}

func (errSCIMNotFound) Error() string { return "SCIM token not found" }

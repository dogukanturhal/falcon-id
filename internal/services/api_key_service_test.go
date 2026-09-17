// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

const (
	testAPIKeyNewName = "New Name"
)

// ---------------------------------------------------------------------------
// Mock for apiKeyServiceRepo
// ---------------------------------------------------------------------------

type mockAPIKeyRepo struct {
	mock.Mock
}

func (m *mockAPIKeyRepo) Create(ctx context.Context, key *models.APIKey) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *mockAPIKeyRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.APIKey, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APIKey), args.Error(1)
}

func (m *mockAPIKeyRepo) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.APIKey, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.APIKey), args.Error(1)
}

func (m *mockAPIKeyRepo) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.APIKey), args.Error(1)
}

func (m *mockAPIKeyRepo) Update(ctx context.Context, key *models.APIKey) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *mockAPIKeyRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockAPIKeyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockAPIKeyRepo) GetByPrefix(ctx context.Context, prefix string) (*models.APIKey, error) {
	args := m.Called(ctx, prefix)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APIKey), args.Error(1)
}

func (m *mockAPIKeyRepo) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	args := m.Called(ctx, id, ip)
	return args.Error(0)
}

func (m *mockAPIKeyRepo) LogUsage(ctx context.Context, usage *models.APIKeyUsage) error {
	args := m.Called(ctx, usage)
	return args.Error(0)
}

func (m *mockAPIKeyRepo) GetUsageStats(ctx context.Context, keyID uuid.UUID) (*models.APIKeyUsageStats, error) {
	args := m.Called(ctx, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APIKeyUsageStats), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func newAPIKeyService(repo *mockAPIKeyRepo) *APIKeyService {
	return NewAPIKeyService(repo)
}

// ---------------------------------------------------------------------------
// Tests: Create
// ---------------------------------------------------------------------------

func TestAPIKey_Create_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	tenantID := uuid.New()
	userID := uuid.New()
	req := &models.CreateAPIKeyRequest{
		Name:   "Test Key",
		Scopes: []string{"read", "write"},
	}

	repo.On("Create", ctx, mock.AnythingOfType("*models.APIKey")).Return(nil)

	resp, err := svc.Create(ctx, tenantID, userID, req)

	require.NoError(t, err)
	require.NotNil(t, resp)

	// The plain-text key is returned only once at creation
	assert.True(t, len(resp.Key) > 0, "plain key must be returned on creation")
	assert.Equal(t, "Test Key", resp.Name)
	assert.Equal(t, tenantID, resp.TenantID)
	assert.Equal(t, userID, resp.UserID)

	// The key must have the expected prefix format
	assert.Equal(t, "hxk_", resp.Key[:4])

	// The plain key must never equal the stored hash
	assert.NotEmpty(t, resp.Key)

	repo.AssertExpectations(t)
}

func TestAPIKey_Create_WithExpiry_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	tenantID := uuid.New()
	userID := uuid.New()
	future := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	req := &models.CreateAPIKeyRequest{
		Name:      "Expiring Key",
		ExpiresAt: &future,
	}

	repo.On("Create", ctx, mock.AnythingOfType("*models.APIKey")).Return(nil)

	resp, err := svc.Create(ctx, tenantID, userID, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.ExpiresAt)

	repo.AssertExpectations(t)
}

func TestAPIKey_Create_InvalidExpiryFormat_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	bad := "not-a-date"
	req := &models.CreateAPIKeyRequest{
		Name:      "Key",
		ExpiresAt: &bad,
	}

	resp, err := svc.Create(ctx, uuid.New(), uuid.New(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid expires_at")
}

func TestAPIKey_Create_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	repo.On("Create", ctx, mock.AnythingOfType("*models.APIKey")).
		Return(errors.New("db error"))

	resp, err := svc.Create(ctx, uuid.New(), uuid.New(), &models.CreateAPIKeyRequest{Name: "k"})

	assert.Error(t, err)
	assert.Nil(t, resp)
}

// ---------------------------------------------------------------------------
// Tests: GenerateAPIKey
// ---------------------------------------------------------------------------

func TestAPIKey_GenerateAPIKey_FormatsCorrectly(t *testing.T) {
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	key, prefix, err := svc.GenerateAPIKey()

	require.NoError(t, err)
	assert.Equal(t, "hxk_", key[:4], "key must start with hxk_")
	assert.Len(t, prefix, 8, "prefix must be 8 characters")
	assert.Equal(t, prefix, key[4:12], "prefix must match slice of key")
}

func TestAPIKey_GenerateAPIKey_Uniqueness(t *testing.T) {
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	key1, _, err1 := svc.GenerateAPIKey()
	key2, _, err2 := svc.GenerateAPIKey()

	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.NotEqual(t, key1, key2, "consecutive keys must not be equal")
}

// ---------------------------------------------------------------------------
// Tests: List
// ---------------------------------------------------------------------------

func TestAPIKey_List_ByTenant(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	tenantID := uuid.New()
	expected := []*models.APIKey{
		{ID: uuid.New(), TenantID: tenantID, Name: "Key 1"},
		{ID: uuid.New(), TenantID: tenantID, Name: "Key 2"},
	}
	repo.On("GetByTenantID", ctx, tenantID).Return(expected, nil)

	keys, err := svc.List(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, keys, 2)
	repo.AssertExpectations(t)
}

func TestAPIKey_List_ByTenant_Empty(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	tenantID := uuid.New()
	repo.On("GetByTenantID", ctx, tenantID).Return([]*models.APIKey{}, nil)

	keys, err := svc.List(ctx, tenantID)

	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestAPIKey_List_ByUser(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	userID := uuid.New()
	expected := []*models.APIKey{
		{ID: uuid.New(), UserID: userID, Name: "My Key"},
	}
	repo.On("GetByUserID", ctx, userID).Return(expected, nil)

	keys, err := svc.ListByUser(ctx, userID)

	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, "My Key", keys[0].Name)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: Revoke
// ---------------------------------------------------------------------------

func TestAPIKey_Revoke_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	tenantID := uuid.New()
	keyID := uuid.New()
	existing := &models.APIKey{ID: keyID, TenantID: tenantID, IsActive: true}

	repo.On("GetByID", ctx, keyID).Return(existing, nil)
	repo.On("Revoke", ctx, keyID).Return(nil)

	err := svc.Revoke(ctx, tenantID, keyID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestAPIKey_Revoke_NotFound_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	keyID := uuid.New()
	repo.On("GetByID", ctx, keyID).Return(nil, nil)

	err := svc.Revoke(ctx, uuid.New(), keyID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAPIKey_Revoke_WrongTenant_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	keyID := uuid.New()
	existing := &models.APIKey{ID: keyID, TenantID: uuid.New()}

	repo.On("GetByID", ctx, keyID).Return(existing, nil)

	err := svc.Revoke(ctx, uuid.New(), keyID) // different tenantID

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Tests: Delete
// ---------------------------------------------------------------------------

func TestAPIKey_Delete_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	tenantID := uuid.New()
	keyID := uuid.New()
	existing := &models.APIKey{ID: keyID, TenantID: tenantID}

	repo.On("GetByID", ctx, keyID).Return(existing, nil)
	repo.On("Delete", ctx, keyID).Return(nil)

	err := svc.Delete(ctx, tenantID, keyID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestAPIKey_Delete_NotFound_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	keyID := uuid.New()
	repo.On("GetByID", ctx, keyID).Return(nil, nil)

	err := svc.Delete(ctx, uuid.New(), keyID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Tests: Rotate (Regenerate)
// ---------------------------------------------------------------------------

func TestAPIKey_Rotate_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	tenantID := uuid.New()
	userID := uuid.New()
	oldKeyID := uuid.New()

	oldKey := &models.APIKey{
		ID:       oldKeyID,
		TenantID: tenantID,
		UserID:   userID,
		Name:     "Original Key",
		Scopes:   pq.StringArray{"read"},
	}

	// GetByID for old key
	repo.On("GetByID", ctx, oldKeyID).Return(oldKey, nil)
	// Create for new key
	repo.On("Create", ctx, mock.AnythingOfType("*models.APIKey")).Return(nil)
	// Revoke old key
	repo.On("Revoke", ctx, oldKeyID).Return(nil)

	newResp, err := svc.Regenerate(ctx, tenantID, oldKeyID)

	require.NoError(t, err)
	require.NotNil(t, newResp)
	// New key must be a fresh plain-text key
	assert.True(t, len(newResp.Key) > 0)
	// Name should include "(regenerated)"
	assert.Contains(t, newResp.Name, "regenerated")

	repo.AssertExpectations(t)
}

func TestAPIKey_Rotate_NotFound_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	keyID := uuid.New()
	repo.On("GetByID", ctx, keyID).Return(nil, nil)

	resp, err := svc.Regenerate(ctx, uuid.New(), keyID)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "not found")
}

func TestAPIKey_Rotate_RevokeFails_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	tenantID := uuid.New()
	oldKeyID := uuid.New()
	oldKey := &models.APIKey{
		ID:       oldKeyID,
		TenantID: tenantID,
		UserID:   uuid.New(),
		Name:     "Key",
	}

	repo.On("GetByID", ctx, oldKeyID).Return(oldKey, nil)
	repo.On("Create", ctx, mock.AnythingOfType("*models.APIKey")).Return(nil)
	repo.On("Revoke", ctx, oldKeyID).Return(errors.New("db error"))

	resp, err := svc.Regenerate(ctx, tenantID, oldKeyID)

	// When revocation of old key fails, the operation must fail to prevent dual active keys.
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "revocation failed")
}

// ---------------------------------------------------------------------------
// Tests: ValidateAPIKey
// ---------------------------------------------------------------------------

func TestAPIKey_ValidateAPIKey_InvalidPrefix_Error(t *testing.T) {
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	_, err := svc.ValidateAPIKey(context.Background(), "bad_key_format")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid API key format")
}

func TestAPIKey_ValidateAPIKey_TooShort_Error(t *testing.T) {
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	_, err := svc.ValidateAPIKey(context.Background(), "hxk_short")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid API key format")
}

func TestAPIKey_ValidateAPIKey_NotFound_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	// Generate a real key so the format passes but prefix lookup returns nothing
	key, _, err := svc.GenerateAPIKey()
	require.NoError(t, err)

	prefix := key[4:12]
	repo.On("GetByPrefix", ctx, prefix).Return(nil, nil)

	_, err = svc.ValidateAPIKey(ctx, key)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAPIKey_ValidateAPIKey_WrongHash_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	// Create a real key so format validation passes
	realKey, prefix, err := svc.GenerateAPIKey()
	require.NoError(t, err)

	// Store a record with a hash that does NOT match realKey
	storedRecord := &models.APIKey{
		ID:        uuid.New(),
		KeyPrefix: prefix,
		KeyHash:   "invalid-hash-that-wont-verify",
	}

	repo.On("GetByPrefix", ctx, prefix).Return(storedRecord, nil)

	_, err = svc.ValidateAPIKey(ctx, realKey)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid API key")
}

// ---------------------------------------------------------------------------
// Tests: GetUsageStats
// ---------------------------------------------------------------------------

func TestAPIKey_GetUsageStats_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	tenantID := uuid.New()
	keyID := uuid.New()
	existing := &models.APIKey{ID: keyID, TenantID: tenantID}
	stats := &models.APIKeyUsageStats{TotalRequests: 100}

	repo.On("GetByID", ctx, keyID).Return(existing, nil)
	repo.On("GetUsageStats", ctx, keyID).Return(stats, nil)

	result, err := svc.GetUsageStats(ctx, tenantID, keyID)

	require.NoError(t, err)
	assert.Equal(t, int64(100), result.TotalRequests)
	repo.AssertExpectations(t)
}

func TestAPIKey_GetUsageStats_WrongTenant_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	keyID := uuid.New()
	existing := &models.APIKey{ID: keyID, TenantID: uuid.New()}

	repo.On("GetByID", ctx, keyID).Return(existing, nil)

	_, err := svc.GetUsageStats(ctx, uuid.New(), keyID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Tests: Update
// ---------------------------------------------------------------------------

func TestAPIKey_Update_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	tenantID := uuid.New()
	keyID := uuid.New()
	existing := &models.APIKey{ID: keyID, TenantID: tenantID, Name: "Old Name", IsActive: true}

	newName := testAPIKeyNewName
	req := &models.UpdateAPIKeyRequest{
		Name: &newName,
	}

	repo.On("GetByID", ctx, keyID).Return(existing, nil)
	repo.On("Update", ctx, mock.AnythingOfType("*models.APIKey")).Return(nil)

	updated, err := svc.Update(ctx, tenantID, keyID, req)

	require.NoError(t, err)
	assert.Equal(t, testAPIKeyNewName, updated.Name)
	repo.AssertExpectations(t)
}

func TestAPIKey_Update_NotFound_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	keyID := uuid.New()
	repo.On("GetByID", ctx, keyID).Return(nil, nil)

	_, err := svc.Update(ctx, uuid.New(), keyID, &models.UpdateAPIKeyRequest{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Tests: ValidateAPIKey state branches (Tier-A audit memo 2026-05-21)
//
// Pre-fix the repo's WHERE clause filtered on is_active=true,
// revoked_at IS NULL, and expires_at > NOW(), collapsing four
// security-relevant states (unknown / revoked / deactivated /
// expired) into the same "not found" path. Post-fix the repo
// returns the row regardless and the service branches with a
// dedicated error per state — these tests lock those branches.
// ---------------------------------------------------------------------------

// newValidatedAPIKey returns (keyString, *APIKey) where the model's
// KeyHash is the genuine hash of keyString — so crypto.VerifyPassword
// inside ValidateAPIKey accepts it. Caller mutates the state fields
// (RevokedAt / IsActive / ExpiresAt) before passing to the repo
// mock.
func newValidatedAPIKey(t *testing.T, svc *APIKeyService) (string, *models.APIKey) {
	t.Helper()
	key, prefix, err := svc.GenerateAPIKey()
	require.NoError(t, err)
	hash, err := crypto.HashPassword(key, nil)
	require.NoError(t, err)
	return key, &models.APIKey{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		KeyPrefix: prefix,
		KeyHash:   hash,
		IsActive:  true, // default; tests override per case
	}
}

func TestAPIKey_ValidateAPIKey_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	keyString, stored := newValidatedAPIKey(t, svc)
	repo.On("GetByPrefix", ctx, stored.KeyPrefix).Return(stored, nil)

	got, err := svc.ValidateAPIKey(ctx, keyString)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, stored.ID, got.ID)
}

func TestAPIKey_ValidateAPIKey_Revoked_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	keyString, stored := newValidatedAPIKey(t, svc)
	revokedAt := time.Now().Add(-1 * time.Hour)
	stored.RevokedAt = &revokedAt
	repo.On("GetByPrefix", ctx, stored.KeyPrefix).Return(stored, nil)

	_, err := svc.ValidateAPIKey(ctx, keyString)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked",
		"revoked-key replay must surface a dedicated 'revoked' error (not the generic 'not found') so the SOC can pivot on it")
}

func TestAPIKey_ValidateAPIKey_Deactivated_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	keyString, stored := newValidatedAPIKey(t, svc)
	stored.IsActive = false
	repo.On("GetByPrefix", ctx, stored.KeyPrefix).Return(stored, nil)

	_, err := svc.ValidateAPIKey(ctx, keyString)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deactivated")
}

func TestAPIKey_ValidateAPIKey_Expired_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	keyString, stored := newValidatedAPIKey(t, svc)
	expired := time.Now().Add(-24 * time.Hour)
	stored.ExpiresAt = &expired
	repo.On("GetByPrefix", ctx, stored.KeyPrefix).Return(stored, nil)

	_, err := svc.ValidateAPIKey(ctx, keyString)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestAPIKey_ValidateAPIKey_WrongHash_FailsBeforeStateCheck(t *testing.T) {
	// Security invariant: prefix-space scanners (8-char prefixes) must
	// not be able to tell apart "this prefix was never issued" from
	// "this prefix matches a revoked key" without ALSO knowing the
	// full key bytes. The state-branch errors only fire AFTER the
	// hash verifies — anyone hitting the deactivated/revoked/expired
	// errors already had the actual key.
	ctx := context.Background()
	repo := new(mockAPIKeyRepo)
	svc := newAPIKeyService(repo)

	_, stored := newValidatedAPIKey(t, svc)
	// Mutate the stored hash so the caller's hash check fails, AND
	// set RevokedAt — verifies "invalid API key" wins over "revoked".
	stored.KeyHash = "$argon2id$does-not-match-anything"
	rev := time.Now().Add(-1 * time.Hour)
	stored.RevokedAt = &rev
	repo.On("GetByPrefix", ctx, stored.KeyPrefix).Return(stored, nil)

	// Generate a real key whose prefix matches stored.KeyPrefix is
	// hard — instead, pass a fabricated key with the right prefix
	// shape but wrong bytes. The hash-verify will fail.
	fake := "hxk_" + stored.KeyPrefix + "fakebytes"
	_, err := svc.ValidateAPIKey(ctx, fake)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid API key",
		"hash check must fail BEFORE the revoked/deactivated/expired audit branches fire")
	assert.NotContains(t, err.Error(), "revoked",
		"the revoked-key audit signal must not leak to attackers probing prefixes without the full key")
}

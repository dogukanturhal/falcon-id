// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mock: passwordPolicyServiceRepo
// ---------------------------------------------------------------------------

type MockPasswordPolicyRepo struct {
	mock.Mock
}

func (m *MockPasswordPolicyRepo) GetByTenantID(ctx context.Context, tenantID uuid.UUID) (*models.PasswordPolicy, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PasswordPolicy), args.Error(1)
}

func (m *MockPasswordPolicyRepo) Upsert(ctx context.Context, policy *models.PasswordPolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *MockPasswordPolicyRepo) IsCommonPassword(ctx context.Context, passwordHash string) (bool, error) {
	args := m.Called(ctx, passwordHash)
	return args.Bool(0), args.Error(1)
}

func (m *MockPasswordPolicyRepo) GetPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]models.PasswordHistory, error) {
	args := m.Called(ctx, userID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.PasswordHistory), args.Error(1)
}

func (m *MockPasswordPolicyRepo) AddPasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	args := m.Called(ctx, userID, passwordHash)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newPasswordPolicyService(repo *MockPasswordPolicyRepo) *PasswordPolicyService {
	return NewPasswordPolicyService(repo)
}

func defaultPolicy(tenantID uuid.UUID) *models.PasswordPolicy {
	return models.DefaultPasswordPolicy(tenantID)
}

// ---------------------------------------------------------------------------
// Tests: GetPolicy
// ---------------------------------------------------------------------------

func TestPasswordPolicyService_GetPolicy_ReturnsTenantPolicy(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.PasswordPolicy{
		ID:        uuid.New(),
		TenantID:  tenantID,
		MinLength: 12,
	}

	repo.On("GetByTenantID", ctx, tenantID).Return(policy, nil)

	result, err := svc.GetPolicy(ctx, tenantID)

	require.NoError(t, err)
	assert.Equal(t, 12, result.MinLength)
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_GetPolicy_ReturnsDefaultWhenNone(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	repo.On("GetByTenantID", ctx, tenantID).Return((*models.PasswordPolicy)(nil), nil)

	result, err := svc.GetPolicy(ctx, tenantID)

	require.NoError(t, err)
	require.NotNil(t, result)
	// Default policy has MinLength=8
	assert.Equal(t, 8, result.MinLength)
	assert.Equal(t, tenantID, result.TenantID)
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_GetPolicy_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	repo.On("GetByTenantID", ctx, tenantID).Return((*models.PasswordPolicy)(nil), errors.New("db failure"))

	result, err := svc.GetPolicy(ctx, tenantID)

	assert.Error(t, err)
	assert.Nil(t, result)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: UpdatePolicy
// ---------------------------------------------------------------------------

func TestPasswordPolicyService_UpdatePolicy_ValidSettings(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	userID := uuid.New()

	existing := defaultPolicy(tenantID)
	repo.On("GetByTenantID", ctx, tenantID).Return(existing, nil)
	repo.On("Upsert", ctx, mock.AnythingOfType("*models.PasswordPolicy")).Return(nil)

	minLen := 14
	requireUpper := false
	req := &models.PasswordPolicyRequest{
		MinLength:        &minLen,
		RequireUppercase: &requireUpper,
	}

	policy, err := svc.UpdatePolicy(ctx, tenantID, req, userID)

	require.NoError(t, err)
	assert.Equal(t, 14, policy.MinLength)
	assert.False(t, policy.RequireUppercase)
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_UpdatePolicy_MinLengthTooSmall(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	userID := uuid.New()

	existing := defaultPolicy(tenantID)
	repo.On("GetByTenantID", ctx, tenantID).Return(existing, nil)

	minLen := 4 // below 6
	req := &models.PasswordPolicyRequest{MinLength: &minLen}

	policy, err := svc.UpdatePolicy(ctx, tenantID, req, userID)

	assert.Error(t, err)
	assert.Nil(t, policy)
	assert.Contains(t, err.Error(), "cannot be less than 6")
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_UpdatePolicy_MaxLengthLessThanMin(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	userID := uuid.New()

	existing := defaultPolicy(tenantID) // MinLength = 8
	repo.On("GetByTenantID", ctx, tenantID).Return(existing, nil)

	maxLen := 6 // less than current min 8
	req := &models.PasswordPolicyRequest{MaxLength: &maxLen}

	policy, err := svc.UpdatePolicy(ctx, tenantID, req, userID)

	assert.Error(t, err)
	assert.Nil(t, policy)
	assert.Contains(t, err.Error(), "cannot be less than minimum")
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_UpdatePolicy_InvalidLockoutThreshold(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	userID := uuid.New()

	existing := defaultPolicy(tenantID)
	repo.On("GetByTenantID", ctx, tenantID).Return(existing, nil)

	// lockout threshold max is 20
	threshold := 25
	req := &models.PasswordPolicyRequest{LockoutThreshold: &threshold}

	policy, err := svc.UpdatePolicy(ctx, tenantID, req, userID)

	assert.Error(t, err)
	assert.Nil(t, policy)
	assert.Contains(t, err.Error(), "lockout threshold must be between")
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_UpdatePolicy_CreatesDefaultWhenNone(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	userID := uuid.New()

	repo.On("GetByTenantID", ctx, tenantID).Return((*models.PasswordPolicy)(nil), nil)
	repo.On("Upsert", ctx, mock.AnythingOfType("*models.PasswordPolicy")).Return(nil)

	minLen := 10
	req := &models.PasswordPolicyRequest{MinLength: &minLen}

	policy, err := svc.UpdatePolicy(ctx, tenantID, req, userID)

	require.NoError(t, err)
	assert.Equal(t, 10, policy.MinLength)
	assert.Equal(t, &userID, policy.CreatedBy)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ValidatePassword
// ---------------------------------------------------------------------------

func TestPasswordPolicyService_ValidatePassword_MeetsPolicy(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.PasswordPolicy{
		TenantID:                tenantID,
		MinLength:               8,
		RequireUppercase:        true,
		RequireLowercase:        true,
		RequireNumbers:          true,
		RequireSpecial:          false,
		DisallowUsername:        false,
		DisallowCommonPasswords: false,
	}

	repo.On("GetByTenantID", ctx, tenantID).Return(policy, nil)

	err := svc.ValidatePassword(ctx, tenantID, "SecurePass1", "testuser", nil)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_ValidatePassword_TooShort(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.PasswordPolicy{
		TenantID:  tenantID,
		MinLength: 12,
	}

	repo.On("GetByTenantID", ctx, tenantID).Return(policy, nil)

	err := svc.ValidatePassword(ctx, tenantID, "short", "user", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least 12")
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_ValidatePassword_MissingUppercase(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.PasswordPolicy{
		TenantID:         tenantID,
		MinLength:        8,
		RequireUppercase: true,
	}

	repo.On("GetByTenantID", ctx, tenantID).Return(policy, nil)

	err := svc.ValidatePassword(ctx, tenantID, "alllowercase1", "user", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "uppercase")
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_ValidatePassword_MissingLowercase(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.PasswordPolicy{
		TenantID:         tenantID,
		MinLength:        8,
		RequireLowercase: true,
	}

	repo.On("GetByTenantID", ctx, tenantID).Return(policy, nil)

	err := svc.ValidatePassword(ctx, tenantID, "ALLUPPERCASE1", "user", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "lowercase")
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_ValidatePassword_MissingDigit(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.PasswordPolicy{
		TenantID:       tenantID,
		MinLength:      8,
		RequireNumbers: true,
	}

	repo.On("GetByTenantID", ctx, tenantID).Return(policy, nil)

	err := svc.ValidatePassword(ctx, tenantID, "NoNumbers!", "user", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "number")
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_ValidatePassword_MissingSpecial(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.PasswordPolicy{
		TenantID:       tenantID,
		MinLength:      8,
		RequireSpecial: true,
	}

	repo.On("GetByTenantID", ctx, tenantID).Return(policy, nil)

	err := svc.ValidatePassword(ctx, tenantID, "NoSpecial123", "user", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "special")
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_ValidatePassword_ContainsUsername(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.PasswordPolicy{
		TenantID:         tenantID,
		MinLength:        8,
		DisallowUsername: true,
	}

	repo.On("GetByTenantID", ctx, tenantID).Return(policy, nil)

	err := svc.ValidatePassword(ctx, tenantID, "johnsmith123", "johnsmith", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username")
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_ValidatePassword_CommonPassword(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.PasswordPolicy{
		TenantID:                tenantID,
		MinLength:               8,
		DisallowCommonPasswords: true,
	}

	repo.On("GetByTenantID", ctx, tenantID).Return(policy, nil)
	// Mock IsCommonPassword to return true for any hash
	repo.On("IsCommonPassword", ctx, mock.AnythingOfType("string")).Return(true, nil)

	err := svc.ValidatePassword(ctx, tenantID, "password123", "user", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too common")
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_ValidatePassword_ExceedsMaxLength(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	maxLen := 20
	policy := &models.PasswordPolicy{
		TenantID:  tenantID,
		MinLength: 8,
		MaxLength: &maxLen,
	}

	repo.On("GetByTenantID", ctx, tenantID).Return(policy, nil)

	// 25 chars — exceeds MaxLength of 20
	err := svc.ValidatePassword(ctx, tenantID, "ThisPasswordIsWayTooLong123", "user", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceed")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetLockoutSettings
// ---------------------------------------------------------------------------

func TestPasswordPolicyService_GetLockoutSettings_ReturnsValues(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.PasswordPolicy{
		TenantID:               tenantID,
		MinLength:              8,
		LockoutThreshold:       3,
		LockoutDurationMinutes: 15,
		LockoutIncrementFactor: 2.0,
	}

	repo.On("GetByTenantID", ctx, tenantID).Return(policy, nil)

	threshold, duration, factor, err := svc.GetLockoutSettings(ctx, tenantID)

	require.NoError(t, err)
	assert.Equal(t, 3, threshold)
	assert.Equal(t, 15, duration)
	assert.Equal(t, 2.0, factor)
	repo.AssertExpectations(t)
}

func TestPasswordPolicyService_GetLockoutSettings_DefaultsOnError(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	tenantID := uuid.New()
	repo.On("GetByTenantID", ctx, tenantID).Return((*models.PasswordPolicy)(nil), errors.New("db error"))

	threshold, duration, factor, err := svc.GetLockoutSettings(ctx, tenantID)

	// Should return defaults even on error
	assert.Error(t, err)
	assert.Equal(t, 5, threshold)
	assert.Equal(t, 30, duration)
	assert.Equal(t, 1.0, factor)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: AddToPasswordHistory
// ---------------------------------------------------------------------------

func TestPasswordPolicyService_AddToPasswordHistory_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockPasswordPolicyRepo)
	svc := newPasswordPolicyService(repo)

	userID := uuid.New()
	hash := "argon2hash:example"

	repo.On("AddPasswordHistory", ctx, userID, hash).Return(nil)

	err := svc.AddToPasswordHistory(ctx, userID, hash)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ValidatePasswordAgainstPolicy (direct policy struct)
// ---------------------------------------------------------------------------

func TestPasswordPolicyService_ValidateAgainstPolicy_Table(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		password string
		username string
		policy   *models.PasswordPolicy
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid password",
			password: "ValidPass1",
			username: "user",
			policy: &models.PasswordPolicy{
				MinLength:        8,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
			},
			wantErr: false,
		},
		{
			name:     "too short",
			password: "Ab1",
			username: "user",
			policy:   &models.PasswordPolicy{MinLength: 8},
			wantErr:  true,
			errMsg:   "at least 8",
		},
		{
			name:     "missing uppercase",
			password: "lowercase123",
			username: "user",
			policy: &models.PasswordPolicy{
				MinLength:        8,
				RequireUppercase: true,
			},
			wantErr: true,
			errMsg:  "uppercase",
		},
		{
			name:     "missing digit",
			password: "NoDigitsHere",
			username: "user",
			policy: &models.PasswordPolicy{
				MinLength:      8,
				RequireNumbers: true,
			},
			wantErr: true,
			errMsg:  "number",
		},
		{
			name:     "contains username",
			password: "alice12345",
			username: "alice",
			policy: &models.PasswordPolicy{
				MinLength:        8,
				DisallowUsername: true,
			},
			wantErr: true,
			errMsg:  "username",
		},
		{
			name:     "special char required and present",
			password: "Pass@word1",
			username: "user",
			policy: &models.PasswordPolicy{
				MinLength:      8,
				RequireSpecial: true,
			},
			wantErr: false,
		},
		{
			name:     "special char required but missing",
			password: "Password123",
			username: "user",
			policy: &models.PasswordPolicy{
				MinLength:      8,
				RequireSpecial: true,
			},
			wantErr: true,
			errMsg:  "special",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := new(MockPasswordPolicyRepo)
			svc := newPasswordPolicyService(repo)

			err := svc.ValidatePasswordAgainstPolicy(ctx, tc.password, tc.username, nil, tc.policy)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

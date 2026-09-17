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
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// ---------------------------------------------------------------------------
// Mock for serviceAccountServiceRepo
// ---------------------------------------------------------------------------

type mockServiceAccountRepo struct {
	mock.Mock
}

func (m *mockServiceAccountRepo) Create(ctx context.Context, sa *models.ServiceAccount) error {
	args := m.Called(ctx, sa)
	return args.Error(0)
}

func (m *mockServiceAccountRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.ServiceAccount, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ServiceAccount), args.Error(1)
}

func (m *mockServiceAccountRepo) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.ServiceAccount, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ServiceAccount), args.Error(1)
}

func (m *mockServiceAccountRepo) Update(ctx context.Context, sa *models.ServiceAccount) error {
	args := m.Called(ctx, sa)
	return args.Error(0)
}

func (m *mockServiceAccountRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockServiceAccountRepo) UpdateSecret(ctx context.Context, id uuid.UUID, secretHash string) error {
	args := m.Called(ctx, id, secretHash)
	return args.Error(0)
}

func (m *mockServiceAccountRepo) RevokeAllTokens(ctx context.Context, serviceAccountID uuid.UUID) error {
	args := m.Called(ctx, serviceAccountID)
	return args.Error(0)
}

func (m *mockServiceAccountRepo) GetByClientID(ctx context.Context, clientID string) (*models.ServiceAccount, error) {
	args := m.Called(ctx, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ServiceAccount), args.Error(1)
}

func (m *mockServiceAccountRepo) CreateToken(ctx context.Context, token *models.ServiceAccountToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *mockServiceAccountRepo) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	args := m.Called(ctx, id, ip)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Mock for serviceAccountRoleRepo
// ---------------------------------------------------------------------------

type mockServiceAccountRoleRepo struct {
	mock.Mock
}

func (m *mockServiceAccountRoleRepo) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func newServiceAccountService(repo *mockServiceAccountRepo) *ServiceAccountService {
	return newServiceAccountServiceWithRoles(repo, new(mockServiceAccountRoleRepo))
}

func newServiceAccountServiceWithRoles(repo *mockServiceAccountRepo, roleRepo *mockServiceAccountRoleRepo) *ServiceAccountService {
	cfg := &config.Config{
		JWTSecret: "test-jwt-secret-at-least-32-chars-long!!",
	}
	return NewServiceAccountService(repo, roleRepo, cfg)
}

// ---------------------------------------------------------------------------
// Tests: Create
// ---------------------------------------------------------------------------

func TestServiceAccount_Create_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	tenantID := uuid.New()
	userID := uuid.New()
	req := &models.CreateServiceAccountRequest{
		Name:    "CI Bot",
		RoleIDs: []string{"role-id-1"},
	}

	repo.On("Create", ctx, mock.AnythingOfType("*models.ServiceAccount")).Return(nil)

	resp, err := svc.Create(ctx, tenantID, userID, req)

	require.NoError(t, err)
	require.NotNil(t, resp)

	// Client secret must be returned only on creation
	assert.True(t, len(resp.ClientSecret) > 0, "client secret must be returned at creation")
	assert.Equal(t, "hxs_", resp.ClientSecret[:4], "secret must have hxs_ prefix")
	assert.Equal(t, "CI Bot", resp.Name)

	// ClientID must be populated by service
	assert.True(t, len(resp.ClientID) > 0)
	assert.Equal(t, "sa_", resp.ClientID[:3])

	repo.AssertExpectations(t)
}

func TestServiceAccount_Create_DefaultTokenLifetime(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	req := &models.CreateServiceAccountRequest{
		Name:    "Bot",
		RoleIDs: []string{"r1"},
	}

	repo.On("Create", ctx, mock.AnythingOfType("*models.ServiceAccount")).Return(nil)

	resp, err := svc.Create(ctx, uuid.New(), uuid.New(), req)

	require.NoError(t, err)
	// Default token lifetime is 60 minutes when not specified
	assert.Equal(t, 60, resp.TokenLifetimeMinutes)
}

func TestServiceAccount_Create_CustomTokenLifetime(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	lifetime := 120
	req := &models.CreateServiceAccountRequest{
		Name:                 "Bot",
		RoleIDs:              []string{"r1"},
		TokenLifetimeMinutes: &lifetime,
	}

	repo.On("Create", ctx, mock.AnythingOfType("*models.ServiceAccount")).Return(nil)

	resp, err := svc.Create(ctx, uuid.New(), uuid.New(), req)

	require.NoError(t, err)
	assert.Equal(t, 120, resp.TokenLifetimeMinutes)
}

func TestServiceAccount_Create_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	repo.On("Create", ctx, mock.AnythingOfType("*models.ServiceAccount")).
		Return(errors.New("db error"))

	resp, err := svc.Create(ctx, uuid.New(), uuid.New(), &models.CreateServiceAccountRequest{
		Name:    "Bot",
		RoleIDs: []string{"r1"},
	})

	assert.Error(t, err)
	assert.Nil(t, resp)
}

// ---------------------------------------------------------------------------
// Tests: GetByID
// ---------------------------------------------------------------------------

func TestServiceAccount_GetByID_Found(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	saID := uuid.New()
	expected := &models.ServiceAccount{ID: saID, Name: "Test Bot"}

	repo.On("GetByID", ctx, saID).Return(expected, nil)

	sa, err := svc.GetByID(ctx, saID)

	require.NoError(t, err)
	require.NotNil(t, sa)
	assert.Equal(t, "Test Bot", sa.Name)
	repo.AssertExpectations(t)
}

func TestServiceAccount_GetByID_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	saID := uuid.New()
	repo.On("GetByID", ctx, saID).Return(nil, nil)

	sa, err := svc.GetByID(ctx, saID)

	require.NoError(t, err)
	assert.Nil(t, sa)
}

func TestServiceAccount_GetByID_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	saID := uuid.New()
	repo.On("GetByID", ctx, saID).Return(nil, errors.New("db error"))

	sa, err := svc.GetByID(ctx, saID)

	assert.Error(t, err)
	assert.Nil(t, sa)
}

// ---------------------------------------------------------------------------
// Tests: Update
// ---------------------------------------------------------------------------

func TestServiceAccount_Update_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	tenantID := uuid.New()
	saID := uuid.New()
	existing := &models.ServiceAccount{
		ID:       saID,
		TenantID: tenantID,
		Name:     "Old Name",
		IsActive: true,
	}

	newName := "New Name"
	req := &models.UpdateServiceAccountRequest{Name: &newName}

	repo.On("GetByID", ctx, saID).Return(existing, nil)
	repo.On("Update", ctx, mock.AnythingOfType("*models.ServiceAccount")).Return(nil)

	updated, err := svc.Update(ctx, tenantID, saID, req)

	require.NoError(t, err)
	assert.Equal(t, "New Name", updated.Name)
	repo.AssertExpectations(t)
}

func TestServiceAccount_Update_NotFound_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	saID := uuid.New()
	repo.On("GetByID", ctx, saID).Return(nil, nil)

	_, err := svc.Update(ctx, uuid.New(), saID, &models.UpdateServiceAccountRequest{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestServiceAccount_Update_WrongTenant_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	saID := uuid.New()
	existing := &models.ServiceAccount{ID: saID, TenantID: uuid.New()}

	repo.On("GetByID", ctx, saID).Return(existing, nil)

	_, err := svc.Update(ctx, uuid.New(), saID, &models.UpdateServiceAccountRequest{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Tests: Delete
// ---------------------------------------------------------------------------

func TestServiceAccount_Delete_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	tenantID := uuid.New()
	saID := uuid.New()
	existing := &models.ServiceAccount{ID: saID, TenantID: tenantID}

	repo.On("GetByID", ctx, saID).Return(existing, nil)
	repo.On("Delete", ctx, saID).Return(nil)

	err := svc.Delete(ctx, tenantID, saID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestServiceAccount_Delete_NotFound_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	saID := uuid.New()
	repo.On("GetByID", ctx, saID).Return(nil, nil)

	err := svc.Delete(ctx, uuid.New(), saID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestServiceAccount_Delete_WrongTenant_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	saID := uuid.New()
	existing := &models.ServiceAccount{ID: saID, TenantID: uuid.New()}

	repo.On("GetByID", ctx, saID).Return(existing, nil)

	err := svc.Delete(ctx, uuid.New(), saID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Tests: List
// ---------------------------------------------------------------------------

func TestServiceAccount_List_ByTenant(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	tenantID := uuid.New()
	expected := []*models.ServiceAccount{
		{ID: uuid.New(), TenantID: tenantID, Name: "Bot 1"},
		{ID: uuid.New(), TenantID: tenantID, Name: "Bot 2"},
	}
	repo.On("GetByTenantID", ctx, tenantID).Return(expected, nil)

	list, err := svc.List(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, list, 2)
	repo.AssertExpectations(t)
}

func TestServiceAccount_List_Empty(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	tenantID := uuid.New()
	repo.On("GetByTenantID", ctx, tenantID).Return([]*models.ServiceAccount{}, nil)

	list, err := svc.List(ctx, tenantID)

	require.NoError(t, err)
	assert.Empty(t, list)
}

// ---------------------------------------------------------------------------
// Tests: RegenerateSecret
// ---------------------------------------------------------------------------

func TestServiceAccount_RegenerateSecret_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	tenantID := uuid.New()
	saID := uuid.New()
	existing := &models.ServiceAccount{
		ID:       saID,
		TenantID: tenantID,
		Name:     "Bot",
	}

	repo.On("GetByID", ctx, saID).Return(existing, nil)
	repo.On("UpdateSecret", ctx, saID, mock.AnythingOfType("string")).Return(nil)
	repo.On("RevokeAllTokens", ctx, saID).Return(nil)

	resp, err := svc.RegenerateSecret(ctx, tenantID, saID)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, len(resp.ClientSecret) > 0)
	assert.Equal(t, "hxs_", resp.ClientSecret[:4])
	repo.AssertExpectations(t)
}

func TestServiceAccount_RegenerateSecret_NotFound_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	saID := uuid.New()
	repo.On("GetByID", ctx, saID).Return(nil, nil)

	resp, err := svc.RegenerateSecret(ctx, uuid.New(), saID)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Tests: GenerateClientCredentials
// ---------------------------------------------------------------------------

func TestServiceAccount_GenerateClientCredentials_Format(t *testing.T) {
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	clientID, secret, err := svc.GenerateClientCredentials()

	require.NoError(t, err)
	assert.Equal(t, "sa_", clientID[:3])
	assert.Equal(t, "hxs_", secret[:4])
}

func TestServiceAccount_GenerateClientCredentials_Uniqueness(t *testing.T) {
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	id1, sec1, _ := svc.GenerateClientCredentials()
	id2, sec2, _ := svc.GenerateClientCredentials()

	assert.NotEqual(t, id1, id2, "consecutive client IDs must differ")
	assert.NotEqual(t, sec1, sec2, "consecutive secrets must differ")
}

// ---------------------------------------------------------------------------
// Tests: IsEndpointAllowed
// ---------------------------------------------------------------------------

func TestServiceAccount_IsEndpointAllowed(t *testing.T) {
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	tests := []struct {
		name     string
		endpoint string
		allowed  []string
		want     bool
	}{
		{"empty allowed means all allowed", "/api/users", []string{}, true},
		{"exact match", "/api/users", []string{"/api/users"}, true},
		{"no match", "/api/users", []string{"/api/roles"}, false},
		{"wildcard star", "/api/any", []string{"*"}, true},
		{"prefix wildcard match", "/api/users/123", []string{"/api/users/*"}, true},
		{"prefix wildcard no match", "/api/roles/123", []string{"/api/users/*"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.IsEndpointAllowed(tc.endpoint, tc.allowed)
			assert.Equal(t, tc.want, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: RevokeAllTokens
// ---------------------------------------------------------------------------

func TestServiceAccount_RevokeAllTokens_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	tenantID := uuid.New()
	saID := uuid.New()
	existing := &models.ServiceAccount{ID: saID, TenantID: tenantID}

	repo.On("GetByID", ctx, saID).Return(existing, nil)
	repo.On("RevokeAllTokens", ctx, saID).Return(nil)

	err := svc.RevokeAllTokens(ctx, tenantID, saID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestServiceAccount_RevokeAllTokens_NotFound_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	saID := uuid.New()
	repo.On("GetByID", ctx, saID).Return(nil, nil)

	err := svc.RevokeAllTokens(ctx, uuid.New(), saID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Tests: Authenticate state branches (Tier-A audit memo 2026-05-21)
//
// Pre-fix the repo's WHERE clause filtered on is_active=true,
// collapsing "deactivated-SA replay" into "unknown client_id" at the
// SOC log boundary. Post-fix the repo returns the row regardless and
// the service emits a structured warn after a successful hash check.
//
// The client-secret hash check runs BEFORE the state branch so a
// caller without the actual secret cannot tell apart "unknown
// client_id" from "deactivated account" — the audit signal fires
// ONLY for callers holding the full credential.
// ---------------------------------------------------------------------------

// newValidatedSA returns (clientSecret, *ServiceAccount) where the
// model's ClientSecretHash verifies against clientSecret. Caller
// mutates state fields before passing to the repo mock.
func newValidatedSA(t *testing.T) (string, *models.ServiceAccount) {
	t.Helper()
	clientSecret := "test-secret-bytes-not-a-real-secret"
	hash, err := crypto.HashPassword(clientSecret, nil)
	require.NoError(t, err)
	return clientSecret, &models.ServiceAccount{
		ID:                   uuid.New(),
		TenantID:             uuid.New(),
		ClientID:             "test-client-" + uuid.New().String(),
		ClientSecretHash:     hash,
		IsActive:             true,
		TokenLifetimeMinutes: 60,
	}
}

func TestServiceAccount_Authenticate_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	secret, sa := newValidatedSA(t)
	repo.On("GetByClientID", ctx, sa.ClientID).Return(sa, nil)
	repo.On("CreateToken", mock.Anything, mock.AnythingOfType("*models.ServiceAccountToken")).Return(nil)
	repo.On("UpdateLastUsed", mock.Anything, sa.ID, mock.Anything).Return(nil)

	resp, err := svc.Authenticate(ctx, sa.ClientID, secret, "10.0.0.1")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestServiceAccount_Authenticate_UnknownClientID_GenericError(t *testing.T) {
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	repo.On("GetByClientID", ctx, "unknown").Return(nil, nil)
	_, err := svc.Authenticate(ctx, "unknown", "secret", "10.0.0.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestServiceAccount_Authenticate_WrongSecret_GenericError(t *testing.T) {
	// Client-id oracle protection: a probing caller without the
	// secret must get the same response shape regardless of whether
	// the client_id maps to a deactivated row. This test combines
	// "wrong secret" with "deactivated account" and asserts the
	// failure path runs ONLY the hash check (no audit signal would
	// leak the deactivated state).
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	_, sa := newValidatedSA(t)
	sa.IsActive = false // deactivated AND we'll send the wrong secret
	repo.On("GetByClientID", ctx, sa.ClientID).Return(sa, nil)

	_, err := svc.Authenticate(ctx, sa.ClientID, "wrong-secret", "10.0.0.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed",
		"wrong-secret path must surface the generic auth-failed error and not leak the deactivated state to a probing client")
}

func TestServiceAccount_Authenticate_Deactivated_AuditButGenericError(t *testing.T) {
	// Caller HAS the valid secret + the SA is deactivated. The
	// service-side audit signal fires; the client-facing error
	// stays generic so an admin reviewing logs sees the
	// "deactivated_attempted" trail, but the client cannot tell
	// the state from the response alone.
	ctx := context.Background()
	repo := new(mockServiceAccountRepo)
	svc := newServiceAccountService(repo)

	secret, sa := newValidatedSA(t)
	sa.IsActive = false
	repo.On("GetByClientID", ctx, sa.ClientID).Return(sa, nil)

	_, err := svc.Authenticate(ctx, sa.ClientID, secret, "10.0.0.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed",
		"deactivated-account replay must NOT leak its state via the client-facing error — the audit-log differs but the response is identical to other failure modes")
}

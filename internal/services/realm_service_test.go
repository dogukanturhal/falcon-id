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
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// Mock: realmServiceRepo
// ---------------------------------------------------------------------------

type MockRealmRepo struct {
	mock.Mock
}

func (m *MockRealmRepo) SlugExists(ctx context.Context, slug string) (bool, error) {
	args := m.Called(ctx, slug)
	return args.Bool(0), args.Error(1)
}

func (m *MockRealmRepo) Create(ctx context.Context, realm *models.Realm) error {
	args := m.Called(ctx, realm)
	return args.Error(0)
}

func (m *MockRealmRepo) CreateSecurityPolicy(ctx context.Context, policy *models.RealmSecurityPolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *MockRealmRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Realm, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Realm), args.Error(1)
}

func (m *MockRealmRepo) GetBySlug(ctx context.Context, slug string) (*models.Realm, error) {
	args := m.Called(ctx, slug)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Realm), args.Error(1)
}

func (m *MockRealmRepo) GetRealmByDomain(ctx context.Context, domainName string) (*models.Realm, error) {
	args := m.Called(ctx, domainName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Realm), args.Error(1)
}

func (m *MockRealmRepo) Update(ctx context.Context, realm *models.Realm) error {
	args := m.Called(ctx, realm)
	return args.Error(0)
}

func (m *MockRealmRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status models.RealmStatus) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *MockRealmRepo) List(ctx context.Context, filters repositories.RealmFilters) ([]models.Realm, int64, error) {
	args := m.Called(ctx, filters)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.Realm), args.Get(1).(int64), args.Error(2)
}

func (m *MockRealmRepo) GetSecurityPolicy(ctx context.Context, realmID uuid.UUID) (*models.RealmSecurityPolicy, error) {
	args := m.Called(ctx, realmID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RealmSecurityPolicy), args.Error(1)
}

func (m *MockRealmRepo) UpdateSecurityPolicy(ctx context.Context, policy *models.RealmSecurityPolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *MockRealmRepo) CreateIdentityProvider(ctx context.Context, idp *models.RealmIdentityProvider) error {
	args := m.Called(ctx, idp)
	return args.Error(0)
}

func (m *MockRealmRepo) ListIdentityProviders(ctx context.Context, realmID uuid.UUID) ([]models.RealmIdentityProvider, error) {
	args := m.Called(ctx, realmID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.RealmIdentityProvider), args.Error(1)
}

func (m *MockRealmRepo) DeleteIdentityProvider(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRealmRepo) GetIdentityProvider(ctx context.Context, id uuid.UUID) (*models.RealmIdentityProvider, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RealmIdentityProvider), args.Error(1)
}

func (m *MockRealmRepo) UpdateIdentityProvider(ctx context.Context, idp *models.RealmIdentityProvider) error {
	args := m.Called(ctx, idp)
	return args.Error(0)
}

func (m *MockRealmRepo) CountTenantsInRealm(ctx context.Context, realmID uuid.UUID) (int, error) {
	args := m.Called(ctx, realmID)
	return args.Int(0), args.Error(1)
}

func (m *MockRealmRepo) AssignTenant(ctx context.Context, realmID, tenantID uuid.UUID, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, realmID, tenantID, assignedBy)
	return args.Error(0)
}

func (m *MockRealmRepo) GetTenantRealm(ctx context.Context, tenantID uuid.UUID) (*models.Realm, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Realm), args.Error(1)
}

func (m *MockRealmRepo) ListRealmTenants(ctx context.Context, realmID uuid.UUID) ([]models.RealmTenant, error) {
	args := m.Called(ctx, realmID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.RealmTenant), args.Error(1)
}

func (m *MockRealmRepo) AssignAdmin(ctx context.Context, assignment *models.RealmAdminAssignment) error {
	args := m.Called(ctx, assignment)
	return args.Error(0)
}

func (m *MockRealmRepo) ListRealmAdmins(ctx context.Context, realmID uuid.UUID) ([]models.RealmAdminAssignment, error) {
	args := m.Called(ctx, realmID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.RealmAdminAssignment), args.Error(1)
}

func (m *MockRealmRepo) RemoveAdmin(ctx context.Context, realmID, adminID uuid.UUID) error {
	args := m.Called(ctx, realmID, adminID)
	return args.Error(0)
}

func (m *MockRealmRepo) LogAudit(ctx context.Context, log *models.RealmAuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockRealmRepo) ListAuditLogs(ctx context.Context, realmID uuid.UUID, filters repositories.AuditLogFilters) ([]models.RealmAuditLog, int64, error) {
	args := m.Called(ctx, realmID, filters)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.RealmAuditLog), args.Get(1).(int64), args.Error(2)
}

func (m *MockRealmRepo) ListDomains(ctx context.Context, realmID uuid.UUID) ([]models.RealmDomain, error) {
	args := m.Called(ctx, realmID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.RealmDomain), args.Error(1)
}

func (m *MockRealmRepo) GetDomainByName(ctx context.Context, domainName string) (*models.RealmDomain, error) {
	args := m.Called(ctx, domainName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RealmDomain), args.Error(1)
}

func (m *MockRealmRepo) CreateDomain(ctx context.Context, domain *models.RealmDomain) error {
	args := m.Called(ctx, domain)
	return args.Error(0)
}

func (m *MockRealmRepo) SetPrimaryDomain(ctx context.Context, realmID, domainID uuid.UUID) error {
	args := m.Called(ctx, realmID, domainID)
	return args.Error(0)
}

func (m *MockRealmRepo) GetDomainByID(ctx context.Context, domainID uuid.UUID) (*models.RealmDomain, error) {
	args := m.Called(ctx, domainID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RealmDomain), args.Error(1)
}

func (m *MockRealmRepo) DeleteDomain(ctx context.Context, domainID uuid.UUID) error {
	args := m.Called(ctx, domainID)
	return args.Error(0)
}

func (m *MockRealmRepo) UpdateDomain(ctx context.Context, domain *models.RealmDomain) error {
	args := m.Called(ctx, domain)
	return args.Error(0)
}

func (m *MockRealmRepo) GetDefaultRealm(ctx context.Context) (*models.Realm, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Realm), args.Error(1)
}

func (m *MockRealmRepo) GetUserAvailableRealms(ctx context.Context, userID uuid.UUID, primaryRealmID uuid.UUID) ([]*models.Realm, error) {
	args := m.Called(ctx, userID, primaryRealmID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Realm), args.Error(1)
}

func (m *MockRealmRepo) UserHasRealmAccess(ctx context.Context, userID, realmID, primaryRealmID uuid.UUID) (bool, error) {
	args := m.Called(ctx, userID, realmID, primaryRealmID)
	return args.Bool(0), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func newRealmService(repo *MockRealmRepo) *RealmService {
	return NewRealmService(repo, &config.Config{}, zap.NewNop())
}

// ---------------------------------------------------------------------------
// Tests: Create
// ---------------------------------------------------------------------------

func TestRealmService_Create_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	createdBy := uuid.New()
	req := &models.CreateRealmRequest{
		Slug:        "acme-corp",
		DisplayName: "Acme Corporation",
		Type:        models.RealmTypeEnterprise,
	}

	repo.On("SlugExists", ctx, "acme-corp").Return(false, nil)
	repo.On("Create", ctx, mock.AnythingOfType("*models.Realm")).Return(nil)
	repo.On("CreateSecurityPolicy", ctx, mock.AnythingOfType("*models.RealmSecurityPolicy")).Return(nil)

	realm, err := svc.Create(ctx, req, &createdBy)

	require.NoError(t, err)
	require.NotNil(t, realm)
	assert.Equal(t, "acme-corp", realm.Slug)
	assert.Equal(t, models.RealmTypeEnterprise, realm.Type)
	assert.Equal(t, models.RealmStatusActive, realm.Status)
	repo.AssertExpectations(t)
}

func TestRealmService_Create_DuplicateSlug(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	req := &models.CreateRealmRequest{
		Slug:        "acme-corp",
		DisplayName: "Acme",
		Type:        models.RealmTypeShared,
	}

	repo.On("SlugExists", ctx, "acme-corp").Return(true, nil)

	realm, err := svc.Create(ctx, req, nil)

	assert.Error(t, err)
	assert.Nil(t, realm)
	assert.Contains(t, err.Error(), "already exists")
	repo.AssertExpectations(t)
}

func TestRealmService_Create_InvalidSlug(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	tests := []struct {
		name string
		slug string
		msg  string
	}{
		{"too short", "a", "between 2 and 63"},
		{"starts with dash", "-bad", "slug must start"},
		{"reserved", "admin", "reserved"},
		{"uppercase", "MyRealm", "slug must start"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &models.CreateRealmRequest{
				Slug:        tc.slug,
				DisplayName: "Test",
				Type:        models.RealmTypeShared,
			}
			realm, err := svc.Create(ctx, req, nil)
			assert.Error(t, err)
			assert.Nil(t, realm)
			assert.Contains(t, err.Error(), tc.msg)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: GetByID
// ---------------------------------------------------------------------------

func TestRealmService_GetByID_Found(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	expected := &models.Realm{
		ID:          realmID,
		Slug:        "test-realm",
		DisplayName: "Test Realm",
		Type:        models.RealmTypeShared,
		Status:      models.RealmStatusActive,
	}

	repo.On("GetByID", ctx, realmID).Return(expected, nil)
	repo.On("GetSecurityPolicy", ctx, realmID).Return((*models.RealmSecurityPolicy)(nil), nil)

	realm, err := svc.GetByID(ctx, realmID)

	require.NoError(t, err)
	require.NotNil(t, realm)
	assert.Equal(t, realmID, realm.ID)
	assert.Equal(t, "test-realm", realm.Slug)
	repo.AssertExpectations(t)
}

func TestRealmService_GetByID_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	repo.On("GetByID", ctx, realmID).Return((*models.Realm)(nil), nil)

	realm, err := svc.GetByID(ctx, realmID)

	assert.Error(t, err)
	assert.Nil(t, realm)
	assert.Contains(t, err.Error(), "realm not found")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: Update
// ---------------------------------------------------------------------------

func TestRealmService_Update_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	existing := &models.Realm{
		ID:          realmID,
		Slug:        "my-realm",
		DisplayName: "Old Name",
		Status:      models.RealmStatusActive,
	}

	newName := testAPIKeyNewName
	req := &models.UpdateRealmRequest{
		DisplayName: &newName,
	}

	repo.On("GetByID", ctx, realmID).Return(existing, nil)
	repo.On("Update", ctx, mock.AnythingOfType("*models.Realm")).Return(nil)

	realm, err := svc.Update(ctx, realmID, req)

	require.NoError(t, err)
	require.NotNil(t, realm)
	assert.Equal(t, testAPIKeyNewName, realm.DisplayName)
	repo.AssertExpectations(t)
}

func TestRealmService_Update_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	repo.On("GetByID", ctx, realmID).Return((*models.Realm)(nil), nil)

	newName := testAPIKeyNewName
	realm, err := svc.Update(ctx, realmID, &models.UpdateRealmRequest{DisplayName: &newName})

	assert.Error(t, err)
	assert.Nil(t, realm)
	assert.Contains(t, err.Error(), "realm not found")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: Archive (delete equivalent — service has no hard Delete; Archive acts as soft-delete)
// ---------------------------------------------------------------------------

func TestRealmService_Archive_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	existing := &models.Realm{
		ID:          realmID,
		Slug:        "my-realm",
		Status:      models.RealmStatusActive,
		TenantCount: 0,
	}

	repo.On("GetByID", ctx, realmID).Return(existing, nil)
	repo.On("UpdateStatus", ctx, realmID, models.RealmStatusArchived).Return(nil)

	err := svc.Archive(ctx, realmID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestRealmService_Archive_CannotArchiveDefault(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	// Use the well-known default realm ID
	existing := &models.Realm{
		ID:     models.DefaultRealmID,
		Slug:   "default",
		Status: models.RealmStatusActive,
	}

	repo.On("GetByID", ctx, models.DefaultRealmID).Return(existing, nil)

	err := svc.Archive(ctx, models.DefaultRealmID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot archive the default realm")
	repo.AssertExpectations(t)
}

func TestRealmService_Archive_HasTenants(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	existing := &models.Realm{
		ID:          realmID,
		Slug:        "busy-realm",
		Status:      models.RealmStatusActive,
		TenantCount: 3,
	}

	repo.On("GetByID", ctx, realmID).Return(existing, nil)

	err := svc.Archive(ctx, realmID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot archive realm with")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: List
// ---------------------------------------------------------------------------

func TestRealmService_List_Pagination(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realms := []models.Realm{
		{ID: uuid.New(), Slug: "realm-1", DisplayName: "Realm 1", Type: models.RealmTypeShared, Status: models.RealmStatusActive},
		{ID: uuid.New(), Slug: "realm-2", DisplayName: "Realm 2", Type: models.RealmTypeShared, Status: models.RealmStatusActive},
	}

	filters := repositories.RealmFilters{Page: 1, PageSize: 20}
	repo.On("List", ctx, filters).Return(realms, int64(2), nil)

	result, err := svc.List(ctx, filters)

	require.NoError(t, err)
	assert.Len(t, result.Realms, 2)
	assert.Equal(t, int64(2), result.Total)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 20, result.PageSize)
	assert.Equal(t, 1, result.TotalPages)
	repo.AssertExpectations(t)
}

func TestRealmService_List_DefaultPagination(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	// filters with zero values should be corrected to defaults
	corrected := repositories.RealmFilters{Page: 1, PageSize: 20}
	repo.On("List", ctx, corrected).Return([]models.Realm{}, int64(0), nil)

	result, err := svc.List(ctx, repositories.RealmFilters{Page: 0, PageSize: 0})

	require.NoError(t, err)
	assert.NotNil(t, result)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: AssignTenant / ListRealmTenants
// ---------------------------------------------------------------------------

func TestRealmService_AssignTenant_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	tenantID := uuid.New()
	assignedBy := uuid.New()

	maxTenants := 10
	existing := &models.Realm{
		ID:         realmID,
		Slug:       "my-realm",
		Status:     models.RealmStatusActive,
		MaxTenants: &maxTenants,
	}

	repo.On("GetByID", ctx, realmID).Return(existing, nil)
	repo.On("CountTenantsInRealm", ctx, realmID).Return(5, nil)
	repo.On("AssignTenant", ctx, realmID, tenantID, &assignedBy).Return(nil)

	err := svc.AssignTenant(ctx, realmID, tenantID, &assignedBy)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestRealmService_AssignTenant_QuotaExceeded(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	tenantID := uuid.New()

	maxTenants := 5
	existing := &models.Realm{
		ID:         realmID,
		Slug:       "full-realm",
		Status:     models.RealmStatusActive,
		MaxTenants: &maxTenants,
	}

	repo.On("GetByID", ctx, realmID).Return(existing, nil)
	repo.On("CountTenantsInRealm", ctx, realmID).Return(5, nil)

	err := svc.AssignTenant(ctx, realmID, tenantID, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum tenant limit")
	repo.AssertExpectations(t)
}

func TestRealmService_AssignTenant_InactiveRealm(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	existing := &models.Realm{
		ID:     realmID,
		Status: models.RealmStatusSuspended,
	}

	repo.On("GetByID", ctx, realmID).Return(existing, nil)

	err := svc.AssignTenant(ctx, realmID, uuid.New(), nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "inactive realm")
	repo.AssertExpectations(t)
}

func TestRealmService_ListRealmTenants_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	tenants := []models.RealmTenant{
		{RealmID: realmID, TenantID: uuid.New()},
		{RealmID: realmID, TenantID: uuid.New()},
	}

	repo.On("ListRealmTenants", ctx, realmID).Return(tenants, nil)

	result, err := svc.ListRealmTenants(ctx, realmID)

	require.NoError(t, err)
	assert.Len(t, result, 2)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: Suspend (cannot suspend default realm)
// ---------------------------------------------------------------------------

func TestRealmService_Suspend_CannotSuspendDefault(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	existing := &models.Realm{
		ID:     models.DefaultRealmID,
		Slug:   "default",
		Status: models.RealmStatusActive,
	}

	repo.On("GetByID", ctx, models.DefaultRealmID).Return(existing, nil)

	err := svc.Suspend(ctx, models.DefaultRealmID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot suspend the default realm")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ValidatePassword (security policy path)
// ---------------------------------------------------------------------------

func TestRealmService_ValidatePassword_MeetsPolicy(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	policy := &models.RealmSecurityPolicy{
		ID:                       uuid.New(),
		RealmID:                  realmID,
		PasswordMinLength:        8,
		PasswordMaxLength:        128,
		PasswordRequireUppercase: true,
		PasswordRequireLowercase: true,
		PasswordRequireDigits:    true,
		PasswordRequireSpecial:   false,
	}

	repo.On("GetSecurityPolicy", ctx, realmID).Return(policy, nil)

	err := svc.ValidatePassword(ctx, realmID, "SecurePass123")

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestRealmService_ValidatePassword_TooShort(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	policy := &models.RealmSecurityPolicy{
		RealmID:           realmID,
		PasswordMinLength: 12,
		PasswordMaxLength: 128,
	}

	repo.On("GetSecurityPolicy", ctx, realmID).Return(policy, nil)

	err := svc.ValidatePassword(ctx, realmID, "short")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least 12 characters")
	repo.AssertExpectations(t)
}

func TestRealmService_ValidatePassword_MissingUppercase(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	policy := &models.RealmSecurityPolicy{
		RealmID:                  realmID,
		PasswordMinLength:        8,
		PasswordMaxLength:        128,
		PasswordRequireUppercase: true,
	}

	repo.On("GetSecurityPolicy", ctx, realmID).Return(policy, nil)

	err := svc.ValidatePassword(ctx, realmID, "alllowercase1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "uppercase")
	repo.AssertExpectations(t)
}

func TestRealmService_ValidatePassword_MissingDigit(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	policy := &models.RealmSecurityPolicy{
		RealmID:               realmID,
		PasswordMinLength:     8,
		PasswordMaxLength:     128,
		PasswordRequireDigits: true,
	}

	repo.On("GetSecurityPolicy", ctx, realmID).Return(policy, nil)

	err := svc.ValidatePassword(ctx, realmID, "NoDigitsHere")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "digit")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetBySlug (cache path)
// ---------------------------------------------------------------------------

func TestRealmService_GetBySlug_DBFallback(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	expected := &models.Realm{
		ID:     uuid.New(),
		Slug:   "enterprise-realm",
		Status: models.RealmStatusActive,
	}

	repo.On("GetBySlug", ctx, "enterprise-realm").Return(expected, nil)

	realm, err := svc.GetBySlug(ctx, "enterprise-realm")

	require.NoError(t, err)
	require.NotNil(t, realm)
	assert.Equal(t, "enterprise-realm", realm.Slug)
	repo.AssertExpectations(t)
}

func TestRealmService_GetBySlug_CacheHit(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	expected := &models.Realm{
		ID:     uuid.New(),
		Slug:   "cached-realm",
		Status: models.RealmStatusActive,
	}

	// First call populates L1 cache
	repo.On("GetBySlug", ctx, "cached-realm").Return(expected, nil).Once()

	realm1, err := svc.GetBySlug(ctx, "cached-realm")
	require.NoError(t, err)
	require.NotNil(t, realm1)

	// Second call should hit cache — repo NOT called again
	realm2, err := svc.GetBySlug(ctx, "cached-realm")
	require.NoError(t, err)
	require.NotNil(t, realm2)

	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetDefaultRealm
// ---------------------------------------------------------------------------

func TestRealmService_GetDefaultRealm(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	defaultRealm := &models.Realm{
		ID:   models.DefaultRealmID,
		Slug: "default",
	}

	repo.On("GetDefaultRealm", ctx).Return(defaultRealm, nil)

	realm, err := svc.GetDefaultRealm(ctx)

	require.NoError(t, err)
	assert.Equal(t, models.DefaultRealmID, realm.ID)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: AssignAdmin / RemoveAdmin
// ---------------------------------------------------------------------------

func TestRealmService_AssignAdmin_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	adminID := uuid.New()
	createdBy := uuid.New()

	existing := &models.Realm{
		ID:     realmID,
		Status: models.RealmStatusActive,
	}

	req := &models.AssignRealmAdminRequest{
		AdminID: adminID,
		Role:    models.RealmAdminRoleAdmin,
	}

	repo.On("GetByID", ctx, realmID).Return(existing, nil)
	repo.On("AssignAdmin", ctx, mock.AnythingOfType("*models.RealmAdminAssignment")).Return(nil)

	err := svc.AssignAdmin(ctx, realmID, req, &createdBy)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestRealmService_RemoveAdmin_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	adminID := uuid.New()

	repo.On("RemoveAdmin", ctx, realmID, adminID).Return(nil)

	err := svc.RemoveAdmin(ctx, realmID, adminID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetSecurityPolicy / UpdateSecurityPolicy
// ---------------------------------------------------------------------------

func TestRealmService_GetSecurityPolicy_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	policy := &models.RealmSecurityPolicy{
		ID:                realmID,
		RealmID:           realmID,
		PasswordMinLength: 10,
	}

	repo.On("GetSecurityPolicy", ctx, realmID).Return(policy, nil)

	result, err := svc.GetSecurityPolicy(ctx, realmID)

	require.NoError(t, err)
	assert.Equal(t, 10, result.PasswordMinLength)
	repo.AssertExpectations(t)
}

func TestRealmService_GetSecurityPolicy_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	repo.On("GetSecurityPolicy", ctx, realmID).Return((*models.RealmSecurityPolicy)(nil), nil)

	result, err := svc.GetSecurityPolicy(ctx, realmID)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "security policy not found")
	repo.AssertExpectations(t)
}

func TestRealmService_UpdateSecurityPolicy_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	realmID := uuid.New()
	existing := &models.RealmSecurityPolicy{
		ID:                realmID,
		RealmID:           realmID,
		PasswordMinLength: 8,
	}

	newMinLen := 12
	mfaRequired := true
	req := &models.UpdateRealmSecurityPolicyRequest{
		PasswordMinLength: &newMinLen,
		MFARequired:       &mfaRequired,
	}

	repo.On("GetSecurityPolicy", ctx, realmID).Return(existing, nil)
	repo.On("UpdateSecurityPolicy", ctx, mock.AnythingOfType("*models.RealmSecurityPolicy")).Return(nil)

	policy, err := svc.UpdateSecurityPolicy(ctx, realmID, req)

	require.NoError(t, err)
	assert.Equal(t, 12, policy.PasswordMinLength)
	assert.True(t, policy.MFARequired)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: validateRealmSlug (internal helper — tested indirectly via Create)
// ---------------------------------------------------------------------------

func TestRealmService_SlugValidation_Table(t *testing.T) {
	tests := []struct {
		slug    string
		wantErr bool
		desc    string
	}{
		{"valid-slug", false, "normal slug"},
		{"ab", false, "minimum length 2"},
		{"a", true, "length 1 too short"},
		{"admin", true, "reserved slug"},
		{"api", true, "reserved slug api"},
		{"-starts-dash", true, "starts with dash"},
		{"ends-dash-", true, "ends with dash"},
		{"UPPER", true, "uppercase not allowed"},
		{"valid-123", false, "alphanumeric with digits"},
	}

	ctx := context.Background()
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			repo := new(MockRealmRepo)
			svc := newRealmService(repo)

			if !tc.wantErr {
				repo.On("SlugExists", ctx, tc.slug).Return(false, nil)
				repo.On("Create", ctx, mock.AnythingOfType("*models.Realm")).Return(nil)
				repo.On("CreateSecurityPolicy", ctx, mock.Anything).Return(nil)
			}

			req := &models.CreateRealmRequest{
				Slug:        tc.slug,
				DisplayName: "Test",
				Type:        models.RealmTypeShared,
			}
			_, err := svc.Create(ctx, req, nil)
			if tc.wantErr {
				assert.Error(t, err, "expected error for slug: %s", tc.slug)
			} else {
				assert.NoError(t, err, "unexpected error for slug: %s", tc.slug)
			}
		})
	}
}

// Ensure errors from repo propagate correctly
func TestRealmService_Create_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(MockRealmRepo)
	svc := newRealmService(repo)

	req := &models.CreateRealmRequest{
		Slug:        "new-realm",
		DisplayName: "New Realm",
		Type:        models.RealmTypeShared,
	}

	repo.On("SlugExists", ctx, "new-realm").Return(false, nil)
	repo.On("Create", ctx, mock.AnythingOfType("*models.Realm")).Return(errors.New("db error"))

	realm, err := svc.Create(ctx, req, nil)

	assert.Error(t, err)
	assert.Nil(t, realm)
	repo.AssertExpectations(t)
}

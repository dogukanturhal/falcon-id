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
)

// ---------------------------------------------------------------------------
// Mock: ldapServiceIDPRepo
// ---------------------------------------------------------------------------

type MockLDAPIDPRepo struct {
	mock.Mock
}

func (m *MockLDAPIDPRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.IdentityProvider, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.IdentityProvider), args.Error(1)
}

func (m *MockLDAPIDPRepo) GetByTenantAndType(ctx context.Context, tenantID uuid.UUID, providerType string) ([]*models.IdentityProvider, error) {
	args := m.Called(ctx, tenantID, providerType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.IdentityProvider), args.Error(1)
}

func (m *MockLDAPIDPRepo) GetAllByType(ctx context.Context, providerType string) ([]*models.IdentityProvider, error) {
	args := m.Called(ctx, providerType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.IdentityProvider), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mock: ldapServiceUserRepo
// ---------------------------------------------------------------------------

type MockLDAPUserRepo struct {
	mock.Mock
}

func (m *MockLDAPUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockLDAPUserRepo) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error) {
	args := m.Called(ctx, tenantID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockLDAPUserRepo) GetByFederationID(ctx context.Context, federationType, federationID string) (*models.User, error) {
	args := m.Called(ctx, federationType, federationID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockLDAPUserRepo) LinkFederation(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, federationType, federationID, federationSource string) error {
	args := m.Called(ctx, userID, tenantID, federationType, federationID, federationSource)
	return args.Error(0)
}

func (m *MockLDAPUserRepo) GetByFederationSource(ctx context.Context, federationType, federationSource string) ([]models.User, error) {
	args := m.Called(ctx, federationType, federationSource)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.User), args.Error(1)
}

func (m *MockLDAPUserRepo) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockLDAPUserRepo) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockLDAPUserRepo) AssignRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, userID, roleIDs, assignedBy)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Mock: ldapServiceRoleRepo
// ---------------------------------------------------------------------------

type MockLDAPRoleRepo struct {
	mock.Mock
}

func (m *MockLDAPRoleRepo) GetDefaultRoles(ctx context.Context, tenantID uuid.UUID) ([]models.Role, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *MockLDAPRoleRepo) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error) {
	args := m.Called(ctx, tenantID, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestLDAPService(idpRepo ldapServiceIDPRepo, userRepo ldapServiceUserRepo, roleRepo ldapServiceRoleRepo) *LDAPService {
	cfg := &config.Config{Environment: "development"}
	return NewLDAPService(cfg, idpRepo, userRepo, roleRepo)
}

// buildLDAPProvider builds a minimal, enabled IdentityProvider with an LDAP config.
func buildLDAPProvider(tenantID uuid.UUID) *models.IdentityProvider {
	return &models.IdentityProvider{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Type:      "ldap",
		Name:      "corp-ldap",
		IsEnabled: true,
		LDAPConfig: &models.LDAPConfig{
			Host:            "ldap.example.com",
			Port:            389,
			BindDN:          "cn=svc,dc=example,dc=com",
			BindPassword:    "secret",
			BaseDN:          "dc=example,dc=com",
			UsernameAttr:    "sAMAccountName",
			EmailAttr:       "mail",
			FirstNameAttr:   "givenName",
			LastNameAttr:    "sn",
			DisplayNameAttr: "displayName",
			CreateUsers:     true,
			UpdateUsers:     true,
		},
	}
}

// ---------------------------------------------------------------------------
// Tests: Authenticate – repository / provider layer (no real LDAP required)
// ---------------------------------------------------------------------------

func TestLDAPService_Authenticate_ProviderNotFound(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	providerID := uuid.New()

	mockIDP := new(MockLDAPIDPRepo)
	mockUser := new(MockLDAPUserRepo)
	mockRole := new(MockLDAPRoleRepo)
	svc := newTestLDAPService(mockIDP, mockUser, mockRole)

	mockIDP.On("GetByID", ctx, providerID).Return(nil, errors.New("not found"))

	user, err := svc.Authenticate(ctx, tenantID, providerID, "alice", "password")

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "failed to get identity provider")
	mockIDP.AssertExpectations(t)
}

func TestLDAPService_Authenticate_ProviderNilReturn(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	providerID := uuid.New()

	mockIDP := new(MockLDAPIDPRepo)
	mockUser := new(MockLDAPUserRepo)
	mockRole := new(MockLDAPRoleRepo)
	svc := newTestLDAPService(mockIDP, mockUser, mockRole)

	// Repository returns (nil, nil) meaning "not found"
	mockIDP.On("GetByID", ctx, providerID).Return(nil, nil)

	user, err := svc.Authenticate(ctx, tenantID, providerID, "alice", "password")

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "identity provider not found")
}

func TestLDAPService_Authenticate_DisabledProvider(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	providerID := uuid.New()

	mockIDP := new(MockLDAPIDPRepo)
	mockUser := new(MockLDAPUserRepo)
	mockRole := new(MockLDAPRoleRepo)
	svc := newTestLDAPService(mockIDP, mockUser, mockRole)

	provider := buildLDAPProvider(tenantID)
	provider.ID = providerID
	provider.IsEnabled = false

	mockIDP.On("GetByID", ctx, providerID).Return(provider, nil)

	user, err := svc.Authenticate(ctx, tenantID, providerID, "alice", "password")

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "identity provider is disabled")
}

func TestLDAPService_Authenticate_MissingLDAPConfig(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	providerID := uuid.New()

	mockIDP := new(MockLDAPIDPRepo)
	mockUser := new(MockLDAPUserRepo)
	mockRole := new(MockLDAPRoleRepo)
	svc := newTestLDAPService(mockIDP, mockUser, mockRole)

	provider := buildLDAPProvider(tenantID)
	provider.ID = providerID
	provider.LDAPConfig = nil // no LDAP config

	mockIDP.On("GetByID", ctx, providerID).Return(provider, nil)

	user, err := svc.Authenticate(ctx, tenantID, providerID, "alice", "password")

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "LDAP configuration not found")
}

// ---------------------------------------------------------------------------
// Tests: SyncUsers – provider layer validation
// ---------------------------------------------------------------------------

func TestLDAPService_SyncUsers_ProviderNotFound(t *testing.T) {
	ctx := context.Background()
	providerID := uuid.New()

	mockIDP := new(MockLDAPIDPRepo)
	mockUser := new(MockLDAPUserRepo)
	mockRole := new(MockLDAPRoleRepo)
	svc := newTestLDAPService(mockIDP, mockUser, mockRole)

	mockIDP.On("GetByID", ctx, providerID).Return(nil, errors.New("provider not found"))

	result, err := svc.SyncUsers(ctx, providerID, false)

	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, err.Error(), "failed to get identity provider")
	mockIDP.AssertExpectations(t)
}

func TestLDAPService_SyncUsers_NilProviderReturn(t *testing.T) {
	ctx := context.Background()
	providerID := uuid.New()

	mockIDP := new(MockLDAPIDPRepo)
	mockUser := new(MockLDAPUserRepo)
	mockRole := new(MockLDAPRoleRepo)
	svc := newTestLDAPService(mockIDP, mockUser, mockRole)

	mockIDP.On("GetByID", ctx, providerID).Return(nil, nil)

	result, err := svc.SyncUsers(ctx, providerID, false)

	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, err.Error(), "identity provider not found")
}

func TestLDAPService_SyncUsers_MissingLDAPConfig(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	providerID := uuid.New()

	mockIDP := new(MockLDAPIDPRepo)
	mockUser := new(MockLDAPUserRepo)
	mockRole := new(MockLDAPRoleRepo)
	svc := newTestLDAPService(mockIDP, mockUser, mockRole)

	provider := buildLDAPProvider(tenantID)
	provider.ID = providerID
	provider.LDAPConfig = nil

	mockIDP.On("GetByID", ctx, providerID).Return(provider, nil)

	result, err := svc.SyncUsers(ctx, providerID, false)

	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, err.Error(), "LDAP configuration not found")
}

// ---------------------------------------------------------------------------
// Tests: applyLDAPDefaults
// ---------------------------------------------------------------------------

func TestLDAPService_ApplyLDAPDefaults_SetsAttributeDefaults(t *testing.T) {
	svc := newTestLDAPService(nil, nil, nil)

	cfg := &models.LDAPConfig{
		Host:   "ldap.example.com",
		BaseDN: "dc=example,dc=com",
	}

	result := svc.applyLDAPDefaults(cfg)

	assert.Equal(t, "sAMAccountName", result.UsernameAttr)
	assert.Equal(t, "mail", result.EmailAttr)
	assert.Equal(t, "givenName", result.FirstNameAttr)
	assert.Equal(t, "sn", result.LastNameAttr)
	assert.Equal(t, "displayName", result.DisplayNameAttr)
	assert.Equal(t, "memberOf", result.GroupAttr)
	assert.Equal(t, 389, result.Port, "default non-TLS port should be 389")
}

func TestLDAPService_ApplyLDAPDefaults_TLSPort(t *testing.T) {
	svc := newTestLDAPService(nil, nil, nil)

	cfg := &models.LDAPConfig{
		Host:   "ldaps.example.com",
		UseTLS: true,
	}

	result := svc.applyLDAPDefaults(cfg)

	assert.Equal(t, 636, result.Port, "TLS port should default to 636")
}

func TestLDAPService_ApplyLDAPDefaults_PreservesExistingValues(t *testing.T) {
	svc := newTestLDAPService(nil, nil, nil)

	cfg := &models.LDAPConfig{
		Host:         "ldap.example.com",
		Port:         10389,
		UsernameAttr: "uid",
		EmailAttr:    "email",
	}

	result := svc.applyLDAPDefaults(cfg)

	assert.Equal(t, 10389, result.Port, "explicit port must not be overridden")
	assert.Equal(t, "uid", result.UsernameAttr)
	assert.Equal(t, "email", result.EmailAttr)
}

func TestLDAPService_ApplyLDAPDefaults_DoesNotMutateOriginal(t *testing.T) {
	svc := newTestLDAPService(nil, nil, nil)

	original := &models.LDAPConfig{
		Host:   "ldap.example.com",
		BaseDN: "dc=corp,dc=com",
	}

	_ = svc.applyLDAPDefaults(original)

	// The original must be unchanged (function should return a copy)
	assert.Empty(t, original.UsernameAttr, "original config must not be mutated")
}

// ---------------------------------------------------------------------------
// Tests: GetActiveLDAPProviders
// ---------------------------------------------------------------------------

func TestLDAPService_GetActiveLDAPProviders_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockIDP := new(MockLDAPIDPRepo)
	mockUser := new(MockLDAPUserRepo)
	mockRole := new(MockLDAPRoleRepo)
	svc := newTestLDAPService(mockIDP, mockUser, mockRole)

	providers := []*models.IdentityProvider{
		buildLDAPProvider(tenantID),
		buildLDAPProvider(tenantID),
	}

	mockIDP.On("GetByTenantAndType", ctx, tenantID, "ldap").Return(providers, nil)

	got, err := svc.GetActiveLDAPProviders(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, got, 2)
	mockIDP.AssertExpectations(t)
}

func TestLDAPService_GetActiveLDAPProviders_RepositoryError(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockIDP := new(MockLDAPIDPRepo)
	mockUser := new(MockLDAPUserRepo)
	mockRole := new(MockLDAPRoleRepo)
	svc := newTestLDAPService(mockIDP, mockUser, mockRole)

	mockIDP.On("GetByTenantAndType", ctx, tenantID, "ldap").
		Return(nil, errors.New("db error"))

	got, err := svc.GetActiveLDAPProviders(ctx, tenantID)

	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "failed to list LDAP providers")
}

// ---------------------------------------------------------------------------
// Tests: TestConnection (production environment enforcement)
// ---------------------------------------------------------------------------

func TestLDAPService_Connect_ProductionRequiresTLS(t *testing.T) {
	mockIDP := new(MockLDAPIDPRepo)
	mockUser := new(MockLDAPUserRepo)
	mockRole := new(MockLDAPRoleRepo)

	cfg := &config.Config{Environment: "production"}
	svc := NewLDAPService(cfg, mockIDP, mockUser, mockRole)

	ldapCfg := &models.LDAPConfig{
		Host:   "ldap.example.com",
		Port:   389,
		UseTLS: false, // plain, which is not allowed in production
	}

	conn, err := svc.Connect(ldapCfg)

	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "TLS")
}

func TestLDAPService_Connect_ProductionForbidsSkipTLSVerify(t *testing.T) {
	mockIDP := new(MockLDAPIDPRepo)
	mockUser := new(MockLDAPUserRepo)
	mockRole := new(MockLDAPRoleRepo)

	cfg := &config.Config{Environment: "production"}
	svc := NewLDAPService(cfg, mockIDP, mockUser, mockRole)

	ldapCfg := &models.LDAPConfig{
		Host:          "ldap.example.com",
		Port:          636,
		UseTLS:        true,
		SkipTLSVerify: true, // not allowed in production
	}

	conn, err := svc.Connect(ldapCfg)

	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "SkipTLSVerify")
}

// ---------------------------------------------------------------------------
// Tests: mapGroupsToRoles (via provider lookup)
// ---------------------------------------------------------------------------

func TestLDAPService_MapGroupsToRoles_NoGroupMappings(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	providerID := uuid.New()
	userID := uuid.New()

	mockIDP := new(MockLDAPIDPRepo)
	mockUser := new(MockLDAPUserRepo)
	mockRole := new(MockLDAPRoleRepo)
	svc := newTestLDAPService(mockIDP, mockUser, mockRole)

	provider := buildLDAPProvider(tenantID)
	provider.ID = providerID
	provider.LDAPConfig.GroupMappings = nil // no mappings configured

	mockIDP.On("GetByID", ctx, providerID).Return(provider, nil)

	// No role repo calls expected when no mappings exist
	err := svc.mapGroupsToRoles(ctx, providerID, userID, []string{"Admins"})

	require.NoError(t, err)
	mockIDP.AssertExpectations(t)
	mockRole.AssertExpectations(t)
}

func TestLDAPService_MapGroupsToRoles_MapsGroupToRole(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	providerID := uuid.New()
	userID := uuid.New()
	roleID := uuid.New()

	mockIDP := new(MockLDAPIDPRepo)
	mockUser := new(MockLDAPUserRepo)
	mockRole := new(MockLDAPRoleRepo)
	svc := newTestLDAPService(mockIDP, mockUser, mockRole)

	provider := buildLDAPProvider(tenantID)
	provider.ID = providerID
	provider.LDAPConfig.GroupMappings = map[string]string{
		"Admins": "admin",
	}

	role := &models.Role{ID: roleID, Name: "admin", TenantID: tenantID}

	mockIDP.On("GetByID", ctx, providerID).Return(provider, nil)
	mockRole.On("GetByName", ctx, tenantID, "admin").Return(role, nil)
	mockUser.On("AssignRoles", ctx, userID, []uuid.UUID{roleID}, (*uuid.UUID)(nil)).Return(nil)

	err := svc.mapGroupsToRoles(ctx, providerID, userID, []string{"Admins"})

	require.NoError(t, err)
	mockIDP.AssertExpectations(t)
	mockRole.AssertExpectations(t)
	mockUser.AssertExpectations(t)
}

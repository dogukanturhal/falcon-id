// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// Mock: samlServiceSAMLRepo
// ---------------------------------------------------------------------------

type MockSAMLRepo struct {
	mock.Mock
}

func (m *MockSAMLRepo) Create(ctx context.Context, sp *models.SAMLServiceProvider) error {
	args := m.Called(ctx, sp)
	return args.Error(0)
}

func (m *MockSAMLRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.SAMLServiceProvider, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SAMLServiceProvider), args.Error(1)
}

func (m *MockSAMLRepo) GetByEntityID(ctx context.Context, tenantID uuid.UUID, entityID string) (*models.SAMLServiceProvider, error) {
	args := m.Called(ctx, tenantID, entityID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SAMLServiceProvider), args.Error(1)
}

func (m *MockSAMLRepo) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.SAMLServiceProvider, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SAMLServiceProvider), args.Error(1)
}

func (m *MockSAMLRepo) Update(ctx context.Context, sp *models.SAMLServiceProvider) error {
	args := m.Called(ctx, sp)
	return args.Error(0)
}

func (m *MockSAMLRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSAMLRepo) CreateAssertionLog(ctx context.Context, log *models.SAMLAssertionLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockSAMLRepo) GetAssertionLogs(ctx context.Context, spID uuid.UUID, limit int) ([]*models.SAMLAssertionLog, error) {
	args := m.Called(ctx, spID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SAMLAssertionLog), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mock: samlServiceUserRepo
// ---------------------------------------------------------------------------

type MockSAMLUserRepo struct {
	mock.Mock
}

func (m *MockSAMLUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestSAMLService(t *testing.T, samlRepo samlServiceSAMLRepo, userRepo samlServiceUserRepo) *SAMLService {
	t.Helper()
	cfg := &config.Config{ServicePort: "8080"}
	svc, err := NewSAMLService(samlRepo, userRepo, cfg)
	require.NoError(t, err)
	return svc
}

func buildSAMLServiceProvider(tenantID uuid.UUID) *models.SAMLServiceProvider {
	sloURL := "https://sp.example.com/saml/slo"
	return &models.SAMLServiceProvider{
		ID:                uuid.New(),
		TenantID:          tenantID,
		Name:              "Test SP",
		EntityID:          "https://sp.example.com/saml/metadata",
		ACSURL:            "https://sp.example.com/saml/acs",
		SLOURL:            &sloURL,
		NameIDFormat:      models.NameIDFormatEmailAddress,
		SignAssertions:    false, // disabled for test speed (no signing overhead)
		EncryptAssertions: false,
		AttributeMapping: func() models.JSONMap {
			m := make(models.JSONMap)
			for k, v := range models.DefaultAttributeMapping() {
				m[k] = v
			}
			return m
		}(),
		AllowedAttributes: models.DefaultAllowedAttributes(),
		IsActive:          true,
	}
}

// ---------------------------------------------------------------------------
// Tests: CreateServiceProvider
// ---------------------------------------------------------------------------

func TestSAMLService_CreateServiceProvider_ValidRequest(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	creatorID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	req := &models.CreateSAMLServiceProviderRequest{
		Name:     "My SAML SP",
		EntityID: "https://sp.example.com/metadata",
		ACSURL:   "https://sp.example.com/acs",
	}

	mockSAMLRepo.On("Create", ctx, mock.AnythingOfType("*models.SAMLServiceProvider")).Return(nil)

	sp, err := svc.CreateServiceProvider(ctx, tenantID, req, &creatorID)

	require.NoError(t, err)
	assert.NotNil(t, sp)
	assert.Equal(t, req.Name, sp.Name)
	assert.Equal(t, req.EntityID, sp.EntityID)
	assert.Equal(t, req.ACSURL, sp.ACSURL)
	assert.Equal(t, models.NameIDFormatEmailAddress, sp.NameIDFormat, "default NameID format")
	assert.True(t, sp.SignAssertions, "assertions should be signed by default")
	assert.True(t, sp.IsActive)
	assert.Equal(t, &creatorID, sp.CreatedBy)
	mockSAMLRepo.AssertExpectations(t)
}

func TestSAMLService_CreateServiceProvider_CustomNameIDFormat(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	req := &models.CreateSAMLServiceProviderRequest{
		Name:         "Persistent SP",
		EntityID:     "https://sp2.example.com/metadata",
		ACSURL:       "https://sp2.example.com/acs",
		NameIDFormat: models.NameIDFormatPersistent,
	}

	mockSAMLRepo.On("Create", ctx, mock.AnythingOfType("*models.SAMLServiceProvider")).Return(nil)

	sp, err := svc.CreateServiceProvider(ctx, tenantID, req, nil)

	require.NoError(t, err)
	assert.Equal(t, models.NameIDFormatPersistent, sp.NameIDFormat)
}

func TestSAMLService_CreateServiceProvider_RepositoryError(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	req := &models.CreateSAMLServiceProviderRequest{
		Name:     "Failing SP",
		EntityID: "https://fail.example.com/metadata",
		ACSURL:   "https://fail.example.com/acs",
	}

	mockSAMLRepo.On("Create", ctx, mock.AnythingOfType("*models.SAMLServiceProvider")).
		Return(errors.New("db constraint violation"))

	sp, err := svc.CreateServiceProvider(ctx, tenantID, req, nil)

	assert.Error(t, err)
	assert.Nil(t, sp)
	assert.Contains(t, err.Error(), "db constraint violation")
}

// ---------------------------------------------------------------------------
// Tests: GenerateMetadataXML
// ---------------------------------------------------------------------------

func TestSAMLService_GenerateMetadataXML_ContainsRequiredElements(t *testing.T) {
	tenantID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	xmlStr := svc.GenerateMetadataXML(tenantID)

	assert.NotEmpty(t, xmlStr)
	assert.True(t, strings.HasPrefix(xmlStr, "<?xml"), "must start with XML declaration")
	assert.Contains(t, xmlStr, "EntityDescriptor", "must contain EntityDescriptor element")
	assert.Contains(t, xmlStr, "IDPSSODescriptor", "must contain IDPSSODescriptor element")
	assert.Contains(t, xmlStr, "SingleSignOnService", "must contain SSO service element")
	assert.Contains(t, xmlStr, tenantID.String(), "entity ID must embed tenant ID")
}

func TestSAMLService_GetIDPMetadata_URLsContainTenantID(t *testing.T) {
	tenantID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	meta := svc.GetIDPMetadata(tenantID)

	assert.Contains(t, meta.EntityID, tenantID.String())
	assert.Contains(t, meta.SSOURL, tenantID.String())
	// SLO is deliberately NOT advertised: the endpoint does not terminate
	// sessions, so publishing a URL for it tells relying parties that logout
	// propagates when it does not. This assertion is the regression guard --
	// re-advertise only together with a real implementation.
	assert.Empty(t, meta.SLOURL, "SLO URL must not be advertised while SLO is unimplemented")
	assert.NotEmpty(t, meta.Certificate, "certificate must be embedded in metadata")
	assert.NotEmpty(t, meta.NameIDFormats)
}

// ---------------------------------------------------------------------------
// Tests: GenerateAssertion
// ---------------------------------------------------------------------------

func TestSAMLService_GenerateAssertion_EmailNameID(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	sp := buildSAMLServiceProvider(tenantID)
	sp.NameIDFormat = models.NameIDFormatEmailAddress

	firstName := "Jane"
	lastName := "Doe"
	user := &models.User{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Username:  "janedoe",
		Email:     "jane.doe@example.com",
		FirstName: &firstName,
		LastName:  &lastName,
	}

	assertion, err := svc.GenerateAssertion(ctx, sp, user, "_req123")

	require.NoError(t, err)
	assert.Equal(t, user.Email, assertion.Subject, "subject must be email for EmailAddress format")
	assert.Equal(t, sp.EntityID, assertion.Audience)
	assert.Equal(t, sp.ACSURL, assertion.Recipient)
	assert.Equal(t, "_req123", assertion.InResponseTo)
	assert.NotEmpty(t, assertion.ID)
	assert.NotEmpty(t, assertion.SessionIndex)
	assert.True(t, assertion.NotOnOrAfter.After(assertion.IssueInstant))
}

func TestSAMLService_GenerateAssertion_PersistentNameID(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	sp := buildSAMLServiceProvider(tenantID)
	sp.NameIDFormat = models.NameIDFormatPersistent

	user := &models.User{
		ID:       uuid.New(),
		TenantID: tenantID,
		Username: "persistentuser",
		Email:    "persistent@example.com",
	}

	assertion, err := svc.GenerateAssertion(ctx, sp, user, "_req456")

	require.NoError(t, err)
	assert.Equal(t, user.ID.String(), assertion.Subject, "subject must be user UUID for Persistent format")
}

func TestSAMLService_GenerateAssertion_AttributeMapping(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	sp := buildSAMLServiceProvider(tenantID)
	// Use default attribute mapping and allowed attributes
	sp.AttributeMapping = models.JSONMap{
		"email":      "email",
		"first_name": "first_name",
	}
	sp.AllowedAttributes = []string{"email", "first_name"}

	firstName := "Alice"
	user := &models.User{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Username:  "alice",
		Email:     "alice@example.com",
		FirstName: &firstName,
	}

	assertion, err := svc.GenerateAssertion(ctx, sp, user, "_req789")

	require.NoError(t, err)
	assert.NotEmpty(t, assertion.Attributes)
	if vals, ok := assertion.Attributes["email"]; ok {
		assert.Equal(t, []string{user.Email}, vals)
	}
}

// ---------------------------------------------------------------------------
// Tests: GenerateAssertionXML
// ---------------------------------------------------------------------------

func TestSAMLService_GenerateAssertionXML_ValidXML(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	sp := buildSAMLServiceProvider(tenantID)
	user := &models.User{
		ID:       uuid.New(),
		TenantID: tenantID,
		Username: "xmltestuser",
		Email:    "xmltest@example.com",
	}

	assertion, err := svc.GenerateAssertion(ctx, sp, user, "_reqXML")
	require.NoError(t, err)

	xmlStr, err := svc.GenerateAssertionXML(assertion)

	require.NoError(t, err)
	assert.Contains(t, xmlStr, "<saml:Assertion")
	assert.Contains(t, xmlStr, "</saml:Assertion>")
	assert.Contains(t, xmlStr, assertion.ID)
	assert.Contains(t, xmlStr, sp.EntityID)
}

// ---------------------------------------------------------------------------
// Tests: GetServiceProvider / ListServiceProviders
// ---------------------------------------------------------------------------

func TestSAMLService_GetServiceProvider_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	spID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	expected := buildSAMLServiceProvider(tenantID)
	expected.ID = spID

	mockSAMLRepo.On("GetByID", ctx, spID).Return(expected, nil)

	got, err := svc.GetServiceProvider(ctx, spID)

	require.NoError(t, err)
	assert.Equal(t, spID, got.ID)
	mockSAMLRepo.AssertExpectations(t)
}

func TestSAMLService_ListServiceProviders_ByTenant(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	sps := []*models.SAMLServiceProvider{
		buildSAMLServiceProvider(tenantID),
		buildSAMLServiceProvider(tenantID),
	}

	mockSAMLRepo.On("GetByTenantID", ctx, tenantID).Return(sps, nil)

	got, err := svc.ListServiceProviders(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, got, 2)
	mockSAMLRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: UpdateServiceProvider
// ---------------------------------------------------------------------------

func TestSAMLService_UpdateServiceProvider_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	spID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	existing := buildSAMLServiceProvider(tenantID)
	existing.ID = spID

	newName := "Updated SP Name"
	req := &models.UpdateSAMLServiceProviderRequest{
		Name: &newName,
	}

	mockSAMLRepo.On("GetByID", ctx, spID).Return(existing, nil)
	mockSAMLRepo.On("Update", ctx, mock.AnythingOfType("*models.SAMLServiceProvider")).Return(nil)

	updated, err := svc.UpdateServiceProvider(ctx, spID, req)

	require.NoError(t, err)
	assert.Equal(t, newName, updated.Name)
	mockSAMLRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: DeleteServiceProvider
// ---------------------------------------------------------------------------

func TestSAMLService_DeleteServiceProvider_Success(t *testing.T) {
	ctx := context.Background()
	spID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	mockSAMLRepo.On("Delete", ctx, spID).Return(nil)

	err := svc.DeleteServiceProvider(ctx, spID)

	require.NoError(t, err)
	mockSAMLRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetAssertionLogs
// ---------------------------------------------------------------------------

func TestSAMLService_GetAssertionLogs_DefaultLimit(t *testing.T) {
	ctx := context.Background()
	spID := uuid.New()

	mockSAMLRepo := new(MockSAMLRepo)
	mockUserRepo := new(MockSAMLUserRepo)
	svc := newTestSAMLService(t, mockSAMLRepo, mockUserRepo)

	logs := []*models.SAMLAssertionLog{
		{ID: uuid.New(), SPID: spID, Status: "success"},
	}

	mockSAMLRepo.On("GetAssertionLogs", ctx, spID, 100).Return(logs, nil)

	// limit=0 should default to 100
	got, err := svc.GetAssertionLogs(ctx, spID, 0)

	require.NoError(t, err)
	assert.Len(t, got, 1)
	mockSAMLRepo.AssertExpectations(t)
}

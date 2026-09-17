// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ==================== Mock declarations ====================

// MockConsentRepo mocks consentServiceConsentRepo.
type MockConsentRepo struct {
	mock.Mock
}

func (m *MockConsentRepo) GetConsentTypes(ctx context.Context, tenantID uuid.UUID) ([]models.ConsentType, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.ConsentType), args.Error(1)
}

func (m *MockConsentRepo) GetUserConsents(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]models.UserConsentWithType, error) {
	args := m.Called(ctx, userID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.UserConsentWithType), args.Error(1)
}

func (m *MockConsentRepo) GetPendingRequiredConsents(ctx context.Context, userID, tenantID uuid.UUID) ([]models.ConsentType, error) {
	args := m.Called(ctx, userID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.ConsentType), args.Error(1)
}

func (m *MockConsentRepo) GetConsentTypeByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.ConsentType, error) {
	args := m.Called(ctx, tenantID, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ConsentType), args.Error(1)
}

func (m *MockConsentRepo) GetUserConsent(ctx context.Context, userID, consentTypeID uuid.UUID) (*models.UserConsent, error) {
	args := m.Called(ctx, userID, consentTypeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserConsent), args.Error(1)
}

func (m *MockConsentRepo) UpsertConsent(ctx context.Context, consent *models.UserConsent) error {
	args := m.Called(ctx, consent)
	return args.Error(0)
}

func (m *MockConsentRepo) GetConsentTypeByID(ctx context.Context, id uuid.UUID) (*models.ConsentType, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ConsentType), args.Error(1)
}

func (m *MockConsentRepo) HasGrantedAllRequired(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	args := m.Called(ctx, userID, tenantID)
	return args.Bool(0), args.Error(1)
}

func (m *MockConsentRepo) DeleteUserConsents(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockConsentRepo) GetConsentHistory(ctx context.Context, userID uuid.UUID, since time.Time) ([]models.UserConsentWithType, error) {
	args := m.Called(ctx, userID, since)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.UserConsentWithType), args.Error(1)
}

func (m *MockConsentRepo) GetConsentHistoryDetailed(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, limit int) ([]models.ConsentHistoryWithType, error) {
	args := m.Called(ctx, userID, tenantID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.ConsentHistoryWithType), args.Error(1)
}

// ==================== Helpers ====================

// newConsentService creates a ConsentService backed by the mock consent repo and
// a real AuditService wired to a MockAuditLogTokenRepo (declared in audit_service_test.go).
func newConsentService(cr *MockConsentRepo) (*ConsentService, *MockAuditLogTokenRepo) { //nolint:unparam // MockAuditLogTokenRepo is returned for potential future use in tests
	auditMock := new(MockAuditLogTokenRepo)
	// LogUserAction calls tokenRepo.CreateAuditLog – stub it for all consent tests.
	auditMock.On("CreateAuditLog", mock.Anything, mock.Anything).Return(nil)
	auditSvc := newTestAuditService(auditMock)
	return NewConsentService(cr, auditSvc), auditMock
}

func buildConsentType(tenantID uuid.UUID, name string, required bool) *models.ConsentType {
	return &models.ConsentType{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        name,
		DisplayName: name + " display",
		Category:    string(models.ConsentCategoryRequired),
		IsRequired:  required,
		IsActive:    true,
		Version:     1,
	}
}

// ==================== GetConsentTypes ====================

func TestConsentService_GetConsentTypes_ReturnsList(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	types := []models.ConsentType{
		*buildConsentType(tenantID, "terms", true),
		*buildConsentType(tenantID, "marketing", false),
	}
	cr.On("GetConsentTypes", ctx, tenantID).Return(types, nil)

	result, err := svc.GetConsentTypes(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestConsentService_GetConsentTypes_RepoError(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	cr.On("GetConsentTypes", ctx, tenantID).Return(nil, errors.New("db error"))

	result, err := svc.GetConsentTypes(ctx, tenantID)

	assert.Error(t, err)
	assert.Nil(t, result)
}

// ==================== GetUserConsents ====================

func TestConsentService_GetUserConsents_ReturnsAllWithStatus(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	ct := buildConsentType(tenantID, "terms", true)
	grantedAt := time.Now()
	consents := []models.UserConsentWithType{
		{
			UserConsent: models.UserConsent{
				ID:            uuid.New(),
				UserID:        userID,
				ConsentTypeID: ct.ID,
				Granted:       true,
				GrantedAt:     &grantedAt,
			},
			ConsentType: *ct,
		},
	}

	cr.On("GetUserConsents", ctx, userID, tenantID).Return(consents, nil)
	cr.On("GetPendingRequiredConsents", ctx, userID, tenantID).Return([]models.ConsentType{}, nil)

	result, err := svc.GetUserConsents(ctx, userID, tenantID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Consents, 1)
	assert.False(t, result.HasPendingRequired)
}

func TestConsentService_GetUserConsents_WithPendingRequired(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	pendingCT := buildConsentType(tenantID, "privacy-policy", true)

	cr.On("GetUserConsents", ctx, userID, tenantID).Return([]models.UserConsentWithType{}, nil)
	cr.On("GetPendingRequiredConsents", ctx, userID, tenantID).Return([]models.ConsentType{*pendingCT}, nil)

	result, err := svc.GetUserConsents(ctx, userID, tenantID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.HasPendingRequired)
	assert.Len(t, result.PendingRequired, 1)
}

// ==================== UpdateConsent (Grant) ====================

func TestConsentService_UpdateConsent_Grant_Valid(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	ct := buildConsentType(tenantID, "terms", false)

	cr.On("GetConsentTypeByName", ctx, tenantID, "terms").Return(ct, nil)
	cr.On("GetUserConsent", ctx, userID, ct.ID).Return(nil, nil)
	cr.On("UpsertConsent", ctx, mock.AnythingOfType("*models.UserConsent")).Return(nil)

	err := svc.UpdateConsent(ctx, userID, tenantID, "terms", true, "127.0.0.1", "test-agent")

	require.NoError(t, err)
	cr.AssertExpectations(t)
}

func TestConsentService_UpdateConsent_Grant_ExistingConsent(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	ct := buildConsentType(tenantID, "analytics", false)
	existingID := uuid.New()
	existing := &models.UserConsent{ID: existingID, UserID: userID, ConsentTypeID: ct.ID}

	cr.On("GetConsentTypeByName", ctx, tenantID, "analytics").Return(ct, nil)
	cr.On("GetUserConsent", ctx, userID, ct.ID).Return(existing, nil)
	cr.On("UpsertConsent", ctx, mock.AnythingOfType("*models.UserConsent")).Return(nil)

	err := svc.UpdateConsent(ctx, userID, tenantID, "analytics", true, "127.0.0.1", "agent")

	require.NoError(t, err)
}

// ==================== UpdateConsent (Withdraw) ====================

func TestConsentService_UpdateConsent_Withdraw_RequiredError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	// Required consent – cannot be revoked
	ct := buildConsentType(tenantID, "terms", true)

	cr.On("GetConsentTypeByName", ctx, tenantID, "terms").Return(ct, nil)

	err := svc.UpdateConsent(ctx, userID, tenantID, "terms", false, "127.0.0.1", "agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot revoke required consent")
	cr.AssertNumberOfCalls(t, "UpsertConsent", 0)
}

func TestConsentService_UpdateConsent_Withdraw_Optional_Valid(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	ct := buildConsentType(tenantID, "marketing", false)

	cr.On("GetConsentTypeByName", ctx, tenantID, "marketing").Return(ct, nil)
	cr.On("GetUserConsent", ctx, userID, ct.ID).Return(nil, nil)
	cr.On("UpsertConsent", ctx, mock.AnythingOfType("*models.UserConsent")).Return(nil)

	err := svc.UpdateConsent(ctx, userID, tenantID, "marketing", false, "127.0.0.1", "agent")

	require.NoError(t, err)
}

func TestConsentService_UpdateConsent_ConsentTypeNotFound(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	cr.On("GetConsentTypeByName", ctx, tenantID, "unknown").Return(nil, nil)

	err := svc.UpdateConsent(ctx, userID, tenantID, "unknown", true, "127.0.0.1", "agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "consent type not found")
}

// ==================== UpdateConsentByID ====================

func TestConsentService_UpdateConsentByID_Grant_Valid(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	ct := buildConsentType(tenantID, "terms", false)

	cr.On("GetConsentTypeByID", ctx, ct.ID).Return(ct, nil)
	cr.On("UpsertConsent", ctx, mock.AnythingOfType("*models.UserConsent")).Return(nil)

	err := svc.UpdateConsentByID(ctx, userID, tenantID, ct.ID, true, "127.0.0.1", "agent")

	require.NoError(t, err)
}

func TestConsentService_UpdateConsentByID_WrongTenant(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()
	otherTenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	ct := buildConsentType(otherTenantID, "terms", false)

	cr.On("GetConsentTypeByID", ctx, ct.ID).Return(ct, nil)

	err := svc.UpdateConsentByID(ctx, userID, tenantID, ct.ID, true, "127.0.0.1", "agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "consent type not found")
}

func TestConsentService_UpdateConsentByID_RevokeRequired_Error(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	ct := buildConsentType(tenantID, "required-type", true)

	cr.On("GetConsentTypeByID", ctx, ct.ID).Return(ct, nil)

	err := svc.UpdateConsentByID(ctx, userID, tenantID, ct.ID, false, "127.0.0.1", "agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot revoke required consent")
}

// ==================== BulkUpdateConsents ====================

func TestConsentService_BulkUpdateConsents_Valid(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	ct1 := buildConsentType(tenantID, "terms", false)
	ct2 := buildConsentType(tenantID, "marketing", false)

	cr.On("GetConsentTypeByID", ctx, ct1.ID).Return(ct1, nil)
	cr.On("UpsertConsent", ctx, mock.AnythingOfType("*models.UserConsent")).Return(nil)
	cr.On("GetConsentTypeByID", ctx, ct2.ID).Return(ct2, nil)

	consents := []struct {
		ConsentTypeID string `json:"consent_type_id"`
		Granted       bool   `json:"granted"`
	}{
		{ConsentTypeID: ct1.ID.String(), Granted: true},
		{ConsentTypeID: ct2.ID.String(), Granted: true},
	}

	err := svc.BulkUpdateConsents(ctx, userID, tenantID, consents, "127.0.0.1", "agent")

	require.NoError(t, err)
	cr.AssertExpectations(t)
}

func TestConsentService_BulkUpdateConsents_InvalidUUID(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	consents := []struct {
		ConsentTypeID string `json:"consent_type_id"`
		Granted       bool   `json:"granted"`
	}{
		{ConsentTypeID: "not-a-valid-uuid", Granted: true},
	}

	err := svc.BulkUpdateConsents(ctx, userID, tenantID, consents, "127.0.0.1", "agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid consent type ID")
}

func TestConsentService_BulkUpdateConsents_RequiredRevoke_Error(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	ct := buildConsentType(tenantID, "required", true)
	cr.On("GetConsentTypeByID", ctx, ct.ID).Return(ct, nil)

	consents := []struct {
		ConsentTypeID string `json:"consent_type_id"`
		Granted       bool   `json:"granted"`
	}{
		{ConsentTypeID: ct.ID.String(), Granted: false},
	}

	err := svc.BulkUpdateConsents(ctx, userID, tenantID, consents, "127.0.0.1", "agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot revoke required consent")
}

// ==================== HasGrantedAllRequired ====================

func TestConsentService_HasGrantedAllRequired_True(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	cr.On("HasGrantedAllRequired", ctx, userID, tenantID).Return(true, nil)

	result, err := svc.HasGrantedAllRequired(ctx, userID, tenantID)

	require.NoError(t, err)
	assert.True(t, result)
}

func TestConsentService_HasGrantedAllRequired_False(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	cr.On("HasGrantedAllRequired", ctx, userID, tenantID).Return(false, nil)

	result, err := svc.HasGrantedAllRequired(ctx, userID, tenantID)

	require.NoError(t, err)
	assert.False(t, result)
}

// ==================== DeleteUserConsents ====================

func TestConsentService_DeleteUserConsents_Valid(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	cr.On("DeleteUserConsents", ctx, userID).Return(nil)

	err := svc.DeleteUserConsents(ctx, userID, tenantID)

	require.NoError(t, err)
	cr.AssertExpectations(t)
}

func TestConsentService_DeleteUserConsents_Error(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	cr.On("DeleteUserConsents", ctx, userID).Return(errors.New("db error"))

	err := svc.DeleteUserConsents(ctx, userID, tenantID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete user consents")
}

// ==================== GetConsentHistory ====================

func TestConsentService_GetConsentHistory_ReturnsList(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	since := time.Now().Add(-30 * 24 * time.Hour)

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	history := []models.UserConsentWithType{
		{UserConsent: models.UserConsent{ID: uuid.New(), UserID: userID, Granted: true}},
	}
	cr.On("GetConsentHistory", ctx, userID, since).Return(history, nil)

	result, err := svc.GetConsentHistory(ctx, userID, since)

	require.NoError(t, err)
	assert.Len(t, result, 1)
}

// ==================== GetConsentHistoryDetailed ====================

func TestConsentService_GetConsentHistoryDetailed_DefaultLimit(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	history := []models.ConsentHistoryWithType{
		{ConsentHistory: models.ConsentHistory{ID: uuid.New(), UserID: userID, Action: "granted"}},
	}
	// When limit is 0, service defaults to 50.
	cr.On("GetConsentHistoryDetailed", ctx, userID, tenantID, 50).Return(history, nil)

	result, err := svc.GetConsentHistoryDetailed(ctx, userID, tenantID, 0)

	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestConsentService_GetConsentHistoryDetailed_CustomLimit(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	cr.On("GetConsentHistoryDetailed", ctx, userID, tenantID, 10).
		Return([]models.ConsentHistoryWithType{}, nil)

	result, err := svc.GetConsentHistoryDetailed(ctx, userID, tenantID, 10)

	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestConsentService_GetConsentHistoryDetailed_ExcessiveLimitClamped(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	cr := new(MockConsentRepo)
	svc, _ := newConsentService(cr)

	// Limit > 100 should be clamped to 50
	cr.On("GetConsentHistoryDetailed", ctx, userID, tenantID, 50).
		Return([]models.ConsentHistoryWithType{}, nil)

	result, err := svc.GetConsentHistoryDetailed(ctx, userID, tenantID, 999)

	require.NoError(t, err)
	assert.Empty(t, result)
}

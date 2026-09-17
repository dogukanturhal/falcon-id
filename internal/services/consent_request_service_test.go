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

// ---------------------------------------------------------------------------
// Mock: adminConsentRequestRepo
// ---------------------------------------------------------------------------

type mockAdminConsentRequestRepo struct {
	mock.Mock
}

func (m *mockAdminConsentRequestRepo) Create(ctx context.Context, req *models.AdminConsentRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *mockAdminConsentRequestRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.AdminConsentRequest, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AdminConsentRequest), args.Error(1)
}

func (m *mockAdminConsentRequestRepo) Decide(ctx context.Context, id uuid.UUID, approverID uuid.UUID, status models.AdminConsentRequestStatus) error {
	args := m.Called(ctx, id, approverID, status)
	return args.Error(0)
}

func (m *mockAdminConsentRequestRepo) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.AdminConsentRequest, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AdminConsentRequest), args.Error(1)
}

func (m *mockAdminConsentRequestRepo) ListByApplication(ctx context.Context, appID uuid.UUID) ([]models.AdminConsentRequest, error) {
	args := m.Called(ctx, appID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AdminConsentRequest), args.Error(1)
}

func (m *mockAdminConsentRequestRepo) ListPending(ctx context.Context, tenantID uuid.UUID) ([]models.AdminConsentRequest, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AdminConsentRequest), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mock: consentGranter
// ---------------------------------------------------------------------------

type mockConsentGranter struct {
	mock.Mock
}

func (m *mockConsentGranter) GrantAdminConsent(ctx context.Context, appID, tenantID, consentedBy uuid.UUID, scopes []string) (*models.AppConsent, error) {
	args := m.Called(ctx, appID, tenantID, consentedBy, scopes)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AppConsent), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newConsentRequestSvc(repo *mockAdminConsentRequestRepo) *ConsentRequestService {
	return NewConsentRequestService(repo)
}

func buildAdminConsentRequest(appID, tenantID, requesterID uuid.UUID) *models.AdminConsentRequest {
	return &models.AdminConsentRequest{
		ID:              uuid.New(),
		ApplicationID:   appID,
		TenantID:        tenantID,
		RequesterID:     requesterID,
		RequestedScopes: []string{"openid", "profile"},
		Status:          models.AdminConsentRequestStatusPending,
		CreatedAt:       time.Now(),
	}
}

// ---------------------------------------------------------------------------
// CreateRequest
// ---------------------------------------------------------------------------

func TestConsentRequestService_CreateRequest_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	requesterID := uuid.New()
	appID := uuid.New()

	repo := new(mockAdminConsentRequestRepo)
	svc := newConsentRequestSvc(repo)

	input := models.CreateAdminConsentRequestInput{
		ApplicationID:   appID,
		RequestedScopes: []string{"openid", "email"},
	}

	repo.On("Create", ctx, mock.AnythingOfType("*models.AdminConsentRequest")).
		Run(func(args mock.Arguments) {
			cr := args.Get(1).(*models.AdminConsentRequest)
			cr.ID = uuid.New()
		}).
		Return(nil)

	result, err := svc.CreateRequest(ctx, tenantID, requesterID, input)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, appID, result.ApplicationID)
	assert.Equal(t, tenantID, result.TenantID)
	assert.Equal(t, requesterID, result.RequesterID)
	assert.Equal(t, models.AdminConsentRequestStatusPending, result.Status)
	repo.AssertExpectations(t)
}

func TestConsentRequestService_CreateRequest_RepoError(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	requesterID := uuid.New()
	appID := uuid.New()

	repo := new(mockAdminConsentRequestRepo)
	svc := newConsentRequestSvc(repo)

	input := models.CreateAdminConsentRequestInput{
		ApplicationID:   appID,
		RequestedScopes: []string{"openid"},
	}

	repo.On("Create", ctx, mock.AnythingOfType("*models.AdminConsentRequest")).
		Return(errors.New("db error"))

	result, err := svc.CreateRequest(ctx, tenantID, requesterID, input)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "ConsentRequestService.CreateRequest")
}

// ---------------------------------------------------------------------------
// ApproveRequest — with consent granter
// ---------------------------------------------------------------------------

func TestConsentRequestService_ApproveRequest_WithGranter(t *testing.T) {
	ctx := context.Background()
	approverID := uuid.New()
	appID := uuid.New()
	tenantID := uuid.New()

	cr := buildAdminConsentRequest(appID, tenantID, uuid.New())

	repo := new(mockAdminConsentRequestRepo)
	svc := newConsentRequestSvc(repo)

	granter := new(mockConsentGranter)
	svc.SetConsentGranter(granter)

	decidedCR := *cr
	decidedCR.Status = models.AdminConsentRequestStatusApproved
	decidedCR.ApproverID = &approverID
	now := time.Now()
	decidedCR.DecidedAt = &now

	// GetByID: first call returns pending, second returns approved
	repo.On("GetByID", ctx, cr.ID).Return(cr, nil).Once()
	repo.On("Decide", ctx, cr.ID, approverID, models.AdminConsentRequestStatusApproved).Return(nil)
	repo.On("GetByID", ctx, cr.ID).Return(&decidedCR, nil).Once()

	granter.On("GrantAdminConsent", ctx, appID, tenantID, approverID, cr.RequestedScopes).
		Return(&models.AppConsent{ID: uuid.New()}, nil)

	result, err := svc.ApproveRequest(ctx, cr.ID, approverID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, models.AdminConsentRequestStatusApproved, result.Status)
	repo.AssertExpectations(t)
	granter.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// ApproveRequest — without consent granter
// ---------------------------------------------------------------------------

func TestConsentRequestService_ApproveRequest_WithoutGranter(t *testing.T) {
	ctx := context.Background()
	approverID := uuid.New()
	appID := uuid.New()
	tenantID := uuid.New()

	cr := buildAdminConsentRequest(appID, tenantID, uuid.New())

	repo := new(mockAdminConsentRequestRepo)
	svc := newConsentRequestSvc(repo) // no granter wired

	decidedCR := *cr
	decidedCR.Status = models.AdminConsentRequestStatusApproved
	decidedCR.ApproverID = &approverID

	repo.On("GetByID", ctx, cr.ID).Return(cr, nil).Once()
	repo.On("Decide", ctx, cr.ID, approverID, models.AdminConsentRequestStatusApproved).Return(nil)
	repo.On("GetByID", ctx, cr.ID).Return(&decidedCR, nil).Once()

	result, err := svc.ApproveRequest(ctx, cr.ID, approverID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, models.AdminConsentRequestStatusApproved, result.Status)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// ApproveRequest — already decided
// ---------------------------------------------------------------------------

func TestConsentRequestService_ApproveRequest_AlreadyDecided(t *testing.T) {
	ctx := context.Background()
	approverID := uuid.New()

	cr := buildAdminConsentRequest(uuid.New(), uuid.New(), uuid.New())
	cr.Status = models.AdminConsentRequestStatusApproved // already approved

	repo := new(mockAdminConsentRequestRepo)
	svc := newConsentRequestSvc(repo)

	repo.On("GetByID", ctx, cr.ID).Return(cr, nil)

	result, err := svc.ApproveRequest(ctx, cr.ID, approverID)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "already approved")
	repo.AssertNotCalled(t, "Decide")
}

// ---------------------------------------------------------------------------
// DenyRequest
// ---------------------------------------------------------------------------

func TestConsentRequestService_DenyRequest_Success(t *testing.T) {
	ctx := context.Background()
	approverID := uuid.New()
	appID := uuid.New()
	tenantID := uuid.New()

	cr := buildAdminConsentRequest(appID, tenantID, uuid.New())

	repo := new(mockAdminConsentRequestRepo)
	svc := newConsentRequestSvc(repo)

	decidedCR := *cr
	decidedCR.Status = models.AdminConsentRequestStatusDenied
	decidedCR.ApproverID = &approverID

	repo.On("GetByID", ctx, cr.ID).Return(cr, nil).Once()
	repo.On("Decide", ctx, cr.ID, approverID, models.AdminConsentRequestStatusDenied).Return(nil)
	repo.On("GetByID", ctx, cr.ID).Return(&decidedCR, nil).Once()

	result, err := svc.DenyRequest(ctx, cr.ID, approverID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, models.AdminConsentRequestStatusDenied, result.Status)
	repo.AssertExpectations(t)
}

func TestConsentRequestService_DenyRequest_AlreadyDecided(t *testing.T) {
	ctx := context.Background()
	approverID := uuid.New()

	cr := buildAdminConsentRequest(uuid.New(), uuid.New(), uuid.New())
	cr.Status = models.AdminConsentRequestStatusDenied // already denied

	repo := new(mockAdminConsentRequestRepo)
	svc := newConsentRequestSvc(repo)

	repo.On("GetByID", ctx, cr.ID).Return(cr, nil)

	result, err := svc.DenyRequest(ctx, cr.ID, approverID)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "already denied")
	repo.AssertNotCalled(t, "Decide")
}

// ---------------------------------------------------------------------------
// ListPending
// ---------------------------------------------------------------------------

func TestConsentRequestService_ListPending_ReturnsList(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	repo := new(mockAdminConsentRequestRepo)
	svc := newConsentRequestSvc(repo)

	pending := []models.AdminConsentRequest{
		*buildAdminConsentRequest(uuid.New(), tenantID, uuid.New()),
		*buildAdminConsentRequest(uuid.New(), tenantID, uuid.New()),
	}
	repo.On("ListPending", ctx, tenantID).Return(pending, nil)

	results, err := svc.ListPending(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, results, 2)
	repo.AssertExpectations(t)
}

func TestConsentRequestService_ListPending_RepoError(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	repo := new(mockAdminConsentRequestRepo)
	svc := newConsentRequestSvc(repo)

	repo.On("ListPending", ctx, tenantID).Return(nil, errors.New("db error"))

	results, err := svc.ListPending(ctx, tenantID)

	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "ConsentRequestService.ListPending")
}

// ---------------------------------------------------------------------------
// GetRequest
// ---------------------------------------------------------------------------

func TestConsentRequestService_GetRequest_Found(t *testing.T) {
	ctx := context.Background()
	id := uuid.New()
	cr := buildAdminConsentRequest(uuid.New(), uuid.New(), uuid.New())
	cr.ID = id

	repo := new(mockAdminConsentRequestRepo)
	svc := newConsentRequestSvc(repo)

	repo.On("GetByID", ctx, id).Return(cr, nil)

	result, err := svc.GetRequest(ctx, id)

	require.NoError(t, err)
	assert.Equal(t, id, result.ID)
}

func TestConsentRequestService_GetRequest_NotFound(t *testing.T) {
	ctx := context.Background()
	id := uuid.New()

	repo := new(mockAdminConsentRequestRepo)
	svc := newConsentRequestSvc(repo)

	repo.On("GetByID", ctx, id).Return(nil, nil)

	result, err := svc.GetRequest(ctx, id)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "not found")
}

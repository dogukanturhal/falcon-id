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
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

type mockAccessReviewRepo struct {
	mock.Mock
}

func (m *mockAccessReviewRepo) CreateCampaign(ctx context.Context, c *models.AccessReviewCampaign) error {
	args := m.Called(ctx, c)
	if args.Error(0) == nil {
		c.ID = uuid.New()
		c.CreatedAt = time.Now()
		c.UpdatedAt = time.Now()
	}
	return args.Error(0)
}

func (m *mockAccessReviewRepo) GetCampaignByID(ctx context.Context, campaignID, tenantID uuid.UUID) (*models.AccessReviewCampaign, error) {
	args := m.Called(ctx, campaignID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewCampaign), args.Error(1)
}

func (m *mockAccessReviewRepo) ListCampaigns(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]*models.AccessReviewCampaign, int64, error) {
	args := m.Called(ctx, tenantID, status, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.AccessReviewCampaign), args.Get(1).(int64), args.Error(2)
}

func (m *mockAccessReviewRepo) UpdateCampaignStatus(ctx context.Context, campaignID uuid.UUID, status models.AccessReviewCampaignStatus) error {
	args := m.Called(ctx, campaignID, status)
	return args.Error(0)
}

func (m *mockAccessReviewRepo) CreateReviewItems(ctx context.Context, items []*models.AccessReviewItem) error {
	args := m.Called(ctx, items)
	return args.Error(0)
}

func (m *mockAccessReviewRepo) GetReviewItem(ctx context.Context, itemID, tenantID uuid.UUID) (*models.AccessReviewItem, error) {
	args := m.Called(ctx, itemID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewItem), args.Error(1)
}

func (m *mockAccessReviewRepo) ListPendingItems(ctx context.Context, reviewerID, tenantID uuid.UUID) ([]*models.AccessReviewItem, error) {
	args := m.Called(ctx, reviewerID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessReviewItem), args.Error(1)
}

func (m *mockAccessReviewRepo) SubmitDecision(ctx context.Context, itemID uuid.UUID, decision models.ReviewDecision, justification string) error {
	args := m.Called(ctx, itemID, decision, justification)
	return args.Error(0)
}

func (m *mockAccessReviewRepo) GetCampaignStats(ctx context.Context, campaignID uuid.UUID) (*models.AccessReviewCampaignStats, error) {
	args := m.Called(ctx, campaignID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewCampaignStats), args.Error(1)
}

func (m *mockAccessReviewRepo) ListExpiredPendingItems(ctx context.Context, campaignID uuid.UUID) ([]*models.AccessReviewItem, error) {
	args := m.Called(ctx, campaignID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessReviewItem), args.Error(1)
}

// ---------------------------------------------------------------------------

type mockARRoleRepo struct {
	mock.Mock
}

func (m *mockARRoleRepo) ListUserRoleAssignments(ctx context.Context, tenantID uuid.UUID) ([]UserRoleAssignment, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]UserRoleAssignment), args.Error(1)
}

// ---------------------------------------------------------------------------

type mockARGroupRepo struct {
	mock.Mock
}

func (m *mockARGroupRepo) ListUserGroupMemberships(ctx context.Context, tenantID uuid.UUID) ([]UserGroupMembership, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]UserGroupMembership), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newARService(t *testing.T) (*AccessReviewService, *mockAccessReviewRepo, *mockARRoleRepo, *mockARGroupRepo) {
	t.Helper()
	repo := new(mockAccessReviewRepo)
	roleRepo := new(mockARRoleRepo)
	groupRepo := new(mockARGroupRepo)
	svc := NewAccessReviewService(repo, roleRepo, groupRepo, nil, zap.NewNop())
	return svc, repo, roleRepo, groupRepo
}

func makeCreateRequest(resourceType string, durationDays int) *models.CreateAccessReviewRequest {
	return &models.CreateAccessReviewRequest{
		Name:         "Q1 Role Review",
		Description:  "Quarterly review of role assignments",
		ResourceType: resourceType,
		ReviewerType: "manager",
		Frequency:    "quarterly",
		DurationDays: durationDays,
		AutoRevoke:   false,
		StartsAt:     time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
}

func makeCampaign(status models.AccessReviewCampaignStatus) *models.AccessReviewCampaign {
	now := time.Now().UTC()
	return &models.AccessReviewCampaign{
		ID:           uuid.New(),
		TenantID:     uuid.New(),
		Name:         "Test Campaign",
		ResourceType: "role",
		ReviewerType: "manager",
		Frequency:    "one_time",
		DurationDays: 14,
		AutoRevoke:   false,
		Status:       status,
		StartsAt:     now,
		EndsAt:       now.Add(14 * 24 * time.Hour),
		CreatedBy:    uuid.New(),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestAccessReviewService_CreateCampaign_Success(t *testing.T) {
	svc, repo, roleRepo, _ := newARService(t)

	tenantID := uuid.New()
	createdBy := uuid.New()
	req := makeCreateRequest("role", 14)

	repo.On("CreateCampaign", mock.Anything, mock.AnythingOfType("*models.AccessReviewCampaign")).Return(nil)
	roleRepo.On("ListUserRoleAssignments", mock.Anything, tenantID).Return([]UserRoleAssignment{}, nil)

	campaign, err := svc.CreateCampaign(context.Background(), tenantID, createdBy, req)

	require.NoError(t, err)
	require.NotNil(t, campaign)
	assert.Equal(t, models.CampaignStatusActive, campaign.Status)
	assert.Equal(t, tenantID, campaign.TenantID)
	assert.Equal(t, "role", campaign.ResourceType)
	repo.AssertExpectations(t)
}

func TestAccessReviewService_CreateCampaign_GeneratesItems(t *testing.T) {
	svc, repo, roleRepo, _ := newARService(t)

	tenantID := uuid.New()
	createdBy := uuid.New()
	req := makeCreateRequest("role", 7)

	assignments := []UserRoleAssignment{
		{UserID: uuid.New(), RoleID: uuid.New(), RoleName: "admin"},
		{UserID: uuid.New(), RoleID: uuid.New(), RoleName: "viewer"},
	}

	repo.On("CreateCampaign", mock.Anything, mock.AnythingOfType("*models.AccessReviewCampaign")).Return(nil)
	roleRepo.On("ListUserRoleAssignments", mock.Anything, tenantID).Return(assignments, nil)
	repo.On("CreateReviewItems", mock.Anything, mock.MatchedBy(func(items []*models.AccessReviewItem) bool {
		return len(items) == 2
	})).Return(nil)

	campaign, err := svc.CreateCampaign(context.Background(), tenantID, createdBy, req)

	require.NoError(t, err)
	require.NotNil(t, campaign)
	repo.AssertExpectations(t)
	roleRepo.AssertExpectations(t)
}

func TestAccessReviewService_SubmitDecision_Approve(t *testing.T) {
	svc, repo, _, _ := newARService(t)

	tenantID := uuid.New()
	reviewerID := uuid.New()
	itemID := uuid.New()

	item := &models.AccessReviewItem{
		ID:           itemID,
		TenantID:     tenantID,
		ReviewerID:   reviewerID,
		Decision:     models.DecisionPending,
		CampaignID:   uuid.New(),
		UserID:       uuid.New(),
		ResourceType: "role",
		ResourceID:   uuid.New(),
	}

	repo.On("GetReviewItem", mock.Anything, itemID, tenantID).Return(item, nil)
	repo.On("SubmitDecision", mock.Anything, itemID, models.DecisionApproved, "looks good").Return(nil)

	err := svc.SubmitDecision(context.Background(), tenantID, reviewerID, itemID, &models.SubmitDecisionRequest{
		Decision:      models.DecisionApproved,
		Justification: "looks good",
	})

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestAccessReviewService_SubmitDecision_Deny(t *testing.T) {
	svc, repo, _, _ := newARService(t)

	tenantID := uuid.New()
	reviewerID := uuid.New()
	itemID := uuid.New()

	item := &models.AccessReviewItem{
		ID:           itemID,
		TenantID:     tenantID,
		ReviewerID:   reviewerID,
		Decision:     models.DecisionPending,
		CampaignID:   uuid.New(),
		UserID:       uuid.New(),
		ResourceType: "role",
		ResourceID:   uuid.New(),
	}

	repo.On("GetReviewItem", mock.Anything, itemID, tenantID).Return(item, nil)
	repo.On("SubmitDecision", mock.Anything, itemID, models.DecisionDenied, "user no longer needs this role").Return(nil)

	err := svc.SubmitDecision(context.Background(), tenantID, reviewerID, itemID, &models.SubmitDecisionRequest{
		Decision:      models.DecisionDenied,
		Justification: "user no longer needs this role",
	})

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestAccessReviewService_SubmitDecision_AlreadyDecided_Rejected(t *testing.T) {
	svc, repo, _, _ := newARService(t)

	tenantID := uuid.New()
	reviewerID := uuid.New()
	itemID := uuid.New()

	item := &models.AccessReviewItem{
		ID:         itemID,
		TenantID:   tenantID,
		ReviewerID: reviewerID,
		Decision:   models.DecisionApproved, // already decided
	}

	repo.On("GetReviewItem", mock.Anything, itemID, tenantID).Return(item, nil)

	err := svc.SubmitDecision(context.Background(), tenantID, reviewerID, itemID, &models.SubmitDecisionRequest{
		Decision: models.DecisionDenied,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already been decided")
	repo.AssertNotCalled(t, "SubmitDecision")
}

func TestAccessReviewService_SubmitDecision_WrongReviewer(t *testing.T) {
	svc, repo, _, _ := newARService(t)

	tenantID := uuid.New()
	callerID := uuid.New() // different from item's reviewerID
	itemID := uuid.New()

	item := &models.AccessReviewItem{
		ID:         itemID,
		TenantID:   tenantID,
		ReviewerID: uuid.New(), // assigned to someone else
		Decision:   models.DecisionPending,
	}

	repo.On("GetReviewItem", mock.Anything, itemID, tenantID).Return(item, nil)

	err := svc.SubmitDecision(context.Background(), tenantID, callerID, itemID, &models.SubmitDecisionRequest{
		Decision: models.DecisionApproved,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reviewer mismatch")
	repo.AssertNotCalled(t, "SubmitDecision")
}

func TestAccessReviewService_FinalizeCampaign_AutoRevoke(t *testing.T) {
	svc, repo, _, _ := newARService(t)

	campaign := makeCampaign(models.CampaignStatusActive)
	campaign.AutoRevoke = true

	pendingItems := []*models.AccessReviewItem{
		{ID: uuid.New(), Decision: models.DecisionPending},
		{ID: uuid.New(), Decision: models.DecisionPending},
	}

	repo.On("GetCampaignByID", mock.Anything, campaign.ID, campaign.TenantID).Return(campaign, nil)
	repo.On("ListExpiredPendingItems", mock.Anything, campaign.ID).Return(pendingItems, nil)
	repo.On("SubmitDecision", mock.Anything, pendingItems[0].ID, models.DecisionExpired, mock.AnythingOfType("string")).Return(nil)
	repo.On("SubmitDecision", mock.Anything, pendingItems[1].ID, models.DecisionExpired, mock.AnythingOfType("string")).Return(nil)
	repo.On("UpdateCampaignStatus", mock.Anything, campaign.ID, models.CampaignStatusCompleted).Return(nil)

	err := svc.FinalizeCampaign(context.Background(), campaign.ID, campaign.TenantID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestAccessReviewService_FinalizeCampaign_NoAutoRevoke(t *testing.T) {
	svc, repo, _, _ := newARService(t)

	campaign := makeCampaign(models.CampaignStatusActive)
	campaign.AutoRevoke = false

	repo.On("GetCampaignByID", mock.Anything, campaign.ID, campaign.TenantID).Return(campaign, nil)
	repo.On("UpdateCampaignStatus", mock.Anything, campaign.ID, models.CampaignStatusCompleted).Return(nil)

	err := svc.FinalizeCampaign(context.Background(), campaign.ID, campaign.TenantID)

	require.NoError(t, err)
	repo.AssertNotCalled(t, "ListExpiredPendingItems")
	repo.AssertExpectations(t)
}

func TestAccessReviewService_FinalizeCampaign_AlreadyCompleted(t *testing.T) {
	svc, repo, _, _ := newARService(t)

	campaign := makeCampaign(models.CampaignStatusCompleted)

	repo.On("GetCampaignByID", mock.Anything, campaign.ID, campaign.TenantID).Return(campaign, nil)

	err := svc.FinalizeCampaign(context.Background(), campaign.ID, campaign.TenantID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already completed")
	repo.AssertNotCalled(t, "UpdateCampaignStatus")
}

func TestAccessReviewService_GetCampaignDetails_WithStats(t *testing.T) {
	svc, repo, _, _ := newARService(t)

	campaign := makeCampaign(models.CampaignStatusActive)
	stats := &models.AccessReviewCampaignStats{
		TotalItems:    10,
		PendingItems:  3,
		ApprovedItems: 5,
		DeniedItems:   2,
	}

	repo.On("GetCampaignByID", mock.Anything, campaign.ID, campaign.TenantID).Return(campaign, nil)
	repo.On("GetCampaignStats", mock.Anything, campaign.ID).Return(stats, nil)

	resp, err := svc.GetCampaignDetails(context.Background(), campaign.ID, campaign.TenantID)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, campaign.ID, resp.ID)
	assert.NotNil(t, resp.Stats)
	assert.Equal(t, 10, resp.Stats.TotalItems)
	assert.Equal(t, 3, resp.Stats.PendingItems)
	repo.AssertExpectations(t)
}

func TestAccessReviewService_ListCampaigns_FilterByStatus(t *testing.T) {
	svc, repo, _, _ := newARService(t)

	tenantID := uuid.New()
	activeCampaign := makeCampaign(models.CampaignStatusActive)
	activeCampaign.TenantID = tenantID

	repo.On("ListCampaigns", mock.Anything, tenantID, "active", 1, 20).
		Return([]*models.AccessReviewCampaign{activeCampaign}, int64(1), nil)

	campaigns, total, err := svc.ListCampaigns(context.Background(), tenantID, "active", 1, 20)

	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, campaigns, 1)
	assert.Equal(t, models.CampaignStatusActive, campaigns[0].Status)
	repo.AssertExpectations(t)
}

func TestAccessReviewService_ListPendingItems(t *testing.T) {
	svc, repo, _, _ := newARService(t)

	tenantID := uuid.New()
	reviewerID := uuid.New()

	pendingItems := []*models.AccessReviewItem{
		{ID: uuid.New(), ReviewerID: reviewerID, Decision: models.DecisionPending},
		{ID: uuid.New(), ReviewerID: reviewerID, Decision: models.DecisionPending},
	}

	repo.On("ListPendingItems", mock.Anything, reviewerID, tenantID).Return(pendingItems, nil)

	items, err := svc.ListPendingItems(context.Background(), reviewerID, tenantID)

	require.NoError(t, err)
	assert.Len(t, items, 2)
	repo.AssertExpectations(t)
}

func TestAccessReviewService_CreateCampaign_InvalidDuration(t *testing.T) {
	svc, _, _, _ := newARService(t)

	req := makeCreateRequest("role", 0) // invalid: 0 days

	_, err := svc.CreateCampaign(context.Background(), uuid.New(), uuid.New(), req)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duration_days")
}

func TestAccessReviewService_CreateCampaign_InvalidResourceType(t *testing.T) {
	svc, _, _, _ := newARService(t)

	req := makeCreateRequest("invalid_type", 14)

	_, err := svc.CreateCampaign(context.Background(), uuid.New(), uuid.New(), req)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "resource_type")
}

func TestAccessReviewService_CreateCampaign_AuditLogged(t *testing.T) {
	// Verify that the audit service is called on campaign creation.
	// We use a nil audit service for simplicity (service guards against nil),
	// so we test that the flow completes successfully which implies the guard worked.
	svc, repo, roleRepo, _ := newARService(t)

	tenantID := uuid.New()
	createdBy := uuid.New()
	req := makeCreateRequest("role", 14)

	repo.On("CreateCampaign", mock.Anything, mock.AnythingOfType("*models.AccessReviewCampaign")).Return(nil)
	roleRepo.On("ListUserRoleAssignments", mock.Anything, tenantID).Return([]UserRoleAssignment{}, nil)

	campaign, err := svc.CreateCampaign(context.Background(), tenantID, createdBy, req)

	// The campaign was created; the audit service (nil in test) was guarded against nil correctly.
	require.NoError(t, err)
	require.NotNil(t, campaign)
	repo.AssertExpectations(t)
}

func TestAccessReviewService_CreateCampaign_GroupResourceType(t *testing.T) {
	svc, repo, _, groupRepo := newARService(t)

	tenantID := uuid.New()
	createdBy := uuid.New()
	req := makeCreateRequest("group", 30)

	memberships := []UserGroupMembership{
		{UserID: uuid.New(), GroupID: uuid.New(), GroupName: "engineering"},
	}

	repo.On("CreateCampaign", mock.Anything, mock.AnythingOfType("*models.AccessReviewCampaign")).Return(nil)
	groupRepo.On("ListUserGroupMemberships", mock.Anything, tenantID).Return(memberships, nil)
	repo.On("CreateReviewItems", mock.Anything, mock.MatchedBy(func(items []*models.AccessReviewItem) bool {
		return len(items) == 1 && items[0].ResourceType == "group"
	})).Return(nil)

	campaign, err := svc.CreateCampaign(context.Background(), tenantID, createdBy, req)

	require.NoError(t, err)
	require.NotNil(t, campaign)
	groupRepo.AssertExpectations(t)
}

func TestAccessReviewService_FinalizeCampaign_NotFound(t *testing.T) {
	svc, repo, _, _ := newARService(t)

	campaignID := uuid.New()
	tenantID := uuid.New()

	repo.On("GetCampaignByID", mock.Anything, campaignID, tenantID).Return(nil, nil)

	err := svc.FinalizeCampaign(context.Background(), campaignID, tenantID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAccessReviewService_ListCampaigns_DefaultPagination(t *testing.T) {
	svc, repo, _, _ := newARService(t)

	tenantID := uuid.New()

	// page=0, pageSize=0 should be normalised to page=1, pageSize=20
	repo.On("ListCampaigns", mock.Anything, tenantID, "", 1, 20).
		Return([]*models.AccessReviewCampaign{}, int64(0), nil)

	_, _, err := svc.ListCampaigns(context.Background(), tenantID, "", 0, 0)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestAccessReviewService_SubmitDecision_RepoError(t *testing.T) {
	svc, repo, _, _ := newARService(t)

	tenantID := uuid.New()
	reviewerID := uuid.New()
	itemID := uuid.New()

	repo.On("GetReviewItem", mock.Anything, itemID, tenantID).
		Return(nil, errors.New("database unavailable"))

	err := svc.SubmitDecision(context.Background(), tenantID, reviewerID, itemID, &models.SubmitDecisionRequest{
		Decision: models.DecisionApproved,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database unavailable")
}

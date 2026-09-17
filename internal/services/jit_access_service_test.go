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

type mockJITRepo struct {
	mock.Mock
}

func (m *mockJITRepo) Create(ctx context.Context, grant *models.JITAccessGrant) error {
	args := m.Called(ctx, grant)
	return args.Error(0)
}

func (m *mockJITRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.JITAccessGrant, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.JITAccessGrant), args.Error(1)
}

func (m *mockJITRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status models.JITAccessStatus) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *mockJITRepo) Approve(ctx context.Context, id, approverID uuid.UUID, startsAt time.Time) error {
	args := m.Called(ctx, id, approverID, startsAt)
	return args.Error(0)
}

func (m *mockJITRepo) Activate(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockJITRepo) ListByTenant(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]*models.JITAccessGrant, int64, error) {
	args := m.Called(ctx, tenantID, status, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.JITAccessGrant), args.Get(1).(int64), args.Error(2)
}

func (m *mockJITRepo) ListExpiredActive(ctx context.Context, limit int) ([]*models.JITAccessGrant, error) {
	args := m.Called(ctx, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.JITAccessGrant), args.Error(1)
}

type mockJITSpiceDB struct {
	mock.Mock
}

func (m *mockJITSpiceDB) WriteRelationship(ctx context.Context, tenantID uuid.UUID, relationship interface{}) error {
	args := m.Called(ctx, tenantID, relationship)
	return args.Error(0)
}

func (m *mockJITSpiceDB) DeleteRelationship(ctx context.Context, tenantID uuid.UUID, relationship interface{}) error {
	args := m.Called(ctx, tenantID, relationship)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newJITService(t *testing.T) (*JITAccessService, *mockJITRepo, *mockJITSpiceDB) {
	t.Helper()
	repo := new(mockJITRepo)
	spicedb := new(mockJITSpiceDB)
	// Pass nil for auditService — tests do not require audit side-effects.
	svc := NewJITAccessService(repo, spicedb, nil, zap.NewNop())
	return svc, repo, spicedb
}

// makeGrant returns a grant whose status and expiry can be customised by the caller.
func makeGrant(status models.JITAccessStatus, expiresIn time.Duration) *models.JITAccessGrant {
	now := time.Now().UTC()
	return &models.JITAccessGrant{
		ID:            uuid.New(),
		UserID:        uuid.New(),
		RoleID:        uuid.New(),
		TenantID:      uuid.New(),
		Justification: "need elevated access for incident response",
		RequestedAt:   now,
		StartsAt:      now,
		ExpiresAt:     now.Add(expiresIn),
		Status:        status,
		CreatedAt:     now,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestJITAccessService_RequestAccess(t *testing.T) {
	svc, repo, _ := newJITService(t)

	tenantID := uuid.New()
	req := &models.CreateJITAccessRequest{
		UserID:        uuid.New(),
		RoleID:        uuid.New(),
		Justification: "incident response — need billing:admin for 1 hour",
		Duration:      3600,
	}

	repo.On("Create", mock.Anything, mock.MatchedBy(func(g *models.JITAccessGrant) bool {
		g.ID = uuid.New() // simulate DB population
		return g.UserID == req.UserID &&
			g.RoleID == req.RoleID &&
			g.TenantID == tenantID &&
			g.Status == models.JITAccessStatusPending &&
			g.Justification == req.Justification
	})).Return(nil)

	grant, err := svc.RequestAccess(context.Background(), tenantID, req)

	require.NoError(t, err)
	require.NotNil(t, grant)
	assert.Equal(t, models.JITAccessStatusPending, grant.Status)
	assert.Equal(t, req.UserID, grant.UserID)
	assert.Equal(t, req.RoleID, grant.RoleID)
	assert.Equal(t, tenantID, grant.TenantID)
	// ExpiresAt should be roughly now + Duration seconds.
	expectedExpiry := time.Now().UTC().Add(time.Duration(req.Duration) * time.Second)
	assert.WithinDuration(t, expectedExpiry, grant.ExpiresAt, 2*time.Second)
	repo.AssertExpectations(t)
}

func TestJITAccessService_ApproveAccess(t *testing.T) {
	svc, repo, _ := newJITService(t)

	grant := makeGrant(models.JITAccessStatusPending, 2*time.Hour)
	approverID := uuid.New()

	// First GetByID returns the pending grant.
	repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil).Once()
	repo.On("Approve", mock.Anything, grant.ID, approverID, grant.StartsAt).Return(nil)

	// Second GetByID (after approval) returns an updated grant.
	approved := *grant
	approved.Status = models.JITAccessStatusApproved
	approved.ApprovedBy = &approverID
	repo.On("GetByID", mock.Anything, grant.ID).Return(&approved, nil).Once()

	result, err := svc.ApproveAccess(context.Background(), grant.ID, approverID, grant.TenantID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, models.JITAccessStatusApproved, result.Status)
	repo.AssertExpectations(t)
}

// TestJITAccessService_ApproveAccess_CrossTenant is the t-437 regression: an
// approver authenticated for one tenant must not be able to approve a grant
// that belongs to a different tenant, even though they know (or guessed)
// its ID. The grant-ID lookup itself carries no tenant scoping, so this
// must be enforced in the service before any status/self-approval check.
func TestJITAccessService_ApproveAccess_CrossTenant(t *testing.T) {
	svc, repo, _ := newJITService(t)

	grant := makeGrant(models.JITAccessStatusPending, 2*time.Hour)
	foreignApproverID := uuid.New()
	foreignApproverTenantID := uuid.New() // deliberately != grant.TenantID

	repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)

	result, err := svc.ApproveAccess(context.Background(), grant.ID, foreignApproverID, foreignApproverTenantID)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "not found")
	repo.AssertNotCalled(t, "Approve")
}

func TestJITAccessService_ApproveAccess_NotPending(t *testing.T) {
	tests := []struct {
		name   string
		status models.JITAccessStatus
	}{
		{"already approved", models.JITAccessStatusApproved},
		{"already active", models.JITAccessStatusActive},
		{"already expired", models.JITAccessStatusExpired},
		{"already revoked", models.JITAccessStatusRevoked},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, _ := newJITService(t)

			grant := makeGrant(tc.status, 2*time.Hour)
			approverID := uuid.New()

			repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)

			result, err := svc.ApproveAccess(context.Background(), grant.ID, approverID, grant.TenantID)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "not in pending state")
			repo.AssertNotCalled(t, "Approve")
		})
	}
}

func TestJITAccessService_ActivateGrant(t *testing.T) {
	svc, repo, spicedb := newJITService(t)

	grant := makeGrant(models.JITAccessStatusApproved, 2*time.Hour)

	repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)
	spicedb.On("WriteRelationship", mock.Anything, grant.TenantID, mock.Anything).Return(nil)
	repo.On("Activate", mock.Anything, grant.ID).Return(nil)

	err := svc.ActivateGrant(context.Background(), grant.ID, grant.TenantID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
	spicedb.AssertExpectations(t)
}

// TestJITAccessService_ActivateGrant_CrossTenant is the t-437 regression for
// the activation path: activating writes a real SpiceDB role membership, so
// a missing tenant check here is not just an info leak, it's a privilege
// grant into a foreign tenant.
func TestJITAccessService_ActivateGrant_CrossTenant(t *testing.T) {
	svc, repo, spicedb := newJITService(t)

	grant := makeGrant(models.JITAccessStatusApproved, 2*time.Hour)
	foreignTenantID := uuid.New()

	repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)

	err := svc.ActivateGrant(context.Background(), grant.ID, foreignTenantID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	spicedb.AssertNotCalled(t, "WriteRelationship")
	repo.AssertNotCalled(t, "Activate")
}

func TestJITAccessService_ActivateGrant_NotApproved(t *testing.T) {
	tests := []struct {
		name   string
		status models.JITAccessStatus
	}{
		{"pending", models.JITAccessStatusPending},
		{"active", models.JITAccessStatusActive},
		{"expired", models.JITAccessStatusExpired},
		{"revoked", models.JITAccessStatusRevoked},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, spicedb := newJITService(t)

			// Use far-future expiry so the test cannot trigger the IsExpired path
			// (we want to isolate the "not approved" guard).
			grant := makeGrant(tc.status, 24*time.Hour)

			repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)

			err := svc.ActivateGrant(context.Background(), grant.ID, grant.TenantID)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), "not in approved state")
			spicedb.AssertNotCalled(t, "WriteRelationship")
			repo.AssertNotCalled(t, "Activate")
		})
	}
}

func TestJITAccessService_ActivateGrant_Expired(t *testing.T) {
	svc, repo, spicedb := newJITService(t)

	// Approved grant whose expiry is in the past.
	grant := makeGrant(models.JITAccessStatusApproved, -1*time.Minute)

	repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)
	// Service must mark the grant as expired when it detects expiry during activation.
	repo.On("UpdateStatus", mock.Anything, grant.ID, models.JITAccessStatusExpired).Return(nil)

	err := svc.ActivateGrant(context.Background(), grant.ID, grant.TenantID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already expired")
	spicedb.AssertNotCalled(t, "WriteRelationship")
	repo.AssertExpectations(t)
}

func TestJITAccessService_RevokeGrant_Active(t *testing.T) {
	svc, repo, spicedb := newJITService(t)

	grant := makeGrant(models.JITAccessStatusActive, 2*time.Hour)
	revokerID := uuid.New()

	repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)
	// Active grants require SpiceDB relationship removal before DB update.
	spicedb.On("DeleteRelationship", mock.Anything, grant.TenantID, mock.Anything).Return(nil)
	repo.On("UpdateStatus", mock.Anything, grant.ID, models.JITAccessStatusRevoked).Return(nil)

	err := svc.RevokeGrant(context.Background(), grant.ID, revokerID, grant.TenantID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
	spicedb.AssertExpectations(t)
}

// TestJITAccessService_RevokeGrant_CrossTenant is the t-437 regression for
// the revoke path: an admin from tenant A must not be able to revoke (or
// probe the existence/status of) tenant B's grant.
func TestJITAccessService_RevokeGrant_CrossTenant(t *testing.T) {
	svc, repo, spicedb := newJITService(t)

	grant := makeGrant(models.JITAccessStatusActive, 2*time.Hour)
	revokerID := uuid.New()
	foreignTenantID := uuid.New()

	repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)

	err := svc.RevokeGrant(context.Background(), grant.ID, revokerID, foreignTenantID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	spicedb.AssertNotCalled(t, "DeleteRelationship")
	repo.AssertNotCalled(t, "UpdateStatus")
}

func TestJITAccessService_RevokeGrant_Pending(t *testing.T) {
	svc, repo, spicedb := newJITService(t)

	// Pending grants have no SpiceDB relationship, so DeleteRelationship must not be called.
	grant := makeGrant(models.JITAccessStatusPending, 2*time.Hour)
	revokerID := uuid.New()

	repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)
	repo.On("UpdateStatus", mock.Anything, grant.ID, models.JITAccessStatusRevoked).Return(nil)

	err := svc.RevokeGrant(context.Background(), grant.ID, revokerID, grant.TenantID)

	require.NoError(t, err)
	spicedb.AssertNotCalled(t, "DeleteRelationship")
	repo.AssertExpectations(t)
}

func TestJITAccessService_RevokeGrant_AlreadyTerminal(t *testing.T) {
	tests := []struct {
		name   string
		status models.JITAccessStatus
	}{
		{"already expired", models.JITAccessStatusExpired},
		{"already revoked", models.JITAccessStatusRevoked},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, spicedb := newJITService(t)

			grant := makeGrant(tc.status, -1*time.Minute)
			revokerID := uuid.New()

			repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)

			err := svc.RevokeGrant(context.Background(), grant.ID, revokerID, grant.TenantID)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), string(tc.status))
			spicedb.AssertNotCalled(t, "DeleteRelationship")
			repo.AssertNotCalled(t, "UpdateStatus")
		})
	}
}

func TestJITAccessService_ExpireGrants(t *testing.T) {
	svc, repo, spicedb := newJITService(t)

	// Two active grants that have already passed their expiry.
	grant1 := makeGrant(models.JITAccessStatusActive, -5*time.Minute)
	grant2 := makeGrant(models.JITAccessStatusActive, -2*time.Minute)
	expiredGrants := []*models.JITAccessGrant{grant1, grant2}

	repo.On("ListExpiredActive", mock.Anything, 100).Return(expiredGrants, nil)

	spicedb.On("DeleteRelationship", mock.Anything, grant1.TenantID, mock.Anything).Return(nil)
	repo.On("UpdateStatus", mock.Anything, grant1.ID, models.JITAccessStatusExpired).Return(nil)

	spicedb.On("DeleteRelationship", mock.Anything, grant2.TenantID, mock.Anything).Return(nil)
	repo.On("UpdateStatus", mock.Anything, grant2.ID, models.JITAccessStatusExpired).Return(nil)

	err := svc.ExpireGrants(context.Background())

	require.NoError(t, err)
	repo.AssertExpectations(t)
	spicedb.AssertExpectations(t)
}

func TestJITAccessService_ExpireGrants_SpiceDBErrorContinues(t *testing.T) {
	svc, repo, spicedb := newJITService(t)

	// First grant: SpiceDB fails, processing continues to the second grant.
	grant1 := makeGrant(models.JITAccessStatusActive, -5*time.Minute)
	grant2 := makeGrant(models.JITAccessStatusActive, -2*time.Minute)
	expiredGrants := []*models.JITAccessGrant{grant1, grant2}

	repo.On("ListExpiredActive", mock.Anything, 100).Return(expiredGrants, nil)

	spiceDBErr := errors.New("spicedb unavailable")
	spicedb.On("DeleteRelationship", mock.Anything, grant1.TenantID, mock.Anything).Return(spiceDBErr)
	// grant1 DB update is skipped because SpiceDB failed.

	spicedb.On("DeleteRelationship", mock.Anything, grant2.TenantID, mock.Anything).Return(nil)
	repo.On("UpdateStatus", mock.Anything, grant2.ID, models.JITAccessStatusExpired).Return(nil)

	// ExpireGrants returns the last error encountered.
	err := svc.ExpireGrants(context.Background())

	assert.Error(t, err)
	assert.ErrorIs(t, err, spiceDBErr)
	// grant2 must still be processed.
	repo.AssertCalled(t, "UpdateStatus", mock.Anything, grant2.ID, models.JITAccessStatusExpired)
}

func TestJITAccessService_ExpireGrants_NoExpiredGrants(t *testing.T) {
	svc, repo, spicedb := newJITService(t)

	repo.On("ListExpiredActive", mock.Anything, 100).Return([]*models.JITAccessGrant{}, nil)

	err := svc.ExpireGrants(context.Background())

	require.NoError(t, err)
	spicedb.AssertNotCalled(t, "DeleteRelationship")
	repo.AssertNotCalled(t, "UpdateStatus")
}

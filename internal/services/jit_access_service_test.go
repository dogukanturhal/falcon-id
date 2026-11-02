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
	queued []*models.JITAccessGrant
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

func (m *mockJITRepo) FinalizeGrant(ctx context.Context, grant *models.JITAccessGrant, status models.JITAccessStatus) error {
	args := m.Called(ctx, grant.ID, status)
	err := args.Error(0)
	if err == nil && grant.Status == models.JITAccessStatusActive {
		m.queued = append(m.queued, grant)
	}
	return err
}

func (m *mockJITRepo) QueueActivationRollback(ctx context.Context, grant *models.JITAccessGrant) error {
	args := m.Called(ctx, grant.ID)
	err := args.Error(0)
	if err == nil {
		m.queued = append(m.queued, grant)
	}
	return err
}

// A small transactional-repo fake for existing unit tests; the real PostgreSQL
// durability and retry behavior is covered by role_revoke_postgres_test.go.
type jitTestDrainer struct {
	repo   *mockJITRepo
	client jitSpiceDBClient
}

func (d *jitTestDrainer) Drain(ctx context.Context, userID uuid.UUID) error {
	for _, g := range d.repo.queued {
		if g.UserID == userID {
			if _, err := d.client.DeleteUserRole(ctx, g.TenantID, g.UserID, g.RoleID); err != nil {
				return err
			}
		}
	}
	d.repo.queued = nil
	return nil
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

// mockJITSpiceDB implements jitSpiceDBClient (WriteUserRoleUntil/DeleteUserRole —
// the same shape as *pkg/spicedb.Client), matching what ActivateGrant/
// ExpireGrants/RevokeGrant now call directly.
type mockJITSpiceDB struct {
	mock.Mock
}

func (m *mockJITSpiceDB) WriteUserRoleUntil(ctx context.Context, tenantID, userID, roleID uuid.UUID, expiresAt time.Time) (string, error) {
	args := m.Called(ctx, tenantID, userID, roleID, expiresAt)
	return args.String(0), args.Error(1)
}

func (m *mockJITSpiceDB) DeleteUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error) {
	args := m.Called(ctx, tenantID, userID, roleID)
	return args.String(0), args.Error(1)
}

type mockJITEligibleRepo struct {
	mock.Mock
}

func (m *mockJITEligibleRepo) GetForUserRole(ctx context.Context, userID, roleID uuid.UUID) (*models.JITEligible, error) {
	args := m.Called(ctx, userID, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.JITEligible), args.Error(1)
}

type mockJITStepUpRepo struct {
	mock.Mock
}

func (m *mockJITStepUpRepo) HasRecentVerification(ctx context.Context, sessionID uuid.UUID, action string, maxAge time.Duration) (bool, error) {
	args := m.Called(ctx, sessionID, action, maxAge)
	return args.Bool(0), args.Error(1)
}

// mockJITUserRoleWriter implements jitUserRoleWriter. Its writes are
// best-effort/secondary in the service, so most tests stub it permissively
// with .Maybe().
type mockJITUserRoleWriter struct {
	mock.Mock
}

func (m *mockJITUserRoleWriter) AddTimeBoundRole(ctx context.Context, userID, roleID, assignedBy uuid.UUID, expiresAt time.Time) (uuid.UUID, error) {
	args := m.Called(ctx, userID, roleID, assignedBy, expiresAt)
	if args.Get(0) == nil {
		return uuid.Nil, args.Error(1)
	}
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *mockJITUserRoleWriter) RemoveTimeBoundRole(ctx context.Context, userID, roleID uuid.UUID) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type jitServiceDeps struct {
	repo      *mockJITRepo
	spicedb   *mockJITSpiceDB
	eligible  *mockJITEligibleRepo
	stepUp    *mockJITStepUpRepo
	userRoles *mockJITUserRoleWriter
}

func newJITService(t *testing.T) (*JITAccessService, *jitServiceDeps) {
	t.Helper()
	deps := &jitServiceDeps{
		repo:      new(mockJITRepo),
		spicedb:   new(mockJITSpiceDB),
		eligible:  new(mockJITEligibleRepo),
		stepUp:    new(mockJITStepUpRepo),
		userRoles: new(mockJITUserRoleWriter),
	}
	// Secondary iam_user_roles projection writes are best-effort by design
	// (see ActivateGrant/ExpireGrants/RevokeGrant doc comments); permit them
	// unconditionally unless a specific test overrides the expectation.
	deps.userRoles.On("AddTimeBoundRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(uuid.New(), nil).Maybe()
	deps.userRoles.On("RemoveTimeBoundRole", mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Maybe()

	svc := NewJITAccessService(deps.repo, deps.eligible, deps.stepUp, deps.userRoles, deps.spicedb, nil, zap.NewNop())
	svc.SetRoleRevokeDrainer(&jitTestDrainer{repo: deps.repo, client: deps.spicedb})
	return svc, deps
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

// makeEligible returns a standing eligibility row for (userID, roleID) with
// sane defaults; overridden per-field by callers as needed.
func makeEligible(userID, roleID, tenantID uuid.UUID) *models.JITEligible {
	return &models.JITEligible{
		ID:                 uuid.New(),
		UserID:             userID,
		RoleID:             roleID,
		TenantID:           tenantID,
		MaxDurationSeconds: 14400,
		RequiresMFA:        false,
		RequiresApproval:   true,
		CreatedAt:          time.Now().UTC(),
	}
}

// ---------------------------------------------------------------------------
// RequestAccess — eligibility gate
// ---------------------------------------------------------------------------

func TestJITAccessService_RequestAccess_EligibleSucceeds(t *testing.T) {
	svc, deps := newJITService(t)

	tenantID := uuid.New()
	sessionID := uuid.New()
	req := &models.CreateJITAccessRequest{
		UserID:        uuid.New(),
		RoleID:        uuid.New(),
		Justification: "incident response — need billing:admin for 1 hour",
		Duration:      3600,
	}

	elig := makeEligible(req.UserID, req.RoleID, tenantID)
	deps.eligible.On("GetForUserRole", mock.Anything, req.UserID, req.RoleID).Return(elig, nil)

	deps.repo.On("Create", mock.Anything, mock.MatchedBy(func(g *models.JITAccessGrant) bool {
		g.ID = uuid.New() // simulate DB population
		return g.UserID == req.UserID &&
			g.RoleID == req.RoleID &&
			g.TenantID == tenantID &&
			g.Status == models.JITAccessStatusPending &&
			g.Justification == req.Justification
	})).Return(nil)

	grant, err := svc.RequestAccess(context.Background(), tenantID, sessionID, req)

	require.NoError(t, err)
	require.NotNil(t, grant)
	assert.Equal(t, models.JITAccessStatusPending, grant.Status)
	assert.Equal(t, req.UserID, grant.UserID)
	assert.Equal(t, req.RoleID, grant.RoleID)
	assert.Equal(t, tenantID, grant.TenantID)
	expectedExpiry := time.Now().UTC().Add(time.Duration(req.Duration) * time.Second)
	assert.WithinDuration(t, expectedExpiry, grant.ExpiresAt, 2*time.Second)
	deps.repo.AssertExpectations(t)
}

// TestJITAccessService_RequestAccess_NotEligible is the required "elevation
// requires eligibility" behavioral test: a user with NO iam_jit_eligible row
// for the target role must be denied before any grant row is created — the
// control (TestJITAccessService_RequestAccess_EligibleSucceeds above) proves
// the same code path succeeds once an eligibility row exists, so this is not
// merely an always-failing stub.
func TestJITAccessService_RequestAccess_NotEligible(t *testing.T) {
	svc, deps := newJITService(t)

	tenantID := uuid.New()
	sessionID := uuid.New()
	req := &models.CreateJITAccessRequest{
		UserID:        uuid.New(),
		RoleID:        uuid.New(),
		Justification: "trying to self-elevate without a standing eligibility grant",
		Duration:      3600,
	}

	deps.eligible.On("GetForUserRole", mock.Anything, req.UserID, req.RoleID).Return(nil, nil)

	grant, err := svc.RequestAccess(context.Background(), tenantID, sessionID, req)

	require.Error(t, err)
	assert.Nil(t, grant)
	assert.ErrorIs(t, err, ErrNotEligible)
	deps.repo.AssertNotCalled(t, "Create")
}

func TestJITAccessService_RequestAccess_EligibilityOutsideValidityWindow(t *testing.T) {
	svc, deps := newJITService(t)

	tenantID := uuid.New()
	sessionID := uuid.New()
	req := &models.CreateJITAccessRequest{
		UserID:        uuid.New(),
		RoleID:        uuid.New(),
		Justification: "eligibility exists but window has lapsed",
		Duration:      3600,
	}

	elig := makeEligible(req.UserID, req.RoleID, tenantID)
	pastWindow := time.Now().Add(-1 * time.Hour)
	elig.ValidUntil = &pastWindow
	deps.eligible.On("GetForUserRole", mock.Anything, req.UserID, req.RoleID).Return(elig, nil)

	grant, err := svc.RequestAccess(context.Background(), tenantID, sessionID, req)

	require.Error(t, err)
	assert.Nil(t, grant)
	assert.ErrorIs(t, err, ErrEligibilityWindow)
	deps.repo.AssertNotCalled(t, "Create")
}

func TestJITAccessService_RequestAccess_DurationExceedsEligibility(t *testing.T) {
	svc, deps := newJITService(t)

	tenantID := uuid.New()
	sessionID := uuid.New()
	req := &models.CreateJITAccessRequest{
		UserID:        uuid.New(),
		RoleID:        uuid.New(),
		Justification: "requesting 4 hours against a 1-hour eligibility cap",
		Duration:      14400,
	}

	elig := makeEligible(req.UserID, req.RoleID, tenantID)
	elig.MaxDurationSeconds = 3600
	deps.eligible.On("GetForUserRole", mock.Anything, req.UserID, req.RoleID).Return(elig, nil)

	grant, err := svc.RequestAccess(context.Background(), tenantID, sessionID, req)

	require.Error(t, err)
	assert.Nil(t, grant)
	assert.ErrorIs(t, err, ErrDurationExceedsEligibility)
	deps.repo.AssertNotCalled(t, "Create")
}

func TestJITAccessService_RequestAccess_RequiresMFA_StepUpMissing(t *testing.T) {
	svc, deps := newJITService(t)

	tenantID := uuid.New()
	sessionID := uuid.New()
	req := &models.CreateJITAccessRequest{
		UserID:        uuid.New(),
		RoleID:        uuid.New(),
		Justification: "requesting a role that requires a fresh step-up verification",
		Duration:      3600,
	}

	elig := makeEligible(req.UserID, req.RoleID, tenantID)
	elig.RequiresMFA = true
	deps.eligible.On("GetForUserRole", mock.Anything, req.UserID, req.RoleID).Return(elig, nil)
	deps.stepUp.On("HasRecentVerification", mock.Anything, sessionID, JITStepUpAction, jitStepUpMaxAge).Return(false, nil)

	grant, err := svc.RequestAccess(context.Background(), tenantID, sessionID, req)

	require.Error(t, err)
	assert.Nil(t, grant)
	assert.ErrorIs(t, err, ErrStepUpRequired)
	deps.repo.AssertNotCalled(t, "Create")
}

func TestJITAccessService_RequestAccess_RequiresMFA_StepUpPresent(t *testing.T) {
	svc, deps := newJITService(t)

	tenantID := uuid.New()
	sessionID := uuid.New()
	req := &models.CreateJITAccessRequest{
		UserID:        uuid.New(),
		RoleID:        uuid.New(),
		Justification: "requesting a role that requires a fresh step-up verification, already satisfied",
		Duration:      3600,
	}

	elig := makeEligible(req.UserID, req.RoleID, tenantID)
	elig.RequiresMFA = true
	deps.eligible.On("GetForUserRole", mock.Anything, req.UserID, req.RoleID).Return(elig, nil)
	deps.stepUp.On("HasRecentVerification", mock.Anything, sessionID, JITStepUpAction, jitStepUpMaxAge).Return(true, nil)
	deps.repo.On("Create", mock.Anything, mock.Anything).Return(nil)

	grant, err := svc.RequestAccess(context.Background(), tenantID, sessionID, req)

	require.NoError(t, err)
	require.NotNil(t, grant)
	deps.repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// ApproveAccess
// ---------------------------------------------------------------------------

func TestJITAccessService_ApproveAccess(t *testing.T) {
	svc, deps := newJITService(t)

	grant := makeGrant(models.JITAccessStatusPending, 2*time.Hour)
	approverID := uuid.New()

	deps.repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil).Once()
	deps.repo.On("Approve", mock.Anything, grant.ID, approverID, grant.StartsAt).Return(nil)

	approved := *grant
	approved.Status = models.JITAccessStatusApproved
	approved.ApprovedBy = &approverID
	deps.repo.On("GetByID", mock.Anything, grant.ID).Return(&approved, nil).Once()

	result, err := svc.ApproveAccess(context.Background(), grant.ID, approverID, grant.TenantID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, models.JITAccessStatusApproved, result.Status)
	deps.repo.AssertExpectations(t)
}

// TestJITAccessService_ApproveAccess_CrossTenant is the t-437 regression: an
// approver authenticated for one tenant must not be able to approve a grant
// that belongs to a different tenant, even though they know (or guessed)
// its ID. The grant-ID lookup itself carries no tenant scoping, so this
// must be enforced in the service before any status/self-approval check.
func TestJITAccessService_ApproveAccess_CrossTenant(t *testing.T) {
	svc, deps := newJITService(t)

	grant := makeGrant(models.JITAccessStatusPending, 2*time.Hour)
	foreignApproverID := uuid.New()
	foreignApproverTenantID := uuid.New() // deliberately != grant.TenantID

	deps.repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)

	result, err := svc.ApproveAccess(context.Background(), grant.ID, foreignApproverID, foreignApproverTenantID)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "not found")
	deps.repo.AssertNotCalled(t, "Approve")
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
			svc, deps := newJITService(t)

			grant := makeGrant(tc.status, 2*time.Hour)
			approverID := uuid.New()

			deps.repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)

			result, err := svc.ApproveAccess(context.Background(), grant.ID, approverID, grant.TenantID)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "not in pending state")
			deps.repo.AssertNotCalled(t, "Approve")
		})
	}
}

// TestJITAccessService_ApproveAccess_SelfApproval_BlockedWhenApprovalRequired
// covers the default posture: an eligibility row with RequiresApproval=true
// (or no eligibility row at all — it was revoked mid-flight) blocks
// self-approval, same as before this feature's eligibility gate existed.
func TestJITAccessService_ApproveAccess_SelfApproval_BlockedWhenApprovalRequired(t *testing.T) {
	svc, deps := newJITService(t)

	grant := makeGrant(models.JITAccessStatusPending, 2*time.Hour)

	elig := makeEligible(grant.UserID, grant.RoleID, grant.TenantID)
	elig.RequiresApproval = true
	deps.eligible.On("GetForUserRole", mock.Anything, grant.UserID, grant.RoleID).Return(elig, nil)
	deps.repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)

	result, err := svc.ApproveAccess(context.Background(), grant.ID, grant.UserID, grant.TenantID)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "cannot approve your own")
	deps.repo.AssertNotCalled(t, "Approve")
}

// TestJITAccessService_ApproveAccess_SelfApproval_AllowedWhenApprovalNotRequired
// is the counterpart: when the eligibility row explicitly sets
// RequiresApproval=false, the requester may approve (in effect, self-service
// activate) their own request.
func TestJITAccessService_ApproveAccess_SelfApproval_AllowedWhenApprovalNotRequired(t *testing.T) {
	svc, deps := newJITService(t)

	grant := makeGrant(models.JITAccessStatusPending, 2*time.Hour)

	elig := makeEligible(grant.UserID, grant.RoleID, grant.TenantID)
	elig.RequiresApproval = false
	deps.eligible.On("GetForUserRole", mock.Anything, grant.UserID, grant.RoleID).Return(elig, nil)
	deps.repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil).Once()
	deps.repo.On("Approve", mock.Anything, grant.ID, grant.UserID, grant.StartsAt).Return(nil)

	approved := *grant
	approved.Status = models.JITAccessStatusApproved
	approved.ApprovedBy = &grant.UserID
	deps.repo.On("GetByID", mock.Anything, grant.ID).Return(&approved, nil).Once()

	result, err := svc.ApproveAccess(context.Background(), grant.ID, grant.UserID, grant.TenantID)

	require.NoError(t, err)
	require.NotNil(t, result)
	deps.repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// ActivateGrant
// ---------------------------------------------------------------------------

func TestJITAccessService_ActivateGrant(t *testing.T) {
	svc, deps := newJITService(t)

	grant := makeGrant(models.JITAccessStatusApproved, 2*time.Hour)

	deps.repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)
	deps.spicedb.On("WriteUserRoleUntil", mock.Anything, grant.TenantID, grant.UserID, grant.RoleID, grant.ExpiresAt).Return("zedtoken-1", nil)
	deps.repo.On("Activate", mock.Anything, grant.ID).Return(nil)

	err := svc.ActivateGrant(context.Background(), grant.ID, grant.TenantID)

	require.NoError(t, err)
	deps.repo.AssertExpectations(t)
	deps.spicedb.AssertExpectations(t)
}

// TestJITAccessService_ActivateGrant_CrossTenant is the t-437 regression for
// the activation path: activating writes a real SpiceDB role membership, so
// a missing tenant check here is not just an info leak, it's a privilege
// grant into a foreign tenant.
func TestJITAccessService_ActivateGrant_CrossTenant(t *testing.T) {
	svc, deps := newJITService(t)

	grant := makeGrant(models.JITAccessStatusApproved, 2*time.Hour)
	foreignTenantID := uuid.New()

	deps.repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)

	err := svc.ActivateGrant(context.Background(), grant.ID, foreignTenantID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	deps.spicedb.AssertNotCalled(t, "WriteUserRoleUntil")
	deps.repo.AssertNotCalled(t, "Activate")
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
			svc, deps := newJITService(t)

			// Use far-future expiry so the test cannot trigger the IsExpired path
			// (we want to isolate the "not approved" guard).
			grant := makeGrant(tc.status, 24*time.Hour)

			deps.repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)

			err := svc.ActivateGrant(context.Background(), grant.ID, grant.TenantID)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), "not in approved state")
			deps.spicedb.AssertNotCalled(t, "WriteUserRoleUntil")
			deps.repo.AssertNotCalled(t, "Activate")
		})
	}
}

func TestJITAccessService_ActivateGrant_Expired(t *testing.T) {
	svc, deps := newJITService(t)

	// Approved grant whose expiry is in the past.
	grant := makeGrant(models.JITAccessStatusApproved, -1*time.Minute)

	deps.repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)
	// Service must mark the grant as expired when it detects expiry during activation.
	deps.repo.On("UpdateStatus", mock.Anything, grant.ID, models.JITAccessStatusExpired).Return(nil)

	err := svc.ActivateGrant(context.Background(), grant.ID, grant.TenantID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already expired")
	deps.spicedb.AssertNotCalled(t, "WriteUserRoleUntil")
	deps.repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// RevokeGrant
// ---------------------------------------------------------------------------

func TestJITAccessService_RevokeGrant_Active(t *testing.T) {
	svc, deps := newJITService(t)

	grant := makeGrant(models.JITAccessStatusActive, 2*time.Hour)
	revokerID := uuid.New()

	deps.repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)
	// Active grants queue the delete atomically before the post-commit drain.
	deps.spicedb.On("DeleteUserRole", mock.Anything, grant.TenantID, grant.UserID, grant.RoleID).Return("zedtoken-2", nil)
	deps.repo.On("FinalizeGrant", mock.Anything, grant.ID, models.JITAccessStatusRevoked).Return(nil)

	err := svc.RevokeGrant(context.Background(), grant.ID, revokerID, grant.TenantID)

	require.NoError(t, err)
	deps.repo.AssertExpectations(t)
	deps.spicedb.AssertExpectations(t)
}

// TestJITAccessService_RevokeGrant_CrossTenant is the t-437 regression for
// the revoke path: an admin from tenant A must not be able to revoke (or
// probe the existence/status of) tenant B's grant.
func TestJITAccessService_RevokeGrant_CrossTenant(t *testing.T) {
	svc, deps := newJITService(t)

	grant := makeGrant(models.JITAccessStatusActive, 2*time.Hour)
	revokerID := uuid.New()
	foreignTenantID := uuid.New()

	deps.repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)

	err := svc.RevokeGrant(context.Background(), grant.ID, revokerID, foreignTenantID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	deps.spicedb.AssertNotCalled(t, "DeleteUserRole")
	deps.repo.AssertNotCalled(t, "UpdateStatus")
}

func TestJITAccessService_RevokeGrant_Pending(t *testing.T) {
	svc, deps := newJITService(t)

	// Pending grants have no SpiceDB relationship, so DeleteUserRole must not be called.
	grant := makeGrant(models.JITAccessStatusPending, 2*time.Hour)
	revokerID := uuid.New()

	deps.repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)
	deps.repo.On("FinalizeGrant", mock.Anything, grant.ID, models.JITAccessStatusRevoked).Return(nil)

	err := svc.RevokeGrant(context.Background(), grant.ID, revokerID, grant.TenantID)

	require.NoError(t, err)
	deps.spicedb.AssertNotCalled(t, "DeleteUserRole")
	deps.repo.AssertExpectations(t)
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
			svc, deps := newJITService(t)

			grant := makeGrant(tc.status, -1*time.Minute)
			revokerID := uuid.New()

			deps.repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil)

			err := svc.RevokeGrant(context.Background(), grant.ID, revokerID, grant.TenantID)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), string(tc.status))
			deps.spicedb.AssertNotCalled(t, "DeleteUserRole")
			deps.repo.AssertNotCalled(t, "UpdateStatus")
		})
	}
}

// ---------------------------------------------------------------------------
// ExpireGrants
// ---------------------------------------------------------------------------

func TestJITAccessService_ExpireGrants(t *testing.T) {
	svc, deps := newJITService(t)

	// Two active grants that have already passed their expiry.
	grant1 := makeGrant(models.JITAccessStatusActive, -5*time.Minute)
	grant2 := makeGrant(models.JITAccessStatusActive, -2*time.Minute)
	expiredGrants := []*models.JITAccessGrant{grant1, grant2}

	deps.repo.On("ListExpiredActive", mock.Anything, 100).Return(expiredGrants, nil)

	deps.spicedb.On("DeleteUserRole", mock.Anything, grant1.TenantID, grant1.UserID, grant1.RoleID).Return("zt1", nil)
	deps.repo.On("FinalizeGrant", mock.Anything, grant1.ID, models.JITAccessStatusExpired).Return(nil)

	deps.spicedb.On("DeleteUserRole", mock.Anything, grant2.TenantID, grant2.UserID, grant2.RoleID).Return("zt2", nil)
	deps.repo.On("FinalizeGrant", mock.Anything, grant2.ID, models.JITAccessStatusExpired).Return(nil)

	err := svc.ExpireGrants(context.Background())

	require.NoError(t, err)
	deps.repo.AssertExpectations(t)
	deps.spicedb.AssertExpectations(t)
}

func TestJITAccessService_ExpireGrants_PersistenceErrorContinues(t *testing.T) {
	svc, deps := newJITService(t)

	// First transaction fails, processing continues to the second grant.
	grant1 := makeGrant(models.JITAccessStatusActive, -5*time.Minute)
	grant2 := makeGrant(models.JITAccessStatusActive, -2*time.Minute)
	expiredGrants := []*models.JITAccessGrant{grant1, grant2}

	deps.repo.On("ListExpiredActive", mock.Anything, 100).Return(expiredGrants, nil)

	dbErr := errors.New("database unavailable")
	deps.repo.On("FinalizeGrant", mock.Anything, grant1.ID, models.JITAccessStatusExpired).Return(dbErr)

	deps.spicedb.On("DeleteUserRole", mock.Anything, grant2.TenantID, grant2.UserID, grant2.RoleID).Return("zt2", nil)
	deps.repo.On("FinalizeGrant", mock.Anything, grant2.ID, models.JITAccessStatusExpired).Return(nil)

	err := svc.ExpireGrants(context.Background())

	assert.Error(t, err)
	assert.ErrorIs(t, err, dbErr)
	deps.spicedb.AssertNotCalled(t, "DeleteUserRole", mock.Anything, grant1.TenantID, grant1.UserID, grant1.RoleID)
	deps.repo.AssertCalled(t, "FinalizeGrant", mock.Anything, grant2.ID, models.JITAccessStatusExpired)
}

func TestJITAccessService_ExpireGrants_NoExpiredGrants(t *testing.T) {
	svc, deps := newJITService(t)

	deps.repo.On("ListExpiredActive", mock.Anything, 100).Return([]*models.JITAccessGrant{}, nil)

	err := svc.ExpireGrants(context.Background())

	require.NoError(t, err)
	deps.spicedb.AssertNotCalled(t, "DeleteUserRole")
	deps.repo.AssertNotCalled(t, "UpdateStatus")
}

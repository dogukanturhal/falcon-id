// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

func newLifecycleTestService(repo *MockUserRepository, audit *mockUserDisableAudit) *UserService {
	return &UserService{
		config:   &config.Config{},
		userRepo: repo,
		auditService: audit,
		logger:   zap.NewNop(),
	}
}

// ---------------------------------------------------------------------------
// AdminSoftDeleteUser
// ---------------------------------------------------------------------------

// TestAdminSoftDeleteUser_BlocksProtectedTenant is the behavioural test for
// the "refuse to delete the exampletenant tenant outright" guard.
// CONTROL: TestAdminSoftDeleteUser_AllowsOrdinaryTenant proves the same
// call path succeeds for a non-protected tenant, so this failure is the
// guard firing, not some unrelated error.
func TestAdminSoftDeleteUser_BlocksProtectedTenant(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	protectedTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	targetID := uuid.New()
	user := &models.User{ID: targetID, TenantID: protectedTenantID, Username: "svc-account", IsActive: true}

	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()

	_, err := s.AdminSoftDeleteUser(context.Background(), uuid.New(), targetID, "test")
	require.ErrorIs(t, err, ErrProtectedTenant)

	// Control assertion: HasRole/CountActiveOwners/SetDeletionState must
	// NEVER be reached once the protected-tenant guard fires.
	repo.AssertNotCalled(t, "HasRole")
	repo.AssertNotCalled(t, "SetDeletionState")
}

// TestAdminSoftDeleteUser_AllowsOrdinaryTenant is the control for the
// guard test above: same call shape, ordinary tenant, must succeed.
func TestAdminSoftDeleteUser_AllowsOrdinaryTenant(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	tenantID := uuid.New()
	targetID := uuid.New()
	user := &models.User{ID: targetID, TenantID: tenantID, Username: "alice", IsActive: true}

	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()
	repo.On("HasRole", mock.Anything, targetID, "owner").Return(false, nil).Once()
	repo.On("SetDeletionState", mock.Anything, targetID, "admin_deleted", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	repo.On("Update", mock.Anything, mock.MatchedBy(func(u *models.User) bool { return u.ID == targetID && !u.IsActive })).Return(nil).Once()
	audit.On("LogUserAction", mock.Anything, mock.Anything, mock.Anything, &targetID, "user_admin_disabled", true, mock.Anything).Once()
	audit.On("LogUserAction", mock.Anything, tenantID, mock.Anything, &targetID, "user_admin_soft_deleted", true, mock.Anything).Once()

	got, err := s.AdminSoftDeleteUser(context.Background(), uuid.New(), targetID, "test reason")
	require.NoError(t, err)
	assert.Equal(t, "admin_deleted", got.ActivationStatus)
	assert.False(t, got.IsActive)
	repo.AssertExpectations(t)
}

// TestAdminSoftDeleteUser_BlocksLastOwner is the behavioural test for the
// "refuse to delete the last owner of a tenant" guard.
// CONTROL: TestAdminSoftDeleteUser_AllowsOwnerWhenNotLast proves the same
// call path succeeds when a second owner exists.
func TestAdminSoftDeleteUser_BlocksLastOwner(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	tenantID := uuid.New()
	targetID := uuid.New()
	user := &models.User{ID: targetID, TenantID: tenantID, Username: "owner1", IsActive: true}

	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()
	repo.On("HasRole", mock.Anything, targetID, "owner").Return(true, nil).Once()
	repo.On("CountActiveOwners", mock.Anything, tenantID).Return(1, nil).Once()

	_, err := s.AdminSoftDeleteUser(context.Background(), uuid.New(), targetID, "test")
	require.ErrorIs(t, err, ErrLastOwner)
	repo.AssertNotCalled(t, "SetDeletionState")
}

// TestAdminSoftDeleteUser_AllowsOwnerWhenNotLast is the control: same
// shape, CountActiveOwners returns 2, must succeed.
func TestAdminSoftDeleteUser_AllowsOwnerWhenNotLast(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	tenantID := uuid.New()
	targetID := uuid.New()
	user := &models.User{ID: targetID, TenantID: tenantID, Username: "owner1", IsActive: true}

	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()
	repo.On("HasRole", mock.Anything, targetID, "owner").Return(true, nil).Once()
	repo.On("CountActiveOwners", mock.Anything, tenantID).Return(2, nil).Once()
	repo.On("SetDeletionState", mock.Anything, targetID, "admin_deleted", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	repo.On("Update", mock.Anything, mock.Anything).Return(nil).Once()
	audit.On("LogUserAction", mock.Anything, mock.Anything, mock.Anything, &targetID, "user_admin_disabled", true, mock.Anything).Once()
	audit.On("LogUserAction", mock.Anything, tenantID, mock.Anything, &targetID, "user_admin_soft_deleted", true, mock.Anything).Once()

	_, err := s.AdminSoftDeleteUser(context.Background(), uuid.New(), targetID, "test")
	require.NoError(t, err)
}

// TestAdminSoftDeleteUser_AlreadyDeletedRefused proves double soft-delete
// is refused (idempotency guard), not silently accepted.
func TestAdminSoftDeleteUser_AlreadyDeletedRefused(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	targetID := uuid.New()
	user := &models.User{ID: targetID, TenantID: uuid.New(), ActivationStatus: "admin_deleted"}
	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()

	_, err := s.AdminSoftDeleteUser(context.Background(), uuid.New(), targetID, "test")
	require.ErrorIs(t, err, ErrUserAlreadyDeleted)
}

// ---------------------------------------------------------------------------
// AdminRestoreUser
// ---------------------------------------------------------------------------

// TestAdminRestoreUser_RefusesNonDeletedUser is the behavioural control
// proving restore cannot be called on a user who was never soft-deleted.
func TestAdminRestoreUser_RefusesNonDeletedUser(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	targetID := uuid.New()
	user := &models.User{ID: targetID, TenantID: uuid.New(), ActivationStatus: "active"}
	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()

	_, err := s.AdminRestoreUser(context.Background(), uuid.New(), targetID)
	require.ErrorIs(t, err, ErrUserNotSoftDeleted)
	repo.AssertNotCalled(t, "SetDeletionState")
}

// TestAdminRestoreUser_ReactivatesSoftDeletedUser proves restore clears
// the deletion state and flips is_active back on. This is the control
// pairing for the guard test above: same shape, but the user IS
// soft-deleted, so it must succeed.
func TestAdminRestoreUser_ReactivatesSoftDeletedUser(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	tenantID := uuid.New()
	targetID := uuid.New()
	now := time.Now()
	user := &models.User{
		ID: targetID, TenantID: tenantID, ActivationStatus: "admin_deleted",
		IsActive: false, DeletionScheduledAt: &now,
	}
	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()
	repo.On("SetDeletionState", mock.Anything, targetID, "active", (*time.Time)(nil), (*time.Time)(nil), (*string)(nil)).Return(nil).Once()
	repo.On("Update", mock.Anything, mock.MatchedBy(func(u *models.User) bool { return u.ID == targetID && u.IsActive })).Return(nil).Once()
	audit.On("LogUserAction", mock.Anything, tenantID, mock.Anything, &targetID, "user_admin_restored", true, mock.Anything).Once()

	got, err := s.AdminRestoreUser(context.Background(), uuid.New(), targetID)
	require.NoError(t, err)
	assert.Equal(t, "active", got.ActivationStatus)
	assert.True(t, got.IsActive)
	assert.Nil(t, got.DeletionScheduledAt)
}

// ---------------------------------------------------------------------------
// AdminHardDeleteUser
// ---------------------------------------------------------------------------

// TestAdminHardDeleteUser_RequiresMatchingConfirmation is the
// behavioural test for the confirmation-echo requirement.
// CONTROL: TestAdminHardDeleteUser_SucceedsWithMatchingConfirmation
// proves the exact same call succeeds once the confirmation matches.
func TestAdminHardDeleteUser_RequiresMatchingConfirmation(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	targetID := uuid.New()
	user := &models.User{ID: targetID, TenantID: uuid.New(), Username: "bob", ActivationStatus: "admin_deleted"}
	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()

	_, err := s.AdminHardDeleteUser(context.Background(), uuid.New(), targetID, "not-bob", false, "test")
	require.ErrorIs(t, err, ErrConfirmationMismatch)
	repo.AssertNotCalled(t, "HardDeleteUser")
}

// TestAdminHardDeleteUser_SucceedsWithMatchingConfirmation is the
// control for the above.
func TestAdminHardDeleteUser_SucceedsWithMatchingConfirmation(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	tenantID := uuid.New()
	targetID := uuid.New()
	user := &models.User{ID: targetID, TenantID: tenantID, Username: "bob", ActivationStatus: "admin_deleted"}
	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()
	repo.On("HasRole", mock.Anything, targetID, "owner").Return(false, nil).Once()
	repo.On("HardDeleteUser", mock.Anything, targetID).Return(map[string]int{"iam_sessions": 0}, nil).Once()
	audit.On("LogUserAction", mock.Anything, tenantID, mock.Anything, &targetID, "user_admin_hard_deleted", true, mock.Anything).Once()

	residual, err := s.AdminHardDeleteUser(context.Background(), uuid.New(), targetID, "bob", false, "test")
	require.NoError(t, err)
	assert.Equal(t, 0, residual["iam_sessions"])
}

// TestAdminHardDeleteUser_RequiresPriorSoftDeleteUnlessForced is the
// behavioural test for the two-step hard-delete gate.
// CONTROL: TestAdminHardDeleteUser_ForceSkipsSoftDeleteGate proves the
// same call succeeds once force=true is set.
func TestAdminHardDeleteUser_RequiresPriorSoftDeleteUnlessForced(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	targetID := uuid.New()
	user := &models.User{ID: targetID, TenantID: uuid.New(), Username: "carol", ActivationStatus: "active"}
	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()
	repo.On("HasRole", mock.Anything, targetID, "owner").Return(false, nil).Once()

	_, err := s.AdminHardDeleteUser(context.Background(), uuid.New(), targetID, "carol", false, "test")
	require.ErrorIs(t, err, ErrUserNotSoftDeleted)
	repo.AssertNotCalled(t, "HardDeleteUser")
}

// TestAdminHardDeleteUser_ForceSkipsSoftDeleteGate is the control for
// the above: force=true, target never soft-deleted, must succeed.
func TestAdminHardDeleteUser_ForceSkipsSoftDeleteGate(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	tenantID := uuid.New()
	targetID := uuid.New()
	user := &models.User{ID: targetID, TenantID: tenantID, Username: "carol", ActivationStatus: "active", IsActive: true}
	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()
	repo.On("HasRole", mock.Anything, targetID, "owner").Return(false, nil).Once()
	repo.On("HardDeleteUser", mock.Anything, targetID).Return(map[string]int{}, nil).Once()
	audit.On("LogUserAction", mock.Anything, tenantID, mock.Anything, &targetID, "user_admin_hard_deleted", true, mock.Anything).Once()

	_, err := s.AdminHardDeleteUser(context.Background(), uuid.New(), targetID, "carol", true, "emergency erasure")
	require.NoError(t, err)
}

// TestAdminHardDeleteUser_BlocksProtectedTenantEvenWithForce proves the
// protected-tenant guard has NO override — not even force=true bypasses
// it. This is the one guard the task spec calls out as non-negotiable.
func TestAdminHardDeleteUser_BlocksProtectedTenantEvenWithForce(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	protectedTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	targetID := uuid.New()
	user := &models.User{ID: targetID, TenantID: protectedTenantID, Username: "svc"}
	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()

	_, err := s.AdminHardDeleteUser(context.Background(), uuid.New(), targetID, "svc", true, "test")
	require.ErrorIs(t, err, ErrProtectedTenant)
	repo.AssertNotCalled(t, "HardDeleteUser")
}

// TestAdminHardDeleteUser_BlocksLastOwner proves the last-owner guard
// applies to hard-delete too, not only soft-delete.
func TestAdminHardDeleteUser_BlocksLastOwner(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	tenantID := uuid.New()
	targetID := uuid.New()
	user := &models.User{ID: targetID, TenantID: tenantID, Username: "owner1", ActivationStatus: "admin_deleted"}
	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()
	repo.On("HasRole", mock.Anything, targetID, "owner").Return(true, nil).Once()
	repo.On("CountActiveOwners", mock.Anything, tenantID).Return(1, nil).Once()

	_, err := s.AdminHardDeleteUser(context.Background(), uuid.New(), targetID, "owner1", true, "test")
	require.ErrorIs(t, err, ErrLastOwner)
	repo.AssertNotCalled(t, "HardDeleteUser")
}

// TestAdminHardDeleteUser_ResidualRowsPropagateAsFailure proves that a
// nonzero residual-row count from the repository (i.e. the completeness
// sweep found leftovers and the transaction rolled back) surfaces as an
// error, not as a false success.
func TestAdminHardDeleteUser_ResidualRowsPropagateAsFailure(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)

	tenantID := uuid.New()
	targetID := uuid.New()
	user := &models.User{ID: targetID, TenantID: tenantID, Username: "dave", ActivationStatus: "admin_deleted"}
	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()
	repo.On("HasRole", mock.Anything, targetID, "owner").Return(false, nil).Once()
	repo.On("HardDeleteUser", mock.Anything, targetID).
		Return(nil, assert.AnError).Once()

	_, err := s.AdminHardDeleteUser(context.Background(), uuid.New(), targetID, "dave", false, "test")
	require.Error(t, err)
}

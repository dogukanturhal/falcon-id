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

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// fakeSeatLifecycle records calls and can simulate a full tenant on Reactivate.
type fakeSeatLifecycle struct {
	deactivated []uuid.UUID
	reactivated []uuid.UUID
	full        bool
}

func (f *fakeSeatLifecycle) Deactivate(_ context.Context, _, userID uuid.UUID) (bool, error) {
	f.deactivated = append(f.deactivated, userID)
	return true, nil
}

func (f *fakeSeatLifecycle) Reactivate(_ context.Context, _, userID uuid.UUID) (bool, error) {
	if f.full {
		return false, repositories.ErrSeatLimitReached
	}
	f.reactivated = append(f.reactivated, userID)
	return true, nil
}

func TestAdminSoftDeleteUser_ReleasesMemberSeat(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)
	seats := &fakeSeatLifecycle{}
	s.SetSeatMembershipLifecycle(seats)

	tenantID, targetID := uuid.New(), uuid.New()
	user := &models.User{ID: targetID, TenantID: tenantID, Username: "alice", IsActive: true}
	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()
	repo.On("HasRole", mock.Anything, targetID, "owner").Return(false, nil).Once()
	repo.On("SetDeletionState", mock.Anything, targetID, "admin_deleted", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	repo.On("Update", mock.Anything, mock.Anything).Return(nil).Once()
	audit.On("LogUserAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, true, mock.Anything)

	_, err := s.AdminSoftDeleteUser(context.Background(), uuid.New(), targetID, "x")
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{targetID}, seats.deactivated)
}

func TestAdminRestoreUser_FullTenantRefusedBeforeAnyChange(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)
	seats := &fakeSeatLifecycle{full: true}
	s.SetSeatMembershipLifecycle(seats)

	targetID := uuid.New()
	now := time.Now()
	user := &models.User{ID: targetID, TenantID: uuid.New(), ActivationStatus: "admin_deleted", DeletionScheduledAt: &now}
	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()

	_, err := s.AdminRestoreUser(context.Background(), uuid.New(), targetID)
	require.ErrorIs(t, err, repositories.ErrSeatLimitReached)
	repo.AssertNotCalled(t, "SetDeletionState", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assert.Empty(t, seats.reactivated)
}

func TestAdminRestoreUser_OccupiesSeat(t *testing.T) {
	repo := new(MockUserRepository)
	audit := new(mockUserDisableAudit)
	s := newLifecycleTestService(repo, audit)
	seats := &fakeSeatLifecycle{}
	s.SetSeatMembershipLifecycle(seats)

	targetID := uuid.New()
	now := time.Now()
	user := &models.User{ID: targetID, TenantID: uuid.New(), ActivationStatus: "admin_deleted", DeletionScheduledAt: &now}
	repo.On("GetByID", mock.Anything, targetID).Return(user, nil).Once()
	repo.On("SetDeletionState", mock.Anything, targetID, "active", (*time.Time)(nil), (*time.Time)(nil), (*string)(nil)).Return(nil).Once()
	repo.On("Update", mock.Anything, mock.Anything).Return(nil).Once()
	audit.On("LogUserAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, true, mock.Anything)

	_, err := s.AdminRestoreUser(context.Background(), uuid.New(), targetID)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{targetID}, seats.reactivated)
}

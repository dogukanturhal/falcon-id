// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// mockConsumerRoleRepo satisfies consumerRoleBootstrapRepo via testify.
type mockConsumerRoleRepo struct {
	mock.Mock
}

func (m *mockConsumerRoleRepo) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error) {
	args := m.Called(ctx, tenantID, name)
	row, _ := args.Get(0).(*models.Role)
	return row, args.Error(1)
}

func (m *mockConsumerRoleRepo) Create(ctx context.Context, role *models.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func TestTryBootstrapConsumerRole_CreatesWhenMissing(t *testing.T) {
	repo := &mockConsumerRoleRepo{}
	repo.On("GetByName", mock.Anything, models.WellKnownTenantConsumer, ConsumerUserRoleName).
		Return((*models.Role)(nil), nil)
	repo.On("Create", mock.Anything, mock.MatchedBy(func(r *models.Role) bool {
		return r.TenantID == models.WellKnownTenantConsumer &&
			r.Name == ConsumerUserRoleName &&
			r.DisplayName == "Consumer User" &&
			r.IsSystem &&
			!r.IsDefault
	})).Return(nil)

	err := tryBootstrapConsumerRole(context.Background(), repo)
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestTryBootstrapConsumerRole_SkipsWhenAlreadyExists(t *testing.T) {
	repo := &mockConsumerRoleRepo{}
	existing := &models.Role{
		ID:       uuid.New(),
		TenantID: models.WellKnownTenantConsumer,
		Name:     ConsumerUserRoleName,
	}
	repo.On("GetByName", mock.Anything, models.WellKnownTenantConsumer, ConsumerUserRoleName).
		Return(existing, nil)

	err := tryBootstrapConsumerRole(context.Background(), repo)
	require.NoError(t, err)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestTryBootstrapConsumerRole_ReturnsErrorOnGetByNameFailure(t *testing.T) {
	repo := &mockConsumerRoleRepo{}
	repo.On("GetByName", mock.Anything, models.WellKnownTenantConsumer, ConsumerUserRoleName).
		Return((*models.Role)(nil), errors.New("connection refused"))

	err := tryBootstrapConsumerRole(context.Background(), repo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check for existing role")
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestTryBootstrapConsumerRole_ReturnsErrorOnCreateFailure(t *testing.T) {
	repo := &mockConsumerRoleRepo{}
	repo.On("GetByName", mock.Anything, models.WellKnownTenantConsumer, ConsumerUserRoleName).
		Return((*models.Role)(nil), nil)
	repo.On("Create", mock.Anything, mock.Anything).
		Return(errors.New("duplicate key value violates unique constraint"))

	err := tryBootstrapConsumerRole(context.Background(), repo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create consumer role")
}

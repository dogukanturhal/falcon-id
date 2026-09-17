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

// mockConsumerTenantRepo satisfies consumerTenantBootstrapRepo for the
// boot-hook tests. Same pattern as mockSeedRepo in
// oauth_client_slo_bootstrap_test.go.
type mockConsumerTenantRepo struct {
	mock.Mock
}

func (m *mockConsumerTenantRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	args := m.Called(ctx, id)
	row, _ := args.Get(0).(*models.Tenant)
	return row, args.Error(1)
}

func (m *mockConsumerTenantRepo) Create(ctx context.Context, tenant *models.Tenant) error {
	args := m.Called(ctx, tenant)
	return args.Error(0)
}

// existingConsumerTenant returns a steady-state row matching what
// tryBootstrapConsumerTenant should produce. Used by the idempotency
// path to assert "no Create call".
func existingConsumerTenant() *models.Tenant {
	return &models.Tenant{
		ID:            models.WellKnownTenantConsumer,
		Name:          "hexxlock-consumer",
		Slug:          "hexxlock-consumer",
		DisplayName:   "HexxLock Personal Accounts",
		Status:        "active",
		Type:          models.TenantType("personal"),
		Plan:          "consumer",
		BillingExempt: true,
	}
}

func TestTryBootstrapConsumerTenant_CreatesWhenMissing(t *testing.T) {
	repo := &mockConsumerTenantRepo{}
	repo.On("GetByID", mock.Anything, models.WellKnownTenantConsumer).
		Return((*models.Tenant)(nil), nil)
	// Lock the canonical attributes via a matcher so a future refactor
	// can't silently drop billing_exempt or change plan/type/slug.
	repo.On("Create", mock.Anything, mock.MatchedBy(func(t *models.Tenant) bool {
		return t.ID == models.WellKnownTenantConsumer &&
			t.Slug == "hexxlock-consumer" &&
			t.Name == "hexxlock-consumer" &&
			t.Type == models.TenantType("personal") &&
			t.Plan == "consumer" &&
			t.Status == "active" &&
			t.BillingExempt
	})).Return(nil)

	err := tryBootstrapConsumerTenant(context.Background(), repo)
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestTryBootstrapConsumerTenant_SkipsWhenAlreadyExists(t *testing.T) {
	repo := &mockConsumerTenantRepo{}
	repo.On("GetByID", mock.Anything, models.WellKnownTenantConsumer).
		Return(existingConsumerTenant(), nil)

	err := tryBootstrapConsumerTenant(context.Background(), repo)
	require.NoError(t, err)
	// MUST NOT call Create — locks the idempotency contract.
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestTryBootstrapConsumerTenant_ReturnsErrorOnGetByIDFailure(t *testing.T) {
	// Production wrapper bootstrapConsumerTenant turns this error into
	// logger.Fatal (crash-loop). The inner function returns the error
	// so tests can assert it cleanly.
	repo := &mockConsumerTenantRepo{}
	repo.On("GetByID", mock.Anything, models.WellKnownTenantConsumer).
		Return((*models.Tenant)(nil), errors.New("connection refused"))

	err := tryBootstrapConsumerTenant(context.Background(), repo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check for existing tenant")
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestTryBootstrapConsumerTenant_ReturnsErrorOnCreateFailure(t *testing.T) {
	// Regression-lock for the !226 enum bug: if Create returns an
	// error (whatever shape — e.g. invalid enum value, FK violation,
	// permission denied), the function must surface it as a returned
	// error so the wrapper can Fatal. A silent return here would
	// leave the consumer tenant absent + every personal signup
	// failing downstream.
	repo := &mockConsumerTenantRepo{}
	repo.On("GetByID", mock.Anything, models.WellKnownTenantConsumer).
		Return((*models.Tenant)(nil), nil)
	repo.On("Create", mock.Anything, mock.Anything).
		Return(errors.New(`ERROR: invalid input value for enum tenant_type: "consumer" (SQLSTATE 22P02)`))

	err := tryBootstrapConsumerTenant(context.Background(), repo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create consumer tenant")
	assert.Contains(t, err.Error(), "tenant_type")
}

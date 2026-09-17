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
)

// ─── mock repo (worker-narrow interface) ─────────────────────────────────────

type mockWorkerRepo struct{ mock.Mock }

func (m *mockWorkerRepo) ListForRecheck(ctx context.Context, limit int) ([]*models.TenantHost, error) {
	args := m.Called(ctx, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.TenantHost), args.Error(1)
}

func (m *mockWorkerRepo) MarkVerified(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockWorkerRepo) RecordVerificationFailure(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockWorkerRepo) Suspend(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func TestVerificationWorker_MatchingTXT_MarksVerifiedAndInvalidatesCache(t *testing.T) {
	repo := new(mockWorkerRepo)
	dns := new(mockHostDNSResolver)

	id := uuid.New()
	token := strings.Repeat("a", 64)
	repo.On("ListForRecheck", mock.Anything, 100).Return([]*models.TenantHost{{
		ID:                id,
		Host:              "crm.acme.com",
		Status:            models.TenantHostStatusPendingVerification,
		VerificationToken: token,
	}}, nil)
	dns.On("LookupTXT", mock.Anything, "_hexxlock-verify.crm.acme.com").
		Return([]string{"junk", token}, nil)
	repo.On("MarkVerified", mock.Anything, id).Return(nil)

	invalidated := ""
	w := NewTenantHostVerificationWorker(repo, dns, func(h string) { invalidated = h }, nil)
	require.NoError(t, w.ReconcileOnce(context.Background()))
	assert.Equal(t, "crm.acme.com", invalidated)
	repo.AssertExpectations(t)
}

func TestVerificationWorker_NoMatch_IncrementsFailures(t *testing.T) {
	repo := new(mockWorkerRepo)
	dns := new(mockHostDNSResolver)

	id := uuid.New()
	repo.On("ListForRecheck", mock.Anything, 100).Return([]*models.TenantHost{{
		ID:                   id,
		Host:                 "old.acme.com",
		Status:               models.TenantHostStatusActive,
		VerificationToken:    strings.Repeat("b", 64),
		VerificationFailures: 3,
	}}, nil)
	dns.On("LookupTXT", mock.Anything, "_hexxlock-verify.old.acme.com").
		Return([]string{"random-other-value"}, nil)
	repo.On("RecordVerificationFailure", mock.Anything, id).Return(nil)

	w := NewTenantHostVerificationWorker(repo, dns, nil, nil)
	require.NoError(t, w.ReconcileOnce(context.Background()))
	// 3 + 1 = 4 < default suspendAfter (14) — Suspend NOT called.
	repo.AssertNotCalled(t, "Suspend", mock.Anything, mock.Anything)
}

func TestVerificationWorker_FailuresHitThreshold_AutoSuspend(t *testing.T) {
	repo := new(mockWorkerRepo)
	dns := new(mockHostDNSResolver)

	id := uuid.New()
	repo.On("ListForRecheck", mock.Anything, 100).Return([]*models.TenantHost{{
		ID:                   id,
		Host:                 "dead.acme.com",
		Status:               models.TenantHostStatusActive,
		VerificationToken:    strings.Repeat("c", 64),
		VerificationFailures: 13, // one more failure → 14 → suspend
	}}, nil)
	dns.On("LookupTXT", mock.Anything, "_hexxlock-verify.dead.acme.com").
		Return(nil, errors.New("dns: NXDOMAIN"))
	repo.On("RecordVerificationFailure", mock.Anything, id).Return(nil)
	repo.On("Suspend", mock.Anything, id).Return(nil)

	invalidated := ""
	w := NewTenantHostVerificationWorker(repo, dns, func(h string) { invalidated = h }, nil)
	require.NoError(t, w.ReconcileOnce(context.Background()))
	repo.AssertCalled(t, "Suspend", mock.Anything, id)
	assert.Equal(t, "dead.acme.com", invalidated)
}

func TestVerificationWorker_DNSError_IncrementsFailures(t *testing.T) {
	repo := new(mockWorkerRepo)
	dns := new(mockHostDNSResolver)

	id := uuid.New()
	repo.On("ListForRecheck", mock.Anything, 100).Return([]*models.TenantHost{{
		ID:                id,
		Host:              "transient.acme.com",
		Status:            models.TenantHostStatusActive,
		VerificationToken: strings.Repeat("d", 64),
	}}, nil)
	dns.On("LookupTXT", mock.Anything, "_hexxlock-verify.transient.acme.com").
		Return(nil, errors.New("dns: SERVFAIL"))
	repo.On("RecordVerificationFailure", mock.Anything, id).Return(nil)

	w := NewTenantHostVerificationWorker(repo, dns, nil, nil)
	require.NoError(t, w.ReconcileOnce(context.Background()))
	repo.AssertCalled(t, "RecordVerificationFailure", mock.Anything, id)
	repo.AssertNotCalled(t, "Suspend", mock.Anything, mock.Anything)
}

func TestVerificationWorker_SuspendThresholdTunable(t *testing.T) {
	repo := new(mockWorkerRepo)
	dns := new(mockHostDNSResolver)

	id := uuid.New()
	repo.On("ListForRecheck", mock.Anything, 100).Return([]*models.TenantHost{{
		ID:                   id,
		Host:                 "x.com",
		Status:               models.TenantHostStatusActive,
		VerificationToken:    strings.Repeat("e", 64),
		VerificationFailures: 2,
	}}, nil)
	dns.On("LookupTXT", mock.Anything, "_hexxlock-verify.x.com").Return([]string{"nope"}, nil)
	repo.On("RecordVerificationFailure", mock.Anything, id).Return(nil)
	repo.On("Suspend", mock.Anything, id).Return(nil)

	w := NewTenantHostVerificationWorker(repo, dns, nil, nil)
	w.SetSuspendAfter(3) // 2 + 1 = 3 → suspend at this iteration
	require.NoError(t, w.ReconcileOnce(context.Background()))
	repo.AssertCalled(t, "Suspend", mock.Anything, id)
}

func TestVerificationWorker_EmptyList_NoOp(t *testing.T) {
	repo := new(mockWorkerRepo)
	repo.On("ListForRecheck", mock.Anything, 100).Return([]*models.TenantHost{}, nil)
	w := NewTenantHostVerificationWorker(repo, nil, nil, nil)
	require.NoError(t, w.ReconcileOnce(context.Background()))
	repo.AssertNotCalled(t, "RecordVerificationFailure", mock.Anything, mock.Anything)
}

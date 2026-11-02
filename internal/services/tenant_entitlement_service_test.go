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
// Mocks
// ---------------------------------------------------------------------------

type mockEntitlementRepo struct {
	mock.Mock
}

func (m *mockEntitlementRepo) UpsertModule(ctx context.Context, e *models.ModuleEntitlement) (bool, error) {
	args := m.Called(ctx, e)
	return args.Bool(0), args.Error(1)
}

func (m *mockEntitlementRepo) UpsertFlags(ctx context.Context, f *models.TenantEntitlementFlags) (bool, error) {
	args := m.Called(ctx, f)
	return args.Bool(0), args.Error(1)
}

func (m *mockEntitlementRepo) GetByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ModuleEntitlement, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.ModuleEntitlement), args.Error(1)
}

func (m *mockEntitlementRepo) GetFlags(ctx context.Context, tenantID uuid.UUID) (*models.TenantEntitlementFlags, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TenantEntitlementFlags), args.Error(1)
}

// mockEntitlementCache implements entitlementCache. GetFresh/GetLKG copy a
// pre-seeded envelope into `out` via a simple type assertion (avoiding a
// real JSON round-trip keeps these tests focused on the service's control
// flow, not the cache's own (de)serialization, which pkg/redis has its own
// tests for).
type mockEntitlementCache struct {
	mock.Mock
}

func (m *mockEntitlementCache) GetFresh(ctx context.Context, tenantID string, out interface{}) (bool, error) {
	args := m.Called(ctx, tenantID, out)
	if hit, ok := args.Get(0).(bool); ok && hit {
		if seeded, ok := args.Get(2).(EntitlementEnvelope); ok {
			*out.(*EntitlementEnvelope) = seeded
		}
	}
	return args.Bool(0), args.Error(1)
}

func (m *mockEntitlementCache) GetLKG(ctx context.Context, tenantID string, out interface{}) (bool, error) {
	args := m.Called(ctx, tenantID, out)
	if hit, ok := args.Get(0).(bool); ok && hit {
		if seeded, ok := args.Get(2).(EntitlementEnvelope); ok {
			*out.(*EntitlementEnvelope) = seeded
		}
	}
	return args.Bool(0), args.Error(1)
}

func (m *mockEntitlementCache) Set(ctx context.Context, tenantID string, envelope interface{}) error {
	args := m.Called(ctx, tenantID, envelope)
	return args.Error(0)
}

func (m *mockEntitlementCache) InvalidateFresh(ctx context.Context, tenantID string) error {
	args := m.Called(ctx, tenantID)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// GetEntitlements: fresh cache hit
// ---------------------------------------------------------------------------

func TestGetEntitlements_FreshCacheHit_NeverTouchesRepo(t *testing.T) {
	repo := &mockEntitlementRepo{}
	cache := &mockEntitlementCache{}
	svc := NewTenantEntitlementService(repo, cache)

	tenantID := uuid.New()
	seeded := EntitlementEnvelope{
		Modules:          []EntitlementModule{{Code: "crm", Status: "active"}},
		Flags:            map[string]bool{"beta": true},
		Limits:           map[string]int64{"production_bom_depth": 10},
		TrialEligibility: map[string]bool{"crm": false},
	}
	cache.On("GetFresh", mock.Anything, tenantID.String(), mock.Anything).
		Return(true, nil, seeded)

	got, err := svc.GetEntitlements(context.Background(), tenantID)
	require.NoError(t, err)
	assert.Equal(t, seeded, got)
	assert.False(t, got.Stale)
	repo.AssertNotCalled(t, "GetByTenant", mock.Anything, mock.Anything)
	repo.AssertNotCalled(t, "GetFlags", mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// GetEntitlements: cache miss -> Postgres succeeds -> cache is warmed
// ---------------------------------------------------------------------------

func TestGetEntitlements_CacheMiss_PostgresSucceeds_WarmsCache(t *testing.T) {
	repo := &mockEntitlementRepo{}
	cache := &mockEntitlementCache{}
	svc := NewTenantEntitlementService(repo, cache)

	tenantID := uuid.New()
	cache.On("GetFresh", mock.Anything, tenantID.String(), mock.Anything).Return(false, nil, nil)

	dbRows := []models.ModuleEntitlement{
		{ModuleCode: "crm", Status: models.ModuleEntitlementStatusExpired, EverTrialed: false, EverSubscribed: false},
		{ModuleCode: "marketing", Status: models.ModuleEntitlementStatusExpired, EverTrialed: true, EverSubscribed: false},
	}
	repo.On("GetByTenant", mock.Anything, tenantID).Return(dbRows, nil)
	repo.On("GetFlags", mock.Anything, tenantID).Return(&models.TenantEntitlementFlags{
		TenantID: tenantID, Flags: map[string]bool{"beta": true},
	}, nil)
	cache.On("Set", mock.Anything, tenantID.String(), mock.Anything).Return(nil)

	got, err := svc.GetEntitlements(context.Background(), tenantID)
	require.NoError(t, err)

	require.Len(t, got.Modules, 2)
	assert.Equal(t, "crm", got.Modules[0].Code)
	assert.Equal(t, "expired", got.Modules[0].Status)
	assert.True(t, got.TrialEligibility["crm"], "never trialed/subscribed crm should be trial-eligible")
	assert.False(t, got.TrialEligibility["marketing"], "previously-trialed marketing must never be trial-eligible again")
	assert.True(t, got.Flags["beta"])
	assert.False(t, got.Stale)

	cache.AssertCalled(t, "Set", mock.Anything, tenantID.String(), mock.Anything)
}

// ---------------------------------------------------------------------------
// GetEntitlements: cache miss -> Postgres fails -> LKG hit
// ---------------------------------------------------------------------------

func TestGetEntitlements_PostgresFails_FallsBackToLKG(t *testing.T) {
	repo := &mockEntitlementRepo{}
	cache := &mockEntitlementCache{}
	svc := NewTenantEntitlementService(repo, cache)

	tenantID := uuid.New()
	cache.On("GetFresh", mock.Anything, tenantID.String(), mock.Anything).Return(false, nil, nil)
	repo.On("GetByTenant", mock.Anything, tenantID).Return(nil, errors.New("connection refused"))

	lkg := EntitlementEnvelope{
		Modules:          []EntitlementModule{{Code: "crm", Status: "active"}},
		Flags:            map[string]bool{},
		Limits:           map[string]int64{"production_bom_depth": 10},
		TrialEligibility: map[string]bool{"crm": false},
	}
	cache.On("GetLKG", mock.Anything, tenantID.String(), mock.Anything).Return(true, nil, lkg)

	got, err := svc.GetEntitlements(context.Background(), tenantID)
	require.NoError(t, err, "fail-closed contract: this must never surface as an error")
	assert.True(t, got.Stale, "legacy LKG without a stale field must still be marked stale")
	lkg.Stale = true
	assert.Equal(t, lkg, got)
}

// ---------------------------------------------------------------------------
// GetEntitlements: Postgres fails, LKG also misses -> FAIL CLOSED
// ---------------------------------------------------------------------------

func TestGetEntitlements_PostgresFails_NoLKG_FailsClosed(t *testing.T) {
	repo := &mockEntitlementRepo{}
	cache := &mockEntitlementCache{}
	svc := NewTenantEntitlementService(repo, cache)

	tenantID := uuid.New()
	cache.On("GetFresh", mock.Anything, tenantID.String(), mock.Anything).Return(false, nil, nil)
	repo.On("GetByTenant", mock.Anything, tenantID).Return(nil, errors.New("db down"))
	cache.On("GetLKG", mock.Anything, tenantID.String(), mock.Anything).Return(false, nil, nil)

	got, err := svc.GetEntitlements(context.Background(), tenantID)
	require.NoError(t, err)
	assert.Empty(t, got.Modules, "fail-closed: no modules")
	assert.True(t, got.Stale, "outage must not look like an authoritative empty snapshot")
	assert.Empty(t, got.Flags, "fail-closed: no flags")
	assert.Empty(t, got.TrialEligibility, "fail-closed: trial_eligibility must be empty, never default-eligible")
}

// ---------------------------------------------------------------------------
// GetEntitlements: LKG read itself errors -> still FAIL CLOSED (not a 5xx)
// ---------------------------------------------------------------------------

func TestGetEntitlements_LKGReadErrors_FailsClosed(t *testing.T) {
	repo := &mockEntitlementRepo{}
	cache := &mockEntitlementCache{}
	svc := NewTenantEntitlementService(repo, cache)

	tenantID := uuid.New()
	cache.On("GetFresh", mock.Anything, tenantID.String(), mock.Anything).Return(false, nil, nil)
	repo.On("GetByTenant", mock.Anything, tenantID).Return(nil, errors.New("db down"))
	cache.On("GetLKG", mock.Anything, tenantID.String(), mock.Anything).Return(false, errors.New("redis down"), nil)

	got, err := svc.GetEntitlements(context.Background(), tenantID)
	require.NoError(t, err)
	assert.Empty(t, got.Modules)
	assert.True(t, got.Stale)
}

// ---------------------------------------------------------------------------
// GetEntitlements: no cache configured at all (nil interface) -> Postgres
// failure fails closed directly, no panic on nil cache.
// ---------------------------------------------------------------------------

func TestGetEntitlements_NoCacheConfigured_PostgresFails_FailsClosedWithoutPanic(t *testing.T) {
	repo := &mockEntitlementRepo{}
	svc := NewTenantEntitlementService(repo, nil)

	tenantID := uuid.New()
	repo.On("GetByTenant", mock.Anything, tenantID).Return(nil, errors.New("db down"))

	assert.NotPanics(t, func() {
		got, err := svc.GetEntitlements(context.Background(), tenantID)
		require.NoError(t, err)
		assert.Empty(t, got.Modules)
		assert.True(t, got.Stale)
	})
}

func TestGetEntitlements_NoCacheConfigured_PostgresSucceeds(t *testing.T) {
	repo := &mockEntitlementRepo{}
	svc := NewTenantEntitlementService(repo, nil)

	tenantID := uuid.New()
	repo.On("GetByTenant", mock.Anything, tenantID).Return([]models.ModuleEntitlement{
		{ModuleCode: "crm", Status: models.ModuleEntitlementStatusActive},
	}, nil)
	repo.On("GetFlags", mock.Anything, tenantID).Return(nil, nil)

	got, err := svc.GetEntitlements(context.Background(), tenantID)
	require.NoError(t, err)
	require.Len(t, got.Modules, 1)
	assert.Equal(t, "crm", got.Modules[0].Code)
	assert.False(t, got.Stale)
}

func TestGetEntitlements_EmptySourceIsNotStale(t *testing.T) {
	repo := &mockEntitlementRepo{}
	tenant := uuid.New()
	repo.On("GetByTenant", mock.Anything, tenant).Return([]models.ModuleEntitlement{}, nil)
	repo.On("GetFlags", mock.Anything, tenant).Return(nil, nil)
	env, err := NewTenantEntitlementService(repo, nil).GetEntitlements(context.Background(), tenant)
	require.NoError(t, err)
	require.Empty(t, env.Modules)
	require.False(t, env.Stale, "valid empty snapshot may be used by authoritative readers")
}

// ---------------------------------------------------------------------------
// PutSnapshot
// ---------------------------------------------------------------------------

func TestPutSnapshot_InvalidStatus_Rejected(t *testing.T) {
	repo := &mockEntitlementRepo{}
	cache := &mockEntitlementCache{}
	svc := NewTenantEntitlementService(repo, cache)

	err := svc.PutSnapshot(context.Background(), &models.ModuleEntitlement{
		TenantID:   uuid.New(),
		ModuleCode: "crm",
		Status:     "cancelled", // not a valid ModuleEntitlementStatus
	})
	require.Error(t, err)
	repo.AssertNotCalled(t, "UpsertModule", mock.Anything, mock.Anything)
}

func TestPutSnapshot_Applied_InvalidatesFreshCache(t *testing.T) {
	repo := &mockEntitlementRepo{}
	cache := &mockEntitlementCache{}
	svc := NewTenantEntitlementService(repo, cache)

	tenantID := uuid.New()
	e := &models.ModuleEntitlement{TenantID: tenantID, ModuleCode: "crm", Status: models.ModuleEntitlementStatusActive, EventVersion: 5}
	repo.On("UpsertModule", mock.Anything, e).Return(true, nil)
	cache.On("InvalidateFresh", mock.Anything, tenantID.String()).Return(nil)

	err := svc.PutSnapshot(context.Background(), e)
	require.NoError(t, err)
	cache.AssertCalled(t, "InvalidateFresh", mock.Anything, tenantID.String())
}

// TestPutSnapshot_StaleDuplicate_Idempotent verifies the consumer/PUT
// idempotency contract end to end at the service layer: when the
// repository reports the event_version guard rejected the write
// (applied=false — a stale/duplicate/out-of-order redelivery), PutSnapshot
// returns nil (not an error) and does NOT invalidate the cache, since
// nothing actually changed.
func TestPutSnapshot_StaleDuplicate_Idempotent(t *testing.T) {
	repo := &mockEntitlementRepo{}
	cache := &mockEntitlementCache{}
	svc := NewTenantEntitlementService(repo, cache)

	tenantID := uuid.New()
	e := &models.ModuleEntitlement{TenantID: tenantID, ModuleCode: "crm", Status: models.ModuleEntitlementStatusActive, EventVersion: 1}
	repo.On("UpsertModule", mock.Anything, e).Return(false, nil)

	err := svc.PutSnapshot(context.Background(), e)
	require.NoError(t, err)
	cache.AssertNotCalled(t, "InvalidateFresh", mock.Anything, mock.Anything)
}

func TestPutSnapshot_NoCacheConfigured_DoesNotPanic(t *testing.T) {
	repo := &mockEntitlementRepo{}
	svc := NewTenantEntitlementService(repo, nil)

	e := &models.ModuleEntitlement{TenantID: uuid.New(), ModuleCode: "crm", Status: models.ModuleEntitlementStatusActive, EventVersion: 1}
	repo.On("UpsertModule", mock.Anything, e).Return(true, nil)

	assert.NotPanics(t, func() {
		err := svc.PutSnapshot(context.Background(), e)
		require.NoError(t, err)
	})
}

func TestPutFlagsSnapshot_Applied_InvalidatesFreshCache(t *testing.T) {
	repo := &mockEntitlementRepo{}
	cache := &mockEntitlementCache{}
	svc := NewTenantEntitlementService(repo, cache)

	tenantID := uuid.New()
	f := &models.TenantEntitlementFlags{TenantID: tenantID, Flags: map[string]bool{"beta": true}, EventVersion: 3}
	repo.On("UpsertFlags", mock.Anything, f).Return(true, nil)
	cache.On("InvalidateFresh", mock.Anything, tenantID.String()).Return(nil)

	err := svc.PutFlagsSnapshot(context.Background(), f)
	require.NoError(t, err)
	cache.AssertCalled(t, "InvalidateFresh", mock.Anything, tenantID.String())
}

var _ = time.Second // keep time import if unused elsewhere in file variants

// ---------------------------------------------------------------------------
// Per-module trial fields (spec 25 section 6) + legacy cache shape
// ---------------------------------------------------------------------------

func TestGetEntitlements_PerModuleTrialFields(t *testing.T) {
	repo := &mockEntitlementRepo{}
	svc := NewTenantEntitlementService(repo, nil)
	tenantID := uuid.New()
	trialEnd := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	graceEnd := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	compSource, compTier := "operator-comp", "professional"
	repo.On("GetByTenant", mock.Anything, tenantID).Return([]models.ModuleEntitlement{
		{ModuleCode: "bundle-pro", Status: models.ModuleEntitlementStatusExpired},
		{ModuleCode: "crm", Status: models.ModuleEntitlementStatusTrialing, EverTrialed: true, ExpiresAt: &trialEnd},
		{ModuleCode: "hr", Status: models.ModuleEntitlementStatusGrace, EverTrialed: true, ExpiresAt: &graceEnd},
		{ModuleCode: "marketing", Status: models.ModuleEntitlementStatusExpired, EverTrialed: true},
		{ModuleCode: "mm", Status: models.ModuleEntitlementStatusActive, EverSubscribed: true},
		{ModuleCode: "pm", Status: models.ModuleEntitlementStatusExpired},
		{ModuleCode: "accounting", Status: models.ModuleEntitlementStatusActive, Source: &compSource, TierCode: &compTier},
	}, nil)
	repo.On("GetFlags", mock.Anything, tenantID).Return(nil, nil)

	env, err := svc.GetEntitlements(context.Background(), tenantID)
	require.NoError(t, err)
	got := map[string]EntitlementModule{}
	for _, m := range env.Modules {
		got[m.Code] = m
	}
	assert.Equal(t, "bundle_not_trialable", got["bundle-pro"].TrialReason)
	assert.False(t, got["bundle-pro"].TrialEligible)
	assert.Equal(t, "trial_active", got["crm"].TrialReason)
	require.NotNil(t, got["crm"].TrialEndsAt)
	assert.Equal(t, "2026-10-10T12:00:00Z", *got["crm"].TrialEndsAt)
	assert.Nil(t, got["crm"].GraceEndsAt)
	assert.Equal(t, "in_grace", got["hr"].TrialReason)
	require.NotNil(t, got["hr"].GraceEndsAt)
	assert.Equal(t, "2026-10-17T12:00:00Z", *got["hr"].GraceEndsAt)
	assert.Nil(t, got["hr"].TrialEndsAt)
	assert.Equal(t, "already_trialed", got["marketing"].TrialReason)
	assert.Equal(t, "already_subscribed", got["mm"].TrialReason)
	assert.True(t, got["pm"].TrialEligible)
	assert.Equal(t, "eligible", got["pm"].TrialReason)
	assert.Equal(t, "complimentary", got["accounting"].TrialReason)
	assert.False(t, got["accounting"].TrialEligible)
	assert.Equal(t, &compSource, got["accounting"].Source)
	assert.Equal(t, &compTier, got["accounting"].TierCode)
	assert.Nil(t, got["mm"].Source, "legacy source is unknown, not inferred paid")
	// Legacy map mirrors modules[].trial_eligible.
	assert.Equal(t, map[string]bool{"bundle-pro": false, "crm": false, "hr": false, "marketing": false, "mm": false, "pm": true, "accounting": false}, env.TrialEligibility)
}

// A snapshot cached before the per-module fields existed (no trial_reason)
// must be upgraded from the legacy trial_eligibility map, never granting
// eligibility the map did not.
func TestGetEntitlements_LegacyCachedEnvelope_Normalized(t *testing.T) {
	legacy := EntitlementEnvelope{
		Modules:          []EntitlementModule{{Code: "crm", Status: "active"}, {Code: "pm", Status: "expired"}},
		Flags:            map[string]bool{},
		TrialEligibility: map[string]bool{"crm": false, "pm": true},
	}
	cache := &mockEntitlementCache{}
	tenantID := uuid.New()
	cache.On("GetFresh", mock.Anything, tenantID.String(), mock.Anything).Return(true, nil, legacy)
	svc := NewTenantEntitlementService(&mockEntitlementRepo{}, cache)

	env, err := svc.GetEntitlements(context.Background(), tenantID)
	require.NoError(t, err)
	assert.False(t, env.Modules[0].TrialEligible)
	assert.Equal(t, "not_eligible", env.Modules[0].TrialReason)
	assert.True(t, env.Modules[1].TrialEligible)
	assert.Equal(t, "eligible", env.Modules[1].TrialReason)
	assert.NotNil(t, env.Limits, "pre-0020 cached envelope must serve limits {} not null")
}

// ---------------------------------------------------------------------------
// SpiceDB entitled_module mirror
// ---------------------------------------------------------------------------

type syncCall struct {
	module    string
	entitled  bool
	expiresAt *time.Time
}

type fakeEntitledSyncer struct {
	calls []syncCall
	err   error
}

func (f *fakeEntitledSyncer) SyncEntitledModule(_ context.Context, _ uuid.UUID, module string, entitled bool, expiresAt *time.Time) error {
	f.calls = append(f.calls, syncCall{module, entitled, expiresAt})
	return f.err
}

func TestPutSnapshot_SyncsEntitledModuleToSpiceDB(t *testing.T) {
	end := time.Now().Add(48 * time.Hour)
	for _, tt := range []struct {
		name     string
		status   models.ModuleEntitlementStatus
		entitled bool
	}{
		{"active", models.ModuleEntitlementStatusActive, true},
		{"trialing", models.ModuleEntitlementStatusTrialing, true},
		{"grace", models.ModuleEntitlementStatusGrace, true},
		{"expired is removed", models.ModuleEntitlementStatusExpired, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockEntitlementRepo{}
			syncer := &fakeEntitledSyncer{}
			svc := NewTenantEntitlementService(repo, nil)
			svc.SetSpiceDBSyncer(syncer)
			e := &models.ModuleEntitlement{TenantID: uuid.New(), ModuleCode: "crm", Status: tt.status, ExpiresAt: &end, EventVersion: 2}
			repo.On("UpsertModule", mock.Anything, e).Return(true, nil)

			require.NoError(t, svc.PutSnapshot(context.Background(), e))
			require.Len(t, syncer.calls, 1)
			assert.Equal(t, tt.entitled, syncer.calls[0].entitled)
			assert.Equal(t, "crm", syncer.calls[0].module)
			assert.Equal(t, &end, syncer.calls[0].expiresAt)
		})
	}
}

func TestPutSnapshot_SpiceDBFailure_ReturnedSoRedeliveryRetries(t *testing.T) {
	repo := &mockEntitlementRepo{}
	syncer := &fakeEntitledSyncer{err: errors.New("spicedb down")}
	svc := NewTenantEntitlementService(repo, nil)
	svc.SetSpiceDBSyncer(syncer)
	tenantID := uuid.New()
	e := &models.ModuleEntitlement{TenantID: tenantID, ModuleCode: "crm", Status: models.ModuleEntitlementStatusActive, EventVersion: 2}

	repo.On("UpsertModule", mock.Anything, e).Return(true, nil).Once()
	require.Error(t, svc.PutSnapshot(context.Background(), e))

	// Redelivery: the version guard now rejects the write (applied=false), but
	// the stored row is re-synced so the tuple converges.
	syncer.err = nil
	repo.On("UpsertModule", mock.Anything, e).Return(false, nil).Once()
	repo.On("GetByTenant", mock.Anything, tenantID).Return([]models.ModuleEntitlement{*e}, nil)
	require.NoError(t, svc.PutSnapshot(context.Background(), e))
	require.Len(t, syncer.calls, 2)
	assert.True(t, syncer.calls[1].entitled)
}

type fakeModuleGrantHook struct {
	calls []string
	err   error
	panic bool
}

func (f *fakeModuleGrantHook) EnsureModuleAccess(_ context.Context, _ uuid.UUID, code string) (*ModuleAccessResult, error) {
	f.calls = append(f.calls, code)
	if f.panic {
		panic("hook exploded")
	}
	return &ModuleAccessResult{}, f.err
}

func TestPutSnapshot_GrantingSnapshotCallsModuleGrantHook(t *testing.T) {
	repo := &mockEntitlementRepo{}
	svc := NewTenantEntitlementService(repo, nil)
	hook := &fakeModuleGrantHook{}
	svc.SetModuleGrantHook(hook)

	tenantID := uuid.New()
	e := &models.ModuleEntitlement{TenantID: tenantID, ModuleCode: "crm", Status: models.ModuleEntitlementStatusActive, EventVersion: 2}
	repo.On("UpsertModule", mock.Anything, e).Return(true, nil)
	repo.On("GetByTenant", mock.Anything, tenantID).Return([]models.ModuleEntitlement{*e}, nil)

	require.NoError(t, svc.PutSnapshot(context.Background(), e))
	assert.Equal(t, []string{"crm"}, hook.calls)
}

func TestPutSnapshot_ExpiredSnapshotDoesNotCallModuleGrantHook(t *testing.T) {
	repo := &mockEntitlementRepo{}
	svc := NewTenantEntitlementService(repo, nil)
	hook := &fakeModuleGrantHook{}
	svc.SetModuleGrantHook(hook)

	tenantID := uuid.New()
	e := &models.ModuleEntitlement{TenantID: tenantID, ModuleCode: "crm", Status: models.ModuleEntitlementStatusExpired, EventVersion: 2}
	repo.On("UpsertModule", mock.Anything, e).Return(true, nil)
	repo.On("GetByTenant", mock.Anything, tenantID).Return([]models.ModuleEntitlement{*e}, nil)

	require.NoError(t, svc.PutSnapshot(context.Background(), e))
	assert.Empty(t, hook.calls)
}

func TestPutSnapshot_StaleRedeliveryOfGrantingRowCallsModuleGrantHook(t *testing.T) {
	repo := &mockEntitlementRepo{}
	svc := NewTenantEntitlementService(repo, nil)
	hook := &fakeModuleGrantHook{}
	svc.SetModuleGrantHook(hook)

	tenantID := uuid.New()
	stale := &models.ModuleEntitlement{TenantID: tenantID, ModuleCode: "hr", Status: models.ModuleEntitlementStatusExpired, EventVersion: 1}
	stored := models.ModuleEntitlement{TenantID: tenantID, ModuleCode: "hr", Status: models.ModuleEntitlementStatusTrialing, EventVersion: 5}
	repo.On("UpsertModule", mock.Anything, stale).Return(false, nil)
	repo.On("GetByTenant", mock.Anything, tenantID).Return([]models.ModuleEntitlement{stored}, nil)

	require.NoError(t, svc.PutSnapshot(context.Background(), stale))
	assert.Equal(t, []string{"hr"}, hook.calls)
}

func TestPutSnapshot_ModuleGrantHookErrorDoesNotFailPut(t *testing.T) {
	repo := &mockEntitlementRepo{}
	svc := NewTenantEntitlementService(repo, nil)
	hook := &fakeModuleGrantHook{err: errors.New("boom")}
	svc.SetModuleGrantHook(hook)

	tenantID := uuid.New()
	e := &models.ModuleEntitlement{TenantID: tenantID, ModuleCode: "crm", Status: models.ModuleEntitlementStatusActive, EventVersion: 2}
	repo.On("UpsertModule", mock.Anything, e).Return(true, nil)
	repo.On("GetByTenant", mock.Anything, tenantID).Return([]models.ModuleEntitlement{*e}, nil)

	require.NoError(t, svc.PutSnapshot(context.Background(), e))
	assert.Len(t, hook.calls, 1)
}

func TestPutSnapshot_ModuleGrantHookPanicDoesNotFailPut(t *testing.T) {
	repo := &mockEntitlementRepo{}
	svc := NewTenantEntitlementService(repo, nil)
	hook := &fakeModuleGrantHook{panic: true}
	svc.SetModuleGrantHook(hook)

	tenantID := uuid.New()
	e := &models.ModuleEntitlement{TenantID: tenantID, ModuleCode: "crm", Status: models.ModuleEntitlementStatusActive, EventVersion: 2}
	repo.On("UpsertModule", mock.Anything, e).Return(true, nil)
	repo.On("GetByTenant", mock.Anything, tenantID).Return([]models.ModuleEntitlement{*e}, nil)

	require.NoError(t, svc.PutSnapshot(context.Background(), e))
	assert.Len(t, hook.calls, 1)
}

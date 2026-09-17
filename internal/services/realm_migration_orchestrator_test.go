// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// =============================================================================
// Mock: RealmDatabaseLister
// =============================================================================

type mockRealmDBLister struct {
	mock.Mock
}

func (m *mockRealmDBLister) ListActive(ctx context.Context) ([]models.RealmDatabase, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.RealmDatabase), args.Error(1)
}

// =============================================================================
// Mock: PoolOpener
// =============================================================================

type mockPoolOpener struct {
	mock.Mock
}

func (m *mockPoolOpener) OpenPool(ctx context.Context, connectionString string) (*pgxpool.Pool, error) {
	args := m.Called(ctx, connectionString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pgxpool.Pool), args.Error(1)
}

// =============================================================================
// Mock: MigratorRunner
// =============================================================================

type mockMigratorRunner struct {
	mock.Mock
}

func (m *mockMigratorRunner) RunMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	args := m.Called(ctx, pool)
	return args.Error(0)
}

// =============================================================================
// Helpers
// =============================================================================

// newNopLogger returns a zap.Logger that discards all output. Used in tests
// that do not exercise log output.
func newNopLogger() *zap.Logger {
	return zap.NewNop()
}

// fakeRealmDB builds a minimal RealmDatabase for use in tests.
func fakeRealmDB(realmID uuid.UUID, slug string) models.RealmDatabase {
	return models.RealmDatabase{
		ID:             uuid.New(),
		RealmID:        realmID,
		ConnectionName: slug,
		Host:           "localhost",
		Port:           5432,
		DatabaseName:   "hexxlock_realm_" + slug,
		Username:       "realm_" + slug,
		// PasswordEncrypted is intentionally empty — tests never open real pools.
		PasswordEncrypted: "test-password",
		SSLMode:           "disable",
		Status:            string(models.RealmDatabaseStatusActive),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
}

// fakePool returns a nil *pgxpool.Pool. Tests only care that the pointer is
// passed through consistently; they never call pool methods.
//
// We cannot construct a real pgxpool.Pool without a live Postgres instance, so
// we use a typed nil that satisfies the interface contract. The mock
// MigratorRunner captures the pointer value, not the pool state.
func fakePool() *pgxpool.Pool {
	return nil
}

// newOrchestrator is a convenience constructor for tests.
func newOrchestrator(
	lister RealmDatabaseLister,
	opener PoolOpener,
	runner MigratorRunner,
) *RealmMigrationOrchestrator {
	return NewRealmMigrationOrchestrator(lister, opener, runner, newNopLogger())
}

// =============================================================================
// TestOrchestrator_CanaryRollout
// =============================================================================

// TestOrchestrator_CanaryRollout verifies that, when SandboxRealmID is set, the
// orchestrator migrates that realm first and only proceeds to the remaining
// realms after the canary succeeds.
func TestOrchestrator_CanaryRollout(t *testing.T) {
	ctx := context.Background()

	sandboxID := uuid.New()
	otherID1 := uuid.New()
	otherID2 := uuid.New()

	sandbox := fakeRealmDB(sandboxID, "sandbox")
	other1 := fakeRealmDB(otherID1, "realm-a")
	other2 := fakeRealmDB(otherID2, "realm-b")

	lister := &mockRealmDBLister{}
	opener := &mockPoolOpener{}
	runner := &mockMigratorRunner{}

	lister.On("ListActive", ctx).Return([]models.RealmDatabase{sandbox, other1, other2}, nil)

	// All three realms open their pool successfully.
	opener.On("OpenPool", ctx, mock.AnythingOfType("string")).Return(fakePool(), nil)

	// Track migration order to assert canary runs first.
	var order []uuid.UUID
	var orderMu sync.Mutex

	runner.On("RunMigrations", ctx, fakePool()).
		Return(nil).
		Times(3).
		Run(func(_ mock.Arguments) {
			// We cannot distinguish realms by pool (all nil), so we track via
			// the lister — but the runner is called in order: canary, then rest.
			// We just record call index instead.
		})

	// We need a runner that records realm order. Rebuild with a capturing runner.
	capRunner := &capturingRunner{results: map[uuid.UUID]error{
		sandboxID: nil,
		otherID1:  nil,
		otherID2:  nil,
	}}
	capOpener := &capturingOpener{realmOrder: &order, mu: &orderMu, realmsByConn: map[string]uuid.UUID{
		buildConnectionString(sandbox): sandboxID,
		buildConnectionString(other1):  otherID1,
		buildConnectionString(other2):  otherID2,
	}}

	o := newOrchestrator(lister, capOpener, capRunner)

	var progressEvents []RealmMigrationProgress
	var eventsMu sync.Mutex

	cfg := OrchestratorConfig{
		SandboxRealmID:      &sandboxID,
		MaxConcurrent:       2,
		CircuitBreakerLimit: 3,
	}

	result, err := o.RunAll(ctx, cfg, func(p RealmMigrationProgress) {
		eventsMu.Lock()
		defer eventsMu.Unlock()
		progressEvents = append(progressEvents, p)
	})

	require.NoError(t, err)
	assert.Equal(t, 3, result.TotalRealms)
	assert.Equal(t, 3, result.Succeeded)
	assert.Equal(t, 0, result.Failed)
	assert.Equal(t, 0, result.Skipped)
	assert.False(t, result.CircuitBroken)

	// Canary must be first in the order slice.
	orderMu.Lock()
	defer orderMu.Unlock()
	require.GreaterOrEqual(t, len(order), 1, "expected at least one realm to be opened")
	assert.Equal(t, sandboxID, order[0], "canary realm must be migrated first")
}

// TestOrchestrator_CanaryRollout_Aborts verifies that a canary failure stops
// the run before the remaining realms are migrated.
func TestOrchestrator_CanaryRollout_Aborts(t *testing.T) {
	ctx := context.Background()

	sandboxID := uuid.New()
	otherID := uuid.New()

	sandbox := fakeRealmDB(sandboxID, "sandbox")
	other := fakeRealmDB(otherID, "realm-a")

	lister := &mockRealmDBLister{}
	opener := &mockPoolOpener{}
	runner := &mockMigratorRunner{}

	lister.On("ListActive", ctx).Return([]models.RealmDatabase{sandbox, other}, nil)

	canaryConn := buildConnectionString(sandbox)
	opener.On("OpenPool", ctx, canaryConn).Return(fakePool(), nil)
	// The other realm's pool must NOT be opened.
	opener.On("OpenPool", ctx, buildConnectionString(other)).Maybe().Return(fakePool(), nil)

	canaryErr := errors.New("canary migration failed")
	runner.On("RunMigrations", ctx, fakePool()).Return(canaryErr).Once()

	o := newOrchestrator(lister, opener, runner)

	cfg := OrchestratorConfig{
		SandboxRealmID:      &sandboxID,
		MaxConcurrent:       2,
		CircuitBreakerLimit: 3,
	}

	result, err := o.RunAll(ctx, cfg, nil)

	require.NoError(t, err)
	assert.Equal(t, 2, result.TotalRealms)
	assert.Equal(t, 0, result.Succeeded)
	assert.Equal(t, 1, result.Failed)
	assert.False(t, result.CircuitBroken, "circuit breaker should not be tripped by canary; that is a separate guard")

	// The other realm should appear as pending (never attempted).
	var otherResult *RealmMigrationProgress
	for i := range result.RealmResults {
		if result.RealmResults[i].RealmID == otherID {
			otherResult = &result.RealmResults[i]
			break
		}
	}
	require.NotNil(t, otherResult, "other realm must appear in results")
	assert.Equal(t, RealmMigrationPending, otherResult.Status)

	// The other realm's pool must NOT have been opened.
	opener.AssertNotCalled(t, "OpenPool", ctx, buildConnectionString(other))
}

// =============================================================================
// TestOrchestrator_StopsOnCircuitBreaker
// =============================================================================

// TestOrchestrator_StopsOnCircuitBreaker verifies that after CircuitBreakerLimit
// consecutive failures the orchestrator stops scheduling further migrations and
// sets CircuitBroken: true in the result.
func TestOrchestrator_StopsOnCircuitBreaker(t *testing.T) {
	ctx := context.Background()

	// Create 6 realms. The circuit limit is 3 — the orchestrator must stop
	// after 3 consecutive failures and leave the rest as pending.
	const total = 6
	const limit = 3

	realms := make([]models.RealmDatabase, total)
	for i := range realms {
		realms[i] = fakeRealmDB(uuid.New(), fmt.Sprintf("realm-%d", i))
	}

	lister := &mockRealmDBLister{}
	lister.On("ListActive", ctx).Return(realms, nil)

	// Use sequential (MaxConcurrent=1) so the order is deterministic.
	migErr := errors.New("migration error")

	var callCount atomic.Int32
	capRunner := &funcRunner{fn: func(_ context.Context, _ *pgxpool.Pool) error {
		callCount.Add(1)
		return migErr
	}}
	capOpener := &funcOpener{fn: func(_ context.Context, _ string) (*pgxpool.Pool, error) {
		return fakePool(), nil
	}}

	o := newOrchestrator(lister, capOpener, capRunner)

	cfg := OrchestratorConfig{
		MaxConcurrent:       1,
		CircuitBreakerLimit: limit,
	}

	result, err := o.RunAll(ctx, cfg, nil)

	require.NoError(t, err)
	assert.True(t, result.CircuitBroken, "circuit breaker must be tripped")
	assert.Equal(t, total, result.TotalRealms)
	assert.Equal(t, limit, result.Failed, "exactly CircuitBreakerLimit realms must be failed")

	// At most CircuitBreakerLimit migrations must have been attempted.
	assert.LessOrEqual(t, int(callCount.Load()), limit,
		"runner must not be called more than CircuitBreakerLimit times")

	// The remaining realms (those not yet attempted) must be pending.
	pendingCount := 0
	for _, r := range result.RealmResults {
		if r.Status == RealmMigrationPending {
			pendingCount++
		}
	}
	assert.Equal(t, total-limit, pendingCount, "remaining realms must be marked pending")
}

// =============================================================================
// TestOrchestrator_TracksPerRealmProgress
// =============================================================================

// TestOrchestrator_TracksPerRealmProgress verifies that the progress callback
// is invoked for every realm and covers at least the Running and terminal
// (Succeeded/Failed/Skipped) transitions.
//
// Implementation note: because RunMigrations only receives a *pgxpool.Pool
// (always nil in tests), realm identity cannot be inferred there. We use a
// channel-based handshake: the PoolOpener sends the realm ID into a buffered
// channel before returning the pool; RunMigrations receives from that channel
// to determine which error to return.
func TestOrchestrator_TracksPerRealmProgress(t *testing.T) {
	ctx := context.Background()

	realmA := fakeRealmDB(uuid.New(), "realm-a") // will succeed
	realmB := fakeRealmDB(uuid.New(), "realm-b") // will be skipped (no pending)
	realmC := fakeRealmDB(uuid.New(), "realm-c") // will fail

	lister := &mockRealmDBLister{}
	lister.On("ListActive", ctx).Return([]models.RealmDatabase{realmA, realmB, realmC}, nil)

	perRealmErrors := map[uuid.UUID]error{
		realmA.RealmID: nil,
		realmB.RealmID: ErrNoPendingMigrations,
		realmC.RealmID: errors.New("migration failure"),
	}

	// Buffered channel large enough for all realms to avoid deadlock when
	// MaxConcurrent is high.
	realmCh := make(chan uuid.UUID, 3)

	opener := &funcOpenerWithChannel{
		realmsByConn: map[string]uuid.UUID{
			buildConnectionString(realmA): realmA.RealmID,
			buildConnectionString(realmB): realmB.RealmID,
			buildConnectionString(realmC): realmC.RealmID,
		},
		realmCh: realmCh,
	}
	runner := &realmErrRunner{
		realmCh: realmCh,
		results: perRealmErrors,
	}

	o := newOrchestrator(lister, opener, runner)

	type eventKey struct {
		realmID uuid.UUID
		status  RealmMigrationStatus
	}
	seen := make(map[eventKey]bool)
	var mu sync.Mutex

	cfg := OrchestratorConfig{
		// Use MaxConcurrent=1 so that each OpenPool→RunMigrations pair executes
		// serially; this makes the channel handshake safe without additional
		// synchronisation.
		MaxConcurrent:       1,
		CircuitBreakerLimit: 10,
	}

	result, err := o.RunAll(ctx, cfg, func(p RealmMigrationProgress) {
		mu.Lock()
		defer mu.Unlock()
		seen[eventKey{p.RealmID, p.Status}] = true
	})

	require.NoError(t, err)

	// Verify aggregate counts.
	assert.Equal(t, 3, result.TotalRealms)
	assert.Equal(t, 1, result.Succeeded)
	assert.Equal(t, 1, result.Skipped)
	assert.Equal(t, 1, result.Failed)

	mu.Lock()
	defer mu.Unlock()

	// Verify that Running was reported for every realm.
	assert.True(t, seen[eventKey{realmA.RealmID, RealmMigrationRunning}], "realmA running event missing")
	assert.True(t, seen[eventKey{realmB.RealmID, RealmMigrationRunning}], "realmB running event missing")
	assert.True(t, seen[eventKey{realmC.RealmID, RealmMigrationRunning}], "realmC running event missing")

	// Verify terminal states.
	assert.True(t, seen[eventKey{realmA.RealmID, RealmMigrationSucceeded}], "realmA succeeded event missing")
	assert.True(t, seen[eventKey{realmB.RealmID, RealmMigrationSkipped}], "realmB skipped event missing")
	assert.True(t, seen[eventKey{realmC.RealmID, RealmMigrationFailed}], "realmC failed event missing")

	// Succeeded realm must carry a MigratedAt timestamp.
	for _, r := range result.RealmResults {
		if r.RealmID == realmA.RealmID {
			assert.NotNil(t, r.MigratedAt, "succeeded realm must have MigratedAt set")
		}
	}
}

// =============================================================================
// TestOrchestrator_SkipsAlreadyMigratedRealms
// =============================================================================

// TestOrchestrator_SkipsAlreadyMigratedRealms verifies that realms whose
// MigratorRunner returns ErrNoPendingMigrations are counted as Skipped, not
// as Failed, and do not increment the consecutive-failure counter.
func TestOrchestrator_SkipsAlreadyMigratedRealms(t *testing.T) {
	ctx := context.Background()

	const total = 4
	realms := make([]models.RealmDatabase, total)
	for i := range realms {
		realms[i] = fakeRealmDB(uuid.New(), fmt.Sprintf("realm-%d", i))
	}

	lister := &mockRealmDBLister{}
	lister.On("ListActive", ctx).Return(realms, nil)

	capOpener := &funcOpener{fn: func(_ context.Context, _ string) (*pgxpool.Pool, error) {
		return fakePool(), nil
	}}
	// All realms are already up to date.
	capRunner := &funcRunner{fn: func(_ context.Context, _ *pgxpool.Pool) error {
		return ErrNoPendingMigrations
	}}

	o := newOrchestrator(lister, capOpener, capRunner)

	cfg := OrchestratorConfig{
		MaxConcurrent:       2,
		CircuitBreakerLimit: 3,
	}

	result, err := o.RunAll(ctx, cfg, nil)

	require.NoError(t, err)
	assert.Equal(t, total, result.TotalRealms)
	assert.Equal(t, total, result.Skipped)
	assert.Equal(t, 0, result.Succeeded)
	assert.Equal(t, 0, result.Failed)
	assert.False(t, result.CircuitBroken, "skips must not trip the circuit breaker")
}

// =============================================================================
// TestOrchestrator_ConcurrentRealmLimit
// =============================================================================

// TestOrchestrator_ConcurrentRealmLimit verifies that the orchestrator never
// exceeds MaxConcurrent simultaneous migrations.
func TestOrchestrator_ConcurrentRealmLimit(t *testing.T) {
	ctx := context.Background()

	const total = 8
	const maxConcurrent = 3

	realms := make([]models.RealmDatabase, total)
	for i := range realms {
		realms[i] = fakeRealmDB(uuid.New(), fmt.Sprintf("realm-%d", i))
	}

	lister := &mockRealmDBLister{}
	lister.On("ListActive", ctx).Return(realms, nil)

	var (
		inFlight     atomic.Int32
		peakInFlight atomic.Int32
	)

	capOpener := &funcOpener{fn: func(_ context.Context, _ string) (*pgxpool.Pool, error) {
		return fakePool(), nil
	}}
	capRunner := &funcRunner{fn: func(_ context.Context, _ *pgxpool.Pool) error {
		current := inFlight.Add(1)
		// Update peak if this is a new high.
		for {
			peak := peakInFlight.Load()
			if current <= peak {
				break
			}
			if peakInFlight.CompareAndSwap(peak, current) {
				break
			}
		}
		// Simulate work so goroutines overlap.
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		return nil
	}}

	o := newOrchestrator(lister, capOpener, capRunner)

	cfg := OrchestratorConfig{
		MaxConcurrent:       maxConcurrent,
		CircuitBreakerLimit: total + 1, // never trip
	}

	result, err := o.RunAll(ctx, cfg, nil)

	require.NoError(t, err)
	assert.Equal(t, total, result.TotalRealms)
	assert.Equal(t, total, result.Succeeded)
	assert.False(t, result.CircuitBroken)

	assert.LessOrEqual(t, int(peakInFlight.Load()), maxConcurrent,
		"concurrent migrations must not exceed MaxConcurrent")
}

// =============================================================================
// TestOrchestrator_EmptyRealmList
// =============================================================================

// TestOrchestrator_EmptyRealmList verifies graceful handling when no active
// realm databases exist.
func TestOrchestrator_EmptyRealmList(t *testing.T) {
	ctx := context.Background()

	lister := &mockRealmDBLister{}
	lister.On("ListActive", ctx).Return([]models.RealmDatabase{}, nil)

	o := newOrchestrator(lister, &funcOpener{}, &funcRunner{})

	result, err := o.RunAll(ctx, OrchestratorConfig{}, nil)

	require.NoError(t, err)
	assert.Equal(t, 0, result.TotalRealms)
	assert.Equal(t, 0, result.Succeeded)
	assert.False(t, result.CircuitBroken)
}

// TestOrchestrator_ListActiveError verifies that a ListActive error is
// propagated as a RunAll error.
func TestOrchestrator_ListActiveError(t *testing.T) {
	ctx := context.Background()

	lister := &mockRealmDBLister{}
	lister.On("ListActive", ctx).Return(nil, errors.New("db unavailable"))

	o := newOrchestrator(lister, &funcOpener{}, &funcRunner{})

	result, err := o.RunAll(ctx, OrchestratorConfig{}, nil)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "db unavailable")
}

// TestOrchestrator_PoolOpenError verifies that a pool-open failure is recorded
// as a realm failure (not an orchestrator error).
func TestOrchestrator_PoolOpenError(t *testing.T) {
	ctx := context.Background()

	realm := fakeRealmDB(uuid.New(), "realm-x")

	lister := &mockRealmDBLister{}
	lister.On("ListActive", ctx).Return([]models.RealmDatabase{realm}, nil)

	openErr := errors.New("cannot connect")
	capOpener := &funcOpener{fn: func(_ context.Context, _ string) (*pgxpool.Pool, error) {
		return nil, openErr
	}}

	o := newOrchestrator(lister, capOpener, &funcRunner{})

	result, err := o.RunAll(ctx, OrchestratorConfig{MaxConcurrent: 1, CircuitBreakerLimit: 3}, nil)

	require.NoError(t, err)
	assert.Equal(t, 1, result.Failed)
	assert.Contains(t, result.RealmResults[0].ErrorMessage, "cannot connect")
}

// =============================================================================
// Functional helpers used across multiple tests
// =============================================================================

// funcRunner is a MigratorRunner backed by a plain function.
type funcRunner struct {
	fn func(ctx context.Context, pool *pgxpool.Pool) error
}

func (r *funcRunner) RunMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	if r.fn == nil {
		return nil
	}
	return r.fn(ctx, pool)
}

// funcOpener is a PoolOpener backed by a plain function.
type funcOpener struct {
	fn func(ctx context.Context, connStr string) (*pgxpool.Pool, error)
}

func (o *funcOpener) OpenPool(ctx context.Context, connStr string) (*pgxpool.Pool, error) {
	if o.fn == nil {
		return fakePool(), nil
	}
	return o.fn(ctx, connStr)
}

// capturingOpener is a PoolOpener that records the order in which realm
// connection strings are opened.
type capturingOpener struct {
	realmsByConn map[string]uuid.UUID
	realmOrder   *[]uuid.UUID
	mu           *sync.Mutex
}

func (o *capturingOpener) OpenPool(_ context.Context, connStr string) (*pgxpool.Pool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if realmID, ok := o.realmsByConn[connStr]; ok {
		*o.realmOrder = append(*o.realmOrder, realmID)
	}
	return fakePool(), nil
}

// capturingRunner is a MigratorRunner that returns pre-configured errors per realm.
// It determines the realm from a shared connection-string→realm-ID map.
type capturingRunner struct {
	results map[uuid.UUID]error
}

func (r *capturingRunner) RunMigrations(_ context.Context, _ *pgxpool.Pool) error {
	// The pool is always nil in tests; capturingRunner is only used where
	// capturingOpener records the realm first. For the CanaryRollout test we
	// always succeed, so returning nil unconditionally is correct.
	return nil
}

// =============================================================================
// realmAwareRunner (per-realm) for TestOrchestrator_TracksPerRealmProgress
// =============================================================================
//
// To cleanly return a per-realm error without shared mutable state we use a
// purpose-built opener+runner pair where the opener communicates the active
// realm ID to the runner through a channel.

// realmAwareRunner is re-implemented here with a channel-based communication
// approach only used in the per-realm tracking test.
//
// The approach:
//  1. funcOpenerWithSideEffect.OpenPool looks up the realm ID from the conn
//     string and sends it to a channel.
//  2. realmErrRunner.RunMigrations receives the realm ID and returns the
//     configured error.
//
// Because MaxConcurrent in that test is 3 (concurrent), we use a buffered
// channel and a mutex to pair each open with the corresponding run.

// realmErrRunner receives realm IDs via a channel written to by
// funcOpenerWithChannel and returns per-realm errors.
type realmErrRunner struct {
	realmCh chan uuid.UUID
	results map[uuid.UUID]error
}

func (r *realmErrRunner) RunMigrations(_ context.Context, _ *pgxpool.Pool) error {
	realmID := <-r.realmCh
	return r.results[realmID]
}

// funcOpenerWithChannel is a PoolOpener that sends the realm ID (looked up
// from the connection string) into a channel before returning the pool.
type funcOpenerWithChannel struct {
	realmsByConn map[string]uuid.UUID
	realmCh      chan uuid.UUID
}

func (o *funcOpenerWithChannel) OpenPool(_ context.Context, connStr string) (*pgxpool.Pool, error) {
	realmID := o.realmsByConn[connStr]
	o.realmCh <- realmID
	return fakePool(), nil
}

// Override the TracksPerRealmProgress test to use the channel-based pair.
// The test above uses these two types directly:

func init() {
	// Validate that our interface implementations compile correctly.
	var _ RealmDatabaseLister = (*mockRealmDBLister)(nil)
	var _ PoolOpener = (*mockPoolOpener)(nil)
	var _ MigratorRunner = (*mockMigratorRunner)(nil)
	var _ PoolOpener = (*funcOpener)(nil)
	var _ MigratorRunner = (*funcRunner)(nil)
	var _ PoolOpener = (*capturingOpener)(nil)
	var _ MigratorRunner = (*capturingRunner)(nil)
	var _ PoolOpener = (*funcOpenerWithChannel)(nil)
	var _ MigratorRunner = (*realmErrRunner)(nil)
}

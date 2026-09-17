// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

func init() {
	logger.InitLogger("debug", "test")
}

// ─── mockOutboxService ────────────────────────────────────────────────────────

// mockOutboxService is a test double for services.OutboxService.
type mockOutboxService struct {
	addRelationshipEventFn func(ctx context.Context, tx pgx.Tx, event models.RelationshipEvent) error
	processPendingEventsFn func(ctx context.Context, batchSize int) (int, error)
	getStatsFn             func(ctx context.Context) (*models.OutboxStats, error)
	cleanupCompletedFn     func(ctx context.Context, retentionDays int) (int64, error)
	getFailedEventsFn      func(ctx context.Context, limit int) ([]*models.PermissionOutbox, error)
	resetStuckProcessingFn func(ctx context.Context) (int64, error)

	processCallCount atomic.Int32
	cleanupCallCount atomic.Int32
	resetCallCount   atomic.Int32
}

func (m *mockOutboxService) AddRelationshipEvent(ctx context.Context, tx pgx.Tx, event models.RelationshipEvent) error {
	if m.addRelationshipEventFn != nil {
		return m.addRelationshipEventFn(ctx, tx, event)
	}
	return nil
}

func (m *mockOutboxService) ProcessPendingEvents(ctx context.Context, batchSize int) (int, error) {
	m.processCallCount.Add(1)
	if m.processPendingEventsFn != nil {
		return m.processPendingEventsFn(ctx, batchSize)
	}
	return 0, nil
}

func (m *mockOutboxService) GetStats(ctx context.Context) (*models.OutboxStats, error) {
	if m.getStatsFn != nil {
		return m.getStatsFn(ctx)
	}
	return &models.OutboxStats{}, nil
}

func (m *mockOutboxService) CleanupCompleted(ctx context.Context, retentionDays int) (int64, error) {
	m.cleanupCallCount.Add(1)
	if m.cleanupCompletedFn != nil {
		return m.cleanupCompletedFn(ctx, retentionDays)
	}
	return 0, nil
}

func (m *mockOutboxService) GetFailedEvents(ctx context.Context, limit int) ([]*models.PermissionOutbox, error) {
	if m.getFailedEventsFn != nil {
		return m.getFailedEventsFn(ctx, limit)
	}
	return nil, nil
}

func (m *mockOutboxService) ResetStuckProcessing(ctx context.Context) (int64, error) {
	m.resetCallCount.Add(1)
	if m.resetStuckProcessingFn != nil {
		return m.resetStuckProcessingFn(ctx)
	}
	return 0, nil
}

// Ensure the mock satisfies the interface at compile time.
var _ services.OutboxService = (*mockOutboxService)(nil)

// ─── NewOutboxProcessor ───────────────────────────────────────────────────────

func TestNewOutboxProcessor(t *testing.T) {
	svc := &mockOutboxService{}
	p := NewOutboxProcessor(svc, 5*time.Second, 50)

	require.NotNil(t, p)
	assert.Equal(t, 5*time.Second, p.pollInterval)
	assert.Equal(t, 50, p.batchSize)
}

// ─── Stop ────────────────────────────────────────────────────────────────────

func TestStop_IdempotentMultipleCalls(_ *testing.T) {
	svc := &mockOutboxService{}
	p := NewOutboxProcessor(svc, 10*time.Second, 10)

	// Multiple Stop calls must not panic.
	p.Stop()
	p.Stop()
	p.Stop()
}

// ─── Start + context cancellation ────────────────────────────────────────────

func TestStart_StopsOnContextCancellation(t *testing.T) {
	svc := &mockOutboxService{}
	p := NewOutboxProcessor(svc, 1*time.Hour, 10) // long poll interval

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Start(ctx)
	}()

	// Give the goroutine time to initialise.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Good — Start returned after context cancellation.
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestStart_StopsOnStop(t *testing.T) {
	svc := &mockOutboxService{}
	p := NewOutboxProcessor(svc, 1*time.Hour, 10)

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Start(context.Background())
	}()

	time.Sleep(20 * time.Millisecond)
	p.Stop()

	select {
	case <-done:
		// Good.
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop()")
	}
}

// ─── processEvents (via Start) ───────────────────────────────────────────────

func TestStart_ProcessesEventsOnStartup(t *testing.T) {
	// The processor should call ProcessPendingEvents immediately on start.
	processed := make(chan struct{}, 1)
	svc := &mockOutboxService{
		processPendingEventsFn: func(_ context.Context, _ int) (int, error) {
			select {
			case processed <- struct{}{}:
			default:
			}
			return 0, nil
		},
	}

	p := NewOutboxProcessor(svc, 1*time.Hour, 25)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go p.Start(ctx)

	select {
	case <-processed:
		// Good – ProcessPendingEvents was called immediately.
	case <-time.After(2 * time.Second):
		t.Fatal("ProcessPendingEvents was not called on startup")
	}
}

func TestStart_ProcessesBatchSize(t *testing.T) {
	// Verify batchSize is forwarded to ProcessPendingEvents.
	const wantBatch = 42
	var gotBatch int
	ready := make(chan struct{}, 1)
	svc := &mockOutboxService{
		processPendingEventsFn: func(_ context.Context, batchSize int) (int, error) {
			gotBatch = batchSize
			select {
			case ready <- struct{}{}:
			default:
			}
			return 0, nil
		},
	}

	p := NewOutboxProcessor(svc, 1*time.Hour, wantBatch)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go p.Start(ctx)
	<-ready

	assert.Equal(t, wantBatch, gotBatch)
}

func TestStart_LogsWarningOnHighLag(t *testing.T) {
	// When LagSeconds > 60 the processor logs a warning; verify no panic.
	lag := int64(120)
	svc := &mockOutboxService{
		getStatsFn: func(_ context.Context) (*models.OutboxStats, error) {
			return &models.OutboxStats{
				PendingCount: 500,
				LagSeconds:   &lag,
			}, nil
		},
	}

	p := NewOutboxProcessor(svc, 1*time.Hour, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	t.Cleanup(cancel)

	// Must not panic.
	assert.NotPanics(t, func() { p.Start(ctx) })
}

// ─── processEvents – error handling ──────────────────────────────────────────

func TestProcessEvents_GetStatsError(t *testing.T) {
	// If GetStats fails, processEvents should still call ProcessPendingEvents.
	processed := make(chan struct{}, 1)
	svc := &mockOutboxService{
		getStatsFn: func(_ context.Context) (*models.OutboxStats, error) {
			return nil, errors.New("stats error")
		},
		processPendingEventsFn: func(_ context.Context, _ int) (int, error) {
			select {
			case processed <- struct{}{}:
			default:
			}
			return 0, nil
		},
	}

	p := NewOutboxProcessor(svc, 1*time.Hour, 10)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go p.Start(ctx)

	select {
	case <-processed:
		// Good – processing continued despite stats error.
	case <-time.After(2 * time.Second):
		t.Fatal("ProcessPendingEvents was not called after stats error")
	}
}

func TestProcessEvents_ProcessError(t *testing.T) {
	// If ProcessPendingEvents returns an error the processor should continue
	// running (error is logged, not fatal).
	var callCount atomic.Int32
	svc := &mockOutboxService{
		processPendingEventsFn: func(_ context.Context, _ int) (int, error) {
			callCount.Add(1)
			return 0, errors.New("processing error")
		},
	}

	p := NewOutboxProcessor(svc, 20*time.Millisecond, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)

	// Must not panic even with repeated errors.
	assert.NotPanics(t, func() { p.Start(ctx) })
	// It should have been called at least once.
	assert.GreaterOrEqual(t, callCount.Load(), int32(1))
}

// ─── GetStats ─────────────────────────────────────────────────────────────────

func TestGetStats_ReturnsAggregatedStats(t *testing.T) {
	lag := int64(30)
	failedEventID := uuid.New()
	failedEvent := &models.PermissionOutbox{ID: failedEventID, Status: models.OutboxStatusFailed}

	svc := &mockOutboxService{
		getStatsFn: func(_ context.Context) (*models.OutboxStats, error) {
			return &models.OutboxStats{
				PendingCount:    10,
				ProcessingCount: 2,
				FailedCount:     1,
				CompletedCount:  100,
				LagSeconds:      &lag,
			}, nil
		},
		getFailedEventsFn: func(_ context.Context, limit int) ([]*models.PermissionOutbox, error) {
			assert.Equal(t, 100, limit)
			return []*models.PermissionOutbox{failedEvent}, nil
		},
	}

	p := NewOutboxProcessor(svc, 5*time.Second, 25)
	stats, err := p.GetStats(context.Background())
	require.NoError(t, err)

	assert.Equal(t, int64(10), stats.PendingCount)
	assert.Equal(t, int64(2), stats.ProcessingCount)
	assert.Equal(t, int64(1), stats.FailedCount)
	assert.Equal(t, int64(100), stats.CompletedCount)
	require.NotNil(t, stats.LagSeconds)
	assert.Equal(t, int64(30), *stats.LagSeconds)
	assert.Equal(t, 5*time.Second, stats.PollInterval)
	assert.Equal(t, 25, stats.BatchSize)
	require.Len(t, stats.FailedEvents, 1)
	assert.Equal(t, failedEventID, stats.FailedEvents[0].ID)
}

func TestGetStats_GetStatsError(t *testing.T) {
	svc := &mockOutboxService{
		getStatsFn: func(_ context.Context) (*models.OutboxStats, error) {
			return nil, errors.New("db error")
		},
	}

	p := NewOutboxProcessor(svc, 5*time.Second, 10)
	_, err := p.GetStats(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db error")
}

func TestGetStats_GetFailedEventsError(t *testing.T) {
	// GetFailedEvents error should not fail GetStats; failed events just return nil.
	svc := &mockOutboxService{
		getStatsFn: func(_ context.Context) (*models.OutboxStats, error) {
			return &models.OutboxStats{PendingCount: 5}, nil
		},
		getFailedEventsFn: func(_ context.Context, _ int) ([]*models.PermissionOutbox, error) {
			return nil, errors.New("failed events error")
		},
	}

	p := NewOutboxProcessor(svc, 5*time.Second, 10)
	stats, err := p.GetStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(5), stats.PendingCount)
	assert.Nil(t, stats.FailedEvents, "failed events should be nil on error")
}

// ─── cleanupCompleted ────────────────────────────────────────────────────────

func TestCleanupCompleted_InvokedWithRetentionDays(t *testing.T) {
	var gotDays int
	svc := &mockOutboxService{
		cleanupCompletedFn: func(_ context.Context, retentionDays int) (int64, error) {
			gotDays = retentionDays
			return 5, nil
		},
	}

	p := NewOutboxProcessor(svc, 5*time.Second, 10)
	p.cleanupCompleted(context.Background())

	assert.Equal(t, 7, gotDays, "expected 7-day retention")
}

func TestCleanupCompleted_Error(t *testing.T) {
	svc := &mockOutboxService{
		cleanupCompletedFn: func(_ context.Context, _ int) (int64, error) {
			return 0, errors.New("cleanup error")
		},
	}

	p := NewOutboxProcessor(svc, 5*time.Second, 10)
	// Must not panic on error.
	assert.NotPanics(t, func() { p.cleanupCompleted(context.Background()) })
}

// ─── resetStuckEvents ────────────────────────────────────────────────────────

func TestResetStuckEvents_InvokesService(t *testing.T) {
	svc := &mockOutboxService{
		resetStuckProcessingFn: func(_ context.Context) (int64, error) {
			return 3, nil
		},
	}

	p := NewOutboxProcessor(svc, 5*time.Second, 10)
	assert.NotPanics(t, func() { p.resetStuckEvents(context.Background()) })
	assert.Equal(t, int32(1), svc.resetCallCount.Load())
}

func TestResetStuckEvents_Error(t *testing.T) {
	svc := &mockOutboxService{
		resetStuckProcessingFn: func(_ context.Context) (int64, error) {
			return 0, errors.New("reset error")
		},
	}

	p := NewOutboxProcessor(svc, 5*time.Second, 10)
	assert.NotPanics(t, func() { p.resetStuckEvents(context.Background()) })
}

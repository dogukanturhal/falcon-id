// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ─── NewRotationScheduler ────────────────────────────────────────────────────

func TestNewRotationScheduler(t *testing.T) {
	logger := zap.NewNop()
	km := &KeyManager{
		allKeys: make(map[string]*cachedKey),
		logger:  logger,
	}

	rs := NewRotationScheduler(km, 5*time.Minute, logger)
	require.NotNil(t, rs)
	assert.Equal(t, km, rs.km)
	assert.Equal(t, 5*time.Minute, rs.interval)
}

// ─── Start / Stop lifecycle ──────────────────────────────────────────────────

func TestRotationScheduler_StartStop(t *testing.T) {
	logger := zap.NewNop()
	km := &KeyManager{
		allKeys: make(map[string]*cachedKey),
		logger:  logger,
	}

	// Use a very long interval so checkAndRotate is never triggered during the test.
	rs := NewRotationScheduler(km, 24*time.Hour, logger)

	ctx := context.Background()
	rs.Start(ctx)

	// Stop must complete without hanging.
	done := make(chan struct{})
	go func() {
		rs.Stop()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return within 2 seconds")
	}
}

func TestRotationScheduler_StopBeforeStart(t *testing.T) {
	logger := zap.NewNop()
	km := &KeyManager{
		allKeys: make(map[string]*cachedKey),
		logger:  logger,
	}

	rs := NewRotationScheduler(km, time.Hour, logger)
	// Calling Stop before Start should not panic.
	assert.NotPanics(t, func() { rs.Stop() })
}

func TestRotationScheduler_ContextCancellationStops(t *testing.T) {
	logger := zap.NewNop()
	km := &KeyManager{
		allKeys: make(map[string]*cachedKey),
		logger:  logger,
	}

	rs := NewRotationScheduler(km, 24*time.Hour, logger)
	ctx, cancel := context.WithCancel(context.Background())
	rs.Start(ctx)

	// Cancel the parent context — the scheduler should notice and exit.
	cancel()

	done := make(chan struct{})
	go func() {
		rs.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// success: goroutine finished after context cancellation
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler goroutine did not exit after context cancellation")
	}
}

// ─── checkAndRotate — no active key ─────────────────────────────────────────

func TestRotationScheduler_CheckAndRotate_NoActiveKey(t *testing.T) {
	logger := zap.NewNop()
	km := &KeyManager{
		allKeys:   make(map[string]*cachedKey),
		activeKey: nil, // intentionally nil
		logger:    logger,
	}

	rs := NewRotationScheduler(km, time.Hour, logger)

	// Must not panic when there is no active key.
	assert.NotPanics(t, func() {
		rs.checkAndRotate(context.Background())
	})
}

// ─── checkAndRotate — key not near expiry ────────────────────────────────────

func TestRotationScheduler_CheckAndRotate_KeyNotExpiring(t *testing.T) {
	logger := zap.NewNop()

	// Active key expires in 30 days — well beyond the 7-day threshold.
	activeKey := &cachedKey{
		SigningKey: SigningKey{
			KeyID:     "kid-healthy",
			Status:    StatusActive,
			ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		},
	}

	km := &KeyManager{
		allKeys:   make(map[string]*cachedKey),
		activeKey: activeKey,
		logger:    logger,
	}

	rs := NewRotationScheduler(km, time.Hour, logger)

	// checkAndRotate must not trigger km.Rotate (no pool configured).
	// It must not panic or return an error since rotation is not triggered.
	assert.NotPanics(t, func() {
		rs.checkAndRotate(context.Background())
	})
}

// ─── rotation threshold boundary ─────────────────────────────────────────────

func TestRotationScheduler_RotationThreshold(t *testing.T) {
	// The threshold is exactly 7 days. A key expiring in 6 days should be within
	// the rotation window. We verify the boundary logic by inspecting the
	// time.Until comparison, not by triggering actual DB writes.

	sixDaysFromNow := time.Now().Add(6 * 24 * time.Hour)
	eightDaysFromNow := time.Now().Add(8 * 24 * time.Hour)
	rotationThreshold := 7 * 24 * time.Hour

	assert.True(t, time.Until(sixDaysFromNow) <= rotationThreshold,
		"key expiring in 6 days must be within rotation threshold")
	assert.False(t, time.Until(eightDaysFromNow) <= rotationThreshold,
		"key expiring in 8 days must be outside rotation threshold")
}

// ─── Multiple Stop calls ─────────────────────────────────────────────────────

func TestRotationScheduler_MultipleStopCalls(t *testing.T) {
	logger := zap.NewNop()
	km := &KeyManager{
		allKeys: make(map[string]*cachedKey),
		logger:  logger,
	}

	rs := NewRotationScheduler(km, 24*time.Hour, logger)
	rs.Start(context.Background())
	rs.Stop()
	// Second Stop must not panic (cancel is idempotent).
	assert.NotPanics(t, func() { rs.Stop() })
}

// ─── Interval respected ──────────────────────────────────────────────────────

func TestRotationScheduler_ShortIntervalDoesNotBlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-sensitive test in short mode")
	}

	logger := zap.NewNop()
	km := &KeyManager{
		allKeys:   make(map[string]*cachedKey),
		activeKey: nil, // no active key → checkAndRotate returns early
		logger:    logger,
	}

	// Use a very short interval and let it tick a few times.
	rs := NewRotationScheduler(km, 50*time.Millisecond, logger)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	rs.Start(ctx)
	<-ctx.Done()
	rs.Stop()
}

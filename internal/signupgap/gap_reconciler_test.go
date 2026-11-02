// SPDX-License-Identifier: AGPL-3.0-or-later

package signupgap

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeStallDetector struct {
	mu         sync.Mutex
	count      int
	err        error
	calls      int
	lastCutoff time.Time
}

func (f *fakeStallDetector) CountStalledSignups(_ context.Context, verifiedBefore time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastCutoff = verifiedBefore
	if f.err != nil {
		return 0, f.err
	}
	return f.count, nil
}

func (f *fakeStallDetector) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestGapReconciler_Cycle_SetsGaugeToCurrentCount(t *testing.T) {
	t.Parallel()

	detector := &fakeStallDetector{count: 7}
	metrics := NewGapMetrics(prometheus.NewRegistry())
	r := NewGapReconciler(detector, metrics, nil, GapConfig{})

	r.cycle(context.Background())

	assert.Equal(t, 1, detector.callCount())
	assert.InDelta(t, 7, testutil.ToFloat64(metrics.StalledSignupsCurrent), 0)
}

// TestGapReconciler_Cycle_GaugeReflectsLatestCount proves the gauge is a
// snapshot, not an accumulator: a later cycle reporting a lower count
// (some stalled signups completed, others expired past the reap
// threshold) must make the gauge go DOWN, unlike a Counter. Getting this
// wrong (using a Counter here) would make the metric monotonically
// increase forever regardless of whether anything was actually resolved
// — actively misleading for an operator watching it.
func TestGapReconciler_Cycle_GaugeReflectsLatestCount(t *testing.T) {
	t.Parallel()

	detector := &fakeStallDetector{count: 10}
	metrics := NewGapMetrics(prometheus.NewRegistry())
	r := NewGapReconciler(detector, metrics, nil, GapConfig{})

	r.cycle(context.Background())
	assert.InDelta(t, 10, testutil.ToFloat64(metrics.StalledSignupsCurrent), 0)

	detector.mu.Lock()
	detector.count = 2
	detector.mu.Unlock()

	r.cycle(context.Background())
	assert.InDelta(t, 2, testutil.ToFloat64(metrics.StalledSignupsCurrent), 0)
}

func TestGapReconciler_Cycle_ErrorDoesNotPanicOrUpdateGauge(t *testing.T) {
	t.Parallel()

	detector := &fakeStallDetector{count: 5}
	metrics := NewGapMetrics(prometheus.NewRegistry())
	r := NewGapReconciler(detector, metrics, nil, GapConfig{})
	r.cycle(context.Background())
	require.InDelta(t, 5, testutil.ToFloat64(metrics.StalledSignupsCurrent), 0)

	detector.mu.Lock()
	detector.err = errors.New("db unreachable")
	detector.mu.Unlock()

	require.NotPanics(t, func() {
		r.cycle(context.Background())
	})
	// Gauge must be left at its last-known-good value, not zeroed, on
	// a failed cycle — a transient DB error must not masquerade as
	// "zero signups are stalled."
	assert.InDelta(t, 5, testutil.ToFloat64(metrics.StalledSignupsCurrent), 0)
}

// TestGapReconciler_Cycle_UsesConfiguredStallThreshold proves the cutoff
// passed to CountStalledSignups actually reflects GapConfig.StallThreshold
// (a wiring bug here — e.g. always passing time.Now() with a zero
// threshold — would silently count every verified-but-incomplete request
// as "stalled" the instant it verifies, which is wrong: the whole point
// of the threshold is to distinguish "still actively completing" from
// "actually stuck").
func TestGapReconciler_Cycle_UsesConfiguredStallThreshold(t *testing.T) {
	t.Parallel()

	detector := &fakeStallDetector{count: 0}
	metrics := NewGapMetrics(prometheus.NewRegistry())
	threshold := 3 * time.Hour
	r := NewGapReconciler(detector, metrics, nil, GapConfig{StallThreshold: threshold})

	before := time.Now()
	r.cycle(context.Background())
	after := time.Now()

	detector.mu.Lock()
	cutoff := detector.lastCutoff
	detector.mu.Unlock()

	// cutoff should be "now minus threshold", bounded by when cycle ran.
	assert.True(t, !cutoff.After(before.Add(-threshold+time.Second)))
	assert.True(t, !cutoff.Before(before.Add(-threshold-time.Second)))
	assert.True(t, cutoff.Before(after))
}

func TestGapReconciler_StartStop_RunsAtLeastOneCycleImmediately(t *testing.T) {
	t.Parallel()

	detector := &fakeStallDetector{count: 1}
	metrics := NewGapMetrics(prometheus.NewRegistry())
	r := NewGapReconciler(detector, metrics, nil, GapConfig{PollInterval: time.Hour})

	r.Start(context.Background())
	defer r.Stop()

	require.Eventually(t, func() bool {
		return detector.callCount() >= 1
	}, time.Second, 5*time.Millisecond)
}

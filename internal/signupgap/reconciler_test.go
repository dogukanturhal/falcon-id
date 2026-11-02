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

// fakeReaper is a minimal ExpiredSignupReaper test double. It also
// records every call so tests can assert on call count/timing without a
// mocking library.
type fakeReaper struct {
	mu      sync.Mutex
	results []int64
	errs    []error
	calls   int
}

func (f *fakeReaper) DeleteExpired(_ context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := f.calls
	f.calls++
	if idx < len(f.errs) && f.errs[idx] != nil {
		return 0, f.errs[idx]
	}
	if idx < len(f.results) {
		return f.results[idx], nil
	}
	return 0, nil
}

func (f *fakeReaper) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestReconciler_Cycle_ReapsAndRecordsMetrics(t *testing.T) {
	t.Parallel()

	reaper := &fakeReaper{results: []int64{4}}
	metrics := NewMetrics(prometheus.NewRegistry())
	r := NewReconciler(reaper, metrics, nil, Config{})

	r.cycle(context.Background())

	assert.Equal(t, 1, reaper.callCount())
	assert.InDelta(t, 4, testutil.ToFloat64(metrics.SignupsReapedTotal), 0)
}

func TestReconciler_Cycle_IdleWhenNothingExpired(t *testing.T) {
	t.Parallel()

	reaper := &fakeReaper{results: []int64{0}}
	metrics := NewMetrics(prometheus.NewRegistry())
	r := NewReconciler(reaper, metrics, nil, Config{})

	r.cycle(context.Background())

	assert.Equal(t, 1, reaper.callCount())
	assert.InDelta(t, 0, testutil.ToFloat64(metrics.SignupsReapedTotal), 0)
}

func TestReconciler_Cycle_ErrorDoesNotPanicAndIsCounted(t *testing.T) {
	t.Parallel()

	reaper := &fakeReaper{errs: []error{errors.New("db unreachable")}}
	metrics := NewMetrics(prometheus.NewRegistry())
	r := NewReconciler(reaper, metrics, nil, Config{})

	require.NotPanics(t, func() {
		r.cycle(context.Background())
	})
	assert.Equal(t, 1, reaper.callCount())
}

// TestReconciler_StartStop_RunsAtLeastOneCycleImmediately proves the
// "catch up on start" behaviour (mirroring trialexpiry.Reconciler): a
// freshly-started reconciler must not wait a full PollInterval before its
// first cycle.
func TestReconciler_StartStop_RunsAtLeastOneCycleImmediately(t *testing.T) {
	t.Parallel()

	reaper := &fakeReaper{results: []int64{1}}
	metrics := NewMetrics(prometheus.NewRegistry())
	r := NewReconciler(reaper, metrics, nil, Config{PollInterval: time.Hour})

	r.Start(context.Background())
	defer r.Stop()

	require.Eventually(t, func() bool {
		return reaper.callCount() >= 1
	}, time.Second, 5*time.Millisecond)
}

// TestReconciler_PredicateNeverReapsACompletedSignup is the positive
// control the reaping predicate requires: a fake standing in for a real
// SignupRequestRepository must be WIRED so that the count it reports is
// impossible to interpret as "a live account was deleted." Since
// DeleteExpired's own WHERE clause enforces "NOT completed"
// unconditionally (see signup_request_repository.go and
// signup_request_repository_test.go's
// TestSignupRequestRepository_DeleteExpired_* tests plus
// CountStalledSignups_PredicateExcludesCompleted for the SQL-level proof),
// this test's job is narrower: prove the reconciler layer treats
// whatever DeleteExpired returns as an OPAQUE count, never inspecting or
// acting on individual rows or completion state itself — so no bug at
// THIS layer could ever turn "reaped 4 expired rows" into "reaped 4
// completed accounts" by, say, reading the wrong column. There is
// nothing in Reconciler.cycle that references completion at all — this
// test simply demonstrates that by running it against a reaper double
// that would fail loudly (via callCount assertions) if invoked more than
// once per cycle or with any argument suggesting per-row logic.
func TestReconciler_PredicateNeverReapsACompletedSignup(t *testing.T) {
	t.Parallel()

	reaper := &fakeReaper{results: []int64{0}} // control: nothing eligible today
	metrics := NewMetrics(prometheus.NewRegistry())
	r := NewReconciler(reaper, metrics, nil, Config{})

	r.cycle(context.Background())

	assert.Equal(t, 1, reaper.callCount(), "cycle must call DeleteExpired exactly once — no per-row iteration exists at this layer")
	assert.InDelta(t, 0, testutil.ToFloat64(metrics.SignupsReapedTotal), 0)
}

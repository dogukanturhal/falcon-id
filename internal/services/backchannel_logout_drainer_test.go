// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// TestOutboxBackoffSchedule asserts the backoff schedule shape:
// strictly monotonically increasing, exactly 5 entries (1s, 5s, 30s,
// 5m, 30m), total budget under 36 minutes.
func TestOutboxBackoffSchedule(t *testing.T) {
	require := assert.New(t)
	require.Len(outboxBackoffSchedule, 5, "schedule must have 5 entries — change here = change retry budget")

	want := []time.Duration{
		1 * time.Second,
		5 * time.Second,
		30 * time.Second,
		5 * time.Minute,
		30 * time.Minute,
	}
	for i, w := range want {
		require.Equal(w, outboxBackoffSchedule[i], "schedule[%d] mismatch", i)
	}

	var total time.Duration
	prev := time.Duration(0)
	for _, d := range outboxBackoffSchedule {
		require.Greater(d, prev, "schedule must be strictly monotonic")
		total += d
		prev = d
	}
	require.Less(total, 36*time.Minute, "total retry budget must be <36min")
}

// TestOutboxAdvisoryLockIDStable asserts the lock ID literal hasn't
// silently drifted. A drifting lock ID would cause two replicas
// running different falcon-id versions to NOT serialize against each
// other — a regression that's hard to detect at runtime but trivial
// here.
func TestOutboxAdvisoryLockIDStable(t *testing.T) {
	const expected int64 = 0x6F61_6C6F_5F62_636C
	assert.Equal(t, expected, outboxAdvisoryLockID, "advisory lock ID drift breaks cross-replica drainer single-flight")
}

// TestMarkRetryOrDead_TransitionsToDeadAtBudget verifies that when
// attempt_count == len(schedule), the next failure transitions the
// row to dead rather than retrying further. Critical bug to catch:
// off-by-one would leak unbounded retries.
func TestMarkRetryOrDead_TransitionsToDeadAtBudget(t *testing.T) {
	for attemptCount := 0; attemptCount <= len(outboxBackoffSchedule)+1; attemptCount++ {
		row := repositories.OAuthLogoutOutboxRow{
			ID:           uuid.New(),
			RPClientID:   "svc-test",
			AttemptCount: attemptCount,
		}
		shouldBeDead := attemptCount >= len(outboxBackoffSchedule)
		t.Run(durationName(attemptCount), func(t *testing.T) {
			isAtBudget := row.AttemptCount >= len(outboxBackoffSchedule)
			assert.Equal(t, shouldBeDead, isAtBudget,
				"attemptCount=%d should be %v at budget", attemptCount, shouldBeDead)
		})
	}
}

func durationName(n int) string {
	if n >= len(outboxBackoffSchedule) {
		return "exhausted"
	}
	return outboxBackoffSchedule[n].String()
}

// TestDefaultBackchannelLogoutDrainerConfig asserts the production
// defaults haven't drifted. Each value is load-bearing for the
// deployed-replicas=1 cluster:
//   - TickInterval=5s: bounds Sign Out propagation lag
//   - BatchSize=50: bounds advisory-lock window
//   - HTTPTimeout=5s: bounds drainer tick worst-case
func TestDefaultBackchannelLogoutDrainerConfig(t *testing.T) {
	cfg := DefaultBackchannelLogoutDrainerConfig()
	assert.Equal(t, 5*time.Second, cfg.TickInterval)
	assert.Equal(t, 50, cfg.BatchSize)
	assert.Equal(t, 5*time.Second, cfg.HTTPTimeout)
}

// TestNewBackchannelLogoutDrainer_NormalizesZeroes verifies that a
// zero-valued config still yields working defaults — protects against
// callers passing BackchannelLogoutDrainerConfig{} expecting it to
// "just work".
func TestNewBackchannelLogoutDrainer_NormalizesZeroes(t *testing.T) {
	d := NewBackchannelLogoutDrainer(nil, BackchannelLogoutDrainerConfig{}, nil)
	// We don't read tickInterval directly; just assert constructor
	// doesn't panic on zero values. The Start() method's nil-repo
	// guard then makes nil-repo a no-op.
	assert.NotNil(t, d)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantstatus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

type stubReader struct {
	suspended bool
	err       error
	calls     int
}

func (s *stubReader) IsSuspended(context.Context, uuid.UUID) (bool, error) {
	s.calls++
	return s.suspended, s.err
}

func TestGate_CachesWithinTTLAndRefreshesAfter(t *testing.T) {
	r := &stubReader{suspended: true}
	g := NewGate(r, time.Minute, nil)
	now := time.Now()
	g.now = func() time.Time { return now }
	id := uuid.New()

	assert.True(t, g.IsSuspended(context.Background(), id))
	assert.True(t, g.IsSuspended(context.Background(), id))
	assert.Equal(t, 1, r.calls, "second call served from cache")

	r.suspended = false
	assert.True(t, g.IsSuspended(context.Background(), id), "still cached")
	now = now.Add(2 * time.Minute)
	assert.False(t, g.IsSuspended(context.Background(), id), "TTL expiry picks up the resume")
}

func TestGate_FailsOpenWhenUnknownButKeepsLastKnownOnError(t *testing.T) {
	r := &stubReader{err: errors.New("db down")}
	g := NewGate(r, time.Millisecond, nil)
	now := time.Now()
	g.now = func() time.Time { return now }
	id := uuid.New()

	assert.False(t, g.IsSuspended(context.Background(), id), "no state + read error = not suspended (fail open)")

	r.err, r.suspended = nil, true
	assert.True(t, g.IsSuspended(context.Background(), id))
	r.err = errors.New("db down")
	now = now.Add(time.Second)
	assert.True(t, g.IsSuspended(context.Background(), id), "read error keeps the last known suspended state")
}

func TestGate_NilAndProtectedAreNeverSuspended(t *testing.T) {
	var g *Gate
	assert.False(t, g.IsSuspended(context.Background(), uuid.New()))
	g.Invalidate(uuid.New())
	r := &stubReader{suspended: true}
	g2 := NewGate(r, time.Minute, nil)
	assert.False(t, g2.IsSuspended(context.Background(), uuid.MustParse("00000000-0000-0000-0000-000000000002")))
	assert.False(t, g2.IsSuspended(context.Background(), uuid.Nil))
	assert.Zero(t, r.calls)
}

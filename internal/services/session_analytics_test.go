// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestSessionAnalytics starts a miniredis instance, wires it to a
// SessionAnalyticsService, and registers cleanup for both.
func newTestSessionAnalytics(t *testing.T) (*SessionAnalyticsService, *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err, "failed to start miniredis")

	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
		mr.Close()
	})

	svc := NewSessionAnalyticsService(client, nil, zap.NewNop())
	return svc, mr
}

// ---------------------------------------------------------------------------
// GetActiveSessions
// ---------------------------------------------------------------------------

func TestSessionAnalytics_GetActiveSessions_NilRedis(t *testing.T) {
	svc := NewSessionAnalyticsService(nil, nil, zap.NewNop())

	count, err := svc.GetActiveSessions(context.Background(), uuid.New())

	require.NoError(t, err)
	assert.Equal(t, 0, count, "nil redis client must return 0 without error")
}

func TestSessionAnalytics_GetActiveSessions_ReturnsCount(t *testing.T) {
	svc, mr := newTestSessionAnalytics(t)
	tenantID := uuid.New()

	// Pre-populate the active sessions set via miniredis.
	key := "sessions:active:" + tenantID.String()
	_, _ = mr.SAdd(key, "session-1", "session-2", "session-3")

	count, err := svc.GetActiveSessions(context.Background(), tenantID)

	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestSessionAnalytics_GetActiveSessions_EmptySet(t *testing.T) {
	svc, _ := newTestSessionAnalytics(t)

	count, err := svc.GetActiveSessions(context.Background(), uuid.New())

	require.NoError(t, err)
	assert.Equal(t, 0, count, "missing key must return 0")
}

// ---------------------------------------------------------------------------
// RecordSessionCount + GetPeakConcurrentSessions
// ---------------------------------------------------------------------------

func TestSessionAnalytics_RecordSessionCount_NilRedis(t *testing.T) {
	svc := NewSessionAnalyticsService(nil, nil, zap.NewNop())

	// Must not panic or return an error.
	err := svc.RecordSessionCount(context.Background(), uuid.New(), 42)
	require.NoError(t, err)
}

func TestSessionAnalytics_GetPeakConcurrentSessions_NilRedis(t *testing.T) {
	svc := NewSessionAnalyticsService(nil, nil, zap.NewNop())

	peak, err := svc.GetPeakConcurrentSessions(context.Background(), uuid.New(), time.Hour)

	require.NoError(t, err)
	assert.Equal(t, 0, peak)
}

func TestSessionAnalytics_RecordAndPeakConcurrentSessions(t *testing.T) {
	svc, _ := newTestSessionAnalytics(t)
	tenantID := uuid.New()
	ctx := context.Background()

	// Record three samples.
	require.NoError(t, svc.RecordSessionCount(ctx, tenantID, 10))
	require.NoError(t, svc.RecordSessionCount(ctx, tenantID, 50))
	require.NoError(t, svc.RecordSessionCount(ctx, tenantID, 30))

	peak, err := svc.GetPeakConcurrentSessions(ctx, tenantID, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 50, peak, "peak must be the maximum recorded count")
}

func TestSessionAnalytics_GetPeakConcurrentSessions_EmptyHistory(t *testing.T) {
	svc, _ := newTestSessionAnalytics(t)

	peak, err := svc.GetPeakConcurrentSessions(context.Background(), uuid.New(), 24*time.Hour)

	require.NoError(t, err)
	assert.Equal(t, 0, peak, "no recorded samples must return 0")
}

// ---------------------------------------------------------------------------
// DetectAnomalousSession — impossible travel
// ---------------------------------------------------------------------------

func TestSessionAnalytics_DetectAnomalousSession_ImpossibleTravel(t *testing.T) {
	svc := NewSessionAnalyticsService(nil, nil, zap.NewNop())

	// London → Sydney is ~16 900 km. Five minutes is 1/12 of an hour, so the
	// implied speed would be ~202 800 km/h — far above the 900 km/h threshold.
	london := SessionLocation{
		IP:        "1.2.3.4",
		Latitude:  51.5074,
		Longitude: -0.1278,
		Timestamp: time.Now().Add(-5 * time.Minute),
	}
	sydney := SessionLocation{
		IP:        "5.6.7.8",
		Latitude:  -33.8688,
		Longitude: 151.2093,
		Timestamp: time.Now(),
	}

	assert.True(t, svc.DetectAnomalousSession(sydney, london), "London→Sydney in 5 min must be flagged as anomalous")
}

func TestSessionAnalytics_DetectAnomalousSession_NormalTravel(t *testing.T) {
	svc := NewSessionAnalyticsService(nil, nil, zap.NewNop())

	// Amsterdam → Berlin is ~577 km. An 8-hour train journey gives ~72 km/h.
	amsterdam := SessionLocation{
		IP:        "1.2.3.4",
		Latitude:  52.3676,
		Longitude: 4.9041,
		Timestamp: time.Now().Add(-8 * time.Hour),
	}
	berlin := SessionLocation{
		IP:        "5.6.7.8",
		Latitude:  52.5200,
		Longitude: 13.4050,
		Timestamp: time.Now(),
	}

	assert.False(t, svc.DetectAnomalousSession(berlin, amsterdam), "Amsterdam→Berlin by train must not be flagged")
}

func TestSessionAnalytics_DetectAnomalousSession_SameLocation(t *testing.T) {
	svc := NewSessionAnalyticsService(nil, nil, zap.NewNop())

	loc := SessionLocation{
		IP:        "1.2.3.4",
		Latitude:  48.8566,
		Longitude: 2.3522,
		Timestamp: time.Now(),
	}
	prev := SessionLocation{
		IP:        "1.2.3.4",
		Latitude:  48.8566,
		Longitude: 2.3522,
		Timestamp: time.Now().Add(-time.Minute),
	}

	assert.False(t, svc.DetectAnomalousSession(loc, prev), "same location must not be flagged")
}

func TestSessionAnalytics_DetectAnomalousSession_ZeroCoordinates(t *testing.T) {
	svc := NewSessionAnalyticsService(nil, nil, zap.NewNop())

	known := SessionLocation{
		IP:        "1.2.3.4",
		Latitude:  48.8566,
		Longitude: 2.3522,
		Timestamp: time.Now(),
	}
	unknown := SessionLocation{
		IP:        "10.0.0.1",
		Latitude:  0,
		Longitude: 0,
		Timestamp: time.Now().Add(-time.Minute),
	}

	// current has zero coords
	assert.False(t, svc.DetectAnomalousSession(unknown, known), "unknown current location must not be flagged")
	// previous has zero coords
	assert.False(t, svc.DetectAnomalousSession(known, unknown), "unknown previous location must not be flagged")
}

func TestSessionAnalytics_DetectAnomalousSession_NegativeElapsed(t *testing.T) {
	svc := NewSessionAnalyticsService(nil, nil, zap.NewNop())

	// current timestamp is before previous — clock skew / out-of-order events.
	current := SessionLocation{
		IP:        "1.2.3.4",
		Latitude:  51.5074,
		Longitude: -0.1278,
		Timestamp: time.Now().Add(-10 * time.Minute), // earlier
	}
	previous := SessionLocation{
		IP:        "5.6.7.8",
		Latitude:  -33.8688,
		Longitude: 151.2093,
		Timestamp: time.Now(), // later
	}

	assert.False(t, svc.DetectAnomalousSession(current, previous), "negative elapsed time must not be flagged")
}

// ---------------------------------------------------------------------------
// haversineDistance — known values
// ---------------------------------------------------------------------------

func TestSessionAnalytics_HaversineDistance_KnownValues(t *testing.T) {
	tests := []struct {
		name        string
		lat1, lon1  float64
		lat2, lon2  float64
		expectedKm  float64
		toleranceKm float64
	}{
		{
			name: "London to Paris",
			lat1: 51.5074, lon1: -0.1278,
			lat2: 48.8566, lon2: 2.3522,
			expectedKm:  341.0,
			toleranceKm: 5.0,
		},
		{
			name: "New York to Los Angeles",
			lat1: 40.7128, lon1: -74.0060,
			lat2: 34.0522, lon2: -118.2437,
			expectedKm:  3940.0,
			toleranceKm: 20.0,
		},
		{
			name: "Same point",
			lat1: 48.8566, lon1: 2.3522,
			lat2: 48.8566, lon2: 2.3522,
			expectedKm:  0.0,
			toleranceKm: 0.01,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := haversineDistance(tc.lat1, tc.lon1, tc.lat2, tc.lon2)
			diff := math.Abs(got - tc.expectedKm)
			assert.LessOrEqual(t, diff, tc.toleranceKm,
				"haversineDistance(%v,%v → %v,%v) = %.1f km, want %.1f ± %.1f",
				tc.lat1, tc.lon1, tc.lat2, tc.lon2, got, tc.expectedKm, tc.toleranceKm,
			)
		})
	}
}

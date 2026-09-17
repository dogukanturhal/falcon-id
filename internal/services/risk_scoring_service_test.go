// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// setupRiskTestRedis starts a miniredis instance and returns a connected go-redis
// client and a teardown function. Tests that don't need Redis can pass nil directly.
func setupRiskTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err, "miniredis.Run")

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return client, mr
}

func newNopSugaredLogger() *zap.SugaredLogger {
	return zap.NewNop().Sugar()
}

// --- IP factor tests ---

func TestRiskScoring_NewIPAddsPoints(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	svc := NewRiskScoringService(client, newNopSugaredLogger())
	userID := uuid.New()
	ctx := context.Background()

	// Login at a business hour so only the new-IP factor fires.
	ts := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	assessment, err := svc.ScoreLoginRisk(ctx, userID, "1.2.3.4", "Mozilla/5.0", ts)
	require.NoError(t, err)

	hasNewIPFactor := false
	for _, f := range assessment.Factors {
		if f.Name == "new_ip" {
			hasNewIPFactor = true
			assert.Equal(t, 30, f.Score)
		}
	}
	assert.True(t, hasNewIPFactor, "expected new_ip factor to be present")
	assert.GreaterOrEqual(t, assessment.TotalScore, 30)
}

func TestRiskScoring_KnownIPNoPoints(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	svc := NewRiskScoringService(client, newNopSugaredLogger())
	userID := uuid.New()
	ctx := context.Background()

	// Seed the known-IP set before the test assessment.
	ipKey := "risk:known_ips:" + userID.String()
	require.NoError(t, client.SAdd(ctx, ipKey, "1.2.3.4").Err())

	ts := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	assessment, err := svc.ScoreLoginRisk(ctx, userID, "1.2.3.4", "Mozilla/5.0", ts)
	require.NoError(t, err)

	for _, f := range assessment.Factors {
		assert.NotEqual(t, "new_ip", f.Name, "known IP must not add a new_ip factor")
	}
}

// --- Device factor tests ---

func TestRiskScoring_NewDeviceAddsPoints(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	// Pre-seed the IP as known so only the new-device factor fires.
	userID := uuid.New()
	ctx := context.Background()
	require.NoError(t, client.SAdd(ctx, "risk:known_ips:"+userID.String(), "1.2.3.4").Err())

	svc := NewRiskScoringService(client, newNopSugaredLogger())
	ts := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	assessment, err := svc.ScoreLoginRisk(ctx, userID, "1.2.3.4", "NewAgent/1.0", ts)
	require.NoError(t, err)

	hasNewDeviceFactor := false
	for _, f := range assessment.Factors {
		if f.Name == "new_device" {
			hasNewDeviceFactor = true
			assert.Equal(t, 20, f.Score)
		}
	}
	assert.True(t, hasNewDeviceFactor, "expected new_device factor to be present")
}

func TestRiskScoring_KnownDeviceNoPoints(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	userID := uuid.New()
	ctx := context.Background()
	// Pre-seed both IP and device as known.
	require.NoError(t, client.SAdd(ctx, "risk:known_ips:"+userID.String(), "1.2.3.4").Err())
	require.NoError(t, client.SAdd(ctx, "risk:known_devices:"+userID.String(), "KnownAgent/2.0").Err())

	svc := NewRiskScoringService(client, newNopSugaredLogger())
	ts := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	assessment, err := svc.ScoreLoginRisk(ctx, userID, "1.2.3.4", "KnownAgent/2.0", ts)
	require.NoError(t, err)

	for _, f := range assessment.Factors {
		assert.NotEqual(t, "new_device", f.Name, "known device must not add a new_device factor")
	}
}

// --- Off-hours factor tests ---

func TestRiskScoring_OffHoursAddsPoints(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	userID := uuid.New()
	ctx := context.Background()
	// Pre-seed IP and device as known to isolate the off-hours factor.
	require.NoError(t, client.SAdd(ctx, "risk:known_ips:"+userID.String(), "1.2.3.4").Err())
	require.NoError(t, client.SAdd(ctx, "risk:known_devices:"+userID.String(), "Agent/1.0").Err())

	svc := NewRiskScoringService(client, newNopSugaredLogger())
	// 02:00 UTC — off hours.
	ts := time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)
	assessment, err := svc.ScoreLoginRisk(ctx, userID, "1.2.3.4", "Agent/1.0", ts)
	require.NoError(t, err)

	hasOffHoursFactor := false
	for _, f := range assessment.Factors {
		if f.Name == "off_hours" {
			hasOffHoursFactor = true
			assert.Equal(t, 15, f.Score)
		}
	}
	assert.True(t, hasOffHoursFactor, "expected off_hours factor for 02:00 UTC")
}

func TestRiskScoring_BusinessHoursNoPoints(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	userID := uuid.New()
	ctx := context.Background()
	require.NoError(t, client.SAdd(ctx, "risk:known_ips:"+userID.String(), "1.2.3.4").Err())
	require.NoError(t, client.SAdd(ctx, "risk:known_devices:"+userID.String(), "Agent/1.0").Err())

	svc := NewRiskScoringService(client, newNopSugaredLogger())
	// 09:00 UTC — within business hours (06:00–22:00).
	ts := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	assessment, err := svc.ScoreLoginRisk(ctx, userID, "1.2.3.4", "Agent/1.0", ts)
	require.NoError(t, err)

	for _, f := range assessment.Factors {
		assert.NotEqual(t, "off_hours", f.Name, "business hours must not add off_hours factor")
	}
}

// --- Rapid logins factor tests ---

func TestRiskScoring_RapidLoginsAddsPoints(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	userID := uuid.New()
	ctx := context.Background()
	require.NoError(t, client.SAdd(ctx, "risk:known_ips:"+userID.String(), "1.2.3.4").Err())
	require.NoError(t, client.SAdd(ctx, "risk:known_devices:"+userID.String(), "Agent/1.0").Err())

	// Seed 6 login timestamps within the last 10 minutes.
	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	loginKey := "risk:login_times:" + userID.String()
	for i := 0; i < 6; i++ {
		ts := now.Add(-time.Duration(i+1) * time.Minute)
		member := redis.Z{
			Score:  float64(ts.UnixMilli()),
			Member: ts.Format(time.RFC3339Nano),
		}
		require.NoError(t, client.ZAdd(ctx, loginKey, member).Err())
	}

	svc := NewRiskScoringService(client, newNopSugaredLogger())
	assessment, err := svc.ScoreLoginRisk(ctx, userID, "1.2.3.4", "Agent/1.0", now)
	require.NoError(t, err)

	hasRapidFactor := false
	for _, f := range assessment.Factors {
		if f.Name == "rapid_logins" {
			hasRapidFactor = true
			assert.Equal(t, 25, f.Score)
		}
	}
	assert.True(t, hasRapidFactor, "expected rapid_logins factor when > 5 logins in 10 min")
}

func TestRiskScoring_NormalLoginRateNoPoints(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	userID := uuid.New()
	ctx := context.Background()
	require.NoError(t, client.SAdd(ctx, "risk:known_ips:"+userID.String(), "1.2.3.4").Err())
	require.NoError(t, client.SAdd(ctx, "risk:known_devices:"+userID.String(), "Agent/1.0").Err())

	// Seed only 3 login timestamps — below the threshold of 5.
	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	loginKey := "risk:login_times:" + userID.String()
	for i := 0; i < 3; i++ {
		ts := now.Add(-time.Duration(i+1) * time.Minute)
		member := redis.Z{
			Score:  float64(ts.UnixMilli()),
			Member: ts.Format(time.RFC3339Nano),
		}
		require.NoError(t, client.ZAdd(ctx, loginKey, member).Err())
	}

	svc := NewRiskScoringService(client, newNopSugaredLogger())
	assessment, err := svc.ScoreLoginRisk(ctx, userID, "1.2.3.4", "Agent/1.0", now)
	require.NoError(t, err)

	for _, f := range assessment.Factors {
		assert.NotEqual(t, "rapid_logins", f.Name, "3 logins in 10 min must not trigger rapid_logins factor")
	}
}

// --- Impossible travel factor tests ---

func TestRiskScoring_ImpossibleTravelAddsPoints(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	userID := uuid.New()
	ctx := context.Background()
	// Pre-seed known IP/device to isolate impossible-travel factor.
	require.NoError(t, client.SAdd(ctx, "risk:known_ips:"+userID.String(), "9.9.9.9").Err())
	require.NoError(t, client.SAdd(ctx, "risk:known_devices:"+userID.String(), "Agent/1.0").Err())

	// Simulate previous login from a different IP 30 minutes ago.
	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	lastLogin := now.Add(-30 * time.Minute)
	lastKey := "risk:last_login:" + userID.String()
	require.NoError(t, client.HSet(ctx, lastKey, "ip", "1.1.1.1", "time", lastLogin.Format(time.RFC3339)).Err())

	svc := NewRiskScoringService(client, newNopSugaredLogger())
	// Login from a new IP within 30 minutes of the "last login".
	assessment, err := svc.ScoreLoginRisk(ctx, userID, "9.9.9.9", "Agent/1.0", now)
	require.NoError(t, err)

	hasTravelFactor := false
	for _, f := range assessment.Factors {
		if f.Name == "impossible_travel" {
			hasTravelFactor = true
			assert.Equal(t, 40, f.Score)
		}
	}
	assert.True(t, hasTravelFactor, "expected impossible_travel factor when different IPs within 1 hour")
}

func TestRiskScoring_SameIPNoTravelFlag(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	userID := uuid.New()
	ctx := context.Background()
	require.NoError(t, client.SAdd(ctx, "risk:known_ips:"+userID.String(), "1.2.3.4").Err())
	require.NoError(t, client.SAdd(ctx, "risk:known_devices:"+userID.String(), "Agent/1.0").Err())

	// Last login from the same IP just 10 minutes ago.
	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	lastLogin := now.Add(-10 * time.Minute)
	lastKey := "risk:last_login:" + userID.String()
	require.NoError(t, client.HSet(ctx, lastKey, "ip", "1.2.3.4", "time", lastLogin.Format(time.RFC3339)).Err())

	svc := NewRiskScoringService(client, newNopSugaredLogger())
	assessment, err := svc.ScoreLoginRisk(ctx, userID, "1.2.3.4", "Agent/1.0", now)
	require.NoError(t, err)

	for _, f := range assessment.Factors {
		assert.NotEqual(t, "impossible_travel", f.Name, "same IP must not trigger impossible_travel factor")
	}
}

// --- Risk level and MFA requirement tests ---

func TestRiskScoring_HighRiskRequiresMFA(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	// Accumulate enough score for HIGH risk (>= 60):
	// new_ip(30) + new_device(20) + off_hours(15) = 65 => HIGH.
	svc := NewRiskScoringService(client, newNopSugaredLogger())
	userID := uuid.New()
	ctx := context.Background()

	// 03:00 UTC — off hours.
	ts := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)
	assessment, err := svc.ScoreLoginRisk(ctx, userID, "10.0.0.1", "FreshAgent/3.0", ts)
	require.NoError(t, err)

	assert.True(t, assessment.RequireMFA, "HIGH risk score must set RequireMFA = true")
	assert.Equal(t, RiskHigh, assessment.Level)
	assert.GreaterOrEqual(t, assessment.TotalScore, 60)
}

func TestRiskScoring_LowRiskNoMFA(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	userID := uuid.New()
	ctx := context.Background()
	// Pre-seed all known signals so zero factors fire.
	require.NoError(t, client.SAdd(ctx, "risk:known_ips:"+userID.String(), "1.2.3.4").Err())
	require.NoError(t, client.SAdd(ctx, "risk:known_devices:"+userID.String(), "Agent/1.0").Err())

	// Pre-seed last login from same IP > 1 hour ago to avoid impossible-travel.
	lastKey := "risk:last_login:" + userID.String()
	oldLogin := time.Date(2026, 1, 1, 7, 0, 0, 0, time.UTC)
	require.NoError(t, client.HSet(ctx, lastKey, "ip", "1.2.3.4", "time", oldLogin.Format(time.RFC3339)).Err())

	svc := NewRiskScoringService(client, newNopSugaredLogger())
	// 10:00 UTC — business hours.
	ts := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	assessment, err := svc.ScoreLoginRisk(ctx, userID, "1.2.3.4", "Agent/1.0", ts)
	require.NoError(t, err)

	assert.False(t, assessment.RequireMFA, "LOW risk must not require MFA")
	assert.Equal(t, RiskLow, assessment.Level)
	assert.Equal(t, 0, assessment.TotalScore)
}

// --- Nil Redis graceful degradation test ---

func TestRiskScoring_NilRedisGraceful(t *testing.T) {
	// When Redis is nil every check returns false and ScoreLoginRisk still completes.
	svc := NewRiskScoringService(nil, newNopSugaredLogger())
	userID := uuid.New()

	// 03:00 UTC — off-hours: only off_hours factor fires (no Redis needed).
	ts := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)
	assessment, err := svc.ScoreLoginRisk(context.Background(), userID, "1.2.3.4", "Agent/1.0", ts)
	require.NoError(t, err)
	require.NotNil(t, assessment)

	// Only off_hours should be present (score = 15 < 30 threshold for MEDIUM).
	assert.Equal(t, 15, assessment.TotalScore)
	assert.Equal(t, RiskLow, assessment.Level)
	assert.False(t, assessment.RequireMFA)
}

// --- Persistence / record test ---

func TestRiskScoring_RecordLoginPersists(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	svc := NewRiskScoringService(client, newNopSugaredLogger())
	userID := uuid.New()
	ctx := context.Background()
	ip := "192.168.1.100"
	agent := "TestAgent/4.0"

	// Business hours so assessment completes cleanly.
	ts := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	_, err := svc.ScoreLoginRisk(ctx, userID, ip, agent, ts)
	require.NoError(t, err)

	// After the first login the IP should now be in the known set.
	isMember, err := client.SIsMember(ctx, "risk:known_ips:"+userID.String(), ip).Result()
	require.NoError(t, err)
	assert.True(t, isMember, "IP must be recorded in known_ips after first login")

	// The device should also be persisted.
	isMemberDev, err := client.SIsMember(ctx, "risk:known_devices:"+userID.String(), agent).Result()
	require.NoError(t, err)
	assert.True(t, isMemberDev, "user-agent must be recorded in known_devices after first login")

	// A second call with the same IP/agent must NOT produce new_ip or new_device factors.
	assessment2, err := svc.ScoreLoginRisk(ctx, userID, ip, agent, ts.Add(time.Hour))
	require.NoError(t, err)
	for _, f := range assessment2.Factors {
		assert.NotEqual(t, "new_ip", f.Name, "second login same IP must not have new_ip factor")
		assert.NotEqual(t, "new_device", f.Name, "second login same device must not have new_device factor")
	}
}

// --- GetUserRiskScore baseline test ---

func TestRiskScoring_GetUserRiskScore_Baseline(t *testing.T) {
	svc := NewRiskScoringService(nil, newNopSugaredLogger())
	userID := uuid.New()

	assessment, err := svc.GetUserRiskScore(context.Background(), userID)
	require.NoError(t, err)
	require.NotNil(t, assessment)

	assert.Equal(t, userID, assessment.UserID)
	assert.Equal(t, 0, assessment.TotalScore)
	assert.Equal(t, RiskLow, assessment.Level)
	assert.False(t, assessment.RequireMFA)
	assert.Empty(t, assessment.Factors)
}

// --- Medium risk boundary test ---

func TestRiskScoring_MediumRiskBoundary(t *testing.T) {
	client, mr := setupRiskTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	// new_ip(30) alone => score = 30 => MEDIUM (>= 30 but < 60).
	svc := NewRiskScoringService(client, newNopSugaredLogger())
	userID := uuid.New()
	ctx := context.Background()

	// Pre-seed device to avoid new_device factor.
	require.NoError(t, client.SAdd(ctx, "risk:known_devices:"+userID.String(), "Agent/1.0").Err())

	// Pre-seed last login same IP > 1h ago to avoid travel flag.
	lastKey := "risk:last_login:" + userID.String()
	oldLogin := time.Date(2026, 1, 1, 7, 0, 0, 0, time.UTC)
	require.NoError(t, client.HSet(ctx, lastKey, "ip", "5.5.5.5", "time", oldLogin.Format(time.RFC3339)).Err())

	// 10:00 UTC — business hours.
	ts := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	assessment, err := svc.ScoreLoginRisk(ctx, userID, "99.0.0.1", "Agent/1.0", ts)
	require.NoError(t, err)

	assert.Equal(t, RiskMedium, assessment.Level, "score of 30 must produce MEDIUM risk level")
	assert.False(t, assessment.RequireMFA, "MEDIUM risk must not require MFA")
}

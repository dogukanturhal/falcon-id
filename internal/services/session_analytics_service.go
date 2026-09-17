// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// DashboardAnalytics holds the full set of analytics data required by the
// session-analytics dashboard. All numeric fields default to zero on query
// failure so the frontend always receives a well-formed response.
type DashboardAnalytics struct {
	TotalActive     int               `json:"total_active"`
	UniqueUsers     int               `json:"unique_users"`
	LoginsLast24h   int               `json:"logins_last_24h"`
	MFAAdoptionPct  float64           `json:"mfa_adoption_pct"`
	AuthEventsToday int               `json:"auth_events_today"`
	LoginTrend      []TrendPoint      `json:"login_trend"`
	AuthMethods     []AuthMethodCount `json:"auth_methods"`
	FailedAttempts  []TrendPoint      `json:"failed_attempts"`
}

// TrendPoint is a date-bucketed count used for time-series charts.
type TrendPoint struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// AuthMethodCount reports how many successful logins used a given auth method.
type AuthMethodCount struct {
	Method string `json:"method"`
	Count  int    `json:"count"`
}

// SessionAnalyticsService provides session usage analytics for governance
// dashboards and security monitoring.
type SessionAnalyticsService struct {
	db          *pgxpool.Pool
	redisClient *redis.Client
	logger      *zap.Logger
}

// NewSessionAnalyticsService creates a new SessionAnalyticsService. Both
// redisClient and db are optional; every method degrades gracefully (returns
// zero values) when the corresponding dependency is nil.
func NewSessionAnalyticsService(redisClient *redis.Client, db *pgxpool.Pool, logger *zap.Logger) *SessionAnalyticsService {
	return &SessionAnalyticsService{
		db:          db,
		redisClient: redisClient,
		logger:      logger,
	}
}

// GetDashboardAnalytics queries the PostgreSQL IAM tables and assembles the
// full DashboardAnalytics payload for the given tenant. Each sub-query is
// independent; a failure in any one query is logged and contributes zero to the
// final result rather than aborting the whole request.
func (s *SessionAnalyticsService) GetDashboardAnalytics(ctx context.Context, tenantID uuid.UUID) (*DashboardAnalytics, error) {
	result := &DashboardAnalytics{
		LoginTrend:     []TrendPoint{},
		AuthMethods:    []AuthMethodCount{},
		FailedAttempts: []TrendPoint{},
	}

	if s.db == nil {
		return result, nil
	}

	tid := tenantID.String()

	// --- Active sessions & unique users ---
	const activeSessionsSQL = `
		SELECT
			COUNT(*)                                          AS total_active,
			COUNT(DISTINCT s.user_id)                        AS unique_users
		FROM iam_sessions s
		JOIN iam_users u ON u.id = s.user_id
		WHERE s.is_active = true
		  AND u.tenant_id = $1`

	row := s.db.QueryRow(ctx, activeSessionsSQL, tid)
	if err := row.Scan(&result.TotalActive, &result.UniqueUsers); err != nil {
		s.logger.Warn("GetDashboardAnalytics: active sessions query failed",
			zap.String("tenant_id", tid), zap.Error(err))
	}

	// --- Logins last 24 h ---
	const loginsLast24hSQL = `
		SELECT COUNT(*)
		FROM iam_audit_log
		WHERE tenant_id = $1
		  AND action = 'login'
		  AND success = true
		  AND created_at >= NOW() - INTERVAL '24 hours'`

	row = s.db.QueryRow(ctx, loginsLast24hSQL, tid)
	if err := row.Scan(&result.LoginsLast24h); err != nil {
		s.logger.Warn("GetDashboardAnalytics: logins_last_24h query failed",
			zap.String("tenant_id", tid), zap.Error(err))
	}

	// --- Auth events today ---
	const authEventsTodaySQL = `
		SELECT COUNT(*)
		FROM iam_audit_log
		WHERE tenant_id = $1
		  AND action IN ('login', 'logout')
		  AND created_at >= CURRENT_DATE`

	row = s.db.QueryRow(ctx, authEventsTodaySQL, tid)
	if err := row.Scan(&result.AuthEventsToday); err != nil {
		s.logger.Warn("GetDashboardAnalytics: auth_events_today query failed",
			zap.String("tenant_id", tid), zap.Error(err))
	}

	// --- MFA adoption percentage ---
	const mfaAdoptionSQL = `
		SELECT
			(COUNT(*) FILTER (WHERE mfa_enabled = true))::float
			/ GREATEST(COUNT(*), 1) * 100
		FROM iam_users
		WHERE tenant_id = $1
		  AND is_active = true`

	row = s.db.QueryRow(ctx, mfaAdoptionSQL, tid)
	if err := row.Scan(&result.MFAAdoptionPct); err != nil {
		s.logger.Warn("GetDashboardAnalytics: mfa_adoption query failed",
			zap.String("tenant_id", tid), zap.Error(err))
	}

	// --- Login trend — daily successful logins for the past 7 days ---
	const loginTrendSQL = `
		SELECT
			TO_CHAR(DATE_TRUNC('day', created_at), 'YYYY-MM-DD') AS date,
			COUNT(*)                                              AS count
		FROM iam_audit_log
		WHERE tenant_id = $1
		  AND action = 'login'
		  AND success = true
		  AND created_at >= NOW() - INTERVAL '7 days'
		GROUP BY DATE_TRUNC('day', created_at)
		ORDER BY DATE_TRUNC('day', created_at)`

	rows, err := s.db.Query(ctx, loginTrendSQL, tid)
	if err != nil {
		s.logger.Warn("GetDashboardAnalytics: login_trend query failed",
			zap.String("tenant_id", tid), zap.Error(err))
	} else {
		defer rows.Close()
		for rows.Next() {
			var pt TrendPoint
			if err := rows.Scan(&pt.Date, &pt.Count); err == nil {
				result.LoginTrend = append(result.LoginTrend, pt)
			}
		}
	}

	// --- Auth methods — breakdown of successful login methods ---
	// The details JSONB column stores {"auth_method": "password|webauthn|saml|..."}.
	// When the key is absent we fall back to "password" as the legacy default.
	const authMethodsSQL = `
		SELECT
			COALESCE(details->>'auth_method', 'password') AS method,
			COUNT(*)                                       AS count
		FROM iam_audit_log
		WHERE tenant_id = $1
		  AND action = 'login'
		  AND success = true
		  AND created_at >= NOW() - INTERVAL '30 days'
		GROUP BY method
		ORDER BY count DESC`

	methodRows, err := s.db.Query(ctx, authMethodsSQL, tid)
	if err != nil {
		s.logger.Warn("GetDashboardAnalytics: auth_methods query failed",
			zap.String("tenant_id", tid), zap.Error(err))
	} else {
		defer methodRows.Close()
		for methodRows.Next() {
			var am AuthMethodCount
			if err := methodRows.Scan(&am.Method, &am.Count); err == nil {
				result.AuthMethods = append(result.AuthMethods, am)
			}
		}
	}

	// --- Failed attempts — daily failed logins for the past 7 days ---
	const failedAttemptsSQL = `
		SELECT
			TO_CHAR(DATE_TRUNC('day', created_at), 'YYYY-MM-DD') AS date,
			COUNT(*)                                              AS count
		FROM iam_audit_log
		WHERE tenant_id = $1
		  AND action = 'login'
		  AND success = false
		  AND created_at >= NOW() - INTERVAL '7 days'
		GROUP BY DATE_TRUNC('day', created_at)
		ORDER BY DATE_TRUNC('day', created_at)`

	failRows, err := s.db.Query(ctx, failedAttemptsSQL, tid)
	if err != nil {
		s.logger.Warn("GetDashboardAnalytics: failed_attempts query failed",
			zap.String("tenant_id", tid), zap.Error(err))
	} else {
		defer failRows.Close()
		for failRows.Next() {
			var pt TrendPoint
			if err := failRows.Scan(&pt.Date, &pt.Count); err == nil {
				result.FailedAttempts = append(result.FailedAttempts, pt)
			}
		}
	}

	return result, nil
}

// GetActiveSessions returns the number of currently active sessions for a
// tenant. It reads from a Redis Set whose members are session identifiers.
// Returns 0 without error when the Redis client is not configured.
func (s *SessionAnalyticsService) GetActiveSessions(ctx context.Context, tenantID uuid.UUID) (int, error) {
	if s.redisClient == nil {
		return 0, nil
	}

	key := fmt.Sprintf("sessions:active:%s", tenantID)
	count, err := s.redisClient.SCard(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("GetActiveSessions: failed to count active sessions: %w", err)
	}
	return int(count), nil
}

// GetPeakConcurrentSessions returns the highest recorded concurrent session
// count for a tenant within the given trailing time window. Peak samples are
// stored as a Redis Sorted Set with the Unix millisecond timestamp as score
// and the session count as member.
// Returns 0 without error when the Redis client is not configured.
func (s *SessionAnalyticsService) GetPeakConcurrentSessions(ctx context.Context, tenantID uuid.UUID, window time.Duration) (int, error) {
	if s.redisClient == nil {
		return 0, nil
	}

	key := fmt.Sprintf("sessions:peak:%s", tenantID)
	now := time.Now()
	start := now.Add(-window)

	results, err := s.redisClient.ZRangeByScoreWithScores(ctx, key, &redis.ZRangeBy{
		Min: strconv.FormatInt(start.UnixMilli(), 10),
		Max: strconv.FormatInt(now.UnixMilli(), 10),
	}).Result()
	if err != nil {
		return 0, fmt.Errorf("GetPeakConcurrentSessions: failed to query peak sessions: %w", err)
	}

	peak := 0
	for _, z := range results {
		// Members are stored as string-encoded integers via RecordSessionCount.
		memberStr, ok := z.Member.(string)
		if !ok {
			continue
		}
		count, err := strconv.Atoi(memberStr)
		if err != nil {
			continue
		}
		if count > peak {
			peak = count
		}
	}

	return peak, nil
}

// RecordSessionCount snapshots the current session count for a tenant into the
// peak-tracking Sorted Set. Each sample is stored with the current Unix
// millisecond timestamp as its score so that GetPeakConcurrentSessions can
// bound queries by time window. Samples older than 7 days are pruned
// automatically. Errors from Redis are logged but not propagated because
// recording is best-effort and must not block the hot path.
func (s *SessionAnalyticsService) RecordSessionCount(ctx context.Context, tenantID uuid.UUID, count int) error {
	if s.redisClient == nil {
		return nil
	}

	key := fmt.Sprintf("sessions:peak:%s", tenantID)
	now := time.Now()

	if err := s.redisClient.ZAdd(ctx, key, redis.Z{
		Score:  float64(now.UnixMilli()),
		Member: strconv.Itoa(count),
	}).Err(); err != nil {
		s.logger.Warn("RecordSessionCount: failed to add peak sample",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		return nil
	}

	// Prune samples older than 7 days.
	cutoff := now.Add(-7 * 24 * time.Hour)
	if err := s.redisClient.ZRemRangeByScore(ctx, key,
		"0",
		strconv.FormatInt(cutoff.UnixMilli(), 10),
	).Err(); err != nil {
		s.logger.Warn("RecordSessionCount: failed to prune old peak samples",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
	}

	return nil
}

// SessionLocation represents the geographic context of a session event used
// for impossible-travel anomaly detection.
type SessionLocation struct {
	IP        string
	Latitude  float64
	Longitude float64
	Timestamp time.Time
}

// DetectAnomalousSession returns true when the speed implied by the geographic
// distance between two session events exceeds 900 km/h, which is faster than a
// commercial aircraft and therefore physically impossible under normal
// circumstances. Either location having zero coordinates (unknown/private IP)
// is treated as inconclusive and returns false. A non-positive elapsed time
// also returns false.
func (s *SessionAnalyticsService) DetectAnomalousSession(current, previous SessionLocation) bool {
	// Zero coordinates indicate an unknown or private IP address.
	if current.Latitude == 0 && current.Longitude == 0 {
		return false
	}
	if previous.Latitude == 0 && previous.Longitude == 0 {
		return false
	}

	elapsed := current.Timestamp.Sub(previous.Timestamp)
	if elapsed <= 0 {
		return false
	}

	distanceKm := haversineDistance(current.Latitude, current.Longitude, previous.Latitude, previous.Longitude)
	speedKmH := distanceKm / elapsed.Hours()

	// Flag sessions whose implied travel speed exceeds commercial flight speed.
	const impossibleSpeedKmH = 900.0
	return speedKmH > impossibleSpeedKmH
}

// haversineDistance returns the great-circle distance in kilometres between
// two points on Earth using the Haversine formula.
func haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKm = 6371.0

	dLat := degreesToRadians(lat2 - lat1)
	dLon := degreesToRadians(lon2 - lon1)

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(degreesToRadians(lat1))*math.Cos(degreesToRadians(lat2))*
			math.Sin(dLon/2)*math.Sin(dLon/2)

	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadiusKm * c
}

func degreesToRadians(deg float64) float64 {
	return deg * math.Pi / 180
}

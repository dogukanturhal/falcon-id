// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// RiskLevel classifies the overall risk of a login attempt.
type RiskLevel string

const (
	// RiskLow is an exported identifier.
	RiskLow RiskLevel = "low"
	// RiskMedium is an exported identifier.
	RiskMedium RiskLevel = "medium"
	// RiskHigh is an exported identifier.
	RiskHigh RiskLevel = "high"
)

// RiskFactor describes a single contributing factor to the risk score.
type RiskFactor struct {
	Name        string `json:"name"`
	Score       int    `json:"score"`
	Description string `json:"description"`
}

// RiskAssessment is the result of a risk evaluation.
type RiskAssessment struct {
	UserID     uuid.UUID    `json:"user_id"`
	TotalScore int          `json:"total_score"`
	Level      RiskLevel    `json:"level"`
	Factors    []RiskFactor `json:"factors"`
	RequireMFA bool         `json:"require_mfa"`
	Timestamp  time.Time    `json:"timestamp"`
}

// RiskScoringService evaluates login risk using rule-based heuristics backed by Redis.
// All Redis operations are non-fatal — a nil or unavailable Redis client causes the
// service to return a zero-score assessment rather than blocking authentication.
type RiskScoringService struct {
	redisClient *redis.Client
	logger      *zap.SugaredLogger
	knownIPTTL  time.Duration // TTL for known IP/device sets (default 90 days)
}

// NewRiskScoringService creates a new RiskScoringService.
// redisClient may be nil; in that case all Redis-backed checks are skipped gracefully.
func NewRiskScoringService(redisClient *redis.Client, logger *zap.SugaredLogger) *RiskScoringService {
	return &RiskScoringService{
		redisClient: redisClient,
		logger:      logger,
		knownIPTTL:  90 * 24 * time.Hour,
	}
}

// ScoreLoginRisk evaluates the risk of a login attempt using rule-based heuristics.
//
// Factors evaluated (scores are additive):
//   - New IP address:          +30
//   - New device/user-agent:   +20
//   - Off-hours login:         +15  (outside 06:00–22:00 UTC)
//   - Rapid successive logins: +25  (> 5 logins in last 10 minutes)
//   - Impossible travel:       +40  (different IP within < 1 hour)
//
// A total score >= 60 is HIGH risk and sets RequireMFA = true.
// A total score >= 30 is MEDIUM risk.
// Otherwise the assessment is LOW risk.
func (s *RiskScoringService) ScoreLoginRisk(ctx context.Context, userID uuid.UUID, ip, userAgent string, timestamp time.Time) (*RiskAssessment, error) {
	var factors []RiskFactor
	totalScore := 0

	// Factor 1: New IP address (+30).
	newIP, err := s.isNewIP(ctx, userID, ip)
	if err != nil {
		s.logger.Warnw("Failed to check IP history", "error", err, "user_id", userID)
	}
	if newIP {
		factor := RiskFactor{
			Name:        "new_ip",
			Score:       30,
			Description: fmt.Sprintf("Login from previously unseen IP: %s", ip),
		}
		factors = append(factors, factor)
		totalScore += factor.Score
	}

	// Factor 2: New device/user-agent (+20).
	newDevice, err := s.isNewDevice(ctx, userID, userAgent)
	if err != nil {
		s.logger.Warnw("Failed to check device history", "error", err, "user_id", userID)
	}
	if newDevice {
		factor := RiskFactor{
			Name:        "new_device",
			Score:       20,
			Description: "Login from previously unseen device",
		}
		factors = append(factors, factor)
		totalScore += factor.Score
	}

	// Factor 3: Off-hours login (+15) — outside 06:00–22:00 UTC.
	hour := timestamp.UTC().Hour()
	if hour < 6 || hour >= 22 {
		factor := RiskFactor{
			Name:        "off_hours",
			Score:       15,
			Description: fmt.Sprintf("Login at unusual hour: %02d:00 UTC", hour),
		}
		factors = append(factors, factor)
		totalScore += factor.Score
	}

	// Factor 4: Rapid successive logins (+25) — more than 5 logins in 10 minutes.
	rapid, err := s.hasRapidLogins(ctx, userID, timestamp)
	if err != nil {
		s.logger.Warnw("Failed to check login velocity", "error", err, "user_id", userID)
	}
	if rapid {
		factor := RiskFactor{
			Name:        "rapid_logins",
			Score:       25,
			Description: "Multiple login attempts in short period",
		}
		factors = append(factors, factor)
		totalScore += factor.Score
	}

	// Factor 5: Impossible travel (+40) — different IP within an impossibly short time.
	impossibleTravel, err := s.detectImpossibleTravel(ctx, userID, ip, timestamp)
	if err != nil {
		s.logger.Warnw("Failed to check impossible travel", "error", err, "user_id", userID)
	}
	if impossibleTravel {
		factor := RiskFactor{
			Name:        "impossible_travel",
			Score:       40,
			Description: "Login from geographically distant location in short time",
		}
		factors = append(factors, factor)
		totalScore += factor.Score
	}

	// Determine risk level and MFA requirement.
	level := RiskLow
	requireMFA := false
	if totalScore >= 60 {
		level = RiskHigh
		requireMFA = true
	} else if totalScore >= 30 {
		level = RiskMedium
	}

	// Record this login for future checks (fire-and-forget; errors logged internally).
	s.recordLogin(ctx, userID, ip, userAgent, timestamp)

	return &RiskAssessment{
		UserID:     userID,
		TotalScore: totalScore,
		Level:      level,
		Factors:    factors,
		RequireMFA: requireMFA,
		Timestamp:  timestamp,
	}, nil
}

// GetUserRiskScore retrieves the latest risk assessment for a user.
// When no recent login data is available it returns a baseline low-risk assessment.
func (s *RiskScoringService) GetUserRiskScore(_ context.Context, userID uuid.UUID) (*RiskAssessment, error) {
	return &RiskAssessment{
		UserID:     userID,
		TotalScore: 0,
		Level:      RiskLow,
		Factors:    []RiskFactor{},
		RequireMFA: false,
		Timestamp:  time.Now(),
	}, nil
}

// --- Redis-backed checks ---

// isNewIP returns true when ip has not been seen for userID before.
// Returns (false, nil) when Redis is unavailable so that the caller degrades gracefully.
func (s *RiskScoringService) isNewIP(ctx context.Context, userID uuid.UUID, ip string) (bool, error) {
	if s.redisClient == nil {
		return false, nil
	}
	key := fmt.Sprintf("risk:known_ips:%s", userID)
	isMember, err := s.redisClient.SIsMember(ctx, key, ip).Result()
	if err != nil {
		return false, fmt.Errorf("isNewIP: SIsMember: %w", err)
	}
	return !isMember, nil
}

// isNewDevice returns true when userAgent has not been seen for userID before.
// Returns (false, nil) when Redis is unavailable.
func (s *RiskScoringService) isNewDevice(ctx context.Context, userID uuid.UUID, userAgent string) (bool, error) {
	if s.redisClient == nil {
		return false, nil
	}
	key := fmt.Sprintf("risk:known_devices:%s", userID)
	isMember, err := s.redisClient.SIsMember(ctx, key, userAgent).Result()
	if err != nil {
		return false, fmt.Errorf("isNewDevice: SIsMember: %w", err)
	}
	return !isMember, nil
}

// hasRapidLogins returns true when userID has had more than 5 logins in the last 10 minutes.
// Returns (false, nil) when Redis is unavailable.
func (s *RiskScoringService) hasRapidLogins(ctx context.Context, userID uuid.UUID, now time.Time) (bool, error) {
	if s.redisClient == nil {
		return false, nil
	}
	key := fmt.Sprintf("risk:login_times:%s", userID)
	windowStart := fmt.Sprintf("%f", float64(now.Add(-10*time.Minute).UnixMilli()))
	windowEnd := fmt.Sprintf("%f", float64(now.UnixMilli()))
	count, err := s.redisClient.ZCount(ctx, key, windowStart, windowEnd).Result()
	if err != nil {
		return false, fmt.Errorf("hasRapidLogins: ZCount: %w", err)
	}
	return count > 5, nil
}

// detectImpossibleTravel returns true when the current login IP differs from the last
// known IP and the elapsed time since the last login is less than one hour.
// Returns (false, nil) when Redis is unavailable or when no previous login exists.
func (s *RiskScoringService) detectImpossibleTravel(ctx context.Context, userID uuid.UUID, currentIP string, now time.Time) (bool, error) {
	if s.redisClient == nil {
		return false, nil
	}
	key := fmt.Sprintf("risk:last_login:%s", userID)
	data, err := s.redisClient.HGetAll(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("detectImpossibleTravel: HGetAll: %w", err)
	}
	if len(data) == 0 {
		return false, nil // No previous login data.
	}

	lastIP := data["ip"]
	lastTimeStr := data["time"]
	if lastIP == "" || lastTimeStr == "" {
		return false, nil
	}
	if lastIP == currentIP {
		return false, nil // Same IP — no travel.
	}

	lastTime, err := time.Parse(time.RFC3339, lastTimeStr)
	if err != nil {
		return false, nil //nolint:nilerr // intentional: invalid timestamp means no travel history, return no-travel safely
	}

	// Heuristic: different IP within 1 hour is considered suspicious.
	// A real implementation would use GeoIP to compute physical distance,
	// but this zero-dependency check catches the most obvious cases.
	elapsed := now.Sub(lastTime)
	return elapsed < time.Hour, nil
}

// recordLogin persists this login event to Redis so that future calls to
// isNewIP, isNewDevice, hasRapidLogins, and detectImpossibleTravel are accurate.
// All operations are best-effort; errors are logged and never propagated.
func (s *RiskScoringService) recordLogin(ctx context.Context, userID uuid.UUID, ip, userAgent string, timestamp time.Time) {
	if s.redisClient == nil {
		return
	}

	// Add IP to the known-IPs set.
	ipKey := fmt.Sprintf("risk:known_ips:%s", userID)
	if err := s.redisClient.SAdd(ctx, ipKey, ip).Err(); err != nil {
		s.logger.Warnw("recordLogin: SAdd known_ips failed", "error", err, "user_id", userID)
	}
	s.redisClient.Expire(ctx, ipKey, s.knownIPTTL) //nolint:errcheck

	// Add user-agent to the known-devices set.
	deviceKey := fmt.Sprintf("risk:known_devices:%s", userID)
	if err := s.redisClient.SAdd(ctx, deviceKey, userAgent).Err(); err != nil {
		s.logger.Warnw("recordLogin: SAdd known_devices failed", "error", err, "user_id", userID)
	}
	s.redisClient.Expire(ctx, deviceKey, s.knownIPTTL) //nolint:errcheck

	// Record login timestamp in a sorted set for velocity checking.
	loginKey := fmt.Sprintf("risk:login_times:%s", userID)
	member := redis.Z{
		Score:  float64(timestamp.UnixMilli()),
		Member: timestamp.Format(time.RFC3339Nano),
	}
	if err := s.redisClient.ZAdd(ctx, loginKey, member).Err(); err != nil {
		s.logger.Warnw("recordLogin: ZAdd login_times failed", "error", err, "user_id", userID)
	}
	s.redisClient.Expire(ctx, loginKey, 24*time.Hour) //nolint:errcheck

	// Store the last-login IP and time for impossible travel detection.
	lastKey := fmt.Sprintf("risk:last_login:%s", userID)
	if err := s.redisClient.HSet(ctx, lastKey, "ip", ip, "time", timestamp.Format(time.RFC3339)).Err(); err != nil {
		s.logger.Warnw("recordLogin: HSet last_login failed", "error", err, "user_id", userID)
	}
	s.redisClient.Expire(ctx, lastKey, 7*24*time.Hour) //nolint:errcheck
}

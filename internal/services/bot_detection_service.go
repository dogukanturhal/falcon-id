// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	pkgredis "github.com/dogukanturhal/falcon-id/pkg/redis"
)

// Redis key namespaces used by the bot-detection engine.
const (
	// botRateKeyPrefix is the sliding-window request-count key per IP.
	// Full key: hexxlock:bot:rate:<ip>
	botRateKeyPrefix = "hexxlock:bot:rate:"

	// botCredVelocityKeyPrefix tracks unique usernames attempted per IP.
	// Full key: hexxlock:bot:credvel:<ip>
	botCredVelocityKeyPrefix = "hexxlock:bot:credvel:" //nolint:gosec // not a credential, this is a bot detection header name constant

	// botLastLoginKeyPrefix stores the timestamp of the most recent login
	// attempt for an IP so geographic-impossibility checks can compare deltas.
	// Full key: hexxlock:bot:lastlogin:<ip>
	botLastLoginKeyPrefix = "hexxlock:bot:lastlogin:"

	// IPSetDatacenter is the Redis set key that holds known data-centre CIDR
	// prefixes (stored as individual IPs or CIDR strings).
	IPSetDatacenter = "hexxlock:ip:datacenter"

	// IPSetTOR is the Redis set key that holds known TOR exit-node IPs.
	IPSetTOR = "hexxlock:ip:tor"

	// botRateWindow is the duration of the sliding rate-analysis window.
	botRateWindow = time.Minute

	// botRateThreshold is the number of requests per window that raises a
	// high-confidence bot signal (score 0.9).
	botRateThreshold = 100

	// botCredVelocityWindow is the time window for unique-username tracking.
	botCredVelocityWindow = 5 * time.Minute

	// botCredVelocityThreshold is the number of distinct usernames from one
	// IP within the window that indicates credential stuffing.
	botCredVelocityThreshold = 10

	// botGeoImpossibleWindow is how close together two cross-tenant logins
	// from the same IP must be to trigger a geographic-impossibility signal.
	botGeoImpossibleWindow = 10 * time.Second
)

// BotDetectionConfig holds runtime-tunable thresholds for the detection engine.
// All fields have sensible defaults set in LoadBotDetectionConfig.
type BotDetectionConfig struct {
	// Enabled gates the entire engine. When false, Evaluate always returns
	// an allow result with score 0.
	Enabled bool

	// BlockThreshold is the composite score above which the request is blocked.
	// Default: 0.7
	BlockThreshold float64

	// ChallengeThreshold is the composite score above which a challenge is
	// issued instead of an outright block.
	// Default: 0.4
	ChallengeThreshold float64
}

// LoadBotDetectionConfig builds a BotDetectionConfig from environment variables
// using the same Viper-backed Config already loaded by LoadConfig().
// The three fields map directly to:
//
//	BOT_DETECTION_ENABLED          (bool,    default true)
//	BOT_DETECTION_THRESHOLD        (float64, default 0.7)
//	BOT_DETECTION_CHALLENGE_THRESHOLD (float64, default 0.4)
func LoadBotDetectionConfig(enabled bool, blockThreshold, challengeThreshold float64) BotDetectionConfig {
	cfg := BotDetectionConfig{
		Enabled:            enabled,
		BlockThreshold:     blockThreshold,
		ChallengeThreshold: challengeThreshold,
	}

	// Apply defaults when callers pass zero values.
	if cfg.BlockThreshold == 0 {
		cfg.BlockThreshold = 0.7
	}
	if cfg.ChallengeThreshold == 0 {
		cfg.ChallengeThreshold = 0.4
	}

	return cfg
}

// BotDetectionService is the core detection engine. It aggregates multiple
// independent signals into a single composite score and recommends an action.
//
// All Redis operations are best-effort: a Redis outage degrades detection
// quality (fail-open) but does not block legitimate traffic. This mirrors the
// fail-open posture used by the general RateLimitService.
type BotDetectionService struct {
	redis  *pkgredis.Client
	cfg    BotDetectionConfig
	logger *zap.Logger
}

// NewBotDetectionService creates a BotDetectionService.
// redis may be nil in test environments; when nil every Redis-backed signal
// returns score 0 and the engine still operates on in-process signals.
func NewBotDetectionService(
	redisClient *pkgredis.Client,
	cfg BotDetectionConfig,
	log *zap.Logger,
) *BotDetectionService {
	if log == nil {
		log = zap.NewNop()
	}
	return &BotDetectionService{
		redis:  redisClient,
		cfg:    cfg,
		logger: log,
	}
}

// EvaluateRequest is the primary entry point. It accepts the raw request
// signals, runs all detectors, and returns a BotDetectionResult.
//
// The username parameter is optional; pass an empty string for non-login paths.
// When non-empty it is used by the credential-velocity detector.
func (s *BotDetectionService) EvaluateRequest(
	ctx context.Context,
	ip string,
	userAgent string,
	headers map[string]string,
	path string,
	username string,
) models.BotDetectionResult {
	if !s.cfg.Enabled {
		return models.BotDetectionResult{
			Action:        models.BotActionAllow,
			ChallengeType: models.BotChallengeNone,
		}
	}

	signals := make([]models.BotSignal, 0, 6)

	// --- 1. Rate analysis ---
	if sig := s.analyseRate(ctx, ip); sig != nil {
		signals = append(signals, *sig)
	}

	// --- 2. User-agent analysis ---
	if sig := s.analyseUserAgent(userAgent); sig != nil {
		signals = append(signals, *sig)
	}

	// --- 3. IP reputation ---
	if sig := s.analyseIPReputation(ctx, ip); sig != nil {
		signals = append(signals, *sig)
	}

	// --- 4. Request fingerprint (header anomalies) ---
	if sig := s.analyseFingerprint(headers, path); sig != nil {
		signals = append(signals, *sig)
	}

	// --- 5. Credential velocity ---
	if username != "" {
		if sig := s.analyseCredentialVelocity(ctx, ip, username); sig != nil {
			signals = append(signals, *sig)
		}
	}

	// --- 6. Geographic impossibility ---
	if sig := s.analyseGeoImpossibility(ctx, ip, path); sig != nil {
		signals = append(signals, *sig)
	}

	score := combineScores(signals)
	action, challengeType := s.classify(score)

	return models.BotDetectionResult{
		IsBot:         action == models.BotActionBlock,
		Score:         score,
		Signals:       signals,
		Action:        action,
		ChallengeType: challengeType,
	}
}

// RecordLoginAttempt registers an in-flight login attempt for a given IP and
// username. Call this at the beginning of the login handler so that subsequent
// evaluations within the same window can see the accumulated state.
func (s *BotDetectionService) RecordLoginAttempt(ctx context.Context, ip, username string) {
	if s.redis == nil {
		return
	}
	rdb := s.redis.Redis()

	// Record the unique username in the credential-velocity set.
	credKey := botCredVelocityKeyPrefix + ip
	pipe := rdb.Pipeline()
	pipe.SAdd(ctx, credKey, username)
	pipe.Expire(ctx, credKey, botCredVelocityWindow)
	if _, err := pipe.Exec(ctx); err != nil {
		s.logger.Warn("bot_detection: failed to record login attempt",
			zap.String("ip", ip),
			zap.Error(err),
		)
	}

	// Stamp the last-login time for geo-impossibility checks.
	tsKey := botLastLoginKeyPrefix + ip
	if err := rdb.Set(ctx, tsKey, time.Now().UnixNano(), botGeoImpossibleWindow*2).Err(); err != nil {
		s.logger.Warn("bot_detection: failed to stamp last login time",
			zap.String("ip", ip),
			zap.Error(err),
		)
	}
}

// AddDatacenterIP inserts an IP or CIDR range into the datacenter reputation set.
// Used by the seeding / import pipeline; not called in the hot path.
func (s *BotDetectionService) AddDatacenterIP(ctx context.Context, ipOrCIDR string) error {
	if s.redis == nil {
		return nil
	}
	return s.redis.Redis().SAdd(ctx, IPSetDatacenter, ipOrCIDR).Err()
}

// AddTORExitNode inserts a TOR exit-node IP into the TOR reputation set.
func (s *BotDetectionService) AddTORExitNode(ctx context.Context, ip string) error {
	if s.redis == nil {
		return nil
	}
	return s.redis.Redis().SAdd(ctx, IPSetTOR, ip).Err()
}

// ---- private detectors ----

// analyseRate tracks request velocity per IP using a Redis sorted-set sliding
// window. Each member is "timestamp:nanotime" to support duplicate timestamps.
func (s *BotDetectionService) analyseRate(ctx context.Context, ip string) *models.BotSignal {
	if s.redis == nil {
		return nil
	}
	rdb := s.redis.Redis()
	key := botRateKeyPrefix + ip
	now := time.Now()
	windowStart := float64(now.Add(-botRateWindow).UnixNano())
	member := fmt.Sprintf("%d", now.UnixNano())

	pipe := rdb.Pipeline()
	// Remove stale entries outside the window.
	pipe.ZRemRangeByScore(ctx, key, "-inf", fmt.Sprintf("%f", windowStart))
	// Add the current request.
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now.UnixNano()), Member: member})
	// Count entries remaining inside the window.
	countCmd := pipe.ZCard(ctx, key)
	// Let the key expire naturally (window + small buffer).
	pipe.Expire(ctx, key, botRateWindow+10*time.Second)
	if _, err := pipe.Exec(ctx); err != nil {
		s.logger.Warn("bot_detection: rate analysis pipeline error",
			zap.String("ip", ip),
			zap.Error(err),
		)
		return nil
	}

	count := countCmd.Val()
	if count <= botRateThreshold {
		return nil
	}

	// Scale the score logarithmically: at 2×threshold score=0.9, saturates quickly.
	score := clampScore(0.5 + 0.4*(float64(count)/float64(botRateThreshold)-1))
	return &models.BotSignal{
		Type:   models.BotSignalRate,
		Score:  score,
		Detail: fmt.Sprintf("%d requests in last minute (threshold %d)", count, botRateThreshold),
	}
}

// analyseUserAgent checks the User-Agent against the known-bot pattern list.
func (s *BotDetectionService) analyseUserAgent(ua string) *models.BotSignal {
	// An absent User-Agent is itself suspicious on auth endpoints.
	if ua == "" {
		return &models.BotSignal{
			Type:   models.BotSignalUserAgent,
			Score:  0.6,
			Detail: "missing User-Agent header",
		}
	}

	for _, re := range models.KnownBotUAPatterns() {
		if re.MatchString(ua) {
			return &models.BotSignal{
				Type:   models.BotSignalUserAgent,
				Score:  0.95,
				Detail: fmt.Sprintf("User-Agent matches known bot pattern: %s", re.String()),
			}
		}
	}
	return nil
}

// analyseIPReputation checks whether the IP is a known TOR exit node or
// data-centre address using the Redis reputation sets.
func (s *BotDetectionService) analyseIPReputation(ctx context.Context, ip string) *models.BotSignal {
	if s.redis == nil {
		return nil
	}
	rdb := s.redis.Redis()

	// TOR exit node — high score; TOR is almost never a legitimate login source.
	torMember, err := rdb.SIsMember(ctx, IPSetTOR, ip).Result()
	if err == nil && torMember {
		return &models.BotSignal{
			Type:   models.BotSignalIPReputation,
			Score:  0.85,
			Detail: fmt.Sprintf("IP %s is a known TOR exit node", ip),
		}
	}

	// Data-centre IP — moderate score; also check CIDR membership.
	if s.isDatacenterIP(ctx, rdb, ip) {
		return &models.BotSignal{
			Type:   models.BotSignalIPReputation,
			Score:  0.55,
			Detail: fmt.Sprintf("IP %s originates from a known data-centre range", ip),
		}
	}

	return nil
}

// isDatacenterIP checks both exact membership and CIDR containment for the
// datacenter reputation set. CIDR entries are stored as strings like "10.0.0.0/8".
func (s *BotDetectionService) isDatacenterIP(ctx context.Context, rdb *redis.Client, ip string) bool {
	// Exact match first (fast path).
	exact, err := rdb.SIsMember(ctx, IPSetDatacenter, ip).Result()
	if err == nil && exact {
		return true
	}

	// Scan the set for CIDR entries and test containment.
	// This is done lazily; the set is expected to be small (<10k entries).
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	members, err := rdb.SMembers(ctx, IPSetDatacenter).Result()
	if err != nil {
		return false
	}
	for _, m := range members {
		if !strings.Contains(m, "/") {
			continue
		}
		_, cidr, err := net.ParseCIDR(m)
		if err != nil {
			continue
		}
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// analyseFingerprint examines request headers for anomalies that are common in
// automated clients but rare in real browsers.
func (s *BotDetectionService) analyseFingerprint(headers map[string]string, path string) *models.BotSignal {
	score := 0.0
	reasons := make([]string, 0, 3)

	// Real browsers always send Accept-Language.
	if _, ok := headers["Accept-Language"]; !ok {
		score += 0.25
		reasons = append(reasons, "missing Accept-Language")
	}

	// A browser navigating to a login page typically sets a Referer; its
	// absence is weakly suspicious on auth paths only.
	if strings.Contains(path, "/auth/") || strings.Contains(path, "/login") {
		if _, ok := headers["Referer"]; !ok {
			score += 0.15
			reasons = append(reasons, "missing Referer on auth path")
		}
	}

	// Real browsers send a rich Accept header. Minimalist clients often send
	// just "*/*" or "application/json".
	accept := headers["Accept"]
	if accept == "*/*" || accept == "application/json" {
		score += 0.15
		reasons = append(reasons, fmt.Sprintf("suspicious Accept header: %q", accept))
	}

	// Real browsers send sec-fetch-* headers (modern Chromium/Firefox).
	if _, ok := headers["Sec-Fetch-Site"]; !ok {
		score += 0.1
		reasons = append(reasons, "missing Sec-Fetch-Site")
	}

	if score == 0 {
		return nil
	}
	return &models.BotSignal{
		Type:   models.BotSignalFingerprint,
		Score:  clampScore(score),
		Detail: strings.Join(reasons, "; "),
	}
}

// analyseCredentialVelocity checks how many distinct usernames have been
// attempted from this IP within the credential-velocity window.
func (s *BotDetectionService) analyseCredentialVelocity(ctx context.Context, ip, _ string) *models.BotSignal {
	if s.redis == nil {
		return nil
	}
	key := botCredVelocityKeyPrefix + ip
	count, err := s.redis.Redis().SCard(ctx, key).Result()
	if err != nil {
		return nil
	}

	if count < botCredVelocityThreshold {
		return nil
	}

	score := clampScore(0.6 + 0.3*(float64(count)/float64(botCredVelocityThreshold)-1))
	return &models.BotSignal{
		Type:  models.BotSignalCredVelocity,
		Score: score,
		Detail: fmt.Sprintf(
			"%d unique usernames from IP %s in %.0f minutes (threshold %d)",
			count, ip, botCredVelocityWindow.Minutes(), botCredVelocityThreshold,
		),
	}
}

// analyseGeoImpossibility detects when the same IP makes rapid cross-tenant
// login attempts. Because tenant databases are isolated, a single IP hitting
// multiple tenants in quick succession is unusual for legitimate users but
// common in credential-stuffing runs that iterate over a tenant list.
//
// The detector uses the last-login timestamp stored by RecordLoginAttempt.
// If the timestamp is present and within botGeoImpossibleWindow we fire the
// signal, then update the stamp.
func (s *BotDetectionService) analyseGeoImpossibility(ctx context.Context, ip, path string) *models.BotSignal {
	// Only evaluate on login/auth paths to avoid false positives on API calls.
	if !strings.Contains(path, "/auth/") && !strings.Contains(path, "/login") {
		return nil
	}
	if s.redis == nil {
		return nil
	}

	key := botLastLoginKeyPrefix + ip
	tsNano, err := s.redis.Redis().Get(ctx, key).Int64()
	if errors.Is(err, redis.Nil) {
		// No prior record — not suspicious yet.
		return nil
	}
	if err != nil {
		return nil
	}

	elapsed := time.Since(time.Unix(0, tsNano))
	if elapsed > botGeoImpossibleWindow {
		return nil
	}

	return &models.BotSignal{
		Type:  models.BotSignalGeoImpossible,
		Score: 0.75,
		Detail: fmt.Sprintf(
			"IP %s made another login attempt only %dms after the previous one",
			ip, elapsed.Milliseconds(),
		),
	}
}

// ---- helpers ----

// combineScores merges individual signal scores using a weighted max + average
// blend. The algorithm avoids a single noisy signal from dominating while
// ensuring multiple weak signals can collectively cross thresholds.
//
// Formula: combined = max * 0.6 + avg * 0.4
func combineScores(signals []models.BotSignal) float64 {
	if len(signals) == 0 {
		return 0
	}
	var sum, maxScore float64
	for _, sig := range signals {
		sum += sig.Score
		if sig.Score > maxScore {
			maxScore = sig.Score
		}
	}
	avg := sum / float64(len(signals))
	return clampScore(maxScore*0.6 + avg*0.4)
}

// classify maps a composite score to an enforcement action.
func (s *BotDetectionService) classify(score float64) (models.BotDetectionAction, models.BotChallengeType) {
	switch {
	case score >= s.cfg.BlockThreshold:
		return models.BotActionBlock, models.BotChallengeNone
	case score >= s.cfg.ChallengeThreshold:
		// Choose challenge type: high-confidence signals warrant CAPTCHA;
		// lower-confidence signals use the lighter proof-of-work challenge.
		if score >= (s.cfg.BlockThreshold+s.cfg.ChallengeThreshold)/2 {
			return models.BotActionChallenge, models.BotChallengeCAPTCHA
		}
		return models.BotActionChallenge, models.BotChallengeProofOfWork
	default:
		return models.BotActionAllow, models.BotChallengeNone
	}
}

// clampScore ensures a value stays in [0.0, 1.0].
func clampScore(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

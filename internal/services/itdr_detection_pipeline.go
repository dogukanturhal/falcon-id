// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	pkgredis "github.com/dogukanturhal/falcon-id/pkg/redis"
)

// ITDRPipelineConfig holds all threshold values used by the detection pipeline.
// Values are loaded from the database at startup and can be updated at runtime
// via the detection-rules admin API.
type ITDRPipelineConfig struct {
	// ImpossibleTravel
	MaxSpeedKmh   float64
	MinDistanceKm float64

	// Credential stuffing
	StuffingThreshold  int
	StuffingWindowSecs int

	// MFA fatigue
	MFAMaxPrompts int
	MFAWindowSecs int

	// Compromised credential
	HIBPBaseURL string
}

// defaultPipelineConfig returns production-safe defaults matching the seeded
// detection rules in migration 154.
func defaultPipelineConfig() ITDRPipelineConfig {
	return ITDRPipelineConfig{
		MaxSpeedKmh:        500,
		MinDistanceKm:      50,
		StuffingThreshold:  20,
		StuffingWindowSecs: 300, // 5 minutes
		MFAMaxPrompts:      3,
		MFAWindowSecs:      300, // 5 minutes
		HIBPBaseURL:        "https://api.pwnedpasswords.com/range",
	}
}

// ITDRDetectionPipelineImpl is an exported identifier.
// ITDRDetectionPipeline is an exported identifier.
// ITDRDetectionPipeline is an exported identifier.
// ITDRDetectionPipeline is the core ITDR detection engine.  It runs a chain of
// independent detectors for each incoming event and emits ThreatSignals that
// are persisted via ITDRRepository.
//
// Each detector is designed to be fail-open: a transient error (e.g. Redis
// unavailable, HIBP API timeout) is logged but does not block the login flow.
type ITDRDetectionPipelineImpl struct {
	repo        *repositories.ITDRRepository
	redisClient *pkgredis.Client
	cfg         ITDRPipelineConfig
	httpClient  *http.Client
	logger      *zap.Logger
}

// NewITDRDetectionPipelineImpl is an exported identifier.
// NewITDRDetectionPipeline is an exported identifier.
// NewITDRDetectionPipeline is an exported identifier.
// NewITDRDetectionPipeline creates a new pipeline.  Pass nil for httpClient to
// use a default client with a sensible timeout.
func NewITDRDetectionPipelineImpl(
	repo *repositories.ITDRRepository,
	redisClient *pkgredis.Client,
	logger *zap.Logger,
) *ITDRDetectionPipelineImpl {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ITDRDetectionPipelineImpl{
		repo:        repo,
		redisClient: redisClient,
		cfg:         defaultPipelineConfig(),
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
		logger: logger,
	}
}

// SetConfig replaces the runtime configuration.  Call this after loading rules
// from the database to apply operator-configured thresholds.
func (p *ITDRDetectionPipelineImpl) SetConfig(cfg ITDRPipelineConfig) {
	p.cfg = cfg
}

// SetHTTPClient replaces the default HTTP client used for external API calls
// (e.g. HIBP).  Useful for testing.
func (p *ITDRDetectionPipelineImpl) SetHTTPClient(client *http.Client) {
	p.httpClient = client
}

// Run satisfies the ITDRDetectionPipeline interface defined in itdr_service.go.
// The concrete pipeline is event-driven (callers invoke ProcessLoginEvent et al.
// directly); this method is a no-op placeholder for interface compliance.
func (p *ITDRDetectionPipelineImpl) Run(_ context.Context) error {
	return nil
}

// =====================================================================
// Public entry points
// =====================================================================

// ProcessLoginEvent runs all applicable detectors for a login attempt and
// persists any resulting signals.  It returns the aggregate result containing
// all emitted signals.
//
// Errors from individual detectors are logged but do not abort the pipeline.
func (p *ITDRDetectionPipelineImpl) ProcessLoginEvent(
	ctx context.Context,
	event models.ITDRLoginEvent,
) (*models.ITDRDetectionResult, error) {
	result := &models.ITDRDetectionResult{}

	// 1. Credential stuffing burst (applies to failed logins only).
	if !event.Success && event.IPAddress != "" {
		sig, err := p.detectCredentialStuffingBurst(ctx, event)
		if err != nil {
			p.logger.Warn("itdr: credential stuffing detector error", zap.Error(err))
		} else if sig != nil {
			result.Signals = append(result.Signals, *sig)
		}
	}

	// 2. Impossible travel (applies to successful logins only when geo coords are available).
	if event.Success && event.UserID != nil && (event.GeoLat != 0 || event.GeoLon != 0) {
		sig, err := p.detectImpossibleTravel(ctx, event)
		if err != nil {
			p.logger.Warn("itdr: impossible travel detector error", zap.Error(err))
		} else if sig != nil {
			result.Signals = append(result.Signals, *sig)
		}
	}

	// 3. Compromised credential (applies to successful logins when a SHA-1 prefix is available).
	if event.Success && event.PasswordSHA1Prefix != "" {
		sig, err := p.detectCompromisedCredential(ctx, event)
		if err != nil {
			p.logger.Warn("itdr: compromised credential detector error", zap.Error(err))
		} else if sig != nil {
			result.Signals = append(result.Signals, *sig)
		}
	}

	// Persist all signals.
	for i := range result.Signals {
		if err := p.repo.CreateSignal(ctx, &result.Signals[i]); err != nil {
			p.logger.Error("itdr: failed to persist threat signal",
				zap.String("signal_type", string(result.Signals[i].SignalType)),
				zap.Error(err),
			)
		}
	}

	return result, nil
}

// ProcessMFAEvent evaluates MFA fatigue for a push notification event.
func (p *ITDRDetectionPipelineImpl) ProcessMFAEvent(
	ctx context.Context,
	event models.ITDRMFAEvent,
) (*models.ITDRDetectionResult, error) {
	result := &models.ITDRDetectionResult{}

	if !event.Success {
		sig, err := p.detectMFAFatigue(ctx, event)
		if err != nil {
			p.logger.Warn("itdr: mfa fatigue detector error", zap.Error(err))
		} else if sig != nil {
			result.Signals = append(result.Signals, *sig)
			if err := p.repo.CreateSignal(ctx, &result.Signals[0]); err != nil {
				p.logger.Error("itdr: failed to persist mfa fatigue signal", zap.Error(err))
			}
		}
	}

	return result, nil
}

// ProcessSessionEvent evaluates session anomaly detection.
func (p *ITDRDetectionPipelineImpl) ProcessSessionEvent(
	ctx context.Context,
	event models.ITDRSessionEvent,
) (*models.ITDRDetectionResult, error) {
	result := &models.ITDRDetectionResult{}

	sig, err := p.detectSessionAnomaly(ctx, event)
	if err != nil {
		p.logger.Warn("itdr: session anomaly detector error", zap.Error(err))
		return result, nil
	}
	if sig != nil {
		result.Signals = append(result.Signals, *sig)
		if err := p.repo.CreateSignal(ctx, &result.Signals[0]); err != nil {
			p.logger.Error("itdr: failed to persist session anomaly signal", zap.Error(err))
		}
	}

	return result, nil
}

// =====================================================================
// Detector implementations
// =====================================================================

// detectImpossibleTravel compares the geo-coordinates of the current login
// against the most-recent previously recorded geo-coordinates stored in Redis.
// If the implied travel speed exceeds MaxSpeedKmh, a high-severity signal is
// emitted.
//
// Coordinates are stored in Redis with a 24-hour TTL so the comparison window
// is bounded.
func (p *ITDRDetectionPipelineImpl) detectImpossibleTravel(
	ctx context.Context,
	event models.ITDRLoginEvent,
) (*models.ThreatSignal, error) {
	if event.UserID == nil {
		return nil, nil
	}

	key := p.geoKey(*event.UserID)
	rdb := p.redisClient.Redis()

	// Retrieve the previous location: "lat:lon:unix_timestamp".
	prev, err := rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		// No prior record — store current and return.
		p.storeGeoLocation(ctx, key, event.GeoLat, event.GeoLon, event.OccurredAt)
		return nil, nil
	}
	if err != nil {
		// Redis unavailable — fail-open.
		return nil, fmt.Errorf("detectImpossibleTravel: redis get: %w", err)
	}

	var prevLat, prevLon float64
	var prevTS int64
	if _, err := fmt.Sscanf(prev, "%f:%f:%d", &prevLat, &prevLon, &prevTS); err != nil {
		// Corrupted entry — overwrite and continue.
		p.storeGeoLocation(ctx, key, event.GeoLat, event.GeoLon, event.OccurredAt)
		return nil, nil //nolint:nilerr // intentional: corrupted entry is overwritten and processing continues without error
	}

	distanceKm := itdrHaversineKm(prevLat, prevLon, event.GeoLat, event.GeoLon)
	elapsedHours := event.OccurredAt.Sub(time.Unix(prevTS, 0)).Hours()

	// Update the stored location for future comparisons.
	p.storeGeoLocation(ctx, key, event.GeoLat, event.GeoLon, event.OccurredAt)

	// Skip if distance is below the minimum meaningful threshold (avoids
	// false positives from geo-IP imprecision within the same city).
	if distanceKm < p.cfg.MinDistanceKm {
		return nil, nil
	}

	// Avoid division-by-zero for events that are very close in time.
	if elapsedHours < 0.001 {
		elapsedHours = 0.001
	}
	speedKmh := distanceKm / elapsedHours

	if speedKmh <= p.cfg.MaxSpeedKmh {
		return nil, nil
	}

	sig := &models.ThreatSignal{
		SignalType: models.ThreatSignalTypeImpossibleTravel,
		Severity:   models.ThreatSignalSeverityHigh,
		UserID:     event.UserID,
		TenantID:   event.TenantID,
		Details: map[string]interface{}{
			"distance_km":     math.Round(distanceKm*10) / 10,
			"speed_kmh":       math.Round(speedKmh),
			"max_speed_kmh":   p.cfg.MaxSpeedKmh,
			"elapsed_hours":   math.Round(elapsedHours*100) / 100,
			"prev_lat":        prevLat,
			"prev_lon":        prevLon,
			"current_lat":     event.GeoLat,
			"current_lon":     event.GeoLon,
			"current_ip":      event.IPAddress,
			"prev_login_unix": prevTS,
		},
	}

	p.logger.Info("itdr: impossible travel detected",
		zap.String("user_id", event.UserID.String()),
		zap.Float64("speed_kmh", speedKmh),
		zap.Float64("distance_km", distanceKm),
	)

	return sig, nil
}

// detectCredentialStuffingBurst uses Redis INCR + EXPIRE to maintain a
// rolling-window counter of failed login attempts per IP address.  When the
// counter reaches the configured threshold a high-severity signal is emitted.
//
// The counter key carries a TTL equal to the window duration so the counter
// naturally resets after the window closes.
func (p *ITDRDetectionPipelineImpl) detectCredentialStuffingBurst(
	ctx context.Context,
	event models.ITDRLoginEvent,
) (*models.ThreatSignal, error) {
	key := p.stuffingKey(event.IPAddress)
	rdb := p.redisClient.Redis()

	count, err := rdb.Incr(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("detectCredentialStuffingBurst: incr: %w", err)
	}

	// Set or refresh the TTL on every increment so a continuous stream of
	// failures keeps the counter alive for the full window.
	ttl := time.Duration(p.cfg.StuffingWindowSecs) * time.Second
	if err := rdb.Expire(ctx, key, ttl).Err(); err != nil {
		// Non-fatal: the key will eventually expire naturally.
		p.logger.Warn("itdr: failed to set stuffing key TTL", zap.Error(err))
	}

	if count < int64(p.cfg.StuffingThreshold) {
		return nil, nil
	}

	// Emit exactly one signal per threshold crossing to avoid alert flooding.
	// We use the count modulo threshold so we fire at 20, 40, 60, … not every hit.
	if count%int64(p.cfg.StuffingThreshold) != 0 {
		return nil, nil
	}

	sig := &models.ThreatSignal{
		SignalType: models.ThreatSignalTypeCredentialStuffingBurst,
		Severity:   models.ThreatSignalSeverityHigh,
		TenantID:   event.TenantID,
		Details: map[string]interface{}{
			"ip_address":     event.IPAddress,
			"failed_count":   count,
			"threshold":      p.cfg.StuffingThreshold,
			"window_seconds": p.cfg.StuffingWindowSecs,
		},
	}

	p.logger.Info("itdr: credential stuffing burst detected",
		zap.String("ip", event.IPAddress),
		zap.Int64("failed_count", count),
	)

	return sig, nil
}

// detectMFAFatigue uses a Redis counter to track unapproved MFA push
// notifications per user within the configured window.  When the counter
// exceeds MFAMaxPrompts a medium-severity signal is emitted.
func (p *ITDRDetectionPipelineImpl) detectMFAFatigue(
	ctx context.Context,
	event models.ITDRMFAEvent,
) (*models.ThreatSignal, error) {
	key := p.mfaFatigueKey(event.UserID)
	rdb := p.redisClient.Redis()

	count, err := rdb.Incr(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("detectMFAFatigue: incr: %w", err)
	}

	ttl := time.Duration(p.cfg.MFAWindowSecs) * time.Second
	if err := rdb.Expire(ctx, key, ttl).Err(); err != nil {
		p.logger.Warn("itdr: failed to set mfa fatigue key TTL", zap.Error(err))
	}

	if count <= int64(p.cfg.MFAMaxPrompts) {
		return nil, nil
	}

	sig := &models.ThreatSignal{
		SignalType: models.ThreatSignalTypeMFAFatigue,
		Severity:   models.ThreatSignalSeverityMedium,
		UserID:     &event.UserID,
		TenantID:   &event.TenantID,
		Details: map[string]interface{}{
			"prompt_count":   count,
			"max_prompts":    p.cfg.MFAMaxPrompts,
			"window_seconds": p.cfg.MFAWindowSecs,
		},
	}

	p.logger.Info("itdr: mfa fatigue detected",
		zap.String("user_id", event.UserID.String()),
		zap.Int64("prompt_count", count),
	)

	return sig, nil
}

// detectSessionAnomaly compares the IP address and user-agent of the current
// request against the values recorded when the session was first established.
// A mismatch on either attribute generates a high-severity signal indicating
// a potential session hijack.
func (p *ITDRDetectionPipelineImpl) detectSessionAnomaly(
	_ context.Context,
	event models.ITDRSessionEvent,
) (*models.ThreatSignal, error) { //nolint:unparam // error return is always nil currently but kept for interface consistency
	ipChanged := event.CurrentIP != "" &&
		event.OriginalIP != "" &&
		event.CurrentIP != event.OriginalIP

	uaChanged := event.CurrentUserAgent != "" &&
		event.OriginalUserAgent != "" &&
		event.CurrentUserAgent != event.OriginalUserAgent

	if !ipChanged && !uaChanged {
		return nil, nil
	}

	details := map[string]interface{}{
		"session_id":         event.SessionID.String(),
		"ip_changed":         ipChanged,
		"user_agent_changed": uaChanged,
	}
	if ipChanged {
		details["original_ip"] = event.OriginalIP
		details["current_ip"] = event.CurrentIP
	}
	if uaChanged {
		details["original_user_agent"] = event.OriginalUserAgent
		details["current_user_agent"] = event.CurrentUserAgent
	}

	sig := &models.ThreatSignal{
		SignalType: models.ThreatSignalTypeSessionAnomaly,
		Severity:   models.ThreatSignalSeverityHigh,
		UserID:     &event.UserID,
		TenantID:   &event.TenantID,
		Details:    details,
	}

	p.logger.Info("itdr: session anomaly detected",
		zap.String("session_id", event.SessionID.String()),
		zap.Bool("ip_changed", ipChanged),
		zap.Bool("ua_changed", uaChanged),
	)

	return sig, nil
}

// detectCompromisedCredential checks whether the password's SHA-1 hash prefix
// appears in the HaveIBeenPwned (HIBP) k-anonymity dataset.
//
// Implementation follows the HIBP range API:
//  1. SHA-1 hash the password (hex-encoded, upper case).
//  2. Send the first 5 characters as a GET request to
//     api.pwnedpasswords.com/range/{prefix}.
//  3. Scan the response body for a suffix match.
//  4. A match means the exact hash appears in a known breach.
//
// The plaintext password is never sent over the network — only the 5-character
// prefix is transmitted.
func (p *ITDRDetectionPipelineImpl) detectCompromisedCredential(
	ctx context.Context,
	event models.ITDRLoginEvent,
) (*models.ThreatSignal, error) {
	// Use pre-computed SHA-1 prefix from the caller.  The full hash is never
	// stored inside the event; the caller must compute it and zero RawPassword
	// before constructing the ITDRLoginEvent.
	if event.PasswordSHA1Prefix == "" {
		return nil, nil
	}

	prefix := strings.ToUpper(event.PasswordSHA1Prefix)
	if len(prefix) < 5 {
		return nil, fmt.Errorf("detectCompromisedCredential: PasswordSHA1Prefix too short (%d chars)", len(prefix))
	}
	prefix = prefix[:5]

	// suffix is derived from the full hash stored separately in the event.
	// Since we only have the prefix here we cannot derive the suffix without
	// the full hash.  The caller must provide the full 40-char upper-case hex
	// SHA-1 hash via PasswordSHA1Prefix when it is longer than 5 chars, OR the
	// pipeline fetches ALL suffixes for the prefix and returns the count for
	// any match.  For now: require callers to pass the full 40-char hash in
	// PasswordSHA1Prefix so the suffix can be derived.
	if len(event.PasswordSHA1Prefix) != 40 {
		return nil, fmt.Errorf("detectCompromisedCredential: PasswordSHA1Prefix must be the full 40-char SHA-1 hex hash, got %d chars", len(event.PasswordSHA1Prefix))
	}
	suffix := strings.ToUpper(event.PasswordSHA1Prefix)[5:]

	url := p.cfg.HIBPBaseURL + "/" + prefix
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("detectCompromisedCredential: build request: %w", err)
	}
	req.Header.Set("User-Agent", "Falcon-ID-ITDR/1.0")
	req.Header.Set("Add-Padding", "true") // HIBP padding mode hides traffic patterns

	resp, err := p.httpClient.Do(req)
	if err != nil {
		// Network failure — fail-open: do not block the user.
		return nil, fmt.Errorf("detectCompromisedCredential: hibp request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("detectCompromisedCredential: hibp status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("detectCompromisedCredential: read body: %w", err)
	}

	pwned, breachCount := p.searchHIBPResponse(string(body), suffix)
	if !pwned {
		return nil, nil
	}

	sig := &models.ThreatSignal{
		SignalType: models.ThreatSignalTypeCompromisedCredential,
		Severity:   models.ThreatSignalSeverityCritical,
		UserID:     event.UserID,
		TenantID:   event.TenantID,
		Details: map[string]interface{}{
			"hash_prefix":  prefix,
			"breach_count": breachCount,
			"ip_address":   event.IPAddress,
		},
	}

	p.logger.Warn("itdr: compromised credential detected",
		zap.String("user_id", func() string {
			if event.UserID != nil {
				return event.UserID.String()
			}
			return authMethodUnknown
		}()),
		zap.Int("breach_count", breachCount),
	)

	return sig, nil
}

// =====================================================================
// Helpers
// =====================================================================

// searchHIBPResponse scans the HIBP range response body for the given suffix.
// Each line has the format "SUFFIX:COUNT" (upper-case hex).
// Returns (true, count) on a match, (false, 0) otherwise.
func (p *ITDRDetectionPipelineImpl) searchHIBPResponse(body, suffix string) (bool, int) {
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(parts[0], suffix) {
			var count int
			_, _ = fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &count)
			return true, count
		}
	}
	return false, 0
}

// storeGeoLocation persists the current geo-coordinates and timestamp in Redis
// with a 24-hour TTL.  Errors are logged but do not abort the caller.
func (p *ITDRDetectionPipelineImpl) storeGeoLocation(
	ctx context.Context,
	key string,
	lat, lon float64,
	at time.Time,
) {
	val := fmt.Sprintf("%f:%f:%d", lat, lon, at.Unix())
	if err := p.redisClient.Redis().Set(ctx, key, val, 24*time.Hour).Err(); err != nil {
		p.logger.Warn("itdr: failed to store geo location", zap.String("key", key), zap.Error(err))
	}
}

// itdrHaversineKm returns the great-circle distance in kilometres between two
// latitude/longitude coordinates using the Haversine formula.
//
// Note: degreesToRadians is declared in session_analytics_service.go and is
// package-scoped, so it is accessible here without redeclaration.
func itdrHaversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	return haversineDistance(lat1, lon1, lat2, lon2)
}

// =====================================================================
// Redis key helpers
// =====================================================================

const itdrKeyPrefix = "hexxlock:itdr"

func (p *ITDRDetectionPipelineImpl) geoKey(userID uuid.UUID) string {
	return fmt.Sprintf("%s:geo:%s", itdrKeyPrefix, userID.String())
}

func (p *ITDRDetectionPipelineImpl) stuffingKey(ip string) string {
	return fmt.Sprintf("%s:stuffing:%s", itdrKeyPrefix, ip)
}

func (p *ITDRDetectionPipelineImpl) mfaFatigueKey(userID uuid.UUID) string {
	return fmt.Sprintf("%s:mfa_fatigue:%s", itdrKeyPrefix, userID.String())
}

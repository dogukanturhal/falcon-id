// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	deviceValueUnknown    = "Unknown"
	devicePlatformAndroid = "Android"
	devicePlatformIOS     = "iOS"
	devicePlatformWindows = "Windows"
	devicePlatformMacOS   = "macOS"
	devicePlatformLinux   = "Linux"
	deviceBrowserEdge     = "Edge"
	deviceBrowserChrome   = "Chrome"
	deviceBrowserFirefox  = "Firefox"
	deviceBrowserSafari   = "Safari"
)

// deviceFingerprintRepo is the narrow interface consumed by DeviceFingerprintService.
// Accepting an interface (rather than the concrete struct) keeps the service
// testable via mocks without a real database.
type deviceFingerprintRepo interface {
	Upsert(ctx context.Context, rec *models.DeviceFingerprintRecord) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.DeviceFingerprintRecord, error)
	GetByHash(ctx context.Context, userID uuid.UUID, hash string) (*models.DeviceFingerprintRecord, error)
	ListByUser(ctx context.Context, userID, tenantID uuid.UUID) ([]models.DeviceFingerprintRecord, error)
	SetTrustLevel(ctx context.Context, id uuid.UUID, level models.FingerprintTrustLevel) error
	Delete(ctx context.Context, id uuid.UUID) error
	IsKnownHash(ctx context.Context, userID uuid.UUID, hash string) (bool, error)
}

// DeviceFingerprintService identifies and tracks device fingerprints to support
// adaptive MFA (skip MFA for known-trusted devices) and bot/anomaly detection.
//
// This service is separate from DeviceService: DeviceService manages the
// iam_user_devices table (user-facing browser-fingerprint trust), while
// DeviceFingerprintService manages iam_device_fingerprints, which stores richer
// signals (geo, browser version, screen resolution, timezone) and uses a
// structured trust-level enum suitable for risk-scoring pipelines.
type DeviceFingerprintService struct {
	repo deviceFingerprintRepo
}

// NewDeviceFingerprintService creates a new DeviceFingerprintService.
func NewDeviceFingerprintService(repo deviceFingerprintRepo) *DeviceFingerprintService {
	return &DeviceFingerprintService{repo: repo}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// IdentifyDevice resolves the fingerprint for a login request.
//
// It computes a SHA-256 hash from the stable, server-observable signals in
// input (User-Agent, Accept-Language primary token, X-Device-Timezone,
// X-Device-Screen), then upserts a row in iam_device_fingerprints.
//
// Returns:
//   - The upserted fingerprint record (never nil on success).
//   - isNew == true when the (userID, hash) pair was inserted for the first time.
func (s *DeviceFingerprintService) IdentifyDevice(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	input *models.DeviceFingerprintInput,
) (*models.DeviceFingerprintRecord, bool, error) {
	hash := computeFingerprintHash(input)
	platform, browser, browserVersion := parseUserAgentDetails(input.UserAgent)
	lang := primaryLanguage(input.Language)

	// Check whether this is a genuinely new fingerprint before upserting.
	// IsKnownHash uses the unique index and avoids a full row fetch on the
	// hot path (most logins are from known devices).
	known, err := s.repo.IsKnownHash(ctx, userID, hash)
	if err != nil {
		// Non-fatal: fall back to assuming unknown and continue.
		logger.Log.Warn("DeviceFingerprintService.IdentifyDevice: IsKnownHash failed — treating as unknown",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
	}
	isNew := !known

	rec := &models.DeviceFingerprintRecord{
		UserID:          userID,
		TenantID:        tenantID,
		FingerprintHash: hash,
		UserAgent:       input.UserAgent,
		Platform:        platform,
		Browser:         browser,
		BrowserVersion:  browserVersion,
		ScreenRes:       input.ScreenRes,
		Timezone:        input.Timezone,
		Language:        lang,
		IPAddress:       input.IPAddress,
		GeoCountry:      input.GeoCountry,
		GeoCity:         input.GeoCity,
		TrustLevel:      models.FingerprintTrustLevelNew,
	}

	if err := s.repo.Upsert(ctx, rec); err != nil {
		return nil, false, fmt.Errorf("DeviceFingerprintService.IdentifyDevice: %w", err)
	}

	logger.Log.Debug("Device fingerprint identified",
		zap.String("user_id", userID.String()),
		zap.String("fingerprint_hash", hash),
		zap.Bool("is_new", isNew),
		zap.String("trust_level", string(rec.TrustLevel)),
	)

	return rec, isNew, nil
}

// IdentifyDeviceFromRequest is a convenience wrapper that extracts
// DeviceFingerprintInput directly from an *http.Request.
//
// It reads:
//   - User-Agent header
//   - Accept-Language header (primary tag only)
//   - X-Device-Timezone header (optional, forwarded by the BFF)
//   - X-Device-Screen header (optional, forwarded by the BFF)
//   - Remote IP (X-Forwarded-For then RemoteAddr)
func (s *DeviceFingerprintService) IdentifyDeviceFromRequest(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	r *http.Request,
) (*models.DeviceFingerprintRecord, bool, error) {
	input := &models.DeviceFingerprintInput{
		UserAgent: r.UserAgent(),
		IPAddress: extractClientIP(r),
		Language:  r.Header.Get("Accept-Language"),
		ScreenRes: r.Header.Get("X-Device-Screen"),
		Timezone:  r.Header.Get("X-Device-Timezone"),
	}
	return s.IdentifyDevice(ctx, userID, tenantID, input)
}

// TrustDevice marks a fingerprint record as trusted (trust_level = "trusted").
// This is called after a successful MFA verification so that subsequent logins
// from the same device can skip the MFA challenge.
//
// SECURITY: The userID parameter is verified against the record's owner to
// prevent horizontal privilege escalation.
func (s *DeviceFingerprintService) TrustDevice(ctx context.Context, deviceID, userID uuid.UUID) error {
	rec, err := s.repo.GetByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("TrustDevice: %w", err)
	}
	if rec == nil {
		return fmt.Errorf("TrustDevice: device fingerprint not found")
	}
	if rec.UserID != userID {
		// Return a generic "not found" to avoid leaking existence of records
		// owned by other users.
		return fmt.Errorf("TrustDevice: device fingerprint not found")
	}

	if err := s.repo.SetTrustLevel(ctx, deviceID, models.FingerprintTrustLevelTrusted); err != nil {
		return fmt.Errorf("TrustDevice: %w", err)
	}

	logger.Log.Info("Device fingerprint trusted",
		zap.String("device_id", deviceID.String()),
		zap.String("user_id", userID.String()),
	)
	return nil
}

// ListUserDevices returns all fingerprint records for a user within a tenant,
// sorted by last_seen_at descending.
func (s *DeviceFingerprintService) ListUserDevices(
	ctx context.Context,
	userID, tenantID uuid.UUID,
) ([]models.DeviceFingerprintRecord, error) {
	records, err := s.repo.ListByUser(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListUserDevices: %w", err)
	}
	return records, nil
}

// RevokeDevice removes trust from a fingerprint record and deletes it from the
// store. Subsequent logins from the same device will be treated as "new".
//
// SECURITY: Only the owning user may revoke their own devices.
func (s *DeviceFingerprintService) RevokeDevice(ctx context.Context, deviceID, userID uuid.UUID) error {
	rec, err := s.repo.GetByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("RevokeDevice: %w", err)
	}
	if rec == nil {
		return fmt.Errorf("RevokeDevice: device fingerprint not found")
	}
	if rec.UserID != userID {
		return fmt.Errorf("RevokeDevice: device fingerprint not found")
	}

	if err := s.repo.Delete(ctx, deviceID); err != nil {
		return fmt.Errorf("RevokeDevice: %w", err)
	}

	logger.Log.Info("Device fingerprint revoked",
		zap.String("device_id", deviceID.String()),
		zap.String("user_id", userID.String()),
	)
	return nil
}

// IsKnownDevice performs a fast lookup to check whether the fingerprint hash
// derived from input is already associated with userID.
//
// This is the hot-path called by the adaptive MFA engine before deciding
// whether to challenge the user. It returns false on any error (fail-closed).
func (s *DeviceFingerprintService) IsKnownDevice(
	ctx context.Context,
	userID uuid.UUID,
	input *models.DeviceFingerprintInput,
) bool {
	hash := computeFingerprintHash(input)
	known, err := s.repo.IsKnownHash(ctx, userID, hash)
	if err != nil {
		logger.Log.Warn("IsKnownDevice: hash lookup failed — treating as unknown",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return false
	}
	return known
}

// IsKnownDeviceByHash is a variant of IsKnownDevice that accepts a pre-computed
// hash. Use this when the hash has already been computed earlier in the request
// lifecycle to avoid redundant hashing.
func (s *DeviceFingerprintService) IsKnownDeviceByHash(
	ctx context.Context,
	fingerprintHash string,
	userID uuid.UUID,
) bool {
	known, err := s.repo.IsKnownHash(ctx, userID, fingerprintHash)
	if err != nil {
		logger.Log.Warn("IsKnownDeviceByHash: lookup failed — treating as unknown",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return false
	}
	return known
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// computeFingerprintHash derives a deterministic SHA-256 hex digest from the
// stable, server-observable components of DeviceFingerprintInput.
//
// Only signals that are unlikely to change across sessions for the same physical
// device are included. IP address is intentionally excluded because it changes
// on mobile networks and behind NAT.
func computeFingerprintHash(input *models.DeviceFingerprintInput) string {
	platform, browser, browserVersion := parseUserAgentDetails(input.UserAgent)
	lang := primaryLanguage(input.Language)

	normalized := strings.Join([]string{
		strings.ToLower(strings.TrimSpace(input.UserAgent)),
		strings.ToLower(platform),
		strings.ToLower(browser),
		strings.ToLower(browserVersion),
		strings.ToLower(strings.TrimSpace(lang)),
		strings.TrimSpace(input.Timezone),
		strings.TrimSpace(input.ScreenRes),
	}, "|")

	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

// browserVersionRe extracts the major.minor version token after known browser
// identifiers in a User-Agent string.
var browserVersionRe = regexp.MustCompile(`(?:Chrome|Firefox|Safari|Edg|OPR)/(\d+(?:\.\d+)?)`)

// parseUserAgentDetails returns (platform, browser, browserVersion) derived
// from a User-Agent string.  The logic mirrors DeviceService.ParseUserAgent
// but also extracts the browser version number for the richer fingerprint.
func parseUserAgentDetails(ua string) (platform, browser, browserVersion string) {
	platform = deviceValueUnknown
	browser = deviceValueUnknown
	browserVersion = ""

	// Platform / OS detection — mobile-first to avoid Linux/macOS false matches.
	switch {
	case strings.Contains(ua, "Android"):
		platform = devicePlatformAndroid
	case strings.Contains(ua, "iPhone"):
		platform = devicePlatformIOS
	case strings.Contains(ua, "iPad"):
		platform = "iPadOS"
	case strings.Contains(ua, "Windows"):
		platform = devicePlatformWindows
	case strings.Contains(ua, "Mac OS X"):
		platform = devicePlatformMacOS
	case strings.Contains(ua, "Linux"):
		platform = devicePlatformLinux
	case strings.Contains(ua, "CrOS"):
		platform = "ChromeOS"
	}

	// Browser detection — order matters (Edge contains "Chrome").
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = deviceBrowserEdge
	case strings.Contains(ua, "OPR/"), strings.Contains(ua, "Opera"):
		browser = "Opera"
	case strings.Contains(ua, "Chrome/"):
		browser = deviceBrowserChrome
	case strings.Contains(ua, "Firefox/"):
		browser = deviceBrowserFirefox
	case strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome"):
		browser = deviceBrowserSafari
	}

	// Extract numeric version.
	if m := browserVersionRe.FindStringSubmatch(ua); len(m) == 2 {
		browserVersion = m[1]
	}

	return platform, browser, browserVersion
}

// primaryLanguage returns the first language tag from an Accept-Language value.
// For example "en-US,en;q=0.9" → "en-US".
func primaryLanguage(acceptLanguage string) string {
	if acceptLanguage == "" {
		return ""
	}
	parts := strings.SplitN(acceptLanguage, ",", 2)
	lang := strings.TrimSpace(parts[0])
	// Strip quality value if present: "en-US;q=0.9" → "en-US"
	if idx := strings.Index(lang, ";"); idx != -1 {
		lang = lang[:idx]
	}
	return strings.TrimSpace(lang)
}

// extractClientIP returns the best available client IP from the request,
// preferring X-Forwarded-For (set by APISIX gateway) over RemoteAddr.
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For may be a comma-separated list; take the leftmost entry.
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	// Strip port from RemoteAddr.
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

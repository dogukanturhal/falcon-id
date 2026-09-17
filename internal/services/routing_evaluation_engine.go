// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	routingDeviceDesktop = "desktop"
	routingDeviceUnknown = "unknown"
)

// RoutingRuleRepo fetches enhanced routing rules for evaluation.
type RoutingRuleRepo interface {
	ListEnabledByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.EnhancedIDPRoutingRule, error)
}

// NetworkZoneRepo fetches network zones for IP-to-zone resolution.
type NetworkZoneRepo interface {
	ListEnabledByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.NetworkZone, error)
}

// RoutingEvaluationRepo records evaluation audit entries.
type RoutingEvaluationRepo interface {
	Record(ctx context.Context, eval *models.RoutingEvaluation) error
}

// riskLevelOrdinal maps risk level strings to ordinal values for comparison.
// Higher ordinal = higher risk. Used for threshold-based matching where a rule
// with level 'medium' matches medium, high, and critical.
var riskLevelOrdinal = map[string]int{
	"low":      0,
	"medium":   1,
	"high":     2,
	"critical": 3,
}

// RoutingEvaluationEngine processes IDP routing rules in priority order,
// applying multi-criteria matching (email domain, device type, network zone,
// application context, risk levels, time windows) and returning the action
// for the first matching rule.
//
// Design principles:
//   - Rules evaluated in ascending priority order (lower number = higher priority)
//   - First match wins (short-circuit evaluation)
//   - NULL condition fields are wildcards (match any value)
//   - All non-null conditions in a rule must match (AND logic)
//   - Fail-open: if no rule matches, return "no match" (caller decides default)
//   - Risk matching is threshold-based: sign_in_risk_level='medium' matches medium+
//   - Time matching supports overnight windows and timezone-aware evaluation
type RoutingEvaluationEngine struct {
	ruleRepo  RoutingRuleRepo
	zoneRepo  NetworkZoneRepo
	auditRepo RoutingEvaluationRepo
}

// NewRoutingEvaluationEngine creates a new routing evaluation engine.
func NewRoutingEvaluationEngine(
	ruleRepo RoutingRuleRepo,
	zoneRepo NetworkZoneRepo,
	auditRepo RoutingEvaluationRepo,
) *RoutingEvaluationEngine {
	return &RoutingEvaluationEngine{
		ruleRepo:  ruleRepo,
		zoneRepo:  zoneRepo,
		auditRepo: auditRepo,
	}
}

// Evaluate processes routing rules for the given context and returns the result.
// This is the core HRD evaluation method called by DiscoverService.
func (e *RoutingEvaluationEngine) Evaluate(ctx context.Context, evalCtx *models.RoutingEvaluationContext) (*models.RoutingEvaluationResult, error) {
	start := time.Now()

	result := &models.RoutingEvaluationResult{
		Matched: false,
		Action:  models.RoutingActionAllow, // Default: allow local auth
	}

	// 1. Fetch all enabled rules for the tenant, ordered by priority
	rules, err := e.ruleRepo.ListEnabledByTenant(ctx, evalCtx.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch routing rules: %w", err)
	}

	// 2. Resolve network zone from client IP
	resolvedZone := evalCtx.NetworkZone
	if resolvedZone == "" && evalCtx.ClientIP != "" {
		resolvedZone = e.resolveNetworkZone(ctx, evalCtx.TenantID, evalCtx.ClientIP)
	}

	// 3. Resolve device type from User-Agent if not explicitly provided
	resolvedDevice := evalCtx.DeviceType
	if resolvedDevice == "" && evalCtx.UserAgent != "" {
		resolvedDevice = classifyDevice(evalCtx.UserAgent)
	}
	if resolvedDevice == "" {
		resolvedDevice = routingDeviceUnknown
	}

	// 4. Determine the evaluation time (use EvaluationTime if set, otherwise now)
	evalTime := evalCtx.EvaluationTime
	if evalTime.IsZero() {
		evalTime = time.Now()
	}

	// 5. Evaluate rules in priority order (first match wins)
	for i, rule := range rules {
		result.RulesEvaluated = i + 1

		if e.matchesRule(&rule, evalCtx.EmailDomain, resolvedDevice, resolvedZone,
			evalCtx.ApplicationID, evalCtx.SignInRiskLevel, evalCtx.UserRiskLevel, evalTime) {
			result.Matched = true
			result.Rule = &rules[i]
			result.Action = rule.Action
			providerID := rule.IdentityProviderID
			result.ProviderID = &providerID
			result.ProviderType = &rule.ProviderType
			result.ProviderName = &rule.ProviderDisplayName

			if logger.Log != nil {
				logger.Info("IdP routing rule matched",
					zap.String("tenant_id", evalCtx.TenantID.String()),
					zap.String("rule_id", rule.ID.String()),
					zap.Int("priority", rule.Priority),
					zap.String("action", string(rule.Action)),
					zap.String("email_domain", evalCtx.EmailDomain),
					zap.String("device_type", resolvedDevice),
					zap.String("network_zone", resolvedZone),
					zap.String("sign_in_risk", evalCtx.SignInRiskLevel),
					zap.String("user_risk", evalCtx.UserRiskLevel),
				)
			}
			break
		}
	}

	result.EvaluationMs = int(time.Since(start).Milliseconds())

	// 6. Record evaluation for audit/debugging
	e.recordEvaluation(ctx, evalCtx, result, resolvedDevice, resolvedZone)

	return result, nil
}

// matchesRule checks if a single rule matches the given evaluation context.
// All non-null conditions must match (AND logic). NULL conditions are wildcards.
func (e *RoutingEvaluationEngine) matchesRule(
	rule *models.EnhancedIDPRoutingRule,
	emailDomain, deviceType, networkZone string,
	applicationID *uuid.UUID,
	signInRiskLevel, userRiskLevel string,
	evalTime time.Time,
) bool {
	// Check email domain condition
	if rule.RuleType == "email_domain" && rule.RuleValue != "" {
		if !strings.EqualFold(rule.RuleValue, emailDomain) {
			return false
		}
	}

	// Check IP range condition: matching is handled by the network zone resolution below.
	// For raw IP range rules, we skip here (handled by legacy FindByEmailDomain).

	// Check device type condition (NULL = wildcard)
	if rule.DeviceType != nil && *rule.DeviceType != "" {
		if !strings.EqualFold(*rule.DeviceType, deviceType) {
			return false
		}
	}

	// Check network zone condition (NULL = wildcard)
	if rule.NetworkZone != nil && *rule.NetworkZone != "" {
		if !strings.EqualFold(*rule.NetworkZone, networkZone) {
			return false
		}
	}

	// Check application context condition (NULL = wildcard)
	if rule.ApplicationID != nil && *rule.ApplicationID != uuid.Nil {
		if applicationID == nil || *applicationID != *rule.ApplicationID {
			return false
		}
	}

	// Check sign-in risk level condition (NULL = wildcard)
	// Threshold-based: rule's level acts as a minimum threshold
	if rule.SignInRiskLevel != nil && *rule.SignInRiskLevel != "" {
		if !matchesRiskLevel(*rule.SignInRiskLevel, signInRiskLevel) {
			return false
		}
	}

	// Check user risk level condition (NULL = wildcard)
	// Threshold-based: rule's level acts as a minimum threshold
	if rule.UserRiskLevel != nil && *rule.UserRiskLevel != "" {
		if !matchesRiskLevel(*rule.UserRiskLevel, userRiskLevel) {
			return false
		}
	}

	// Check time window condition (NULL = wildcard)
	if rule.TimeStart != nil && rule.TimeEnd != nil && *rule.TimeStart != "" && *rule.TimeEnd != "" {
		if !matchesTimeWindow(*rule.TimeStart, *rule.TimeEnd, rule.Timezone, evalTime) {
			return false
		}
	}

	// Check day-of-week condition (NULL/empty = wildcard)
	if len(rule.DaysOfWeek) > 0 {
		if !matchesDayOfWeek(rule.DaysOfWeek, rule.Timezone, evalTime) {
			return false
		}
	}

	return true
}

// matchesRiskLevel checks if the actual risk level meets or exceeds the required
// threshold. A rule requiring 'medium' matches actual levels of medium, high, or
// critical. Returns false if the actual level is empty or unrecognized (fail-closed
// for missing risk data -- if risk assessment hasn't run, risk-conditioned rules
// won't match).
func matchesRiskLevel(requiredLevel, actualLevel string) bool {
	if actualLevel == "" {
		return false
	}

	requiredOrd, reqOk := riskLevelOrdinal[strings.ToLower(requiredLevel)]
	actualOrd, actOk := riskLevelOrdinal[strings.ToLower(actualLevel)]

	if !reqOk || !actOk {
		return false
	}

	return actualOrd >= requiredOrd
}

// matchesTimeWindow checks if the given time falls within the specified time window.
// Supports overnight windows (e.g., time_start=22:00, time_end=06:00 means 10 PM to 6 AM).
// The time is evaluated in the rule's configured timezone (defaults to UTC).
//
// Time format expected: "HH:MM:SS" or "HH:MM" (parsed as "15:04:05" or "15:04").
func matchesTimeWindow(startStr, endStr string, tz *string, evalTime time.Time) bool {
	// Resolve timezone
	loc := time.UTC
	if tz != nil && *tz != "" {
		parsed, err := time.LoadLocation(*tz)
		if err != nil {
			// Invalid timezone: fail-closed (rule doesn't match)
			if logger.Log != nil {
				logger.Warn("Invalid timezone in routing rule, rule will not match",
					zap.String("timezone", *tz),
					zap.Error(err),
				)
			}
			return false
		}
		loc = parsed
	}

	// Convert evaluation time to the rule's timezone
	localTime := evalTime.In(loc)

	// Parse start and end times
	startTime, err := parseTimeOfDay(startStr)
	if err != nil {
		return false
	}
	endTime, err := parseTimeOfDay(endStr)
	if err != nil {
		return false
	}

	// Extract the time-of-day from the evaluation time as seconds since midnight
	currentSeconds := localTime.Hour()*3600 + localTime.Minute()*60 + localTime.Second()
	startSeconds := startTime.hour*3600 + startTime.minute*60 + startTime.second
	endSeconds := endTime.hour*3600 + endTime.minute*60 + endTime.second

	if startSeconds <= endSeconds {
		// Normal range (e.g., 09:00 to 17:00)
		return currentSeconds >= startSeconds && currentSeconds < endSeconds
	}

	// Overnight range (e.g., 22:00 to 06:00)
	// Matches if current time is >= start OR < end
	return currentSeconds >= startSeconds || currentSeconds < endSeconds
}

// timeOfDay represents a parsed time of day without date component.
type timeOfDay struct {
	hour   int
	minute int
	second int
}

// parseTimeOfDay parses a time string in "HH:MM:SS" or "HH:MM" format.
func parseTimeOfDay(s string) (timeOfDay, error) {
	// Try HH:MM:SS first
	t, err := time.Parse("15:04:05", s)
	if err == nil {
		return timeOfDay{hour: t.Hour(), minute: t.Minute(), second: t.Second()}, nil
	}

	// Try HH:MM
	t, err = time.Parse("15:04", s)
	if err == nil {
		return timeOfDay{hour: t.Hour(), minute: t.Minute(), second: 0}, nil
	}

	return timeOfDay{}, fmt.Errorf("invalid time format %q: expected HH:MM:SS or HH:MM", s)
}

// matchesDayOfWeek checks if the current day of the week (in the rule's timezone)
// is in the allowed days list. Days follow Go's time.Weekday() convention:
// 0=Sunday, 1=Monday, ..., 6=Saturday.
func matchesDayOfWeek(allowedDays []int64, tz *string, evalTime time.Time) bool {
	// Resolve timezone
	loc := time.UTC
	if tz != nil && *tz != "" {
		parsed, err := time.LoadLocation(*tz)
		if err != nil {
			// Invalid timezone: fail-closed
			return false
		}
		loc = parsed
	}

	localTime := evalTime.In(loc)
	currentDay := int64(localTime.Weekday())

	for _, day := range allowedDays {
		if day == currentDay {
			return true
		}
	}

	return false
}

// resolveNetworkZone determines which network zone the client IP belongs to.
func (e *RoutingEvaluationEngine) resolveNetworkZone(ctx context.Context, tenantID uuid.UUID, clientIP string) string {
	if e.zoneRepo == nil {
		return routingDeviceUnknown
	}

	zones, err := e.zoneRepo.ListEnabledByTenant(ctx, tenantID)
	if err != nil {
		if logger.Log != nil {
			logger.Warn("Failed to fetch network zones for routing evaluation",
				zap.Error(err),
				zap.String("tenant_id", tenantID.String()),
			)
		}
		return routingDeviceUnknown
	}

	for _, zone := range zones {
		if zone.ContainsIP(clientIP) {
			return zone.ZoneType
		}
	}

	return "external" // Default: unrecognized IPs are external
}

// classifyDevice determines device type from the User-Agent string.
// This is a simplified classifier -- production systems should use a proper
// device detection library (e.g., ua-parser, device-detector).
func classifyDevice(userAgent string) string {
	ua := strings.ToLower(userAgent)

	// Mobile detection patterns
	mobilePatterns := []string{"iphone", "android", "mobile", "ipod", "windows phone", "blackberry"}
	for _, pattern := range mobilePatterns {
		if strings.Contains(ua, pattern) {
			// Distinguish tablet from mobile
			if strings.Contains(ua, "ipad") || (strings.Contains(ua, "android") && !strings.Contains(ua, "mobile")) {
				return "tablet"
			}
			return "mobile"
		}
	}

	// Tablet detection (iPad handled above, but catch others)
	tabletPatterns := []string{"ipad", "tablet", "kindle", "silk"}
	for _, pattern := range tabletPatterns {
		if strings.Contains(ua, pattern) {
			return "tablet"
		}
	}

	// If it has a known desktop browser identifier, it is desktop
	desktopPatterns := []string{"windows nt", "macintosh", "linux x86_64", "cros"}
	for _, pattern := range desktopPatterns {
		if strings.Contains(ua, pattern) {
			return routingDeviceDesktop
		}
	}

	return routingDeviceUnknown
}

// recordEvaluation writes an audit log entry for the routing evaluation.
func (e *RoutingEvaluationEngine) recordEvaluation(
	_ context.Context,
	evalCtx *models.RoutingEvaluationContext,
	result *models.RoutingEvaluationResult,
	deviceType, networkZone string,
) {
	if e.auditRepo == nil {
		return
	}

	eval := &models.RoutingEvaluation{
		TenantID:       evalCtx.TenantID,
		EmailDomain:    routingStrPtr(evalCtx.EmailDomain),
		DeviceType:     routingStrPtr(deviceType),
		NetworkZone:    routingStrPtr(networkZone),
		ClientIP:       routingStrPtr(evalCtx.ClientIP),
		ApplicationID:  evalCtx.ApplicationID,
		Matched:        result.Matched,
		RulesEvaluated: result.RulesEvaluated,
		EvaluationMs:   &result.EvaluationMs,
	}

	if result.Matched && result.Rule != nil {
		ruleID := result.Rule.ID
		eval.RuleID = &ruleID
		actionStr := string(result.Action)
		eval.ActionTaken = &actionStr
		eval.ProviderID = result.ProviderID
	}

	// Non-blocking: fire and forget. Evaluation audit is best-effort.
	go func() { //nolint:gosec // goroutine must outlive request context
		if err := e.auditRepo.Record(context.Background(), eval); err != nil {
			if logger.Log != nil {
				logger.Warn("Failed to record routing evaluation audit",
					zap.Error(err),
					zap.String("tenant_id", evalCtx.TenantID.String()),
				)
			}
		}
	}()
}

func routingStrPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

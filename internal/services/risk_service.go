// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/clientctx"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

const (
	// NewDeviceWeight is an exported identifier.
	NewDeviceWeight = 30
	// UnusualTimeWeight is an exported identifier.
	UnusualTimeWeight = 20
	// MultipleFailedAttemptsWeight is an exported identifier.
	MultipleFailedAttemptsWeight = 40
	// ImpossibleTravelWeight is an exported identifier.
	ImpossibleTravelWeight = 50
	// NewLocationWeight is an exported identifier.
	NewLocationWeight = 25
	// FirstFederationWeight is an exported identifier.
	FirstFederationWeight = 20

	// FailedAttemptsWindow is an exported identifier.
	FailedAttemptsWindow = 15 * time.Minute
	// RecentSignalsWindow is an exported identifier.
	RecentSignalsWindow = 24 * time.Hour

	// MaxFailedAttemptsForHighRisk is an exported identifier.
	MaxFailedAttemptsForHighRisk = 5
)

// RiskService is an exported type.
type RiskService struct {
	riskRepo     *repositories.RiskRepository
	deviceRepo   *repositories.DeviceRepository
	auditService *AuditService
}

// NewRiskService is an exported function.
func NewRiskService(
	riskRepo *repositories.RiskRepository,
	deviceRepo *repositories.DeviceRepository,
	auditService *AuditService,
) *RiskService {
	return &RiskService{
		riskRepo:     riskRepo,
		deviceRepo:   deviceRepo,
		auditService: auditService,
	}
}

// defaultMFAByLevel returns true when the tenant's per-level default-MFA
// toggles say a login at this risk level must challenge MFA, even without
// a matching iam_risk_policies row.
//
// Without this layer, RequiresMFA only fires when a tenant has explicitly
// configured an iam_risk_policies row with `actions: {"require_mfa": true}`.
// Most tenants don't, so a high-risk login (impossible travel + new device)
// would proceed with no MFA. The default closes the gap.
//
// Per-tenant escape hatches: flip default_mfa_at_medium / default_mfa_at_high
// to false on iam_risk_thresholds. Nil thresholds row falls back to true
// (matches the migration default and the GetThresholds-returns-defaults path).
func defaultMFAByLevel(level models.RiskLevel, thresholds *models.RiskThreshold) bool {
	defaultAtMedium := true
	defaultAtHigh := true
	if thresholds != nil {
		defaultAtMedium = thresholds.DefaultMFAAtMedium
		defaultAtHigh = thresholds.DefaultMFAAtHigh
	}
	switch level {
	case models.RiskLevelHigh, models.RiskLevelCritical:
		return defaultAtHigh
	case models.RiskLevelMedium:
		return defaultAtMedium
	}
	return false
}

// AssessLoginRisk performs risk assessment for a login attempt
func (s *RiskService) AssessLoginRisk(ctx context.Context, riskCtx *models.RiskContext) (*models.RiskAssessment, error) {
	assessment := &models.RiskAssessment{
		TotalScore: 0,
		Level:      models.RiskLevelLow,
		Signals:    []models.RiskSignal{},
		Actions:    []models.RiskAction{},
	}

	// Get thresholds
	thresholds, err := s.riskRepo.GetThresholds(ctx, riskCtx.TenantID)
	if err != nil {
		logger.Error("Failed to get risk thresholds", zap.Error(err))
		// Use defaults
		thresholds = &models.RiskThreshold{
			LowThreshold:      20,
			MediumThreshold:   50,
			HighThreshold:     75,
			CriticalThreshold: 90,
		}
	}

	// Check for new device
	if riskCtx.IsNewDevice {
		signal := s.createSignal(riskCtx, models.RiskSignalNewDevice, NewDeviceWeight,
			map[string]interface{}{"reason": "First login from this device"})
		assessment.Signals = append(assessment.Signals, signal)
		assessment.TotalScore += NewDeviceWeight
	}

	// Check for unusual login time
	if s.isUnusualTime(riskCtx.LoginTime) {
		signal := s.createSignal(riskCtx, models.RiskSignalUnusualTime, UnusualTimeWeight,
			map[string]interface{}{"login_hour": riskCtx.LoginTime.Hour()})
		assessment.Signals = append(assessment.Signals, signal)
		assessment.TotalScore += UnusualTimeWeight
	}

	// Check for multiple failed attempts
	failedCount, err := s.riskRepo.CountFailedAttempts(ctx, riskCtx.UserID, time.Now().Add(-FailedAttemptsWindow))
	if err != nil {
		logger.Error("Failed to count failed attempts", zap.Error(err))
	} else if failedCount > 0 {
		score := int(math.Min(float64(failedCount*10), float64(MultipleFailedAttemptsWeight)))
		signal := s.createSignal(riskCtx, models.RiskSignalMultipleFailedAttempts, score,
			map[string]interface{}{"failed_count": failedCount, "window_minutes": 15})
		assessment.Signals = append(assessment.Signals, signal)
		assessment.TotalScore += score

		if failedCount >= MaxFailedAttemptsForHighRisk {
			riskCtx.FailedAttempts = failedCount
		}
	}

	// Check for impossible travel (if we have last login info)
	if riskCtx.LastLoginIP != nil && riskCtx.LastLoginTime != nil {
		if s.isImpossibleTravel(riskCtx) {
			signal := s.createSignal(riskCtx, models.RiskSignalImpossibleTravel, ImpossibleTravelWeight,
				map[string]interface{}{
					"current_ip":      riskCtx.IPAddress,
					"last_ip":         *riskCtx.LastLoginIP,
					"time_since_last": time.Since(*riskCtx.LastLoginTime).String(),
				})
			assessment.Signals = append(assessment.Signals, signal)
			assessment.TotalScore += ImpossibleTravelWeight
		}
	}

	// Check for first-time SSO federation
	if riskCtx.IsFirstFederation {
		signal := s.createSignal(riskCtx, models.RiskSignalFirstFederation, FirstFederationWeight,
			map[string]interface{}{
				"reason":       "First login via SSO federation",
				"auth_method":  riskCtx.AuthMethod,
				"sso_provider": riskCtx.SSOProvider,
			})
		assessment.Signals = append(assessment.Signals, signal)
		assessment.TotalScore += FirstFederationWeight
	}

	// Cap score at 100
	if assessment.TotalScore > 100 {
		assessment.TotalScore = 100
	}

	// Determine risk level
	assessment.Level = s.getRiskLevel(assessment.TotalScore, thresholds)

	// Get policies and determine actions
	policies, err := s.riskRepo.GetPolicies(ctx, riskCtx.TenantID)
	if err != nil {
		logger.Error("Failed to get risk policies", zap.Error(err))
	} else {
		s.applyPolicies(assessment, policies)
	}

	// Apply default actions based on thresholds
	if thresholds != nil {
		if assessment.TotalScore >= thresholds.CriticalThreshold && thresholds.AutoBlockOnCritical {
			assessment.Blocked = true
			assessment.BlockReason = "Critical risk score exceeded threshold"
		}
	}

	// Set RequiresMFA if any action requires it (from policy match)
	for _, action := range assessment.Actions {
		if action.Type == "require_mfa" {
			assessment.RequiresMFA = true
			break
		}
	}

	// Tier-1 default-MFA enforcement (Slice F). See defaultMFAByLevel.
	if !assessment.RequiresMFA && defaultMFAByLevel(assessment.Level, thresholds) {
		assessment.RequiresMFA = true
	}

	// Store signals
	for i := range assessment.Signals {
		if err := s.riskRepo.CreateSignal(ctx, &assessment.Signals[i]); err != nil {
			logger.Error("Failed to store risk signal", zap.Error(err))
		}
	}

	logger.Info("Risk assessment completed",
		zap.String("user_id", riskCtx.UserID.String()),
		zap.Int("total_score", assessment.TotalScore),
		zap.String("level", string(assessment.Level)),
		zap.Int("signals_count", len(assessment.Signals)),
		zap.Bool("requires_mfa", assessment.RequiresMFA),
		zap.Bool("blocked", assessment.Blocked),
	)

	return assessment, nil
}

func (s *RiskService) createSignal(ctx *models.RiskContext, signalType models.RiskSignalType, score int, details map[string]interface{}) models.RiskSignal {
	return models.RiskSignal{
		ID:          uuid.New(),
		UserID:      ctx.UserID,
		SignalType:  signalType,
		RiskScore:   score,
		IPAddress:   &ctx.IPAddress,
		UserAgent:   &ctx.UserAgent,
		AuthMethod:  ctx.AuthMethod,
		SSOProvider: ctx.SSOProvider,
		Details:     details,
		CreatedAt:   time.Now(),
	}
}

func (s *RiskService) isUnusualTime(loginTime time.Time) bool {
	hour := loginTime.Hour()
	// Consider 1 AM - 5 AM as unusual hours
	return hour >= 1 && hour <= 5
}

func (s *RiskService) isImpossibleTravel(ctx *models.RiskContext) bool {
	if ctx.LastLoginIP == nil || ctx.LastLoginTime == nil {
		return false
	}

	// If the IPs are the same, no impossible travel
	if ctx.IPAddress == *ctx.LastLoginIP {
		return false
	}

	// If more than 24 hours have passed, not impossible travel
	timeSinceLastLogin := time.Since(*ctx.LastLoginTime)
	if timeSinceLastLogin > 24*time.Hour {
		return false
	}

	// Simple heuristic: if different IP and less than 1 hour, could be suspicious
	// In a real implementation, you would use IP geolocation to calculate distance
	// and determine if travel time is physically impossible
	if timeSinceLastLogin < 1*time.Hour {
		// Different IP within 1 hour - potentially suspicious
		return true
	}

	return false
}

func (s *RiskService) getRiskLevel(score int, thresholds *models.RiskThreshold) models.RiskLevel {
	if thresholds == nil {
		// Default thresholds
		switch {
		case score >= 90:
			return models.RiskLevelCritical
		case score >= 75:
			return models.RiskLevelHigh
		case score >= 50:
			return models.RiskLevelMedium
		}
		return models.RiskLevelLow
	}

	switch {
	case score >= thresholds.CriticalThreshold:
		return models.RiskLevelCritical
	case score >= thresholds.HighThreshold:
		return models.RiskLevelHigh
	case score >= thresholds.MediumThreshold:
		return models.RiskLevelMedium
	}
	return models.RiskLevelLow
}

func (s *RiskService) applyPolicies(assessment *models.RiskAssessment, policies []models.RiskPolicy) {
	for _, policy := range policies {
		if !policy.IsActive {
			continue
		}

		if s.policyMatches(assessment, &policy) {
			s.applyPolicyActions(assessment, &policy)
		}
	}
}

func (s *RiskService) policyMatches(assessment *models.RiskAssessment, policy *models.RiskPolicy) bool {
	// Check min_risk_score condition
	if minScore, ok := policy.Conditions["min_risk_score"].(float64); ok {
		if assessment.TotalScore < int(minScore) {
			return false
		}
	}

	// Check signal_types condition
	if signalTypes, ok := policy.Conditions["signal_types"].([]interface{}); ok {
		hasMatchingSignal := false
		for _, st := range signalTypes {
			signalType, ok := st.(string)
			if !ok {
				continue
			}
			for _, signal := range assessment.Signals {
				if string(signal.SignalType) == signalType {
					hasMatchingSignal = true
					break
				}
			}
			if hasMatchingSignal {
				break
			}
		}
		if !hasMatchingSignal && len(signalTypes) > 0 {
			return false
		}
	}

	// Check auth_methods condition
	if authMethods, ok := policy.Conditions["auth_methods"].([]interface{}); ok && len(authMethods) > 0 {
		// If policy specifies auth_methods, check if any signal matches
		hasMatchingMethod := false
		for _, method := range authMethods {
			methodStr, _ := method.(string)
			for _, signal := range assessment.Signals {
				if signal.AuthMethod == methodStr {
					hasMatchingMethod = true
					break
				}
			}
			if hasMatchingMethod {
				break
			}
		}
		if !hasMatchingMethod {
			return false
		}
	}

	return true
}

func (s *RiskService) applyPolicyActions(assessment *models.RiskAssessment, policy *models.RiskPolicy) {
	if requireMFA, ok := policy.Actions["require_mfa"].(bool); ok && requireMFA {
		assessment.Actions = append(assessment.Actions, models.RiskAction{
			Type:        "require_mfa",
			Description: "Multi-factor authentication required",
			PolicyID:    policy.ID.String(),
		})
	}

	if block, ok := policy.Actions["block"].(bool); ok && block {
		assessment.Blocked = true
		assessment.BlockReason = fmt.Sprintf("Blocked by policy: %s", policy.Name)
		assessment.Actions = append(assessment.Actions, models.RiskAction{
			Type:        "block",
			Description: fmt.Sprintf("Login blocked by policy: %s", policy.Name),
			PolicyID:    policy.ID.String(),
		})
	}

	if notifyAdmin, ok := policy.Actions["notify_admin"].(bool); ok && notifyAdmin {
		assessment.Actions = append(assessment.Actions, models.RiskAction{
			Type:        "notify_admin",
			Description: "Administrator notification triggered",
			PolicyID:    policy.ID.String(),
		})
	}

	if sendEmail, ok := policy.Actions["send_email_notification"].(bool); ok && sendEmail {
		assessment.Actions = append(assessment.Actions, models.RiskAction{
			Type:        "send_email",
			Description: "Email notification sent to user",
			PolicyID:    policy.ID.String(),
		})
	}

	// Handle delay_seconds action - can be a number or bool
	if delayValue, ok := policy.Actions["delay_seconds"]; ok {
		var delaySeconds int
		switch v := delayValue.(type) {
		case float64:
			delaySeconds = int(v)
		case int:
			delaySeconds = v
		case bool:
			if v {
				delaySeconds = 5 // default delay
			}
		}
		if delaySeconds > 0 {
			assessment.DelaySeconds = delaySeconds
			assessment.Actions = append(assessment.Actions, models.RiskAction{
				Type:        "delay",
				Description: fmt.Sprintf("Login delayed by %d seconds", delaySeconds),
				PolicyID:    policy.ID.String(),
			})
		}
	}
}

// GetPolicies returns all risk policies for a tenant
func (s *RiskService) GetPolicies(ctx context.Context, tenantID uuid.UUID) ([]models.RiskPolicy, error) {
	return s.riskRepo.GetAllPolicies(ctx, tenantID)
}

// GetPolicyByID returns a risk policy by ID
func (s *RiskService) GetPolicyByID(ctx context.Context, id uuid.UUID) (*models.RiskPolicy, error) {
	return s.riskRepo.GetPolicyByID(ctx, id)
}

// CreatePolicy creates a new risk policy
func (s *RiskService) CreatePolicy(ctx context.Context, tenantID uuid.UUID, req *models.CreateRiskPolicyRequest) (*models.RiskPolicy, error) {
	policy := &models.RiskPolicy{
		TenantID:   tenantID,
		Name:       req.Name,
		Conditions: req.Conditions,
		Actions:    req.Actions,
		Priority:   req.Priority,
		IsActive:   req.IsActive,
	}

	if req.Description != "" {
		policy.Description = &req.Description
	}

	if err := s.riskRepo.CreatePolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to create policy: %w", err)
	}

	logger.Info("Risk policy created",
		zap.String("policy_id", policy.ID.String()),
		zap.String("name", policy.Name),
	)

	return policy, nil
}

// UpdatePolicy updates a risk policy
func (s *RiskService) UpdatePolicy(ctx context.Context, id uuid.UUID, req *models.UpdateRiskPolicyRequest) (*models.RiskPolicy, error) {
	policy, err := s.riskRepo.GetPolicyByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("UpdatePolicy: %w", err)
	}
	if policy == nil {
		return nil, fmt.Errorf("policy not found")
	}

	if req.Name != nil {
		policy.Name = *req.Name
	}
	if req.Description != nil {
		policy.Description = req.Description
	}
	if req.Conditions != nil {
		policy.Conditions = req.Conditions
	}
	if req.Actions != nil {
		policy.Actions = req.Actions
	}
	if req.Priority != nil {
		policy.Priority = *req.Priority
	}
	if req.IsActive != nil {
		policy.IsActive = *req.IsActive
	}

	if err := s.riskRepo.UpdatePolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}

	return policy, nil
}

// DeletePolicy deletes a risk policy
func (s *RiskService) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	return s.riskRepo.DeletePolicy(ctx, id)
}

// GetThresholds returns risk thresholds for a tenant
func (s *RiskService) GetThresholds(ctx context.Context, tenantID uuid.UUID) (*models.RiskThreshold, error) {
	thresholds, err := s.riskRepo.GetThresholds(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetThresholds: %w", err)
	}

	// Return defaults if not found
	if thresholds == nil {
		thresholds = &models.RiskThreshold{
			TenantID:              tenantID,
			LowThreshold:          20,
			MediumThreshold:       50,
			HighThreshold:         75,
			CriticalThreshold:     90,
			AutoBlockOnCritical:   true,
			BlockDurationMinutes:  30,
			NotifyUserOnHighRisk:  true,
			NotifyAdminOnCritical: true,
		}
	}

	return thresholds, nil
}

// UpdateThresholds updates risk thresholds for a tenant
func (s *RiskService) UpdateThresholds(ctx context.Context, tenantID uuid.UUID, req *models.UpdateRiskThresholdRequest) (*models.RiskThreshold, error) {
	thresholds, err := s.riskRepo.GetThresholds(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("UpdateThresholds: %w", err)
	}

	if thresholds == nil {
		thresholds = &models.RiskThreshold{
			TenantID:              tenantID,
			LowThreshold:          20,
			MediumThreshold:       50,
			HighThreshold:         75,
			CriticalThreshold:     90,
			AutoBlockOnCritical:   true,
			BlockDurationMinutes:  30,
			NotifyUserOnHighRisk:  true,
			NotifyAdminOnCritical: true,
		}
	}

	if req.LowThreshold != nil {
		thresholds.LowThreshold = *req.LowThreshold
	}
	if req.MediumThreshold != nil {
		thresholds.MediumThreshold = *req.MediumThreshold
	}
	if req.HighThreshold != nil {
		thresholds.HighThreshold = *req.HighThreshold
	}
	if req.CriticalThreshold != nil {
		thresholds.CriticalThreshold = *req.CriticalThreshold
	}
	if req.AutoBlockOnCritical != nil {
		thresholds.AutoBlockOnCritical = *req.AutoBlockOnCritical
	}
	if req.BlockDurationMinutes != nil {
		thresholds.BlockDurationMinutes = *req.BlockDurationMinutes
	}
	if req.NotifyUserOnHighRisk != nil {
		thresholds.NotifyUserOnHighRisk = *req.NotifyUserOnHighRisk
	}
	if req.NotifyAdminOnCritical != nil {
		thresholds.NotifyAdminOnCritical = *req.NotifyAdminOnCritical
	}

	if err := s.riskRepo.UpsertThresholds(ctx, thresholds); err != nil {
		return nil, fmt.Errorf("failed to update thresholds: %w", err)
	}

	return thresholds, nil
}

// GetUserSignals returns recent risk signals for a user
func (s *RiskService) GetUserSignals(ctx context.Context, userID uuid.UUID, days int) ([]models.RiskSignal, error) {
	since := time.Now().AddDate(0, 0, -days)
	return s.riskRepo.GetUserRecentSignals(ctx, userID, since)
}

// GetUserRecentLoginEvents returns the most recent login risk events for a
// user. Powers the user-facing "Sign-in security events" feed on
// accounts.hexxlock.com — surfaces MFA-challenged + blocked logins so users
// can spot suspicious activity from the audit-trail layer.
//
// `days` defaults to 90 when <= 0; `limit` defaults / caps to 50.
func (s *RiskService) GetUserRecentLoginEvents(
	ctx context.Context,
	userID uuid.UUID,
	days int,
	limit int,
) ([]models.LoginRiskEvent, error) {
	if days <= 0 {
		days = 90
	}
	since := time.Now().AddDate(0, 0, -days)
	return s.riskRepo.GetUserRecentLoginRiskEvents(ctx, userID, since, limit)
}

// GetUserLoginHistoryPaginated returns the user-facing per-attempt login
// history as a paginated list of risk events (success + failure).
// Backing source of truth for /api/v1/auth/login-history (v0.232.241 +).
// Page is 1-indexed; pageSize is bounded [1, 200] at the repo layer.
func (s *RiskService) GetUserLoginHistoryPaginated(
	ctx context.Context,
	userID uuid.UUID,
	page, pageSize int,
) ([]models.LoginRiskEvent, int64, error) {
	return s.riskRepo.GetUserLoginRiskEventsPaginated(ctx, userID, page, pageSize)
}

// RecordLoginEvent persists a per-login rollup of an assessment to
// iam_login_risk_events. Companion to the per-signal CreateSignal calls
// in AssessLoginRisk.
//
// Caller (services/auth_service.go::assessLoginRisk) decides the outcome
// after seeing how the rest of the Login flow consumed the assessment:
//   - LoginRiskOutcomeBlocked when assessment.Blocked
//   - LoginRiskOutcomeMFAChallenged when assessment.RequiresMFA or user.MFAEnabled
//   - LoginRiskOutcomeAllowed otherwise
//
// mfaTrigger is one of the MFATrigger* constants and is required when
// outcome == LoginRiskOutcomeMFAChallenged.
//
// Failures are non-fatal at the call site — log and continue rather than
// fail the login flow on event-log write errors.
func (s *RiskService) RecordLoginEvent(
	ctx context.Context,
	assessment *models.RiskAssessment,
	riskCtx *models.RiskContext,
	outcome string,
	mfaTrigger string,
) error {
	event := &models.LoginRiskEvent{
		UserID:      riskCtx.UserID,
		TenantID:    riskCtx.TenantID,
		TotalScore:  assessment.TotalScore,
		Level:       assessment.Level,
		SignalCount: len(assessment.Signals),
		Outcome:     outcome,
	}
	if riskCtx.IPAddress != "" {
		ip := riskCtx.IPAddress
		event.IPAddress = &ip
	}
	if riskCtx.UserAgent != "" {
		ua := riskCtx.UserAgent
		event.UserAgent = &ua
	}
	if riskCtx.Location != "" {
		loc := riskCtx.Location
		event.Location = &loc
	}
	if mfaTrigger != "" {
		event.MFATrigger = &mfaTrigger
	}
	if assessment.BlockReason != "" {
		reason := assessment.BlockReason
		event.BlockReason = &reason
	}
	// Edge-stamped geo enrichment (platform migration v0.232.247).
	// Sourced from geo-stamp Cloudflare Worker via
	// X-Geo-* headers, stamped onto ctx by auth_handler.go::Login at
	// the trust boundary. Per-field empty-string guard so an absent
	// X-Geo-City doesn't land as "" in the column. IsVPNHint is only
	// stamped when ASNOrg is non-empty — NULL means "didn't classify"
	// rather than "classified false". Same shape as createSession's
	// geo persistence on iam_sessions (auth_credentials_service.go).
	if geo := clientctx.GeoFromContext(ctx); geo != (clientctx.Geo{}) {
		if geo.ASN != "" {
			v := geo.ASN
			event.ASN = &v
		}
		if geo.ASNOrg != "" {
			v := geo.ASNOrg
			event.ASNOrg = &v
		}
		if geo.City != "" {
			v := geo.City
			event.City = &v
		}
		if geo.Region != "" {
			v := geo.Region
			event.Region = &v
		}
		if geo.ASNOrg != "" {
			v := geo.IsVPNHint
			event.IsVPNHint = &v
		}
	}
	return s.riskRepo.CreateLoginRiskEvent(ctx, event)
}

// GetSignalByID retrieves a risk signal by ID
func (s *RiskService) GetSignalByID(ctx context.Context, id uuid.UUID) (*models.RiskSignal, error) {
	return s.riskRepo.GetSignalByID(ctx, id)
}

// ResolveSignal resolves a risk signal
func (s *RiskService) ResolveSignal(ctx context.Context, signalID, resolvedBy uuid.UUID, note string) error {
	return s.riskRepo.ResolveSignal(ctx, signalID, resolvedBy, note)
}

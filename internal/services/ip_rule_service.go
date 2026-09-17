// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ipRuleServiceIPRuleRepo defines the IP rule repository methods needed by IPRuleService.
type ipRuleServiceIPRuleRepo interface {
	GetActiveRules(ctx context.Context, tenantID uuid.UUID) ([]*models.IPRule, error)
	IncrementHitCount(ctx context.Context, id uuid.UUID) error
	LogAction(ctx context.Context, log *models.IPRuleLog) error
	GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.IPRule, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.IPRule, error)
	Create(ctx context.Context, rule *models.IPRule) error
	Update(ctx context.Context, rule *models.IPRule) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetDeniedLogs(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.IPRuleLog, error)
	GetRecentLogs(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.IPRuleLog, error)
}

// IPRuleService handles IP whitelist/blacklist logic
type IPRuleService struct {
	repo  ipRuleServiceIPRuleRepo
	cache sync.Map // map[uuid.UUID][]*models.IPRule - cached rules per tenant
}

// NewIPRuleService is an exported function.
func NewIPRuleService(repo ipRuleServiceIPRuleRepo) *IPRuleService {
	return &IPRuleService{
		repo: repo,
	}
}

// GetRules retrieves IP rules for a tenant (with caching)
func (s *IPRuleService) GetRules(ctx context.Context, tenantID uuid.UUID) ([]*models.IPRule, error) {
	// Try cache first
	if cached, ok := s.cache.Load(tenantID); ok {
		return cached.([]*models.IPRule), nil
	}

	// Fetch from database
	rules, err := s.repo.GetActiveRules(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetRules: failed to get active rules: %w", err)
	}

	// Cache for 5 minutes with auto-eviction
	s.cache.Store(tenantID, rules)
	time.AfterFunc(5*time.Minute, func() {
		s.cache.Delete(tenantID)
	})

	return rules, nil
}

// InvalidateCache invalidates the rules cache for a tenant
func (s *IPRuleService) InvalidateCache(tenantID uuid.UUID) {
	s.cache.Delete(tenantID)
}

// CheckIP checks if an IP address is allowed based on the rules.
// SECURITY: Returns an error when rules cannot be retrieved so callers can
// fail closed. Never swallow the error and allow by default — that would let
// an attacker bypass IP restrictions by triggering a transient store failure.
func (s *IPRuleService) CheckIP(ctx context.Context, tenantID uuid.UUID, ipAddress string, appliesTo models.IPRuleAppliesTo) (*models.IPCheckResult, error) {
	rules, err := s.GetRules(ctx, tenantID)
	if err != nil {
		// Log and propagate so the middleware can abort with 503.
		logger.Error("Failed to get IP rules", zap.Error(err))
		return nil, fmt.Errorf("CheckIP: %w", err)
	}

	// Parse the incoming IP
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		// Invalid IP format, log and allow
		logger.Warn("Invalid IP address format", zap.String("ip", ipAddress))
		return &models.IPCheckResult{Allowed: true}, nil
	}

	// Check rules in priority order (highest first)
	for _, rule := range rules {
		// Check if rule applies to this context
		if rule.AppliesTo != models.IPRuleAppliesToAll && rule.AppliesTo != appliesTo {
			continue
		}

		// Check if IP matches the rule pattern
		if s.matchesIPPattern(ip, rule.IPPattern) {
			// Increment hit count asynchronously (detach from request context)
			go func(ruleID uuid.UUID) { //nolint:gosec // goroutine must outlive request context
				bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := s.repo.IncrementHitCount(bgCtx, ruleID); err != nil {
					logger.Error("Failed to increment rule hit count", zap.Error(err))
				}
			}(rule.ID)

			result := &models.IPCheckResult{
				Allowed:   rule.RuleType == models.IPRuleTypeAllow,
				RuleID:    rule.ID,
				RuleName:  rule.Name,
				RuleType:  string(rule.RuleType),
				MatchedIP: rule.IPPattern,
			}

			return result, nil
		}
	}

	// No rule matched - default to allow
	return &models.IPCheckResult{Allowed: true}, nil
}

// matchesIPPattern checks if an IP matches a pattern (single IP or CIDR)
func (s *IPRuleService) matchesIPPattern(ip net.IP, pattern string) bool {
	// Try parsing as CIDR first
	_, network, err := net.ParseCIDR(pattern)
	if err == nil {
		return network.Contains(ip)
	}

	// Try parsing as single IP
	patternIP := net.ParseIP(pattern)
	if patternIP != nil {
		return ip.Equal(patternIP)
	}

	return false
}

// LogAction logs an IP rule action
func (s *IPRuleService) LogAction(ctx context.Context, tenantID uuid.UUID, ruleID *uuid.UUID, ipAddress, action, endpoint, userAgent string) {
	log := &models.IPRuleLog{
		RuleID:    ruleID,
		TenantID:  &tenantID,
		IPAddress: ipAddress,
		Action:    action,
		Endpoint:  endpoint,
		UserAgent: userAgent,
	}

	if err := s.repo.LogAction(ctx, log); err != nil {
		logger.Error("Failed to log IP rule action", zap.Error(err))
	}
}

// CRUD operations for admin

// ListRules lists all IP rules for a tenant
func (s *IPRuleService) ListRules(ctx context.Context, tenantID uuid.UUID) ([]*models.IPRule, error) {
	return s.repo.GetByTenantID(ctx, tenantID)
}

// GetRule retrieves a single IP rule
func (s *IPRuleService) GetRule(ctx context.Context, id uuid.UUID) (*models.IPRule, error) {
	return s.repo.GetByID(ctx, id)
}

// CreateRule creates a new IP rule
func (s *IPRuleService) CreateRule(ctx context.Context, tenantID, userID uuid.UUID, req *models.CreateIPRuleRequest) (*models.IPRule, error) {
	// Validate IP pattern
	if !s.isValidIPPattern(req.IPPattern) {
		return nil, fmt.Errorf("invalid IP pattern: must be a valid IP address or CIDR notation")
	}

	rule := &models.IPRule{
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		IPPattern:   req.IPPattern,
		RuleType:    models.IPRuleType(req.RuleType),
		Priority:    0,
		IsActive:    true,
		AppliesTo:   models.IPRuleAppliesToAll,
		CreatedBy:   &userID,
		UpdatedBy:   &userID,
	}

	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	if req.IsActive != nil {
		rule.IsActive = *req.IsActive
	}
	if req.AppliesTo != nil {
		rule.AppliesTo = models.IPRuleAppliesTo(*req.AppliesTo)
	}
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("invalid expires_at format: use ISO 8601 format")
		}
		rule.ExpiresAt = &t
	}

	if err := s.repo.Create(ctx, rule); err != nil {
		return nil, fmt.Errorf("CreateRule: failed to create rule: %w", err)
	}

	// Invalidate cache
	s.InvalidateCache(tenantID)

	logger.Info("IP rule created",
		zap.String("rule_id", rule.ID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("name", rule.Name),
		zap.String("type", string(rule.RuleType)),
	)

	return rule, nil
}

// UpdateRule updates an existing IP rule
func (s *IPRuleService) UpdateRule(ctx context.Context, tenantID, userID, ruleID uuid.UUID, req *models.UpdateIPRuleRequest) (*models.IPRule, error) {
	rule, err := s.repo.GetByID(ctx, ruleID)
	if err != nil {
		return nil, fmt.Errorf("UpdateRule: failed to get rule: %w", err)
	}
	if rule == nil {
		return nil, fmt.Errorf("IP rule not found")
	}

	// Verify tenant ownership
	if rule.TenantID != tenantID {
		return nil, fmt.Errorf("IP rule not found")
	}

	// Apply updates
	if req.Name != nil {
		rule.Name = *req.Name
	}
	if req.Description != nil {
		rule.Description = req.Description
	}
	if req.IPPattern != nil {
		if !s.isValidIPPattern(*req.IPPattern) {
			return nil, fmt.Errorf("invalid IP pattern: must be a valid IP address or CIDR notation")
		}
		rule.IPPattern = *req.IPPattern
	}
	if req.RuleType != nil {
		rule.RuleType = models.IPRuleType(*req.RuleType)
	}
	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	if req.IsActive != nil {
		rule.IsActive = *req.IsActive
	}
	if req.AppliesTo != nil {
		rule.AppliesTo = models.IPRuleAppliesTo(*req.AppliesTo)
	}
	if req.ExpiresAt != nil {
		if *req.ExpiresAt == "" {
			rule.ExpiresAt = nil
		} else {
			t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				return nil, fmt.Errorf("invalid expires_at format: use ISO 8601 format")
			}
			rule.ExpiresAt = &t
		}
	}
	rule.UpdatedBy = &userID

	if err := s.repo.Update(ctx, rule); err != nil {
		return nil, fmt.Errorf("UpdateRule: failed to update rule: %w", err)
	}

	// Invalidate cache
	s.InvalidateCache(tenantID)

	logger.Info("IP rule updated",
		zap.String("rule_id", rule.ID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	return rule, nil
}

// DeleteRule deletes an IP rule
func (s *IPRuleService) DeleteRule(ctx context.Context, tenantID, ruleID uuid.UUID) error {
	rule, err := s.repo.GetByID(ctx, ruleID)
	if err != nil {
		return fmt.Errorf("DeleteRule: failed to get rule: %w", err)
	}
	if rule == nil {
		return fmt.Errorf("IP rule not found")
	}

	// Verify tenant ownership
	if rule.TenantID != tenantID {
		return fmt.Errorf("IP rule not found")
	}

	if err := s.repo.Delete(ctx, ruleID); err != nil {
		return fmt.Errorf("DeleteRule: failed to delete rule: %w", err)
	}

	// Invalidate cache
	s.InvalidateCache(tenantID)

	logger.Info("IP rule deleted",
		zap.String("rule_id", ruleID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	return nil
}

// GetLogs retrieves IP rule logs
func (s *IPRuleService) GetLogs(ctx context.Context, tenantID uuid.UUID, limit int, deniedOnly bool) ([]*models.IPRuleLog, error) {
	if deniedOnly {
		return s.repo.GetDeniedLogs(ctx, tenantID, limit)
	}
	return s.repo.GetRecentLogs(ctx, tenantID, limit)
}

// isValidIPPattern validates an IP pattern (IP address or CIDR)
func (s *IPRuleService) isValidIPPattern(pattern string) bool {
	// Try parsing as CIDR
	_, _, err := net.ParseCIDR(pattern)
	if err == nil {
		return true
	}

	// Try parsing as single IP
	ip := net.ParseIP(pattern)
	return ip != nil
}

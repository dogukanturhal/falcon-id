// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

// rateLimitServiceRateLimitRepo defines the rate limit repository methods needed by RateLimitService.
type rateLimitServiceRateLimitRepo interface {
	GetActiveRules(ctx context.Context, tenantID uuid.UUID) ([]*models.RateLimitRule, error)
	LogEvent(ctx context.Context, event *models.RateLimitEvent) error
	GetRulesByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.RateLimitRule, error)
	GetRuleByID(ctx context.Context, id uuid.UUID) (*models.RateLimitRule, error)
	Create(ctx context.Context, rule *models.RateLimitRule) error
	Update(ctx context.Context, rule *models.RateLimitRule) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetBlockedEvents(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.RateLimitEvent, error)
	GetRecentEvents(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.RateLimitEvent, error)
}

// RateLimitEntry represents a single rate limit tracking entry
type RateLimitEntry struct {
	Requests     []time.Time
	BlockedUntil time.Time
	mu           sync.Mutex
}

// RateLimitService handles rate limiting logic
type RateLimitService struct {
	repo             rateLimitServiceRateLimitRepo
	entries          sync.Map // map[string]*RateLimitEntry
	rules            sync.Map // map[uuid.UUID][]*models.RateLimitRule - cached rules per tenant
	redisRateLimiter *redis.RateLimiter
	stopCh           chan struct{}
	stopOnce         sync.Once
}

// NewRateLimitService is an exported function.
func NewRateLimitService(repo rateLimitServiceRateLimitRepo) *RateLimitService {
	service := &RateLimitService{
		repo:   repo,
		stopCh: make(chan struct{}),
	}

	// Start background cleanup goroutine
	go service.cleanupLoop()

	return service
}

// Stop gracefully stops background goroutines
func (s *RateLimitService) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// SetRedisRateLimiter sets the Redis-based rate limiter for distributed rate limiting
func (s *RateLimitService) SetRedisRateLimiter(limiter *redis.RateLimiter) {
	s.redisRateLimiter = limiter
}

// cleanupLoop periodically cleans up old entries
func (s *RateLimitService) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanupOldEntries()
		case <-s.stopCh:
			return
		}
	}
}

// cleanupOldEntries removes entries that haven't been used recently
func (s *RateLimitService) cleanupOldEntries() {
	cutoff := time.Now().Add(-30 * time.Minute)

	s.entries.Range(func(key, value interface{}) bool {
		entry := value.(*RateLimitEntry)
		entry.mu.Lock()
		defer entry.mu.Unlock()

		// Remove if no recent requests and not blocked
		if len(entry.Requests) == 0 && entry.BlockedUntil.Before(time.Now()) {
			s.entries.Delete(key)
		} else if len(entry.Requests) > 0 && entry.Requests[len(entry.Requests)-1].Before(cutoff) {
			s.entries.Delete(key)
		}
		return true
	})
}

// GetRules retrieves rate limit rules for a tenant (with caching)
func (s *RateLimitService) GetRules(ctx context.Context, tenantID uuid.UUID) ([]*models.RateLimitRule, error) {
	// Try cache first
	if cached, ok := s.rules.Load(tenantID); ok {
		return cached.([]*models.RateLimitRule), nil
	}

	// Fetch from database
	rules, err := s.repo.GetActiveRules(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetRules: %w", err)
	}

	// Cache for 5 minutes with auto-eviction
	s.rules.Store(tenantID, rules)
	time.AfterFunc(5*time.Minute, func() {
		s.rules.Delete(tenantID)
	})

	return rules, nil
}

// InvalidateCache invalidates the rules cache for a tenant
func (s *RateLimitService) InvalidateCache(tenantID uuid.UUID) {
	s.rules.Delete(tenantID)
}

// CheckRateLimit checks if a request should be rate limited
func (s *RateLimitService) CheckRateLimit(ctx context.Context, tenantID uuid.UUID, identifier, endpoint, method string) (*models.RateLimitState, error) {
	rules, err := s.GetRules(ctx, tenantID)
	if err != nil {
		// Log error but don't block requests if we can't get rules
		logger.Error("Failed to get rate limit rules", zap.Error(err))
		return nil, nil
	}

	// Find matching rule (highest priority first)
	var matchedRule *models.RateLimitRule
	for _, rule := range rules {
		if s.matchesRule(endpoint, method, rule) {
			matchedRule = rule
			break
		}
	}

	if matchedRule == nil {
		// No matching rule, allow request
		return nil, nil
	}

	// Generate key based on scope
	key := s.generateKey(matchedRule, tenantID, identifier, endpoint)

	// Get or create entry
	entryI, _ := s.entries.LoadOrStore(key, &RateLimitEntry{
		Requests: make([]time.Time, 0),
	})
	entry := entryI.(*RateLimitEntry)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Duration(matchedRule.WindowSeconds) * time.Second)

	// Check if currently blocked
	if entry.BlockedUntil.After(now) {
		return &models.RateLimitState{
			Key:          key,
			Requests:     len(entry.Requests),
			WindowStart:  windowStart,
			WindowEnd:    now,
			Blocked:      true,
			BlockedUntil: entry.BlockedUntil,
			Remaining:    0,
			ResetAt:      entry.BlockedUntil,
		}, nil
	}

	// Clean up old requests outside the window
	validRequests := make([]time.Time, 0)
	for _, req := range entry.Requests {
		if req.After(windowStart) {
			validRequests = append(validRequests, req)
		}
	}
	entry.Requests = validRequests

	// Check if over limit
	if len(entry.Requests) >= matchedRule.MaxRequests {
		// Block the client
		entry.BlockedUntil = now.Add(time.Duration(matchedRule.BlockDurationSeconds) * time.Second)

		// Log blocked event asynchronously (detach from request context)
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		go func() {
			defer cancel()
			s.logBlockedEvent(bgCtx, matchedRule, tenantID, identifier, endpoint, len(entry.Requests))
		}()

		return &models.RateLimitState{
			Key:          key,
			Requests:     len(entry.Requests),
			WindowStart:  windowStart,
			WindowEnd:    now,
			Blocked:      true,
			BlockedUntil: entry.BlockedUntil,
			Remaining:    0,
			ResetAt:      entry.BlockedUntil,
		}, nil
	}

	// Add current request
	entry.Requests = append(entry.Requests, now)

	return &models.RateLimitState{
		Key:         key,
		Requests:    len(entry.Requests),
		WindowStart: windowStart,
		WindowEnd:   now,
		Blocked:     false,
		Remaining:   matchedRule.MaxRequests - len(entry.Requests),
		ResetAt:     windowStart.Add(time.Duration(matchedRule.WindowSeconds) * time.Second),
	}, nil
}

// matchesRule checks if an endpoint and method matches a rule
func (s *RateLimitService) matchesRule(endpoint, method string, rule *models.RateLimitRule) bool {
	// Check method first (if specified)
	if rule.Method != nil && *rule.Method != "" && *rule.Method != method {
		return false
	}

	// Check endpoint pattern
	pattern := rule.EndpointPattern

	// Handle wildcards
	if pattern == "*" {
		return true
	}

	// Handle suffix wildcards (e.g., "/api/*")
	if len(pattern) > 1 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(endpoint) >= len(prefix) && endpoint[:len(prefix)] == prefix
	}

	// Handle glob-like patterns using path.Match
	matched, _ := path.Match(pattern, endpoint)
	if matched {
		return true
	}

	// Exact match
	return pattern == endpoint
}

// generateKey generates a rate limit key based on the rule's scope
func (s *RateLimitService) generateKey(rule *models.RateLimitRule, tenantID uuid.UUID, identifier, endpoint string) string {
	switch rule.Scope {
	case models.RateLimitScopeIP:
		return fmt.Sprintf("rl:%s:%s:%s", tenantID.String(), identifier, rule.EndpointPattern)
	case models.RateLimitScopeUser:
		return fmt.Sprintf("rl:user:%s:%s:%s", tenantID.String(), identifier, rule.EndpointPattern)
	case models.RateLimitScopeTenant:
		return fmt.Sprintf("rl:tenant:%s:%s", tenantID.String(), rule.EndpointPattern)
	case models.RateLimitScopeGlobal:
		return fmt.Sprintf("rl:global:%s", rule.EndpointPattern)
	default:
		return fmt.Sprintf("rl:%s:%s:%s", tenantID.String(), identifier, endpoint)
	}
}

// logBlockedEvent logs a rate limit block event to the database
func (s *RateLimitService) logBlockedEvent(ctx context.Context, rule *models.RateLimitRule, tenantID uuid.UUID, identifier, endpoint string, requestCount int) {
	blockedUntil := time.Now().Add(time.Duration(rule.BlockDurationSeconds) * time.Second)
	event := &models.RateLimitEvent{
		RuleID:       &rule.ID,
		TenantID:     &tenantID,
		Identifier:   identifier,
		Endpoint:     endpoint,
		RequestCount: requestCount,
		Blocked:      true,
		BlockedUntil: &blockedUntil,
	}

	if err := s.repo.LogEvent(ctx, event); err != nil {
		logger.Error("Failed to log rate limit event", zap.Error(err))
	}
}

// CRUD operations for admin

// ListRules lists all rate limit rules for a tenant
func (s *RateLimitService) ListRules(ctx context.Context, tenantID uuid.UUID) ([]*models.RateLimitRule, error) {
	return s.repo.GetRulesByTenantID(ctx, tenantID)
}

// GetRule retrieves a single rate limit rule
func (s *RateLimitService) GetRule(ctx context.Context, id uuid.UUID) (*models.RateLimitRule, error) {
	return s.repo.GetRuleByID(ctx, id)
}

// CreateRule creates a new rate limit rule
func (s *RateLimitService) CreateRule(ctx context.Context, tenantID, userID uuid.UUID, req *models.CreateRateLimitRuleRequest) (*models.RateLimitRule, error) {
	rule := &models.RateLimitRule{
		TenantID:             &tenantID,
		Name:                 req.Name,
		Description:          req.Description,
		EndpointPattern:      req.EndpointPattern,
		Method:               req.Method,
		MaxRequests:          req.MaxRequests,
		WindowSeconds:        req.WindowSeconds,
		BlockDurationSeconds: 300, // Default 5 minutes
		Scope:                models.RateLimitScope(req.Scope),
		IsActive:             true,
		Priority:             0,
		CreatedBy:            &userID,
		UpdatedBy:            &userID,
	}

	if req.BlockDurationSeconds != nil {
		rule.BlockDurationSeconds = *req.BlockDurationSeconds
	}
	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	if req.IsActive != nil {
		rule.IsActive = *req.IsActive
	}

	if err := s.repo.Create(ctx, rule); err != nil {
		return nil, fmt.Errorf("CreateRule: %w", err)
	}

	// Invalidate cache
	s.InvalidateCache(tenantID)

	logger.Info("Rate limit rule created",
		zap.String("rule_id", rule.ID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("name", rule.Name),
	)

	return rule, nil
}

// UpdateRule updates an existing rate limit rule
func (s *RateLimitService) UpdateRule(ctx context.Context, tenantID, userID, ruleID uuid.UUID, req *models.UpdateRateLimitRuleRequest) (*models.RateLimitRule, error) {
	rule, err := s.repo.GetRuleByID(ctx, ruleID)
	if err != nil {
		return nil, fmt.Errorf("UpdateRule: %w", err)
	}
	if rule == nil {
		return nil, fmt.Errorf("rate limit rule not found")
	}

	// Verify tenant ownership
	if rule.TenantID != nil && *rule.TenantID != tenantID {
		return nil, fmt.Errorf("rate limit rule not found")
	}

	// Apply updates
	if req.Name != nil {
		rule.Name = *req.Name
	}
	if req.Description != nil {
		rule.Description = req.Description
	}
	if req.EndpointPattern != nil {
		rule.EndpointPattern = *req.EndpointPattern
	}
	if req.Method != nil {
		rule.Method = req.Method
	}
	if req.MaxRequests != nil {
		rule.MaxRequests = *req.MaxRequests
	}
	if req.WindowSeconds != nil {
		rule.WindowSeconds = *req.WindowSeconds
	}
	if req.BlockDurationSeconds != nil {
		rule.BlockDurationSeconds = *req.BlockDurationSeconds
	}
	if req.Scope != nil {
		rule.Scope = models.RateLimitScope(*req.Scope)
	}
	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	if req.IsActive != nil {
		rule.IsActive = *req.IsActive
	}
	rule.UpdatedBy = &userID

	if err := s.repo.Update(ctx, rule); err != nil {
		return nil, fmt.Errorf("UpdateRule: %w", err)
	}

	// Invalidate cache
	s.InvalidateCache(tenantID)

	logger.Info("Rate limit rule updated",
		zap.String("rule_id", rule.ID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	return rule, nil
}

// DeleteRule deletes a rate limit rule
func (s *RateLimitService) DeleteRule(ctx context.Context, tenantID, ruleID uuid.UUID) error {
	rule, err := s.repo.GetRuleByID(ctx, ruleID)
	if err != nil {
		return fmt.Errorf("DeleteRule: %w", err)
	}
	if rule == nil {
		return fmt.Errorf("rate limit rule not found")
	}

	// Verify tenant ownership
	if rule.TenantID != nil && *rule.TenantID != tenantID {
		return fmt.Errorf("rate limit rule not found")
	}

	if err := s.repo.Delete(ctx, ruleID); err != nil {
		return fmt.Errorf("DeleteRule: %w", err)
	}

	// Invalidate cache
	s.InvalidateCache(tenantID)

	logger.Info("Rate limit rule deleted",
		zap.String("rule_id", ruleID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	return nil
}

// GetEvents retrieves recent rate limit events
func (s *RateLimitService) GetEvents(ctx context.Context, tenantID uuid.UUID, limit int, blockedOnly bool) ([]*models.RateLimitEvent, error) {
	if blockedOnly {
		return s.repo.GetBlockedEvents(ctx, tenantID, limit)
	}
	return s.repo.GetRecentEvents(ctx, tenantID, limit)
}

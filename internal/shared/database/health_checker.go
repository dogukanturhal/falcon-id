// SPDX-License-Identifier: AGPL-3.0-or-later

// Package database provides multi-tenant database connection management for Go services.
package database

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// HealthStatus represents the health state of a connection
type HealthStatus string

const (
	// HealthStatusHealthy is an exported identifier.
	HealthStatusHealthy HealthStatus = "healthy"
	// HealthStatusDegraded is an exported identifier.
	HealthStatusDegraded HealthStatus = "degraded"
	// HealthStatusUnhealthy is an exported identifier.
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	// HealthStatusUnknown is an exported identifier.
	HealthStatusUnknown HealthStatus = "unknown"
)

// HealthCheckResult represents the result of a health check
type HealthCheckResult struct {
	TenantID     uuid.UUID     `json:"tenant_id"`
	Status       HealthStatus  `json:"status"`
	Latency      time.Duration `json:"latency_ms"`
	LastChecked  time.Time     `json:"last_checked"`
	ErrorMessage string        `json:"error_message,omitempty"`
	Consecutive  int           `json:"consecutive_failures"`
}

// TenantHealthRecord tracks health history for a tenant.
// All field mutations must be done while holding mu.
type TenantHealthRecord struct {
	mu                  sync.Mutex
	TenantID            uuid.UUID
	Status              HealthStatus
	LastCheck           time.Time
	LastHealthy         time.Time
	ConsecutiveFailures int
	TotalChecks         int
	FailedChecks        int
	AverageLatency      time.Duration
	MaxLatency          time.Duration
}

// HealthCheckerConfig holds configuration for health checking
type HealthCheckerConfig struct {
	// Interval between health checks
	Interval time.Duration
	// Timeout for each health check
	Timeout time.Duration
	// UnhealthyThreshold - consecutive failures before marking unhealthy
	UnhealthyThreshold int
	// DegradedThreshold - consecutive failures before marking degraded
	DegradedThreshold int
	// EvictUnhealthy - automatically evict unhealthy connections
	EvictUnhealthy bool
	// MaxLatency - latency above this is considered degraded
	MaxLatency time.Duration
	// RecoveryChecks - successful checks needed to recover
	RecoveryChecks int
}

// DefaultHealthCheckerConfig returns default configuration
func DefaultHealthCheckerConfig() HealthCheckerConfig {
	return HealthCheckerConfig{
		Interval:           30 * time.Second,
		Timeout:            5 * time.Second,
		UnhealthyThreshold: 3,
		DegradedThreshold:  1,
		EvictUnhealthy:     true,
		MaxLatency:         1 * time.Second,
		RecoveryChecks:     2,
	}
}

// HealthChecker monitors connection health for tenants
type HealthChecker struct {
	connectionManager *TenantConnectionManager
	config            HealthCheckerConfig
	records           sync.Map // map[uuid.UUID]*TenantHealthRecord
	subscribers       []HealthSubscriber
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	running           bool
	done              chan struct{}
}

// HealthSubscriber is notified of health status changes
type HealthSubscriber interface {
	OnHealthChange(tenantID uuid.UUID, oldStatus, newStatus HealthStatus)
}

// HealthSubscriberFunc is a function adapter for HealthSubscriber
type HealthSubscriberFunc func(tenantID uuid.UUID, oldStatus, newStatus HealthStatus)

// OnHealthChange is an exported function.
func (f HealthSubscriberFunc) OnHealthChange(tenantID uuid.UUID, oldStatus, newStatus HealthStatus) {
	f(tenantID, oldStatus, newStatus)
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(cm *TenantConnectionManager, config HealthCheckerConfig) *HealthChecker {
	return &HealthChecker{
		connectionManager: cm,
		config:            config,
		subscribers:       make([]HealthSubscriber, 0),
	}
}

// Start begins the health checking loop
func (h *HealthChecker) Start(ctx context.Context) {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return
	}
	h.ctx, h.cancel = context.WithCancel(ctx)
	h.running = true
	h.done = make(chan struct{})
	h.mu.Unlock()

	go h.healthCheckLoop()
}

// Stop stops the health checking loop and waits for it to finish
func (h *HealthChecker) Stop() {
	h.mu.Lock()

	if !h.running {
		h.mu.Unlock()
		return
	}

	h.cancel()
	h.running = false
	done := h.done
	h.mu.Unlock()

	// Wait for the health check loop to finish
	if done != nil {
		<-done
	}
}

// Subscribe adds a subscriber for health change notifications
func (h *HealthChecker) Subscribe(subscriber HealthSubscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subscribers = append(h.subscribers, subscriber)
}

// CheckConnection performs a health check for a specific tenant
func (h *HealthChecker) CheckConnection(ctx context.Context, tenantID uuid.UUID) (*HealthCheckResult, error) {
	start := time.Now()

	// Create timeout context
	checkCtx, cancel := context.WithTimeout(ctx, h.config.Timeout)
	defer cancel()

	// Get connection
	db, err := h.connectionManager.GetConnection(checkCtx, tenantID)
	if err != nil {
		return h.recordFailure(tenantID, err, time.Since(start)), nil
	}

	// Ping the connection
	if err := db.PingContext(checkCtx); err != nil {
		return h.recordFailure(tenantID, err, time.Since(start)), nil
	}

	latency := time.Since(start)
	return h.recordSuccess(tenantID, latency), nil
}

// GetHealthStatus returns the current health status for a tenant
func (h *HealthChecker) GetHealthStatus(tenantID uuid.UUID) *HealthCheckResult {
	record, ok := h.records.Load(tenantID)
	if !ok {
		return &HealthCheckResult{
			TenantID: tenantID,
			Status:   HealthStatusUnknown,
		}
	}

	rec := record.(*TenantHealthRecord)
	rec.mu.Lock()
	result := &HealthCheckResult{
		TenantID:    tenantID,
		Status:      rec.Status,
		LastChecked: rec.LastCheck,
		Consecutive: rec.ConsecutiveFailures,
	}
	rec.mu.Unlock()
	return result
}

// GetAllHealthStatuses returns health status for all monitored tenants
func (h *HealthChecker) GetAllHealthStatuses() []*HealthCheckResult {
	var results []*HealthCheckResult

	h.records.Range(func(key, value interface{}) bool {
		tenantID := key.(uuid.UUID)
		rec := value.(*TenantHealthRecord)
		rec.mu.Lock()
		results = append(results, &HealthCheckResult{
			TenantID:    tenantID,
			Status:      rec.Status,
			Latency:     rec.AverageLatency,
			LastChecked: rec.LastCheck,
			Consecutive: rec.ConsecutiveFailures,
		})
		rec.mu.Unlock()
		return true
	})

	return results
}

// MarkUnhealthy manually marks a tenant connection as unhealthy
func (h *HealthChecker) MarkUnhealthy(tenantID uuid.UUID, _ string) {
	record := h.getOrCreateRecord(tenantID)
	record.mu.Lock()
	oldStatus := record.Status
	record.Status = HealthStatusUnhealthy
	record.ConsecutiveFailures = h.config.UnhealthyThreshold
	record.LastCheck = time.Now()
	record.mu.Unlock()

	if oldStatus != HealthStatusUnhealthy {
		h.notifySubscribers(tenantID, oldStatus, HealthStatusUnhealthy)
	}

	if h.config.EvictUnhealthy {
		ctx := h.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		_ = h.connectionManager.InvalidateCache(ctx, tenantID)
	}
}

// ForceHealthCheck immediately runs a health check for a tenant
func (h *HealthChecker) ForceHealthCheck(ctx context.Context, tenantID uuid.UUID) (*HealthCheckResult, error) {
	return h.CheckConnection(ctx, tenantID)
}

// RegisterTenant registers a tenant for health monitoring
func (h *HealthChecker) RegisterTenant(tenantID uuid.UUID) {
	h.getOrCreateRecord(tenantID)
}

// UnregisterTenant removes a tenant from health monitoring
func (h *HealthChecker) UnregisterTenant(tenantID uuid.UUID) {
	h.records.Delete(tenantID)
}

// GetMetrics returns health metrics for monitoring
func (h *HealthChecker) GetMetrics() *HealthMetrics {
	metrics := &HealthMetrics{
		TotalTenants: 0,
		Healthy:      0,
		Degraded:     0,
		Unhealthy:    0,
		Unknown:      0,
	}

	h.records.Range(func(_, value interface{}) bool {
		rec := value.(*TenantHealthRecord)
		rec.mu.Lock()
		status := rec.Status
		avgLatency := rec.AverageLatency
		maxLatency := rec.MaxLatency
		rec.mu.Unlock()

		metrics.TotalTenants++

		switch status {
		case HealthStatusHealthy:
			metrics.Healthy++
		case HealthStatusDegraded:
			metrics.Degraded++
		case HealthStatusUnhealthy:
			metrics.Unhealthy++
		default:
			metrics.Unknown++
		}

		metrics.TotalLatency += avgLatency
		if maxLatency > metrics.MaxLatency {
			metrics.MaxLatency = maxLatency
		}

		return true
	})

	if metrics.TotalTenants > 0 {
		metrics.AverageLatency = time.Duration(int64(metrics.TotalLatency) / int64(metrics.TotalTenants))
	}

	return metrics
}

// HealthMetrics aggregates health statistics
type HealthMetrics struct {
	TotalTenants   int           `json:"total_tenants"`
	Healthy        int           `json:"healthy"`
	Degraded       int           `json:"degraded"`
	Unhealthy      int           `json:"unhealthy"`
	Unknown        int           `json:"unknown"`
	AverageLatency time.Duration `json:"average_latency_ms"`
	MaxLatency     time.Duration `json:"max_latency_ms"`
	TotalLatency   time.Duration `json:"-"`
}

// Internal methods

func (h *HealthChecker) healthCheckLoop() {
	defer close(h.done)
	ticker := time.NewTicker(h.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.runHealthChecks()
		}
	}
}

func (h *HealthChecker) runHealthChecks() {
	var tenantsToCheck []uuid.UUID

	h.records.Range(func(key, _ interface{}) bool {
		tenantID := key.(uuid.UUID)
		tenantsToCheck = append(tenantsToCheck, tenantID)
		return true
	})

	// Run checks concurrently with limited parallelism
	sem := make(chan struct{}, 10) // Max 10 concurrent checks
	var wg sync.WaitGroup

	for _, tenantID := range tenantsToCheck {
		wg.Add(1)
		sem <- struct{}{}

		go func(tid uuid.UUID) {
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(h.ctx, h.config.Timeout)
			defer cancel()

			_, _ = h.CheckConnection(ctx, tid)
		}(tenantID)
	}

	wg.Wait()
}

func (h *HealthChecker) recordSuccess(tenantID uuid.UUID, latency time.Duration) *HealthCheckResult {
	record := h.getOrCreateRecord(tenantID)
	record.mu.Lock()

	oldStatus := record.Status

	record.LastCheck = time.Now()
	record.LastHealthy = time.Now()
	record.TotalChecks++
	record.ConsecutiveFailures = 0

	// Update latency metrics
	if record.TotalChecks == 1 {
		record.AverageLatency = latency
	} else {
		// Exponential moving average
		record.AverageLatency = time.Duration(float64(record.AverageLatency)*0.9 + float64(latency)*0.1)
	}
	if latency > record.MaxLatency {
		record.MaxLatency = latency
	}

	// Determine status based on latency
	if latency > h.config.MaxLatency {
		record.Status = HealthStatusDegraded
	} else {
		record.Status = HealthStatusHealthy
	}

	status := record.Status
	lastCheck := record.LastCheck
	record.mu.Unlock()

	// Notify if status changed (outside lock to avoid holding lock during callbacks)
	if oldStatus != status {
		h.notifySubscribers(tenantID, oldStatus, status)
	}

	return &HealthCheckResult{
		TenantID:    tenantID,
		Status:      status,
		Latency:     latency,
		LastChecked: lastCheck,
		Consecutive: 0,
	}
}

func (h *HealthChecker) recordFailure(tenantID uuid.UUID, err error, latency time.Duration) *HealthCheckResult {
	record := h.getOrCreateRecord(tenantID)
	record.mu.Lock()

	oldStatus := record.Status

	record.LastCheck = time.Now()
	record.TotalChecks++
	record.FailedChecks++
	record.ConsecutiveFailures++

	// Determine status based on consecutive failures
	if record.ConsecutiveFailures >= h.config.UnhealthyThreshold {
		record.Status = HealthStatusUnhealthy
	} else if record.ConsecutiveFailures >= h.config.DegradedThreshold {
		record.Status = HealthStatusDegraded
	}

	status := record.Status
	lastCheck := record.LastCheck
	consecutive := record.ConsecutiveFailures
	record.mu.Unlock()

	// Notify if status changed (outside lock)
	if oldStatus != status {
		h.notifySubscribers(tenantID, oldStatus, status)
	}

	// Evict unhealthy connections if configured
	if status == HealthStatusUnhealthy && h.config.EvictUnhealthy {
		ctx := h.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		_ = h.connectionManager.InvalidateCache(ctx, tenantID)
	}

	return &HealthCheckResult{
		TenantID:     tenantID,
		Status:       status,
		Latency:      latency,
		LastChecked:  lastCheck,
		ErrorMessage: err.Error(),
		Consecutive:  consecutive,
	}
}

func (h *HealthChecker) getOrCreateRecord(tenantID uuid.UUID) *TenantHealthRecord {
	fresh := &TenantHealthRecord{
		TenantID: tenantID,
		Status:   HealthStatusUnknown,
	}
	actual, _ := h.records.LoadOrStore(tenantID, fresh)
	return actual.(*TenantHealthRecord)
}

func (h *HealthChecker) notifySubscribers(tenantID uuid.UUID, oldStatus, newStatus HealthStatus) {
	h.mu.RLock()
	subscribers := make([]HealthSubscriber, len(h.subscribers))
	copy(subscribers, h.subscribers)
	h.mu.RUnlock()

	for _, sub := range subscribers {
		go func(s HealthSubscriber) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.OnHealthChange(tenantID, oldStatus, newStatus)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				// Subscriber timed out — prevent goroutine leak
			}
		}(sub)
	}
}

// HealthCheckService provides HTTP endpoints for health monitoring
type HealthCheckService struct {
	checker *HealthChecker
}

// NewHealthCheckService creates a new health check service
func NewHealthCheckService(checker *HealthChecker) *HealthCheckService {
	return &HealthCheckService{checker: checker}
}

// CheckHealth performs a health check for a specific tenant
func (s *HealthCheckService) CheckHealth(ctx context.Context, tenantID uuid.UUID) (*HealthCheckResult, error) {
	return s.checker.CheckConnection(ctx, tenantID)
}

// GetStatus returns the current health status
func (s *HealthCheckService) GetStatus(tenantID uuid.UUID) *HealthCheckResult {
	return s.checker.GetHealthStatus(tenantID)
}

// GetAllStatuses returns all tenant health statuses
func (s *HealthCheckService) GetAllStatuses() []*HealthCheckResult {
	return s.checker.GetAllHealthStatuses()
}

// GetMetrics returns aggregated health metrics
func (s *HealthCheckService) GetMetrics() *HealthMetrics {
	return s.checker.GetMetrics()
}

// DeepHealthCheck performs a comprehensive health check
func (s *HealthCheckService) DeepHealthCheck(ctx context.Context, tenantID uuid.UUID) (*DeepHealthCheckResult, error) {
	result := &DeepHealthCheckResult{
		TenantID:  tenantID,
		Timestamp: time.Now(),
		Checks:    make([]HealthCheckDetail, 0),
	}

	// 1. Connection check
	connStart := time.Now()
	db, err := s.checker.connectionManager.GetConnection(ctx, tenantID)
	connLatency := time.Since(connStart)
	result.Checks = append(result.Checks, HealthCheckDetail{
		Name:    "connection",
		Status:  boolToStatus(err == nil),
		Latency: connLatency,
		Error:   errToString(err),
	})

	if err != nil {
		result.OverallStatus = HealthStatusUnhealthy
		return result, nil //nolint:nilerr // intentional: connection failure is encoded in the result struct, not returned as an error
	}

	// 2. Ping check
	pingStart := time.Now()
	pingErr := db.PingContext(ctx)
	pingLatency := time.Since(pingStart)
	result.Checks = append(result.Checks, HealthCheckDetail{
		Name:    "ping",
		Status:  boolToStatus(pingErr == nil),
		Latency: pingLatency,
		Error:   errToString(pingErr),
	})

	// 3. Query check
	queryStart := time.Now()
	var one int
	queryErr := db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
	queryLatency := time.Since(queryStart)
	result.Checks = append(result.Checks, HealthCheckDetail{
		Name:    "query",
		Status:  boolToStatus(queryErr == nil),
		Latency: queryLatency,
		Error:   errToString(queryErr),
	})

	// 4. Pool stats
	stats := db.Stats()
	result.PoolStats = &PoolStats{
		MaxOpenConnections: stats.MaxOpenConnections,
		OpenConnections:    stats.OpenConnections,
		InUse:              stats.InUse,
		Idle:               stats.Idle,
		WaitCount:          stats.WaitCount,
		WaitDuration:       stats.WaitDuration,
		MaxIdleClosed:      stats.MaxIdleClosed,
		MaxLifetimeClosed:  stats.MaxLifetimeClosed,
	}

	// Determine overall status
	allHealthy := true
	anyUnhealthy := false
	for _, check := range result.Checks {
		if check.Status == HealthStatusUnhealthy {
			anyUnhealthy = true
			allHealthy = false
		} else if check.Status != HealthStatusHealthy {
			allHealthy = false
		}
	}

	switch {
	case anyUnhealthy:
		result.OverallStatus = HealthStatusUnhealthy
	case allHealthy:
		result.OverallStatus = HealthStatusHealthy
	default:
		result.OverallStatus = HealthStatusDegraded
	}

	return result, nil
}

// DeepHealthCheckResult contains detailed health information
type DeepHealthCheckResult struct {
	TenantID      uuid.UUID           `json:"tenant_id"`
	Timestamp     time.Time           `json:"timestamp"`
	OverallStatus HealthStatus        `json:"overall_status"`
	Checks        []HealthCheckDetail `json:"checks"`
	PoolStats     *PoolStats          `json:"pool_stats,omitempty"`
}

// HealthCheckDetail contains details for a specific check
type HealthCheckDetail struct {
	Name    string        `json:"name"`
	Status  HealthStatus  `json:"status"`
	Latency time.Duration `json:"latency_ms"`
	Error   string        `json:"error,omitempty"`
}

// PoolStats contains database pool statistics
type PoolStats struct {
	MaxOpenConnections int           `json:"max_open_connections"`
	OpenConnections    int           `json:"open_connections"`
	InUse              int           `json:"in_use"`
	Idle               int           `json:"idle"`
	WaitCount          int64         `json:"wait_count"`
	WaitDuration       time.Duration `json:"wait_duration_ms"`
	MaxIdleClosed      int64         `json:"max_idle_closed"`
	MaxLifetimeClosed  int64         `json:"max_lifetime_closed"`
}

func boolToStatus(ok bool) HealthStatus {
	if ok {
		return HealthStatusHealthy
	}
	return HealthStatusUnhealthy
}

func errToString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

// HealthCheckMiddleware provides middleware for health checks
type HealthCheckMiddleware struct {
	checker      *HealthChecker
	blockOnCheck bool
}

// NewHealthCheckMiddleware creates health check middleware
func NewHealthCheckMiddleware(checker *HealthChecker, blockOnCheck bool) *HealthCheckMiddleware {
	return &HealthCheckMiddleware{
		checker:      checker,
		blockOnCheck: blockOnCheck,
	}
}

// CheckBeforeConnection checks health before allowing connection
func (m *HealthCheckMiddleware) CheckBeforeConnection(_ context.Context, tenantID uuid.UUID) error {
	status := m.checker.GetHealthStatus(tenantID)

	if status.Status == HealthStatusUnhealthy {
		return fmt.Errorf("tenant connection unhealthy: %d consecutive failures", status.Consecutive)
	}

	return nil
}

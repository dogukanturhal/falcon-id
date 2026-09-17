// SPDX-License-Identifier: AGPL-3.0-or-later

package platform

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

const (
	metricsStatusHealthy   = "healthy"
	metricsStatusUnhealthy = "unhealthy"
	metricsStatusDegraded  = "degraded"
)

// MetricsHandler handles platform metrics API endpoints
type MetricsHandler struct {
	db          *pgxpool.Pool
	redisClient *redis.Client
	registry    *ServiceRegistry
}

// NewMetricsHandler creates a new metrics handler
func NewMetricsHandler(db *pgxpool.Pool) *MetricsHandler {
	reg, err := LoadRegistry()
	if err != nil {
		log.Printf("WARN: failed to load service registry: %v (falling back to empty)", err)
		reg = &ServiceRegistry{}
	}
	return &MetricsHandler{db: db, registry: reg}
}

// SetRedisClient sets the Redis client for real-time metrics
func (h *MetricsHandler) SetRedisClient(client *redis.Client) {
	h.redisClient = client
}

// ResourceMetrics contains system resource usage
type ResourceMetrics struct {
	CPUUsagePercent    float64 `json:"cpu_usage_percent"`
	MemoryUsageMB      float64 `json:"memory_usage_mb"`
	MemoryTotalMB      float64 `json:"memory_total_mb"`
	MemoryUsagePercent float64 `json:"memory_usage_percent"`
	DiskUsageGB        float64 `json:"disk_usage_gb"`
	DiskTotalGB        float64 `json:"disk_total_gb"`
	DiskUsagePercent   float64 `json:"disk_usage_percent"`
	NetworkInMbps      float64 `json:"network_in_mbps"`
	NetworkOutMbps     float64 `json:"network_out_mbps"`
}

// ServiceHealth represents health status of a service
type ServiceHealth struct {
	Name      string                 `json:"name"`
	Status    string                 `json:"status"`
	LatencyMs int64                  `json:"latency_ms"`
	LastCheck time.Time              `json:"last_check"`
	Category  string                 `json:"category,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// DatabaseMetrics contains database statistics
type DatabaseMetrics struct {
	ActiveConnections      int     `json:"active_connections"`
	MaxConnections         int     `json:"max_connections"`
	ConnectionUsagePercent float64 `json:"connection_usage_percent"`
	QueriesPerSecond       float64 `json:"queries_per_second"`
	AvgQueryTimeMs         float64 `json:"avg_query_time_ms"`
	ReplicationLagMs       int64   `json:"replication_lag_ms"`
	CacheHitRatio          float64 `json:"cache_hit_ratio"`
	DatabaseSizeGB         float64 `json:"database_size_gb"`
}

// QuotaUsage represents quota usage for a tenant
type QuotaUsage struct {
	TenantID   uuid.UUID           `json:"tenant_id"`
	TenantName string              `json:"tenant_name"`
	Plan       string              `json:"plan"`
	Quotas     map[string]QuotaVal `json:"quotas"`
}

// QuotaVal represents a single quota value
type QuotaVal struct {
	Used    int     `json:"used"`
	Limit   int     `json:"limit"`
	Percent float64 `json:"percent"`
}

// FullHealthResponse represents the complete health response
type FullHealthResponse struct {
	Status   string          `json:"status"`
	Services []ServiceHealth `json:"services"`
	Database DatabaseHealth  `json:"database"`
	Cache    CacheHealth     `json:"cache"`
	Uptime   string          `json:"uptime"`
}

// DatabaseHealth represents database health info
type DatabaseHealth struct {
	Status          string `json:"status"`
	ConnectionsUsed int    `json:"connections_used"`
	ConnectionsMax  int    `json:"connections_max"`
	ResponseTimeMs  int64  `json:"response_time"`
}

// CacheHealth represents cache health info
type CacheHealth struct {
	Status              string  `json:"status"`
	MemoryUsedMB        float64 `json:"memory_used_mb"`
	MemoryUsagePercent  float64 `json:"memory_usage_percent"`
	HitRate             float64 `json:"hit_rate"`
	HitRatePercent      float64 `json:"hit_rate_percent"`
	ResponseTimeMs      int64   `json:"response_time_ms"`
	ConnectedClients    int64   `json:"connected_clients"`
	OpsPerSecond        int64   `json:"ops_per_second"`
	TotalKeys           int64   `json:"total_keys"`
	KeyspaceHits        int64   `json:"keyspace_hits"`
	KeyspaceMisses      int64   `json:"keyspace_misses"`
	UptimeSeconds       int64   `json:"uptime_seconds"`
	RedisVersion        string  `json:"redis_version,omitempty"`
	MemoryFragmentation float64 `json:"memory_fragmentation_ratio"`
}

// startTime tracks when the service started
var startTime = time.Now()

// GetSystemMetrics returns comprehensive system metrics
// GET /api/v1/platform/metrics/system
func (h *MetricsHandler) GetSystemMetrics(c *gin.Context) {
	ctx := c.Request.Context()

	// Get resource metrics
	resources := h.getResourceMetrics()

	// Get service health
	services := h.getServiceHealth(ctx)

	// Get database metrics
	database := h.getDatabaseMetrics(ctx)

	c.JSON(http.StatusOK, gin.H{
		"timestamp": time.Now().UTC(),
		"services":  services,
		"resources": resources,
		"database":  database,
	})
}

// GetServiceHealth returns health status of all services
// GET /api/v1/platform/metrics/health
func (h *MetricsHandler) GetServiceHealth(c *gin.Context) {
	ctx := c.Request.Context()
	services := h.getServiceHealth(ctx)

	// Determine overall status
	overallStatus := metricsStatusHealthy
	for _, svc := range services {
		if svc.Status == metricsStatusUnhealthy {
			overallStatus = metricsStatusUnhealthy
			break
		}
		if svc.Status == metricsStatusDegraded && overallStatus != metricsStatusUnhealthy {
			overallStatus = metricsStatusDegraded
		}
	}

	// Get database health
	dbStart := time.Now()
	dbStatus := metricsStatusHealthy
	if err := h.db.Ping(ctx); err != nil {
		dbStatus = metricsStatusUnhealthy
	}
	dbLatency := time.Since(dbStart).Milliseconds()
	dbStats := h.db.Stat()

	// Calculate uptime
	uptime := time.Since(startTime)
	uptimeStr := formatUptime(uptime)

	// Get Redis/Cache health
	cacheHealth := h.getCacheHealth(ctx)

	response := FullHealthResponse{
		Status:   overallStatus,
		Services: services,
		Database: DatabaseHealth{
			Status:          dbStatus,
			ConnectionsUsed: int(dbStats.AcquiredConns()),
			ConnectionsMax:  int(dbStats.MaxConns()),
			ResponseTimeMs:  dbLatency,
		},
		Cache:  cacheHealth,
		Uptime: uptimeStr,
	}

	c.JSON(http.StatusOK, response)
}

// formatUptime formats duration into human readable string
func formatUptime(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// GetResourceUsage returns system resource usage
// GET /api/v1/platform/metrics/resources
func (h *MetricsHandler) GetResourceUsage(c *gin.Context) {
	c.JSON(http.StatusOK, h.getResourceMetrics())
}

// GetDatabaseMetrics returns database statistics
// GET /api/v1/platform/metrics/database
func (h *MetricsHandler) GetDatabaseMetrics(c *gin.Context) {
	c.JSON(http.StatusOK, h.getDatabaseMetrics(c.Request.Context()))
}

// GetCacheMetrics returns Redis/cache statistics
// GET /api/v1/platform/metrics/cache
func (h *MetricsHandler) GetCacheMetrics(c *gin.Context) {
	ctx := c.Request.Context()
	cacheHealth := h.getCacheHealth(ctx)
	c.JSON(http.StatusOK, cacheHealth)
}

// GetQuotaUsage returns quota usage for all tenants
// GET /api/v1/platform/quotas/usage
func (h *MetricsHandler) GetQuotaUsage(c *gin.Context) {
	ctx := c.Request.Context()

	// Query only tables that exist in the IAM database.
	// tenant_subscriptions and tenant_modules live in the subscription-management
	// database, so we cannot join them here.
	tenantsQuery := `
		SELECT
			t.id   AS tenant_id,
			t.name AS tenant_name,
			(SELECT COUNT(*) FROM iam_users u WHERE u.tenant_id = t.id) AS used_users
		FROM iam_tenants t
		WHERE t.status = 'active'
		ORDER BY t.name
	`

	rows, err := h.db.Query(ctx, tenantsQuery)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get quota usage"})
		return
	}
	defer rows.Close()

	quotas := make([]QuotaUsage, 0)
	for rows.Next() {
		var tenantID uuid.UUID
		var tenantName string
		var usedUsers int

		err := rows.Scan(&tenantID, &tenantName, &usedUsers)
		if err != nil {
			continue
		}

		// Get quota details for this tenant from tenant_quotas table (best-effort)
		quotaMap := h.getTenantQuotaMap(ctx, tenantID)

		// Set user quota from actual user count
		if _, ok := quotaMap["users"]; !ok {
			quotaMap["users"] = QuotaVal{Used: usedUsers, Limit: 50, Percent: calcPercent(usedUsers, 50)}
		} else {
			quotaMap["users"] = QuotaVal{Used: usedUsers, Limit: quotaMap["users"].Limit, Percent: calcPercent(usedUsers, quotaMap["users"].Limit)}
		}

		quotas = append(quotas, QuotaUsage{
			TenantID:   tenantID,
			TenantName: tenantName,
			Plan:       "starter",
			Quotas:     quotaMap,
		})
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get quota usage"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tenants": quotas})
}

// getTenantQuotaMap retrieves quota values from tenant_quotas table
func (h *MetricsHandler) getTenantQuotaMap(ctx context.Context, tenantID uuid.UUID) map[string]QuotaVal {
	quotaMap := make(map[string]QuotaVal)

	query := `
		SELECT resource, "limit", used
		FROM tenant_quotas
		WHERE tenant_id = $1
	`

	rows, err := h.db.Query(ctx, query, tenantID)
	if err != nil {
		return quotaMap
	}
	defer rows.Close()

	for rows.Next() {
		var resource string
		var limit, used int

		if err := rows.Scan(&resource, &limit, &used); err != nil {
			continue
		}

		quotaMap[resource] = QuotaVal{
			Used:    used,
			Limit:   limit,
			Percent: calcPercent(used, limit),
		}
	}
	// Best-effort: row iteration errors result in partial quota data
	_ = rows.Err()

	return quotaMap
}

// GetTenantQuotaUsage returns quota usage for a specific tenant
// GET /api/v1/platform/quotas/:tenant_id
func (h *MetricsHandler) GetTenantQuotaUsage(c *gin.Context) {
	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	ctx := c.Request.Context()

	// Query only tables that exist in the IAM database.
	query := `
		SELECT
			t.id   AS tenant_id,
			t.name AS tenant_name,
			(SELECT COUNT(*) FROM iam_users u WHERE u.tenant_id = t.id) AS used_users
		FROM iam_tenants t
		WHERE t.id = $1
	`

	var tenantName string
	var usedUsers int

	err = h.db.QueryRow(ctx, query, tenantID).Scan(
		&tenantID, &tenantName, &usedUsers,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
		return
	}

	// Get quota details for this tenant (best-effort)
	quotaMap := h.getTenantQuotaMap(ctx, tenantID)

	// Update users with actual usage
	if _, ok := quotaMap["users"]; !ok {
		quotaMap["users"] = QuotaVal{Used: usedUsers, Limit: 50, Percent: calcPercent(usedUsers, 50)}
	} else {
		quotaMap["users"] = QuotaVal{Used: usedUsers, Limit: quotaMap["users"].Limit, Percent: calcPercent(usedUsers, quotaMap["users"].Limit)}
	}

	c.JSON(http.StatusOK, QuotaUsage{
		TenantID:   tenantID,
		TenantName: tenantName,
		Plan:       "starter",
		Quotas:     quotaMap,
	})
}

func (h *MetricsHandler) getResourceMetrics() ResourceMetrics {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	memUsageMB := float64(mem.Alloc) / 1024 / 1024
	memTotalMB := float64(mem.Sys) / 1024 / 1024

	// Note: For production, use proper system monitoring (node_exporter, etc.)
	// These are placeholder values based on Go runtime
	return ResourceMetrics{
		CPUUsagePercent:    float64(runtime.NumGoroutine()) / 100 * 10, // Rough estimate
		MemoryUsageMB:      memUsageMB,
		MemoryTotalMB:      memTotalMB,
		MemoryUsagePercent: (memUsageMB / memTotalMB) * 100,
		DiskUsageGB:        0, // Would need syscall for real value
		DiskTotalGB:        0, // Would need syscall for real value
		DiskUsagePercent:   0, // Would need syscall for real value
		NetworkInMbps:      0, // Would need netstat for real value
		NetworkOutMbps:     0, // Would need netstat for real value
	}
}

func (h *MetricsHandler) getServiceHealth(ctx context.Context) []ServiceHealth {
	// Internal checks (fast, local)
	services := []ServiceHealth{
		h.checkService(ctx, "PostgreSQL", h.checkPostgres),
		h.checkService(ctx, "IAM (Falcon-ID)", h.checkSelf),
	}
	services[0].Category = "infrastructure"
	services[1].Category = "platform"

	// Registry-driven external checks — run in parallel
	defs := h.registry.Services
	if len(defs) == 0 {
		return services
	}

	results := make([]ServiceHealth, len(defs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // max 20 concurrent health checks

	for i, def := range defs {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, d ServiceDefinition) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = h.checkRegisteredService(ctx, d)
		}(i, def)
	}
	wg.Wait()

	return append(services, results...)
}

// checkRegisteredService health-checks a service from the registry.
func (h *MetricsHandler) checkRegisteredService(ctx context.Context, def ServiceDefinition) ServiceHealth {
	if def.IsTCP() {
		sh := h.checkTCPService(ctx, def.Name, def.HealthURL())
		sh.Category = def.Category
		return sh
	}

	start := time.Now()
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, def.HealthURL(), nil)
	if err != nil {
		return ServiceHealth{
			Name:      def.Name,
			Status:    metricsStatusUnhealthy,
			LatencyMs: 0,
			LastCheck: time.Now().UTC(),
			Category:  def.Category,
			Details:   map[string]interface{}{"error": err.Error()},
		}
	}
	resp, err := client.Do(httpReq)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return ServiceHealth{
			Name:      def.Name,
			Status:    metricsStatusUnhealthy,
			LatencyMs: latency,
			LastCheck: time.Now().UTC(),
			Category:  def.Category,
			Details:   map[string]interface{}{"error": err.Error()},
		}
	}
	defer resp.Body.Close() //nolint:errcheck

	// Any HTTP response means the service is up. Only 5xx indicates degradation.
	status := metricsStatusHealthy
	if resp.StatusCode >= 500 {
		status = metricsStatusDegraded
	}

	return ServiceHealth{
		Name:      def.Name,
		Status:    status,
		LatencyMs: latency,
		LastCheck: time.Now().UTC(),
		Category:  def.Category,
		Details:   map[string]interface{}{"status_code": resp.StatusCode},
	}
}

func (h *MetricsHandler) checkService(ctx context.Context, name string, checker func(context.Context) (string, int64, map[string]interface{})) ServiceHealth {
	start := time.Now()
	status, latency, details := checker(ctx)
	if latency == 0 {
		latency = time.Since(start).Milliseconds()
	}

	return ServiceHealth{
		Name:      name,
		Status:    status,
		LatencyMs: latency,
		LastCheck: time.Now().UTC(),
		Details:   details,
	}
}

func (h *MetricsHandler) checkPostgres(ctx context.Context) (string, int64, map[string]interface{}) {
	start := time.Now()
	if err := h.db.Ping(ctx); err != nil {
		return metricsStatusUnhealthy, time.Since(start).Milliseconds(), map[string]interface{}{"error": err.Error()}
	}
	return metricsStatusHealthy, time.Since(start).Milliseconds(), nil
}

func (h *MetricsHandler) checkSelf(_ context.Context) (string, int64, map[string]interface{}) {
	return metricsStatusHealthy, 0, map[string]interface{}{
		"goroutines": runtime.NumGoroutine(),
		"version":    "1.0.0",
	}
}

// checkTCPService checks if a TCP service is reachable
func (h *MetricsHandler) checkTCPService(ctx context.Context, name, address string) ServiceHealth {
	start := time.Now()

	// Extract host:port from URL-like format
	host := address
	if len(address) > 7 && address[:7] == "http://" {
		host = address[7:]
	}

	dialer := &net.Dialer{Timeout: 1 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return ServiceHealth{
			Name:      name,
			Status:    metricsStatusUnhealthy,
			LatencyMs: latency,
			LastCheck: time.Now().UTC(),
			Details:   map[string]interface{}{"error": err.Error()},
		}
	}
	conn.Close() //nolint:errcheck,gosec

	return ServiceHealth{
		Name:      name,
		Status:    metricsStatusHealthy,
		LatencyMs: latency,
		LastCheck: time.Now().UTC(),
		Details:   map[string]interface{}{"connection": "ok"},
	}
}

func (h *MetricsHandler) getCacheHealth(ctx context.Context) CacheHealth {
	if h.redisClient == nil {
		return CacheHealth{
			Status: "not_configured",
		}
	}

	start := time.Now()

	// Test Redis connection
	if err := h.redisClient.Health(ctx); err != nil {
		return CacheHealth{
			Status:         metricsStatusUnhealthy,
			ResponseTimeMs: time.Since(start).Milliseconds(),
		}
	}

	latency := time.Since(start).Milliseconds()

	// Get Redis stats
	stats, err := h.redisClient.Stats(ctx)
	if err != nil {
		return CacheHealth{
			Status:         metricsStatusDegraded,
			ResponseTimeMs: latency,
		}
	}

	return CacheHealth{
		Status:              metricsStatusHealthy,
		MemoryUsedMB:        stats.UsedMemoryMB,
		MemoryUsagePercent:  stats.MemoryUsagePercent,
		HitRate:             stats.HitRate,
		HitRatePercent:      stats.HitRate,
		ResponseTimeMs:      latency,
		ConnectedClients:    stats.ConnectedClients,
		OpsPerSecond:        stats.OpsPerSecond,
		TotalKeys:           stats.TotalKeys,
		KeyspaceHits:        stats.KeyspaceHits,
		KeyspaceMisses:      stats.KeyspaceMisses,
		UptimeSeconds:       stats.UptimeSeconds,
		RedisVersion:        stats.RedisVersion,
		MemoryFragmentation: stats.MemoryFragmentation,
	}
}

func (h *MetricsHandler) getDatabaseMetrics(ctx context.Context) DatabaseMetrics {
	metrics := DatabaseMetrics{}

	// Get connection stats from pgxpool
	stats := h.db.Stat()
	metrics.ActiveConnections = int(stats.AcquiredConns())
	metrics.MaxConnections = int(stats.MaxConns())
	if metrics.MaxConnections > 0 {
		metrics.ConnectionUsagePercent = float64(stats.AcquiredConns()) / float64(stats.MaxConns()) * 100
	}

	// Get database size
	var sizeBytes int64
	err := h.db.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&sizeBytes)
	if err == nil {
		metrics.DatabaseSizeGB = float64(sizeBytes) / 1024 / 1024 / 1024
	}

	// Get cache hit ratio
	var hitRatio float64
	err = h.db.QueryRow(ctx, `
		SELECT
			COALESCE(
				sum(heap_blks_hit) / NULLIF(sum(heap_blks_hit) + sum(heap_blks_read), 0),
				0
			) as cache_hit_ratio
		FROM pg_statio_user_tables
	`).Scan(&hitRatio)
	if err == nil {
		metrics.CacheHitRatio = hitRatio
	}

	// Get replication lag (if replica)
	var lagBytes int64
	err = h.db.QueryRow(ctx, `
		SELECT COALESCE(
			pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn),
			0
		)::bigint
		FROM pg_stat_replication
		LIMIT 1
	`).Scan(&lagBytes)
	if err == nil && lagBytes > 0 {
		// Rough estimate: 1MB = ~1ms lag (very approximate)
		metrics.ReplicationLagMs = lagBytes / 1024 / 1024
	}

	return metrics
}

func calcPercent(used, limit int) float64 {
	if limit == 0 {
		return 0
	}
	return float64(used) / float64(limit) * 100
}

// RegisterRoutes registers metrics routes
func (h *MetricsHandler) RegisterRoutes(rg *gin.RouterGroup) {
	metrics := rg.Group("/metrics")
	{
		metrics.GET("/system", h.GetSystemMetrics)
		metrics.GET("/health", h.GetServiceHealth)
		metrics.GET("/resources", h.GetResourceUsage)
		metrics.GET("/database", h.GetDatabaseMetrics)
		metrics.GET("/cache", h.GetCacheMetrics)
	}

	quotas := rg.Group("/quotas")
	{
		quotas.GET("/usage", h.GetQuotaUsage)
		quotas.GET("/:tenant_id", h.GetTenantQuotaUsage)
	}
}

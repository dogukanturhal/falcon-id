// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Client wraps the Redis client with logging and health checks
type Client struct {
	rdb    *redis.Client
	logger *zap.Logger
}

// Config holds Redis connection configuration
// SECURITY: For production deployments, use TLS connections (rediss:// URL scheme)
// or configure TLS explicitly with TLSEnabled=true
type Config struct {
	URL             string
	MaxRetries      int
	MinIdleConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	DialTimeout     time.Duration
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration

	// TLS Configuration
	// SECURITY: Enable TLS for production deployments to encrypt data in transit
	TLSEnabled    bool   // Enable TLS (alternative to using rediss:// URL)
	TLSCACertFile string // Path to CA certificate file for verifying server
	TLSCertFile   string // Path to client certificate file (for mTLS)
	TLSKeyFile    string // Path to client private key file (for mTLS)
	TLSSkipVerify bool   // SECURITY WARNING: Only use in development
	TLSServerName string // Override server name for TLS verification

	// Environment is used to enforce security constraints (e.g. reject TLSSkipVerify in production)
	Environment string
}

// DefaultConfig returns sensible default configuration
func DefaultConfig(url string) *Config {
	return &Config{
		URL:             url,
		MaxRetries:      3,
		MinIdleConns:    5,
		MaxIdleConns:    10,
		ConnMaxLifetime: 30 * time.Minute,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		TLSEnabled:      false,
		TLSSkipVerify:   false,
	}
}

// buildTLSConfig creates a TLS configuration from the Redis config
func buildTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.TLSSkipVerify, //nolint:gosec // InsecureSkipVerify is user-configurable
	}

	// Set server name if provided
	if cfg.TLSServerName != "" {
		tlsConfig.ServerName = cfg.TLSServerName
	}

	// Load CA certificate if provided
	if cfg.TLSCACertFile != "" {
		caCert, err := os.ReadFile(cfg.TLSCACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate and key for mTLS if provided
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// NewClient creates a new Redis client with the given configuration
func NewClient(cfg *Config, logger *zap.Logger) (*Client, error) {
	opt, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	// SECURITY: Reject InsecureSkipVerify in production/staging environments
	if cfg.TLSSkipVerify && (cfg.Environment == "production" || cfg.Environment == "staging") {
		return nil, fmt.Errorf("Redis TLS InsecureSkipVerify is not allowed in %s environment", cfg.Environment)
	}

	opt.MaxRetries = cfg.MaxRetries
	opt.MinIdleConns = cfg.MinIdleConns
	opt.MaxIdleConns = cfg.MaxIdleConns
	opt.ConnMaxLifetime = cfg.ConnMaxLifetime
	opt.DialTimeout = cfg.DialTimeout
	opt.ReadTimeout = cfg.ReadTimeout
	opt.WriteTimeout = cfg.WriteTimeout

	// Configure TLS if enabled (or if URL uses rediss:// scheme)
	if cfg.TLSEnabled && opt.TLSConfig == nil {
		tlsConfig, err := buildTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
		opt.TLSConfig = tlsConfig
		logger.Info("Redis TLS enabled",
			zap.Bool("skip_verify", cfg.TLSSkipVerify),
			zap.Bool("mtls", cfg.TLSCertFile != ""),
		)
	}

	rdb := redis.NewClient(opt)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &Client{
		rdb:    rdb,
		logger: logger,
	}, nil
}

// Close closes the Redis connection
func (c *Client) Close() error {
	return c.rdb.Close()
}

// Health checks the Redis connection health
func (c *Client) Health(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

// Redis returns the underlying Redis client for advanced operations
func (c *Client) Redis() *redis.Client {
	return c.rdb
}

// Get retrieves a value from Redis
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	return c.rdb.Get(ctx, key).Result()
}

// Set stores a value in Redis with expiration
func (c *Client) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return c.rdb.Set(ctx, key, value, expiration).Err()
}

// Del deletes a key from Redis
func (c *Client) Del(ctx context.Context, keys ...string) error {
	return c.rdb.Del(ctx, keys...).Err()
}

// Exists checks if keys exist in Redis
func (c *Client) Exists(ctx context.Context, keys ...string) (int64, error) {
	return c.rdb.Exists(ctx, keys...).Result()
}

// Expire sets a timeout on a key
func (c *Client) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return c.rdb.Expire(ctx, key, expiration).Err()
}

// TTL returns the remaining time to live of a key
func (c *Client) TTL(ctx context.Context, key string) (time.Duration, error) {
	return c.rdb.TTL(ctx, key).Result()
}

// Incr increments the value of a key
func (c *Client) Incr(ctx context.Context, key string) (int64, error) {
	return c.rdb.Incr(ctx, key).Result()
}

// IncrBy increments the value of a key by a specific amount
func (c *Client) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	return c.rdb.IncrBy(ctx, key, value).Result()
}

// SetNX sets a value if the key does not exist
func (c *Client) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	err := c.rdb.SetArgs(ctx, key, value, redis.SetArgs{Mode: "NX", TTL: expiration}).Err()
	if err == redis.Nil {
		return false, nil
	}
	return err == nil, err
}

// Pipeline returns a Redis pipeline for batching commands
func (c *Client) Pipeline() redis.Pipeliner {
	return c.rdb.Pipeline()
}

// TxPipeline returns a Redis transaction pipeline
func (c *Client) TxPipeline() redis.Pipeliner {
	return c.rdb.TxPipeline()
}

// RedisStats contains Redis server statistics.
//
//nolint:revive // stutter accepted: redis.RedisStats is the established API name
type RedisStats struct {
	// Memory
	UsedMemoryBytes     int64   `json:"used_memory_bytes"`
	UsedMemoryMB        float64 `json:"used_memory_mb"`
	MaxMemoryBytes      int64   `json:"max_memory_bytes"`
	MemoryUsagePercent  float64 `json:"memory_usage_percent"`
	MemoryFragmentation float64 `json:"memory_fragmentation_ratio"`

	// Connections
	ConnectedClients int64 `json:"connected_clients"`
	BlockedClients   int64 `json:"blocked_clients"`

	// Stats
	TotalConnectionsReceived int64   `json:"total_connections_received"`
	TotalCommandsProcessed   int64   `json:"total_commands_processed"`
	OpsPerSecond             int64   `json:"ops_per_second"`
	HitRate                  float64 `json:"hit_rate"`
	KeyspaceHits             int64   `json:"keyspace_hits"`
	KeyspaceMisses           int64   `json:"keyspace_misses"`

	// Keys
	TotalKeys   int64 `json:"total_keys"`
	ExpiresKeys int64 `json:"expires_keys"`

	// Server
	UptimeSeconds int64  `json:"uptime_seconds"`
	RedisVersion  string `json:"redis_version"`
}

// Stats returns Redis server statistics
func (c *Client) Stats(ctx context.Context) (*RedisStats, error) {
	// Get INFO command output
	info, err := c.rdb.Info(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get Redis info: %w", err)
	}

	stats := &RedisStats{}

	// Parse INFO output
	parseRedisInfo(info, stats)

	// Get DBSIZE for total keys if not parsed
	if stats.TotalKeys == 0 {
		dbSize, err := c.rdb.DBSize(ctx).Result()
		if err == nil {
			stats.TotalKeys = dbSize
		}
	}

	return stats, nil
}

// parseRedisInfo parses the Redis INFO command output
func parseRedisInfo(info string, stats *RedisStats) {
	lines := make(map[string]string)
	for _, line := range splitLines(info) {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		parts := splitKeyValue(line)
		if len(parts) == 2 {
			lines[parts[0]] = parts[1]
		}
	}

	// Memory
	if v, ok := lines["used_memory"]; ok {
		stats.UsedMemoryBytes = parseInt64(v)
		stats.UsedMemoryMB = float64(stats.UsedMemoryBytes) / 1024 / 1024
	}
	if v, ok := lines["maxmemory"]; ok {
		stats.MaxMemoryBytes = parseInt64(v)
		if stats.MaxMemoryBytes > 0 {
			stats.MemoryUsagePercent = float64(stats.UsedMemoryBytes) / float64(stats.MaxMemoryBytes) * 100
		}
	}
	if v, ok := lines["mem_fragmentation_ratio"]; ok {
		stats.MemoryFragmentation = parseFloat64(v)
	}

	// Connections
	if v, ok := lines["connected_clients"]; ok {
		stats.ConnectedClients = parseInt64(v)
	}
	if v, ok := lines["blocked_clients"]; ok {
		stats.BlockedClients = parseInt64(v)
	}

	// Stats
	if v, ok := lines["total_connections_received"]; ok {
		stats.TotalConnectionsReceived = parseInt64(v)
	}
	if v, ok := lines["total_commands_processed"]; ok {
		stats.TotalCommandsProcessed = parseInt64(v)
	}
	if v, ok := lines["instantaneous_ops_per_sec"]; ok {
		stats.OpsPerSecond = parseInt64(v)
	}
	if v, ok := lines["keyspace_hits"]; ok {
		stats.KeyspaceHits = parseInt64(v)
	}
	if v, ok := lines["keyspace_misses"]; ok {
		stats.KeyspaceMisses = parseInt64(v)
	}

	// Calculate hit rate
	totalOps := stats.KeyspaceHits + stats.KeyspaceMisses
	if totalOps > 0 {
		stats.HitRate = float64(stats.KeyspaceHits) / float64(totalOps) * 100
	}

	// Server
	if v, ok := lines["uptime_in_seconds"]; ok {
		stats.UptimeSeconds = parseInt64(v)
	}
	if v, ok := lines["redis_version"]; ok {
		stats.RedisVersion = v
	}
}

// Helper functions for parsing
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func splitKeyValue(s string) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

func parseInt64(s string) int64 {
	var result int64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*10 + int64(c-'0')
		}
	}
	return result
}

func parseFloat64(s string) float64 {
	var result float64
	var decimal float64
	var inDecimal bool

	for _, c := range s {
		if c == '.' {
			inDecimal = true
			decimal = 0.1
			continue
		}
		if c >= '0' && c <= '9' {
			if inDecimal {
				result += float64(c-'0') * decimal
				decimal *= 0.1
			} else {
				result = result*10 + float64(c-'0')
			}
		}
	}
	return result
}

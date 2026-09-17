// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

const (
	// meterKeyTTL keeps counters in Redis for 25 hours so the background
	// flusher has a full hour of slack after a bucket closes before the data
	// would be evicted.
	meterKeyTTL = 25 * time.Hour
)

// MeteringMiddleware records per-tenant API consumption into Redis hash counters
// keyed by tenant and UTC-hour bucket.
//
// Key format:  meter:{tenant_id}:{YYYYMMDDHH}
// Hash fields: requests, errors, compute_ms
//
// A background MeteringFlusher drains these counters into iam_tenant_usage_records
// once per hour.  When Redis is unavailable the middleware is a no-op so it
// never blocks the request path.
//
// The tenant ID is read from the "tenant_id" Gin context key populated by the
// ExtractTenant middleware that runs earlier in the chain.
func MeteringMiddleware(redisClient redis.Cmdable) gin.HandlerFunc {
	return func(c *gin.Context) {
		if redisClient == nil {
			c.Next()
			return
		}

		start := time.Now()
		c.Next()
		elapsed := time.Since(start)

		tenantID, ok := c.Get("tenant_id")
		if !ok || tenantID == "" {
			return
		}

		// Hourly bucket: YYYYMMDDHH in UTC.
		hour := time.Now().UTC().Truncate(time.Hour).Format("2006010215")
		key := fmt.Sprintf("meter:%v:%s", tenantID, hour)

		ctx := context.Background()

		pipe := redisClient.Pipeline()
		pipe.HIncrBy(ctx, key, "requests", 1)
		pipe.HIncrByFloat(ctx, key, "compute_ms", float64(elapsed.Milliseconds()))
		if c.Writer.Status() >= 500 {
			pipe.HIncrBy(ctx, key, "errors", 1)
		}
		// Refresh TTL on every write.  The flusher deletes the key after
		// successfully persisting it, so the TTL is a safety net for orphaned keys.
		pipe.Expire(ctx, key, meterKeyTTL)

		if _, err := pipe.Exec(ctx); err != nil {
			// Metering is best-effort — log at debug level and continue.
			// We deliberately do not import the logger package here to keep
			// this middleware lightweight and dependency-free.
			_ = err
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

const (
	// throttleDelay is injected into every request from a noisy tenant.
	throttleDelay = 100 * time.Millisecond
)

// TenantThrottleMiddleware reads the per-tenant noisy-neighbor flag written by
// TenantResourceMonitor and applies back-pressure:
//
//   - Flag value == "1": add a 100 ms delay and set X-RateLimit-Throttled header.
//   - Flag value >= "2": return HTTP 429 Too Many Requests immediately.
//   - Flag absent / Redis unavailable: pass through unchanged (fail-open).
//
// The tenant ID is read from the "tenant_id" Gin context key that is populated
// by the ExtractTenant middleware earlier in the chain.
func TenantThrottleMiddleware(redisClient redis.Cmdable) gin.HandlerFunc {
	return func(c *gin.Context) {
		if redisClient == nil {
			c.Next()
			return
		}

		tenantID, ok := c.Get("tenant_id")
		if !ok || tenantID == "" {
			c.Next()
			return
		}

		noisyKey := fmt.Sprintf("tenant_noisy:%v", tenantID)
		val, err := redisClient.Get(context.Background(), noisyKey).Result()
		if err != nil {
			c.Next()
			return
		}

		level := parseTenantNoisyLevel(val)

		switch level {
		case 1:
			time.Sleep(throttleDelay)
			c.Header("X-RateLimit-Throttled", "true")
		case 2:
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":   "tenant_throttled",
				"message": "This tenant is consuming excessive platform resources. Please reduce request rate.",
			})
			return
		}

		c.Next()
	}
}

// parseTenantNoisyLevel converts the Redis flag value to a throttle level (0=none, 1=soft, 2=hard).
func parseTenantNoisyLevel(val string) int {
	switch val {
	case "":
		return 0
	case "1":
		return 1
	default:
		if val >= "2" {
			return 2
		}
		return 1
	}
}

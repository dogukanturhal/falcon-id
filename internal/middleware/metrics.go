// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/dogukanturhal/falcon-id/pkg/metrics"
)

var (
	// uuidRegex matches UUID patterns in paths
	uuidRegex = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	// numericRegex matches numeric IDs in paths
	numericRegex = regexp.MustCompile(`/\d+(/|$)`)
)

// normalizePathForMetrics reduces cardinality by replacing UUIDs/IDs with placeholders
func normalizePathForMetrics(path string) string {
	// Replace UUIDs with :id
	normalized := uuidRegex.ReplaceAllString(path, ":id")
	// Replace numeric IDs with :id
	normalized = numericRegex.ReplaceAllString(normalized, "/:id$1")
	return normalized
}

// PrometheusMetrics returns a middleware that records HTTP metrics
func PrometheusMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Get path for metrics (use route template if available)
		path := c.FullPath()
		if path == "" {
			path = normalizePathForMetrics(c.Request.URL.Path)
		}
		method := c.Request.Method

		// Track requests in flight
		metrics.HTTPRequestsInFlight.Inc()
		defer metrics.HTTPRequestsInFlight.Dec()

		c.Next()

		// Record metrics after request completes
		status := strconv.Itoa(c.Writer.Status())
		duration := time.Since(start).Seconds()

		metrics.HTTPRequestsTotal.WithLabelValues(method, path, status).Inc()
		metrics.HTTPRequestDuration.WithLabelValues(method, path).Observe(duration)
	}
}

// isUUID checks if a string is a valid UUID
func isUUID(s string) bool {
	return len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-'
}

// isNumeric checks if a string contains only digits
func isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// normalizePathSegments normalizes path by replacing dynamic segments
func normalizePathSegments(path string) string {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if isUUID(seg) || isNumeric(seg) {
			segments[i] = ":id"
		}
	}
	return strings.Join(segments, "/")
}

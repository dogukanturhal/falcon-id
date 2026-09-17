// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const provisioningStateActive = "active"

// HTTPModuleEntitlementChecker checks module entitlement via HTTP calls to db-provisioner,
// with Redis caching to avoid per-request HTTP calls.
//
// Fail-open behavior: HTTP errors or cache misses result in allowing access.
type HTTPModuleEntitlementChecker struct {
	dbProvisionerURL string
	httpClient       *http.Client
	redisClient      goredis.Cmdable
	cacheTTL         time.Duration
}

// NewHTTPModuleEntitlementChecker creates a new HTTP-backed entitlement checker.
// cacheTTL defaults to 60 seconds if zero.
func NewHTTPModuleEntitlementChecker(dbProvisionerURL string, redisClient goredis.Cmdable) *HTTPModuleEntitlementChecker {
	return &HTTPModuleEntitlementChecker{
		dbProvisionerURL: dbProvisionerURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		redisClient: redisClient,
		cacheTTL:    60 * time.Second,
	}
}

// instanceListResponse is the shape returned by db-provisioner's
// GET /api/v1/platform/instances?tenant_id=X&state=active endpoint.
type instanceListResponse struct {
	Items []struct {
		ProductSlug       string `json:"product_slug"`
		ProvisioningState string `json:"provisioning_state"`
	} `json:"items"`
}

// IsTenantEntitled checks if the tenant has an active product instance that
// provides the requested module. Fail-open: returns (true, nil) on any HTTP error.
func (c *HTTPModuleEntitlementChecker) IsTenantEntitled(ctx context.Context, tenantID uuid.UUID, module string) (bool, error) {
	cacheKey := fmt.Sprintf("entitlement:%s:%s", tenantID.String(), module)

	// 1. Check Redis cache first.
	if c.redisClient != nil {
		cached, err := c.redisClient.Get(ctx, cacheKey).Result()
		if err == nil {
			return cached == "1", nil
		}
		// Cache miss or error — continue to HTTP call.
	}

	// 2. Call db-provisioner.
	url := fmt.Sprintf("%s/api/v1/platform/instances?tenant_id=%s&state=active", c.dbProvisionerURL, tenantID.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		logger.Warn("HTTPModuleEntitlementChecker: failed to build request (fail-open)",
			zap.String("tenant_id", tenantID.String()),
			zap.String("module", module),
			zap.Error(err),
		)
		return true, nil
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Warn("HTTPModuleEntitlementChecker: HTTP call failed (fail-open)",
			zap.String("tenant_id", tenantID.String()),
			zap.String("module", module),
			zap.Error(err),
		)
		return true, nil
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		logger.Warn("HTTPModuleEntitlementChecker: non-200 response (fail-open)",
			zap.String("tenant_id", tenantID.String()),
			zap.String("module", module),
			zap.Int("status", resp.StatusCode),
		)
		return true, nil
	}

	var payload instanceListResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		logger.Warn("HTTPModuleEntitlementChecker: failed to decode response (fail-open)",
			zap.String("tenant_id", tenantID.String()),
			zap.String("module", module),
			zap.Error(err),
		)
		return true, nil
	}

	// 3. Check if any active instance matches the requested module.
	entitled := false
	for _, item := range payload.Items {
		if item.ProvisioningState == provisioningStateActive && item.ProductSlug == module {
			entitled = true
			break
		}
	}

	// 4. Cache the result.
	if c.redisClient != nil {
		value := "0"
		if entitled {
			value = "1"
		}
		if setErr := c.redisClient.Set(ctx, cacheKey, value, c.cacheTTL).Err(); setErr != nil {
			logger.Debug("HTTPModuleEntitlementChecker: failed to cache result",
				zap.String("cache_key", cacheKey),
				zap.Error(setErr),
			)
		}
	}

	return entitled, nil
}

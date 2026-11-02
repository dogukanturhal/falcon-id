// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	// apiKeyExchangeKeyLimit bounds exchanges per (key_id, client IP): a
	// well-behaved integration exchanges once per token TTL (10 minutes).
	apiKeyExchangeKeyLimit = 30
	// apiKeyExchangeIPLimit bounds all exchanges from one IP, including
	// unparseable credentials and key_id guessing across many ids.
	apiKeyExchangeIPLimit = 120
	// apiKeyExchangeWindow is the fixed window for both counters.
	apiKeyExchangeWindow = time.Minute
	// apiKeyExchangeMaxBody caps the bytes read to find the credentials.
	apiKeyExchangeMaxBody = 8 << 10
)

// APIKeyExchangeRateLimit limits POST /oauth/token/api-key. The bucket key uses
// the PARSED key_id (public lookup id) plus the client IP; the raw client_id is
// never used because it can carry the whole secret. Unparseable credentials fall
// back to the IP-only bucket. A nil Redis client fails open (development).
func APIKeyExchangeRateLimit(rdb redis.Cmdable, log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if rdb == nil {
			c.Next()
			return
		}
		ip := RealClientIP(c)
		keys := []struct {
			key   string
			limit int64
		}{{"apikey_exch:ip:" + ip, apiKeyExchangeIPLimit}}
		if keyID, ok := apiKeyExchangeKeyID(c); ok {
			keys = append(keys, struct {
				key   string
				limit int64
			}{"apikey_exch:kid:" + keyID + ":" + ip, apiKeyExchangeKeyLimit})
		}
		for _, k := range keys {
			n, err := incrWindow(c.Request.Context(), rdb, k.key)
			if err != nil {
				if log != nil {
					log.Warn("api key exchange limiter: redis error, failing open", zap.Error(err))
				}
				continue
			}
			if n > k.limit {
				retry := int64(apiKeyExchangeWindow.Seconds())
				c.Header("Retry-After", strconv.FormatInt(retry, 10))
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"error":             "slow_down",
					"error_description": "too many API key exchange attempts; retry later",
				})
				return
			}
		}
		c.Next()
	}
}

func incrWindow(ctx context.Context, rdb redis.Cmdable, key string) (int64, error) {
	n, err := incrWindowScript.Run(ctx, rdb, []string{key}, int(apiKeyExchangeWindow.Seconds())).Int64()
	if err != nil {
		return 0, fmt.Errorf("incr %s: %w", key, err)
	}
	return n, nil
}

// incrWindowScript is INCR plus EXPIRE on the first hit, atomically; it avoids
// EXPIRE NX, which needs Redis 7+.
var incrWindowScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return n`)

// apiKeyExchangeKeyID extracts the parsed key_id from the request body without
// consuming it (the handler binds the same body afterwards).
func apiKeyExchangeKeyID(c *gin.Context) (string, bool) {
	if c.Request.Body == nil {
		return "", false
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, apiKeyExchangeMaxBody+1))
	if err != nil {
		return "", false
	}
	// Restore the full body for the handler (including any bytes past the cap).
	c.Request.Body = io.NopCloser(io.MultiReader(bytes.NewReader(raw), c.Request.Body))
	if len(raw) > apiKeyExchangeMaxBody {
		return "", false
	}
	var clientID, clientSecret string
	if strings.HasPrefix(c.ContentType(), "application/json") {
		var req struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		if json.Unmarshal(raw, &req) != nil {
			return "", false
		}
		clientID, clientSecret = req.ClientID, req.ClientSecret
	} else {
		form, err := url.ParseQuery(string(raw))
		if err != nil {
			return "", false
		}
		clientID, clientSecret = form.Get("client_id"), form.Get("client_secret")
	}
	keyID, _, ok := services.ParseAPIKeyExchangeCredentials(clientID, clientSecret)
	return keyID, ok
}

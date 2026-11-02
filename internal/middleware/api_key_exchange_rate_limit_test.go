// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

func exchangeRouter(t *testing.T) (*gin.Engine, *miniredis.Miniredis, *string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	var seenBody string
	r := gin.New()
	r.POST("/oauth/token/api-key", APIKeyExchangeRateLimit(rdb, nil), func(c *gin.Context) {
		var req struct {
			ClientID string `form:"client_id"`
		}
		_ = c.ShouldBind(&req)
		seenBody = req.ClientID
		c.Status(http.StatusUnauthorized)
	})
	return r, mr, &seenBody
}

func postExchange(r *gin.Engine, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/token/api-key", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.9:4000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAPIKeyExchangeRateLimit_KeysOnParsedKeyIDNeverTheSecret(t *testing.T) {
	r, mr, seen := exchangeRouter(t)
	keyID, secret, full, err := services.GenerateTenantAPIKey()
	require.NoError(t, err)

	for i := 0; i < apiKeyExchangeKeyLimit; i++ {
		assert.Equal(t, http.StatusUnauthorized, postExchange(r, url.Values{"client_id": {full}}).Code)
	}
	assert.Equal(t, full, *seen, "handler must still see the unmodified body")
	assert.Equal(t, http.StatusTooManyRequests, postExchange(r, url.Values{"client_id": {full}}).Code)

	// Same key_id sent as split client_id/client_secret shares the bucket.
	assert.Equal(t, http.StatusTooManyRequests,
		postExchange(r, url.Values{"client_id": {"lgk_live_" + keyID}, "client_secret": {secret}}).Code)

	for _, k := range mr.Keys() {
		assert.NotContains(t, k, secret, "redis keys must never contain the secret")
	}
	assert.Contains(t, mr.Keys(), "apikey_exch:kid:"+keyID+":203.0.113.9")
}

func TestAPIKeyExchangeRateLimit_UnparseableCredentialsUseIPBucketOnly(t *testing.T) {
	r, mr, _ := exchangeRouter(t)

	for i := 0; i < apiKeyExchangeIPLimit; i++ {
		assert.Equal(t, http.StatusUnauthorized, postExchange(r, url.Values{"client_id": {"garbage-secret-material"}}).Code)
	}
	assert.Equal(t, http.StatusTooManyRequests, postExchange(r, url.Values{"client_id": {"other"}}).Code)
	assert.Equal(t, []string{"apikey_exch:ip:203.0.113.9"}, mr.Keys())
}

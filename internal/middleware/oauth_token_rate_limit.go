// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// oauthTokenBurstConfig protects /oauth/token from a single misconfigured
// client looping refresh / token-exchange. Per-client limits, not
// global, so one noisy client can't starve the queue for the rest of
// the platform. The IP-fallback config below is a defense-in-depth
// layer for malformed requests where no client_id can be parsed.
//
// Burst: 60 req in 60 seconds with a 1-minute block. Sized to absorb
// a token-cache stampede on a redeploy of a moderately-trafficked app
// (each replica refreshing every 13 min → at most a few req/sec) while
// catching a runaway client doing 1 req/sec sustained.
var oauthTokenBurstConfig = AuthRateLimitConfig{
	MaxRequests:   60,
	WindowSeconds: 60,
	BlockDuration: 1 * time.Minute,
}

// oauthTokenHourlyConfig is the sustained-traffic ceiling. Same key
// as the burst limiter so the limits stack: a client blocked on the
// hourly window stays blocked even if it slows below the burst rate.
//
// Sized at 600/hour ≈ 10/min average. A first-party app refreshing
// tokens every 13 minutes per replica with 50 replicas would do
// 50 / (13/60) ≈ 230/hour, well under the limit.
var oauthTokenHourlyConfig = AuthRateLimitConfig{
	MaxRequests:   600,
	WindowSeconds: 3600,
	BlockDuration: 5 * time.Minute,
}

// OAuthTokenPerUserClients (config OAUTH_TOKEN_PER_USER_CLIENT_IDS) lists
// clients whose /oauth/token calls are bucketed per end user instead of per
// client: confidential BFFs that call on behalf of every signed-in user
// (acmeapp-bff) and public native clients, where every install shares one
// client_id. A per-client key would put all users in one 60/min bucket, so
// one busy minute would lock everyone out; these clients' burst/hourly
// windows apply per end user instead (LD-R3-TX-3), under a client-wide
// backstop.

// oauthTokenPerUserClientBurstConfig / ...HourlyConfig cap a per-user
// client as a whole. The per-user key is derived from the request before
// client authentication, so a caller can vary it; the backstop keeps that
// from becoming unbounded while leaving room for the whole user base.
var oauthTokenPerUserClientBurstConfig = AuthRateLimitConfig{
	MaxRequests:   3000,
	WindowSeconds: 60,
	BlockDuration: 1 * time.Minute,
}

var oauthTokenPerUserClientHourlyConfig = AuthRateLimitConfig{
	MaxRequests:   60000,
	WindowSeconds: 3600,
	BlockDuration: 5 * time.Minute,
}

// OAuthTokenRateLimit returns gin middleware that rate-limits requests
// to /oauth/token on a per-client_id key. The identifier is resolved
// from (in order):
//
//  1. POST form field client_id (RFC 6749 §2.3.1).
//  2. Basic auth Authorization header — `Basic base64(client_id:secret)`
//     per RFC 6749 §2.3.1 client_secret_basic. We decode and take the
//     username portion only; the secret is irrelevant for rate limiting
//     and reading it here keeps it out of any logs the limiter writes.
//  3. Falls back to remote IP when neither parses, so malformed bodies
//     can't bypass the limiter by omitting client_id.
//
// Two sliding windows are checked per identifier:
//   - 60 req / 60 s burst (60 s block on trip)
//   - 600 req / 3600 s hourly (5 min block on trip)
//
// This is the cheapest DoS-prevention layer for /oauth/token, the
// single endpoint with the heaviest cryptographic cost (RS256 sign +
// DB write on every successful issuance) per request.
//
// For the multi-user BFFs in oauthTokenPerUserClients the two windows are
// keyed per end user (see resolveOAuthTokenUserKey) and the client as a
// whole is held to the larger backstop windows.
func OAuthTokenRateLimit(perUserClientIDs []string) gin.HandlerFunc {
	perUserClients := make(map[string]bool, len(perUserClientIDs))
	for _, id := range perUserClientIDs {
		perUserClients[id] = true
	}
	return func(c *gin.Context) {
		identifier := resolveOAuthTokenIdentifier(c)
		now := time.Now()

		if cid, ok := strings.CutPrefix(identifier, "cid:"); ok && perUserClients[cid] {
			if _, blocked := checkAndRecordSlidingWindow(
				"oauth_token_client_burst:"+identifier, now, oauthTokenPerUserClientBurstConfig,
			); blocked {
				abortOAuthTokenRateLimited(c, oauthTokenPerUserClientBurstConfig.BlockDuration)
				return
			}
			if _, blocked := checkAndRecordSlidingWindow(
				"oauth_token_client_hourly:"+identifier, now, oauthTokenPerUserClientHourlyConfig,
			); blocked {
				abortOAuthTokenRateLimited(c, oauthTokenPerUserClientHourlyConfig.BlockDuration)
				return
			}
			identifier += "|" + resolveOAuthTokenUserKey(c)
		}

		burstRemaining, burstBlocked := checkAndRecordSlidingWindow(
			"oauth_token_burst:"+identifier, now, oauthTokenBurstConfig,
		)
		if burstBlocked {
			abortOAuthTokenRateLimited(c, oauthTokenBurstConfig.BlockDuration)
			return
		}
		hourlyRemaining, hourlyBlocked := checkAndRecordSlidingWindow(
			"oauth_token_hourly:"+identifier, now, oauthTokenHourlyConfig,
		)
		if hourlyBlocked {
			abortOAuthTokenRateLimited(c, oauthTokenHourlyConfig.BlockDuration)
			return
		}

		remaining := burstRemaining
		if hourlyRemaining < remaining {
			remaining = hourlyRemaining
		}
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))

		c.Next()
	}
}

// resolveOAuthTokenIdentifier returns the per-client rate-limit key.
// Prefers client_id over IP because IP-keying alone would let a single
// host running many clients (e.g. a Crossplane Composition fanning out
// per-service Jobs from the same node) starve itself, while a single
// client running across many replicas would each get their own burst
// budget.
func resolveOAuthTokenIdentifier(c *gin.Context) string {
	if cid := c.PostForm("client_id"); cid != "" {
		return "cid:" + cid
	}
	if cid := decodeBasicAuthClientID(c.GetHeader("Authorization")); cid != "" {
		return "cid:" + cid
	}
	// Fallback: same shape as RemoteAddr-based limiters elsewhere so a
	// malformed request looks identical to those in dashboards.
	host, _ := parseRemoteHost(c.Request.RemoteAddr)
	return "ip:" + host
}

// resolveOAuthTokenUserKey derives the end-user half of a per-user client's
// rate-limit key from the grant's own credential:
//
//   - token exchange: for a client that authenticates (client_secret,
//     Basic, client_assertion) the subject token's sub, parsed WITHOUT
//     verification (only a bucket name; the grant verifies the token); for a
//     public client the subject token digest, because anyone can forge
//     sub=<victim> and lock that user out;
//   - refresh_token / authorization_code: digest of the credential (opaque
//     values, so the digest is the stable per-session handle available here);
//   - otherwise the remote IP.
//
// Raw credentials never become part of the key.
func resolveOAuthTokenUserKey(c *gin.Context) string {
	if st := c.PostForm("subject_token"); st != "" {
		if oauthTokenClientAuthenticates(c) {
			claims := jwt.MapClaims{}
			if _, _, err := jwt.NewParser().ParseUnverified(st, claims); err == nil {
				if sub, _ := claims["sub"].(string); sub != "" {
					return "sub:" + sub
				}
			}
		}
		return "st:" + credentialDigest(st)
	}
	if rt := c.PostForm("refresh_token"); rt != "" {
		return "rt:" + credentialDigest(rt)
	}
	if code := c.PostForm("code"); code != "" {
		return "code:" + credentialDigest(code)
	}
	host, _ := parseRemoteHost(c.Request.RemoteAddr)
	return "ip:" + host
}

// oauthTokenClientAuthenticates reports whether the request carries client
// credentials (confidential client). The limiter runs before authentication,
// so this is a presence check only; a forged value just selects the
// unverified-sub bucket for a client that is listed per-user anyway.
func oauthTokenClientAuthenticates(c *gin.Context) bool {
	return strings.HasPrefix(c.GetHeader("Authorization"), "Basic ") ||
		c.PostForm("client_secret") != "" ||
		c.PostForm("client_assertion") != ""
}

func credentialDigest(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:16])
}

// decodeBasicAuthClientID extracts the client_id (Basic-auth username)
// from an Authorization header. Returns "" on any decode error or when
// the header is empty / not Basic. The secret half is dropped on the
// floor — we never want it in any rate-limit-related log line.
func decodeBasicAuthClientID(authHeader string) string {
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, prefix))
	if err != nil {
		return ""
	}
	idx := strings.IndexByte(string(raw), ':')
	if idx < 0 {
		return ""
	}
	return string(raw[:idx])
}

// parseRemoteHost trims an optional port off a "host:port" RemoteAddr.
// Returns the host alone, or the original string when it doesn't parse.
func parseRemoteHost(remoteAddr string) (host string, ok bool) {
	if i := strings.LastIndexByte(remoteAddr, ':'); i > 0 {
		return remoteAddr[:i], true
	}
	return remoteAddr, false
}

// abortOAuthTokenRateLimited responds with 429 + Retry-After in the
// shape OAuth clients expect (per RFC 6585 §4 + RFC 6749 error format).
func abortOAuthTokenRateLimited(c *gin.Context, blockDuration time.Duration) {
	retryAfter := int64(blockDuration.Seconds())
	if retryAfter < 1 {
		retryAfter = 1
	}
	c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
	c.Header("X-RateLimit-Remaining", "0")
	c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
		"error":             "slow_down",
		"error_description": "/oauth/token rate limit exceeded for this client; back off and retry after the Retry-After window",
	})
}

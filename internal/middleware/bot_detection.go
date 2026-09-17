// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// botScoreKey is the Gin context key used to propagate the computed bot score
// to downstream handlers. Use c.GetFloat64("bot_score") to read it.
const botScoreKey = "bot_score"

// BotDetectionMiddleware wraps BotDetectionService as a Gin middleware.
type BotDetectionMiddleware struct {
	service *services.BotDetectionService
}

// NewBotDetectionMiddleware creates a BotDetectionMiddleware.
func NewBotDetectionMiddleware(service *services.BotDetectionService) *BotDetectionMiddleware {
	return &BotDetectionMiddleware{service: service}
}

// BotDetection returns a Gin HandlerFunc that:
//   - Extracts IP, User-Agent, headers, and path from the request.
//   - Calls BotDetectionService.EvaluateRequest().
//   - Blocks   (HTTP 403) when action == "block",   sets X-Bot-Detection: blocked.
//   - Challenges (HTTP 429) when action == "challenge", sets X-Bot-Detection: challenge
//     and includes the challenge type in the JSON body.
//   - Allows  when action == "allow", sets c.Set("bot_score", score) and continues.
func (m *BotDetectionMiddleware) BotDetection() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Bot detection scores the real client public IP — keying on the
		// APISIX pod IP would lump every request into one bucket and
		// trip the credential-velocity / fingerprint detectors on every
		// concurrent request from any legitimate user.
		ip := ClientIP(c.Request)
		ua := c.GetHeader("User-Agent")
		path := c.Request.URL.Path

		// Build a normalised header map for the fingerprint detector.
		// We copy only the headers the detector cares about to avoid
		// allocating a full copy of the large request header map.
		headers := extractFingerprintHeaders(c)

		// Extract the username field from the query string or a previously
		// parsed body value stored in the Gin context by an earlier middleware.
		// Fall back to empty string when not available; the credential-velocity
		// detector simply skips evaluation in that case.
		username, _ := c.Get("login_username")
		usernameStr, _ := username.(string)

		result := m.service.EvaluateRequest(c.Request.Context(), ip, ua, headers, path, usernameStr)

		switch result.Action {
		case "block":
			logger.Log.Info("bot_detection: blocking request",
				zap.String("ip", ip),
				zap.String("path", path),
				zap.Float64("score", result.Score),
				zap.Any("signals", result.Signals),
			)
			c.Header("X-Bot-Detection", "blocked")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":     "Request blocked: automated client detected.",
				"bot_score": result.Score,
			})
			return

		case "challenge":
			logger.Log.Info("bot_detection: issuing challenge",
				zap.String("ip", ip),
				zap.String("path", path),
				zap.Float64("score", result.Score),
				zap.String("challenge_type", string(result.ChallengeType)),
				zap.Any("signals", result.Signals),
			)
			c.Header("X-Bot-Detection", "challenge")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":          "Challenge required before this request can be processed.",
				"challenge_type": string(result.ChallengeType),
				"bot_score":      result.Score,
			})
			return

		default:
			// action == "allow" — propagate the score for downstream telemetry.
			c.Set(botScoreKey, result.Score)
			c.Next()
		}
	}
}

// extractFingerprintHeaders returns a map of the specific headers the
// fingerprint detector uses. Extracting only the required headers avoids
// iterating over the full http.Header map on every request.
func extractFingerprintHeaders(c *gin.Context) map[string]string {
	headers := make(map[string]string, 5)
	for _, name := range []string{
		"Accept-Language",
		"Referer",
		"Accept",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
	} {
		if v := c.GetHeader(name); v != "" {
			headers[name] = v
		}
	}
	return headers
}

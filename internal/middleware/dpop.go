// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/dpop"
)

// ginContextKey is the Gin context key under which the raw Bearer/DPoP access
// token is stored by auth middleware, enabling ath verification downstream.
const ginContextKeyRawToken = "raw_access_token"

// DPoPMiddleware validates DPoP proof JWTs on incoming requests and prevents
// JTI replay attacks using Redis. It implements RFC 9449 server-side
// requirements for Demonstrating Proof of Possession.
type DPoPMiddleware struct {
	redis  goredis.Cmdable
	logger *zap.Logger
}

// NewDPoPMiddleware creates a new DPoP middleware instance backed by the
// provided Redis client for JTI replay detection.
func NewDPoPMiddleware(redis goredis.Cmdable, logger *zap.Logger) *DPoPMiddleware {
	return &DPoPMiddleware{
		redis:  redis,
		logger: logger,
	}
}

// RequireDPoP returns a gin.HandlerFunc that enforces DPoP token binding on
// every request. Requests missing a valid DPoP proof are rejected.
//
// On success the following values are stored in the Gin context for downstream
// handlers (e.g. the token service):
//   - "dpop_jkt" (string): JWK SHA-256 thumbprint of the proof key
//   - "dpop_jti" (string): unique proof identifier that was consumed
//
// The token service should compare dpop_jkt against the cnf.jkt claim of the
// associated access token to complete binding verification.
func (m *DPoPMiddleware) RequireDPoP() gin.HandlerFunc {
	return func(c *gin.Context) {
		proofJWT := c.GetHeader("DPoP")
		if proofJWT == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "missing DPoP proof header",
			})
			return
		}

		// RFC 9449 §4.2: htu must be the request URI without query and fragment.
		expectedURI := buildRequestURI(c.Request)

		proof, err := dpop.ValidateProof(proofJWT, c.Request.Method, expectedURI)
		if err != nil {
			m.logger.Warn("DPoP proof validation failed",
				zap.String("path", c.Request.URL.Path),
				zap.String("method", c.Request.Method),
				zap.Error(err),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": fmt.Sprintf("invalid DPoP proof: %s", err.Error()),
			})
			return
		}

		// Atomically check and store the JTI to prevent replay attacks.
		if err := m.checkAndStoreJTI(c.Request.Context(), proof.JTI); err != nil {
			m.logger.Warn("DPoP JTI replay detected or cache error",
				zap.String("jti", proof.JTI),
				zap.String("path", c.Request.URL.Path),
				zap.Error(err),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "DPoP proof replay detected",
			})
			return
		}

		c.Set("dpop_jkt", proof.JKT)
		c.Set("dpop_jti", proof.JTI)
		// Store ath for later verification by VerifyTokenBinding.
		// Empty string is stored when the claim is absent (token endpoint flow).
		c.Set("dpop_ath", proof.ATH)

		c.Next()
	}
}

// OptionalDPoP returns a gin.HandlerFunc that validates DPoP if the proof
// header is present, but does not require it.
//
// Behaviour:
//   - Header absent: request continues without DPoP context values set.
//   - Header present and valid: dpop_jkt and dpop_jti are stored in context.
//   - Header present but invalid: request is rejected with 401.
//
// This is appropriate for endpoints that support both plain Bearer tokens and
// DPoP-bound tokens.
func (m *DPoPMiddleware) OptionalDPoP() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.ValidateProofIntoContext(c) {
			return
		}
		c.Next()
	}
}

// BindJKTOnRequest is the token-endpoint counterpart to
// ValidateProofIntoContext. Token-issuance handlers (login, refresh,
// MFA complete, code exchange, social callback, context switch) call
// this BEFORE generating a new access token so that:
//
//   - A presented DPoP proof is validated (signature + htm + htu + iat)
//     and JTI-replay-checked against Redis (exactly like the resource-
//     server path).
//   - The resulting JWK thumbprint is stashed on the request context
//     via dpop.WithJKT so the token generators can pick it up and
//     embed cnf.jkt into the new access token — no additional
//     parameters to thread through every issuance call site.
//
// Returns (newCtx, true) on success (including the "no header present"
// case, which returns the original ctx with JKT=""). Returns
// (request-context, false) when the request has been aborted — callers
// must return immediately to honour the abort.
func (m *DPoPMiddleware) BindJKTOnRequest(c *gin.Context) (context.Context, bool) {
	if !m.ValidateProofIntoContext(c) {
		return c.Request.Context(), false
	}
	jkt := c.GetString("dpop_jkt")
	if jkt == "" {
		// No DPoP header — plain bearer issuance. Not an error.
		return c.Request.Context(), true
	}
	return dpop.WithJKT(c.Request.Context(), jkt), true
}

// ValidateProofIntoContext extracts + validates a DPoP proof when present and
// stores the result on the gin context. It does NOT call c.Next(); callers
// advance the chain themselves. Returns false when the request has been
// aborted (bad proof or replay), true otherwise — including the case when
// no proof header is present (backwards-compatible bearer-token path).
//
// Extracted so AuthMiddleware.RequireAuth can call the same validator
// inline after its own token check, without relying on multiple gin.Use()
// registrations that would require touching every route group.
func (m *DPoPMiddleware) ValidateProofIntoContext(c *gin.Context) bool {
	proofJWT := c.GetHeader("DPoP")
	if proofJWT == "" {
		return true
	}

	expectedURI := buildRequestURI(c.Request)
	proof, err := dpop.ValidateProof(proofJWT, c.Request.Method, expectedURI)
	if err != nil {
		m.logger.Warn("DPoP proof validation failed",
			zap.String("path", c.Request.URL.Path),
			zap.String("method", c.Request.Method),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": fmt.Sprintf("invalid DPoP proof: %s", err.Error()),
		})
		return false
	}

	if err := m.checkAndStoreJTI(c.Request.Context(), proof.JTI); err != nil {
		m.logger.Warn("DPoP JTI replay detected or cache error",
			zap.String("jti", proof.JTI),
			zap.String("path", c.Request.URL.Path),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "DPoP proof replay detected",
		})
		return false
	}

	c.Set("dpop_jkt", proof.JKT)
	c.Set("dpop_jti", proof.JTI)
	c.Set("dpop_ath", proof.ATH)
	return true
}

// VerifyTokenBinding is a standalone gin.HandlerFunc that checks whether the
// DPoP JKT from the validated proof matches the cnf.jkt claim in the access
// token, and that the ath (access token hash) claim in the proof matches the
// SHA-256 hash of the presented access token (RFC 9449 §4.3).
//
// It must be placed after both the auth middleware (which sets "token_cnf_jkt"
// and optionally "raw_access_token") and RequireDPoP (which sets "dpop_jkt"
// and "dpop_ath").
//
// Checks:
//  1. JKT binding: proof key matches the cnf.jkt in the access token.
//  2. ATH binding: proof ath matches BASE64URL(SHA-256(access_token)).
//
// Both checks are skipped independently if the prerequisite context values are
// absent — this allows the same route to serve both DPoP-bound and unbound
// tokens without requiring changes to every route.
func VerifyTokenBinding(c *gin.Context) {
	if !VerifyTokenBindingInline(c) {
		return
	}
	c.Next()
}

// VerifyTokenBindingInline performs the JKT + ATH binding verification
// without advancing the gin chain. Same abort-vs-continue contract as
// ValidateProofIntoContext: returns false when the request has been
// aborted, true otherwise (including the pass-through cases where no
// binding is applicable).
func VerifyTokenBindingInline(c *gin.Context) bool {
	tokenJKT, tokenExists := c.Get("token_cnf_jkt")
	if !tokenExists {
		// The access token carries no cnf.jkt — it was not issued with DPoP
		// binding, so binding verification is not applicable. Nothing to
		// enforce; a bare bearer token is acceptable.
		return true
	}

	proofJKT, proofExists := c.Get("dpop_jkt")
	if !proofExists {
		// The token IS DPoP-bound but no proof was presented — this is a
		// hard reject. Without requiring the proof, the cnf.jkt claim
		// would provide zero protection.
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "DPoP-bound token requires a DPoP proof header",
		})
		return false
	}

	// 1. JKT binding check.
	if proofJKT.(string) != tokenJKT.(string) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "DPoP token binding mismatch: proof key does not match bound key",
		})
		return false
	}

	// 2. ATH binding check (RFC 9449 §4.3).
	proofATH, athExists := c.Get("dpop_ath")
	rawToken, rawExists := c.Get(ginContextKeyRawToken)
	if athExists && rawExists {
		proofATHStr, _ := proofATH.(string)
		rawTokenStr, _ := rawToken.(string)
		if proofATHStr != "" && rawTokenStr != "" {
			expectedATH := dpop.AccessTokenHash(rawTokenStr)
			if proofATHStr != expectedATH {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "DPoP ath mismatch: access token hash does not match proof",
				})
				return false
			}
		}
	}

	return true
}

// checkAndStoreJTI uses Redis SETNX to atomically record the JTI and detect
// replays. It returns nil on the first occurrence of a JTI and a non-nil error
// if the JTI has been seen before or if Redis is unavailable.
//
// The TTL is MaxProofAge plus a 30-second buffer so that JTIs are retained in
// Redis for slightly longer than the validity window, preventing a race at the
// boundary.
func (m *DPoPMiddleware) checkAndStoreJTI(ctx context.Context, jti string) error {
	key := "dpop:jti:" + jti
	ttl := dpop.MaxProofAge + 30*time.Second

	set, err := m.redis.SetNX(ctx, key, "1", ttl).Result()
	if err != nil {
		return fmt.Errorf("DPoP JTI cache error: %w", err)
	}
	if !set {
		return fmt.Errorf("JTI %q already seen (replay attempt)", jti)
	}
	return nil
}

// buildRequestURI constructs the canonical request URI required by RFC 9449
// §4.2 for DPoP htu validation: scheme + "://" + host + path, with no query
// string or fragment.
//
// The scheme is determined from:
//  1. TLS state of the underlying connection (HTTPS if TLS is active).
//  2. X-Forwarded-Proto header (for requests arriving behind a TLS-terminating
//     reverse proxy such as APISIX).
//  3. Plain HTTP as the fallback for local / development requests.
func buildRequestURI(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = strings.ToLower(proto)
		} else {
			scheme = "http"
		}
	}
	return fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)
}

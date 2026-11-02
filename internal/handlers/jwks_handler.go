// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/keys"
)

// JWKSHandler serves the /.well-known/jwks.json endpoint for platform-issued JWTs
// (access tokens, refresh tokens, service tokens). OIDC OAuth tokens are served by
// OAuthProviderHandler.GetJWKS — this handler covers the RS256 migration for session JWTs.
//
// When a KeyManager is wired (DB-backed keys), the endpoint returns ALL active and
// rotated keys so clients can validate tokens issued before a key rotation.
// The response is cached and invalidated when the key set changes.
type JWKSHandler struct {
	mu          sync.RWMutex
	keyProvider *crypto.JWTKeyProvider
	keyManager  *keys.KeyManager
	// oauthKeys is an optional additional key set contributed by the OAuth provider (merged
	// output). When nil, only the platform key is returned.
	oauthKeysFunc func() []models.JWK

	// cached response fields — invalidated when the key provider is swapped.
	cached    *models.JWKSet
	cachedKID string

	// maxAge is the Cache-Control max-age (seconds) advertised to clients. It must stay
	// well under the key publish delay so a pending key is seen before it signs.
	maxAge time.Duration
}

// NewJWKSHandler creates a JWKSHandler. keyProvider may be nil when the service is
// started in HS256-only mode; in that case the endpoint returns an empty key set.
func NewJWKSHandler(keyProvider *crypto.JWTKeyProvider) *JWKSHandler {
	return &JWKSHandler{keyProvider: keyProvider, maxAge: defaultJWKSMaxAge}
}

// defaultJWKSMaxAge is the default Cache-Control max-age for the JWKS response.
const defaultJWKSMaxAge = 300 * time.Second

// SetMaxAge overrides the Cache-Control max-age of the JWKS response (d <= 0 is ignored).
func (h *JWKSHandler) SetMaxAge(d time.Duration) {
	if d <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.maxAge = d
}

// SetOAuthKeysFunc wires in a function that returns the current OAuth key set so that
// the unified JWKS endpoint can merge platform and OAuth keys in a single response.
// This avoids clients having to call two endpoints.
func (h *JWKSHandler) SetOAuthKeysFunc(fn func() []models.JWK) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.oauthKeysFunc = fn
	h.cached = nil // invalidate cache
}

// SetKeyProvider replaces the current key provider and invalidates the cached response.
// Safe to call concurrently.
func (h *JWKSHandler) SetKeyProvider(p *crypto.JWTKeyProvider) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keyProvider = p
	h.cached = nil
	h.cachedKID = ""
}

// SetKeyManager wires in the DB-backed key manager. When set, buildJWKS uses
// KeyManager.AllPublicKeys() instead of the single JWTKeyProvider key, enabling
// graceful key rotation (all active+rotated keys served in a single JWKS response).
func (h *JWKSHandler) SetKeyManager(km *keys.KeyManager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keyManager = km
	h.cached = nil
	h.cachedKID = ""
}

// GetJWKS handles GET /.well-known/platform-jwks.json
//
// @Summary  Platform JWT public keys
// @Tags     well-known
// @Produce  json
// @Success  200  {object}  models.JWKSet
// @Router   /.well-known/platform-jwks.json [get]
func (h *JWKSHandler) GetJWKS(c *gin.Context) {
	jwks := h.buildJWKS()
	h.mu.RLock()
	maxAge := h.maxAge
	h.mu.RUnlock()
	c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d", int(maxAge.Seconds())))
	c.JSON(http.StatusOK, jwks)
}

// buildJWKS assembles and caches the JWKSet. When a KeyManager is wired, all
// active+rotated keys are included so clients can validate tokens issued before a
// key rotation. The cache is keyed by the current active key ID so that a rotation
// is reflected in the next request after the cache is invalidated.
func (h *JWKSHandler) buildJWKS() *models.JWKSet {
	h.mu.Lock()
	defer h.mu.Unlock()

	currentKID := h.resolveCurrentKID()
	if h.cached != nil && h.cachedKID == currentKID {
		return h.cached
	}

	jwks := h.collectKeys()
	jwks = h.mergeOAuthKeys(jwks)

	h.cached = &models.JWKSet{Keys: jwks}
	h.cachedKID = currentKID
	return h.cached
}

// resolveCurrentKID returns the key ID of the currently active signing key.
func (h *JWKSHandler) resolveCurrentKID() string {
	if h.keyManager != nil {
		// The key-set version is part of the cache key so pending/rotated/retired
		// changes (which do not change the active kid) also invalidate the cache.
		suffix := "@" + strconv.FormatUint(h.keyManager.Version(), 10)
		if _, kid, err := h.keyManager.ActiveKey(); err == nil {
			return kid + suffix
		}
		return suffix
	}
	if h.keyProvider != nil {
		return h.keyProvider.KeyID()
	}
	return ""
}

// collectKeys builds the JWK list from either the DB-backed key manager
// or the legacy single-key provider.
func (h *JWKSHandler) collectKeys() []models.JWK {
	if h.keyManager != nil {
		return h.collectKeyManagerKeys()
	}
	if h.keyProvider != nil {
		return h.collectKeyProviderKey()
	}
	return nil
}

// collectKeyManagerKeys returns JWKs for all non-revoked keys in the DB-backed manager.
func (h *JWKSHandler) collectKeyManagerKeys() []models.JWK {
	var jwks []models.JWK
	for _, info := range h.keyManager.AllPublicKeys() {
		rsaPub, ok := info.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		jwks = append(jwks, models.JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: info.Algorithm,
			Kid: info.KeyID,
			N:   base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPub.E)).Bytes()),
		})
	}
	return jwks
}

// collectKeyProviderKey returns the JWK for the single ephemeral key from the legacy provider.
func (h *JWKSHandler) collectKeyProviderKey() []models.JWK {
	pub := h.keyProvider.PublicKey()
	return []models.JWK{{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: h.keyProvider.KeyID(),
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}
}

// mergeOAuthKeys deduplicates and appends OAuth provider keys to the existing list.
func (h *JWKSHandler) mergeOAuthKeys(jwks []models.JWK) []models.JWK {
	if h.oauthKeysFunc == nil {
		return jwks
	}
	oauthKeys := h.oauthKeysFunc()
	seen := make(map[string]struct{}, len(jwks))
	for _, k := range jwks {
		seen[k.Kid] = struct{}{}
	}
	for _, k := range oauthKeys {
		if _, dup := seen[k.Kid]; !dup {
			jwks = append(jwks, k)
			seen[k.Kid] = struct{}{}
		}
	}
	return jwks
}

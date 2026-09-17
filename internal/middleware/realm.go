// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// RealmMiddleware handles realm context extraction and validation
type RealmMiddleware struct {
	realmService *services.RealmService
	config       *config.Config
	logger       *zap.Logger

	// Configuration
	subdomainEnabled bool
	headerEnabled    bool
	urlPrefixEnabled bool
	defaultRealmSlug string
}

// RealmMiddlewareConfig holds configuration for the realm middleware
type RealmMiddlewareConfig struct {
	SubdomainEnabled bool
	HeaderEnabled    bool
	URLPrefixEnabled bool
	DefaultRealmSlug string
}

// NewRealmMiddleware creates a new realm middleware
func NewRealmMiddleware(realmService *services.RealmService, cfg *config.Config, log *zap.Logger) *RealmMiddleware {
	return &RealmMiddleware{
		realmService:     realmService,
		config:           cfg,
		logger:           log,
		subdomainEnabled: true,
		headerEnabled:    true,
		urlPrefixEnabled: true,
		defaultRealmSlug: "default",
	}
}

// Configure updates the middleware configuration
func (m *RealmMiddleware) Configure(cfg RealmMiddlewareConfig) {
	m.subdomainEnabled = cfg.SubdomainEnabled
	m.headerEnabled = cfg.HeaderEnabled
	m.urlPrefixEnabled = cfg.URLPrefixEnabled
	if cfg.DefaultRealmSlug != "" {
		m.defaultRealmSlug = cfg.DefaultRealmSlug
	}
}

// ExtractRealm extracts and validates realm context from the request
// Priority: URL prefix > Header > Subdomain > Default realm
func (m *RealmMiddleware) ExtractRealm() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to resolve realm via custom domain first (short-circuit path)
		if handled := m.tryResolveByCustomDomain(c); handled {
			return
		}

		realmSlug, realmID, extractionSource := m.extractRealmIdentifiers(c)

		realm, err := m.resolveRealm(c, realmSlug, realmID, extractionSource)
		if err != nil {
			return // resolveRealm already called AbortWithStatusJSON
		}

		if statusErr := m.checkRealmStatus(c, realm); statusErr != nil {
			return // checkRealmStatus already called AbortWithStatusJSON
		}

		setRealmContext(c, realm, extractionSource)
		c.Next()
	}
}

// tryResolveByCustomDomain attempts to resolve realm via custom domain lookup.
// Returns true if the request was handled (so caller should return immediately).
func (m *RealmMiddleware) tryResolveByCustomDomain(c *gin.Context) bool {
	host := c.Request.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	realm, err := m.realmService.GetByDomain(c.Request.Context(), host)
	if err != nil || realm == nil {
		return false
	}
	setRealmContext(c, realm, "custom_domain")
	c.Next()
	return true
}

// extractRealmIdentifiers resolves the realm slug, ID, and extraction source from the request.
func (m *RealmMiddleware) extractRealmIdentifiers(c *gin.Context) (realmSlug string, realmID *uuid.UUID, extractionSource string) {
	// Priority 1: URL prefix /realms/{slug}/...
	if m.urlPrefixEnabled {
		if slug := c.Param("realm_slug"); slug != "" {
			return slug, nil, "url_prefix"
		}
	}

	// Priority 2: Header X-Realm-ID or X-Realm-Slug
	if m.headerEnabled {
		if idStr := c.GetHeader("X-Realm-ID"); idStr != "" {
			if id, err := uuid.Parse(idStr); err == nil {
				return "", &id, "header_id"
			}
		}
		if slug := c.GetHeader("X-Realm-Slug"); slug != "" {
			return slug, nil, "header_slug"
		}
	}

	// Priority 3: Subdomain extraction (e.g., acme.hexxlock.com -> acme)
	if m.subdomainEnabled {
		host := c.Request.Host
		subdomain := extractSubdomain(host)
		if subdomain != "" && subdomain != "www" && subdomain != "api" {
			return subdomain, nil, "subdomain"
		}
	}

	// Priority 4: Default realm
	return m.defaultRealmSlug, nil, "default"
}

// resolveRealm fetches the realm from the service and handles not-found / error cases.
// On error it aborts the context and returns a non-nil error so the caller can return early.
func (m *RealmMiddleware) resolveRealm(c *gin.Context, realmSlug string, realmID *uuid.UUID, extractionSource string) (*models.Realm, error) {
	var realm *models.Realm
	var err error

	switch {
	case realmID != nil:
		realm, err = m.realmService.GetByID(c.Request.Context(), *realmID)
	case realmSlug != "":
		realm, err = m.realmService.GetBySlug(c.Request.Context(), realmSlug)
	}

	if err != nil {
		idStr := ""
		if realmID != nil {
			idStr = realmID.String()
		}
		m.logger.Error("Failed to resolve realm", zap.Error(err), zap.String("slug", realmSlug), zap.String("id", idStr))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to resolve realm",
			"code":  "REALM_RESOLUTION_ERROR",
		})
		return nil, err
	}

	if realm != nil {
		return realm, nil
	}

	// Realm not found — try default realm fallback or return 404
	if extractionSource == "default" {
		defaultRealm, defaultErr := m.realmService.GetDefaultRealm(c.Request.Context())
		if defaultErr != nil || defaultRealm == nil {
			m.logger.Error("Default realm not found", zap.Error(defaultErr))
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "Default realm not found",
				"code":  "DEFAULT_REALM_NOT_FOUND",
			})
			return nil, errRealmNotFound
		}
		return defaultRealm, nil
	}

	c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
		"error": "Realm not found",
		"code":  "REALM_NOT_FOUND",
		"slug":  realmSlug,
	})
	return nil, errRealmNotFound
}

// errRealmNotFound is a sentinel error used internally when a realm is not found.
var errRealmNotFound = &realmNotFoundError{}

type realmNotFoundError struct{}

func (e *realmNotFoundError) Error() string { return "realm not found" }

// checkRealmStatus validates the realm status and aborts with 403 when not active.
func (m *RealmMiddleware) checkRealmStatus(c *gin.Context, realm *models.Realm) error {
	if realm.Status == models.RealmStatusActive {
		return nil
	}
	statusMessage := realmStatusMessage(realm.Status)
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":  statusMessage,
		"code":   "REALM_NOT_ACTIVE",
		"status": realm.Status,
	})
	return errRealmNotFound
}

// realmStatusMessage returns a human-readable message for a non-active realm status.
func realmStatusMessage(status models.RealmStatus) string {
	switch status {
	case models.RealmStatusSuspended:
		return "Realm is suspended"
	case models.RealmStatusMigrating:
		return "Realm is undergoing maintenance"
	case models.RealmStatusArchived:
		return "Realm has been archived"
	default:
		return "Realm is not available"
	}
}

// RequireRealm ensures a realm context is present (used after ExtractRealm)
func (m *RealmMiddleware) RequireRealm() gin.HandlerFunc {
	return func(c *gin.Context) {
		realm := GetCurrentRealm(c)
		if realm == nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Realm context is required",
				"code":  "REALM_REQUIRED",
			})
			return
		}
		c.Next()
	}
}

// OptionalRealm extracts realm context if available but doesn't require it
func (m *RealmMiddleware) OptionalRealm() gin.HandlerFunc {
	return func(c *gin.Context) {
		if handled := m.tryOptionalRealmFromHeaderID(c); handled {
			return
		}

		realmSlug := m.resolveOptionalRealmSlug(c)
		if realmSlug != "" {
			realm, err := m.realmService.GetBySlug(c.Request.Context(), realmSlug)
			if err == nil && realm != nil && realm.Status == models.RealmStatusActive {
				setRealmContext(c, realm, "optional")
			}
		}

		c.Next()
	}
}

// tryOptionalRealmFromHeaderID attempts X-Realm-ID header resolution.
// Returns true when a resolution was attempted via X-Realm-ID (caller should call c.Next and return).
func (m *RealmMiddleware) tryOptionalRealmFromHeaderID(c *gin.Context) bool {
	idStr := c.GetHeader("X-Realm-ID")
	if idStr == "" {
		return false
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		// Invalid UUID — skip silently (optional realm)
		c.Next()
		return true
	}

	realm, err := m.realmService.GetByID(c.Request.Context(), id)
	if err == nil && realm != nil {
		setRealmContext(c, realm, "header_id")
	}
	c.Next()
	return true
}

// resolveOptionalRealmSlug returns the slug to use for optional realm resolution.
func (m *RealmMiddleware) resolveOptionalRealmSlug(c *gin.Context) string {
	if slug := c.GetHeader("X-Realm-Slug"); slug != "" {
		return slug
	}
	return c.Param("realm_slug")
}

// setRealmContext sets the realm context in the Gin context
func setRealmContext(c *gin.Context, realm *models.Realm, source string) {
	c.Set("realm", realm)
	c.Set("realm_id", realm.ID)
	c.Set("realm_slug", realm.Slug)
	c.Set("realm_type", string(realm.Type))
	c.Set("realm_source", source)
}

// extractSubdomain extracts the subdomain from a host
// e.g., "acme.hexxlock.com" -> "acme"
// e.g., "api.acme.hexxlock.com" -> "acme" (skips "api")
func extractSubdomain(host string) string {
	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Split by dots
	parts := strings.Split(host, ".")

	// Need at least 3 parts for a subdomain (subdomain.domain.tld)
	if len(parts) < 3 {
		return ""
	}

	// If first part is "api" or "www", check the second part
	subdomain := parts[0]
	if subdomain == "api" || subdomain == "www" {
		if len(parts) >= 4 {
			return parts[1]
		}
		return ""
	}

	return subdomain
}

// ==================== Context Helpers ====================

// GetCurrentRealm returns the current realm from the context
func GetCurrentRealm(c *gin.Context) *models.Realm {
	if realm, exists := c.Get("realm"); exists {
		if r, ok := realm.(*models.Realm); ok {
			return r
		}
	}
	return nil
}

// GetCurrentRealmID returns the current realm ID from the context
func GetCurrentRealmID(c *gin.Context) *uuid.UUID {
	if realmID, exists := c.Get("realm_id"); exists {
		if id, ok := realmID.(uuid.UUID); ok {
			return &id
		}
	}
	return nil
}

// GetCurrentRealmSlug returns the current realm slug from the context
func GetCurrentRealmSlug(c *gin.Context) string {
	if slug, exists := c.Get("realm_slug"); exists {
		if s, ok := slug.(string); ok {
			return s
		}
	}
	return ""
}

// GetRealmType returns the current realm type from the context
func GetRealmType(c *gin.Context) models.RealmType {
	if realmType, exists := c.Get("realm_type"); exists {
		if t, ok := realmType.(string); ok {
			return models.RealmType(t)
		}
	}
	return ""
}

// GetRealmSource returns the source of realm extraction
func GetRealmSource(c *gin.Context) string {
	if source, exists := c.Get("realm_source"); exists {
		if s, ok := source.(string); ok {
			return s
		}
	}
	return ""
}

// MustGetCurrentRealm returns the current realm or aborts the request if not found.
// Use this only in handlers where realm is guaranteed to exist.
// Note: This function aborts the request with 500 error instead of panicking.
func MustGetCurrentRealm(c *gin.Context) *models.Realm {
	realm := GetCurrentRealm(c)
	if realm == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "realm not found in context - ensure RealmMiddleware is applied",
			"code":  "REALM_CONTEXT_MISSING",
		})
		return nil
	}
	return realm
}

// MustGetCurrentRealmID returns the current realm ID or aborts the request if not found.
// Note: This function aborts the request with 500 error instead of panicking.
func MustGetCurrentRealmID(c *gin.Context) uuid.UUID {
	realmID := GetCurrentRealmID(c)
	if realmID == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "realm_id not found in context - ensure RealmMiddleware is applied",
			"code":  "REALM_CONTEXT_MISSING",
		})
		return uuid.Nil
	}
	return *realmID
}

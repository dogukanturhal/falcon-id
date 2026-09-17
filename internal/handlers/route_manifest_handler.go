// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// routeManifestRepo is the narrow repository interface required by
// RouteManifestHandler.
type routeManifestRepo interface {
	UpsertBatch(ctx context.Context, entries []repositories.RouteManifestEntry) (inserted, updated int, err error)
	ListByService(ctx context.Context, serviceSlug string) ([]repositories.RouteManifestEntry, error)
	ListAll(ctx context.Context) ([]repositories.RouteManifestEntry, error)
}

// RouteManifestHandler handles service route manifest self-registration and
// inspection endpoints.
type RouteManifestHandler struct {
	repo routeManifestRepo
	log  *zap.SugaredLogger
}

// NewRouteManifestHandler creates the handler.
func NewRouteManifestHandler(repo routeManifestRepo, log *zap.SugaredLogger) *RouteManifestHandler {
	return &RouteManifestHandler{repo: repo, log: log}
}

// RouteEntry is a single route declaration within a RegisterRouteManifestRequest.
type RouteEntry struct {
	// URIPrefix is the path prefix this service serves, e.g. "/api/v1/crm/".
	URIPrefix string `json:"uri_prefix" binding:"required"`

	// UpstreamHost is the hostname or IP of the service container, e.g. "crm-service".
	UpstreamHost string `json:"upstream_host" binding:"required"`

	// UpstreamPort is the TCP port the service listens on, e.g. 8080.
	UpstreamPort int `json:"upstream_port" binding:"required"`

	// Methods lists the HTTP methods this route accepts.  Defaults to the full
	// set [GET, POST, PUT, PATCH, DELETE, OPTIONS] when omitted.
	Methods []string `json:"methods,omitempty"`

	// RequireAuth indicates whether APISIX should enforce JWT authentication on
	// this prefix.  Defaults to true for all routes; set to false only for
	// public endpoints such as health checks or SAML metadata.
	RequireAuth bool `json:"require_auth"`
}

// RegisterRouteManifestRequest is the JSON body for the registration endpoint.
type RegisterRouteManifestRequest struct {
	// ServiceSlug identifies the calling service, e.g. "crm" or "workflow-engine".
	ServiceSlug string `json:"service_slug" binding:"required"`

	// Routes is the full list of routes this service registration declares.
	// All entries are upserted atomically (best-effort — no transaction across
	// multiple rows because each row targets a distinct key).
	Routes []RouteEntry `json:"routes" binding:"required,min=1"`
}

// RegisterRouteManifestResponse is returned after a successful upsert.
type RegisterRouteManifestResponse struct {
	ServiceSlug string `json:"service_slug"`
	Registered  int    `json:"registered"`
	Updated     int    `json:"updated"`
	Total       int    `json:"total"`
}

// Register handles POST /api/v1/internal/route-manifest/register.
// Services call this on startup to declare the route prefixes they serve.
// The endpoint is idempotent: repeated calls update existing rows.
func (h *RouteManifestHandler) Register(c *gin.Context) {
	var req RegisterRouteManifestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate port range, upstream host safety, and build domain entries.
	entries := make([]repositories.RouteManifestEntry, 0, len(req.Routes))
	for i, r := range req.Routes {
		if !isValidUpstreamHost(r.UpstreamHost) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("routes[%d]: upstream_host %q is not allowed", i, r.UpstreamHost),
			})
			return
		}
		if r.UpstreamPort < 1 || r.UpstreamPort > 65535 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("routes[%d]: upstream_port %d is out of range (1–65535)", i, r.UpstreamPort),
			})
			return
		}
		entries = append(entries, repositories.RouteManifestEntry{
			ServiceSlug:  req.ServiceSlug,
			URIPrefix:    r.URIPrefix,
			UpstreamHost: r.UpstreamHost,
			UpstreamPort: r.UpstreamPort,
			Methods:      r.Methods,
			RequireAuth:  r.RequireAuth,
		})
	}

	inserted, updated, err := h.repo.UpsertBatch(c.Request.Context(), entries)
	if err != nil {
		h.log.Errorw("Route manifest upsert failed",
			"service_slug", req.ServiceSlug,
			"error", err,
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register route manifest"})
		return
	}

	h.log.Infow("Route manifest registered",
		"service_slug", req.ServiceSlug,
		"inserted", inserted,
		"updated", updated,
	)

	c.JSON(http.StatusOK, RegisterRouteManifestResponse{
		ServiceSlug: req.ServiceSlug,
		Registered:  inserted,
		Updated:     updated,
		Total:       inserted + updated,
	})
}

// ListByService handles GET /api/v1/internal/route-manifest/:service_slug.
// Returns all registered routes for the given service.
func (h *RouteManifestHandler) ListByService(c *gin.Context) {
	slug := c.Param("service_slug")
	if slug == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "service_slug path parameter is required"})
		return
	}

	entries, err := h.repo.ListByService(c.Request.Context(), slug)
	if err != nil {
		h.log.Errorw("Failed to list route manifests by service",
			"service_slug", slug,
			"error", err,
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list route manifests"})
		return
	}

	if entries == nil {
		entries = []repositories.RouteManifestEntry{}
	}

	c.JSON(http.StatusOK, gin.H{
		"service_slug": slug,
		"routes":       entries,
		"total":        len(entries),
	})
}

// ListAll handles GET /api/v1/internal/route-manifest.
// Returns all registered routes across every service.  Intended for platform
// admin tooling and APISIX sync jobs.
func (h *RouteManifestHandler) ListAll(c *gin.Context) {
	entries, err := h.repo.ListAll(c.Request.Context())
	if err != nil {
		h.log.Errorw("Failed to list all route manifests", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list route manifests"})
		return
	}

	if entries == nil {
		entries = []repositories.RouteManifestEntry{}
	}

	c.JSON(http.StatusOK, gin.H{
		"routes": entries,
		"total":  len(entries),
	})
}

// isValidUpstreamHost validates that an upstream host is safe to register.
// It rejects IPs (including localhost, metadata services, private ranges),
// known infrastructure service names, and hostnames with suspicious characters.
func isValidUpstreamHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))

	// Block empty
	if host == "" {
		return false
	}

	// Block localhost variants
	if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
		return false
	}

	// Block metadata service IPs (cloud environments)
	if strings.HasPrefix(host, "169.254.") {
		return false
	}

	// Block all raw IP addresses — only allow hostnames
	if net.ParseIP(host) != nil {
		return false
	}

	// Block internal infrastructure services
	blocked := []string{"postgres", "redis", "kafka", "vault", "etcd", "spicedb", "minio"}
	for _, b := range blocked {
		if host == b {
			return false
		}
	}

	// Must look like a valid service hostname (alphanumeric, hyphens, dots)
	for _, r := range host {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.' {
			return false
		}
	}

	return true
}

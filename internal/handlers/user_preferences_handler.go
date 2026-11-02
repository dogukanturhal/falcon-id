// SPDX-License-Identifier: AGPL-3.0-or-later

// Package handlers — UserPreferencesHandler serves the
// /api/v1/users/me/preferences surface.
//
// URL contract (2026-06-02 Option C research — Microsoft Graph-style,
// identity-anchored, no tenant ID in path):
//
//   GET   /api/v1/users/me/preferences                         → full prefs object
//   PATCH /api/v1/users/me/preferences/global                  → JSON Merge Patch onto preferences.global
//   PATCH /api/v1/users/me/preferences/products/{product}      → JSON Merge Patch onto preferences.products.<slug>
//
// GET returns the entire bag so the client can render initial state for
// every namespace it cares about in one round-trip. PATCH paths are
// per-namespace so a AcmeWeb PATCH can't accidentally clobber Hexx-Forge
// state, and a future Hexx-Cloud product can write its subtree without
// even reading siblings.
//
// AuthZ: handler runs behind authMiddleware.RequireAuth() (applied at
// the route-group level in cmd/routes.go). Every operation acts on
// `users.me` — the user_id is read from the JWT-derived context via
// middleware.GetCurrentUserID. Cross-user reads/writes are not
// reachable here; admin-tier user prefs management lives under the
// existing /users/{id} surface with permCoreUsersUpdate.
package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// Cap on the PATCH body — preferences shouldn't be huge. 64KB leaves
// massive headroom for any realistic UI prefs but rejects malicious
// payloads early. Compare to settings handlers which use the same
// shape (handler reads with limited io.LimitReader before unmarshalling).
const maxPreferencesPatchBytes = 64 * 1024

// UserPreferencesHandler is the public type wired in NewHandlers.
type UserPreferencesHandler struct {
	svc    *services.UserPreferencesService
	logger *zap.Logger
}

// NewUserPreferencesHandler constructs a handler.
func NewUserPreferencesHandler(svc *services.UserPreferencesService, logger *zap.Logger) *UserPreferencesHandler {
	return &UserPreferencesHandler{svc: svc, logger: logger}
}

// Get returns the full preferences object for the authenticated user.
// GET /api/v1/users/me/preferences
func (h *UserPreferencesHandler) Get(c *gin.Context) {
	uid := middleware.GetCurrentUserID(c)
	if uid == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	raw, err := h.svc.Get(c.Request.Context(), *uid)
	if err != nil {
		h.logger.Error("user preferences get", zap.Error(err), zap.Stringer("user_id", *uid))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read preferences"})
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

// PatchGlobal merges the request body into preferences.global.
// PATCH /api/v1/users/me/preferences/global
func (h *UserPreferencesHandler) PatchGlobal(c *gin.Context) {
	uid := middleware.GetCurrentUserID(c)
	if uid == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	body, err := readPatchBody(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	out, err := h.svc.PatchGlobal(c.Request.Context(), *uid, body)
	if err != nil {
		h.respondPatchError(c, err, *uid)
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", out)
}

// PatchProduct merges the request body into preferences.products.<slug>.
// PATCH /api/v1/users/me/preferences/products/:product
func (h *UserPreferencesHandler) PatchProduct(c *gin.Context) {
	uid := middleware.GetCurrentUserID(c)
	if uid == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	slug := c.Param("product")
	if !services.IsKnownProduct(slug) {
		// Surface as 404 rather than 400 — from the client's perspective
		// the URL is for an unknown resource. Matches Microsoft Graph's
		// "open extensions" behaviour on unknown owner appIds.
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown product"})
		return
	}
	body, err := readPatchBody(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	out, err := h.svc.PatchProduct(c.Request.Context(), *uid, slug, body)
	if err != nil {
		h.respondPatchError(c, err, *uid)
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", out)
}

// readPatchBody reads + validates the JSON Merge Patch body shape (must
// be a JSON object, bounded size).
func readPatchBody(c *gin.Context) (json.RawMessage, error) {
	defer func() { _ = c.Request.Body.Close() }()
	bytes, err := io.ReadAll(io.LimitReader(c.Request.Body, maxPreferencesPatchBytes+1))
	if err != nil {
		return nil, errors.New("could not read request body")
	}
	if len(bytes) > maxPreferencesPatchBytes {
		return nil, errors.New("request body too large")
	}
	if len(bytes) == 0 {
		return nil, errors.New("request body must be a JSON object")
	}
	return json.RawMessage(bytes), nil
}

// respondPatchError maps service-layer errors to HTTP responses without
// leaking internals.
func (h *UserPreferencesHandler) respondPatchError(c *gin.Context, err error, uid uuid.UUID) {
	switch {
	case errors.Is(err, services.ErrPrefsNotObject), errors.Is(err, services.ErrPrefsInvalidShape):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, services.ErrPrefsUnknownProduct):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	default:
		h.logger.Error("user preferences patch", zap.Error(err), zap.Stringer("user_id", uid))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to patch preferences"})
	}
}

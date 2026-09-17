// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgTAPAuthRequired = "authentication required"
	timeFmtTAPISO8601  = "2006-01-02T15:04:05Z"
)

// TempAccessPassHandler exposes HTTP endpoints for administering Temporary Access Passes.
// TAPs are short-lived, high-entropy codes that allow a user to authenticate
// without their normal credential — analogous to Microsoft Entra's TAP feature.
type TempAccessPassHandler struct {
	tapService *services.TempAccessPassService
}

// NewTempAccessPassHandler creates a TempAccessPassHandler backed by the given service.
func NewTempAccessPassHandler(tapService *services.TempAccessPassService) *TempAccessPassHandler {
	return &TempAccessPassHandler{tapService: tapService}
}

// generateTAPRequest is the JSON body accepted by the Create endpoint.
type generateTAPRequest struct {
	UserID      uuid.UUID `json:"user_id" binding:"required"`
	IsOneTime   bool      `json:"is_one_time"`
	MaxUses     int       `json:"max_uses"`
	DurationMin int       `json:"duration_minutes"` // defaults to 60 when ≤ 0
}

// generateTAPResponse is returned by the Create endpoint.
// The Plaintext field is populated only on creation and is never stored or
// returned again — the caller must record it immediately.
type generateTAPResponse struct {
	ID            uuid.UUID `json:"id"`
	Plaintext     string    `json:"pass"` // shown exactly once
	UserID        uuid.UUID `json:"user_id"`
	IsOneTime     bool      `json:"is_one_time"`
	MaxUses       int       `json:"max_uses"`
	UsesRemaining int       `json:"uses_remaining"`
	ExpiresAt     string    `json:"expires_at"`
	CreatedAt     string    `json:"created_at"`
}

// Create issues a new Temporary Access Pass for the requested user.
//
// @Summary Create Temporary Access Pass
// @Description Issues a new TAP for a user; the plaintext pass is returned only once and cannot be recovered
// @Tags Temporary Access Pass
// @Accept json
// @Produce json
// @Param request body generateTAPRequest true "TAP configuration (user_id, duration, one-time flag)"
// @Success 201 {object} generateTAPResponse "Created TAP with plaintext pass"
// @Failure 400 {object} map[string]string "Validation error or invalid duration"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/temp-access-passes [post]
func (h *TempAccessPassHandler) Create(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgTAPAuthRequired})
		return
	}

	var req generateTAPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	durationMin := req.DurationMin
	if durationMin <= 0 {
		durationMin = 60 // default 1 hour
	}
	if durationMin > 1440 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "duration_minutes cannot exceed 1440 (24 hours)"})
		return
	}

	maxUses := req.MaxUses
	if maxUses <= 0 {
		maxUses = 1
	}
	if req.IsOneTime {
		maxUses = 1
	}

	plaintext, err := h.tapService.GeneratePass(
		c.Request.Context(),
		req.UserID,
		currentUser.TenantID,
		currentUser.ID,
		req.IsOneTime,
		maxUses,
		durationMin,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create temporary access pass"})
		return
	}

	// List the passes to find the newly created one so we can return its metadata.
	passes, err := h.tapService.ListPasses(c.Request.Context(), req.UserID, currentUser.TenantID)
	if err != nil || len(passes) == 0 {
		// Even if the list fails, the pass was created. Return minimal metadata.
		c.JSON(http.StatusCreated, gin.H{
			"pass":    plaintext,
			"user_id": req.UserID,
			"message": "temporary access pass created; metadata unavailable",
		})
		return
	}

	// The most recently created pass for this user is the one we just issued.
	newest := passes[0]
	for _, p := range passes[1:] {
		if p.CreatedAt.After(newest.CreatedAt) {
			newest = p
		}
	}

	c.JSON(http.StatusCreated, generateTAPResponse{
		ID:            newest.ID,
		Plaintext:     plaintext,
		UserID:        newest.UserID,
		IsOneTime:     newest.IsOneTime,
		MaxUses:       newest.MaxUses,
		UsesRemaining: newest.UsesRemaining,
		ExpiresAt:     newest.ExpiresAt.Format(timeFmtTAPISO8601),
		CreatedAt:     newest.CreatedAt.Format(timeFmtTAPISO8601),
	})
}

// List returns all Temporary Access Passes for a given user.
//
// @Summary List Temporary Access Passes
// @Description Returns all active and expired TAPs for the specified user within the current tenant
// @Tags Temporary Access Pass
// @Produce json
// @Param user_id query string true "User UUID to list passes for"
// @Success 200 {object} map[string]interface{} "List of TAPs and count"
// @Failure 400 {object} map[string]string "Missing or invalid user_id"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/temp-access-passes [get]
func (h *TempAccessPassHandler) List(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgTAPAuthRequired})
		return
	}

	userIDStr := c.Query("user_id")
	if userIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id query parameter is required"})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}

	passes, err := h.tapService.ListPasses(c.Request.Context(), userID, currentUser.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list temporary access passes"})
		return
	}

	type tapSummary struct {
		ID            uuid.UUID `json:"id"`
		UserID        uuid.UUID `json:"user_id"`
		IsOneTime     bool      `json:"is_one_time"`
		MaxUses       int       `json:"max_uses"`
		UsesRemaining int       `json:"uses_remaining"`
		ExpiresAt     string    `json:"expires_at"`
		CreatedAt     string    `json:"created_at"`
	}

	summaries := make([]tapSummary, 0, len(passes))
	for _, p := range passes {
		summaries = append(summaries, tapSummary{
			ID:            p.ID,
			UserID:        p.UserID,
			IsOneTime:     p.IsOneTime,
			MaxUses:       p.MaxUses,
			UsesRemaining: p.UsesRemaining,
			ExpiresAt:     p.ExpiresAt.Format(timeFmtTAPISO8601),
			CreatedAt:     p.CreatedAt.Format(timeFmtTAPISO8601),
		})
	}

	c.JSON(http.StatusOK, gin.H{"passes": summaries, "count": len(summaries)})
}

// Revoke immediately invalidates a Temporary Access Pass.
//
// @Summary Revoke Temporary Access Pass
// @Description Immediately invalidates a TAP, preventing any further authentication with it
// @Tags Temporary Access Pass
// @Produce json
// @Param id path string true "TAP UUID"
// @Success 200 {object} map[string]string "Temporary access pass revoked"
// @Failure 400 {object} map[string]string "Invalid TAP ID"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 404 {object} map[string]string "Temporary access pass not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/temp-access-passes/{id} [delete]
func (h *TempAccessPassHandler) Revoke(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgTAPAuthRequired})
		return
	}

	tapID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid TAP id"})
		return
	}

	if err := h.tapService.RevokePass(c.Request.Context(), tapID); err != nil {
		if errors.Is(err, services.ErrTAPNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "temporary access pass not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke temporary access pass"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "temporary access pass revoked"})
}

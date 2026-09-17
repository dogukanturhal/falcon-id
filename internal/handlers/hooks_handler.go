// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/platform-shared/hooks"
)

const (
	msgHooksTenantIDRequired = "tenant ID is required"
	msgHookNotFound          = "hook not found"
)

// HooksHandler manages CRUD operations for tenant webhook configurations
// (HookConfig) and provides a test-fire endpoint for iterative debugging.
//
// Hooks are stored in-memory per tenant in the handler. A production implementation
// would persist them to a database and reload them on service restart.
type HooksHandler struct {
	hooksService *services.AuthHooksService
	engine       *hooks.HookEngine
	logger       *zap.Logger

	// mu guards tenantHooks for concurrent access.
	mu          sync.RWMutex
	tenantHooks map[string][]hooks.HookConfig
}

// NewHooksHandler creates a HooksHandler.
func NewHooksHandler(hooksService *services.AuthHooksService, engine *hooks.HookEngine, logger *zap.Logger) *HooksHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &HooksHandler{
		hooksService: hooksService,
		engine:       engine,
		logger:       logger,
		tenantHooks:  make(map[string][]hooks.HookConfig),
	}
}

// ---------------------------------------------------------------------------
// Request / response models
// ---------------------------------------------------------------------------

// CreateHookRequest is the JSON body for POST /hooks.
type CreateHookRequest struct {
	Name      string            `json:"name"       binding:"required,min=1,max=255"`
	URL       string            `json:"url"        binding:"required,url"`
	Trigger   hooks.TriggerType `json:"trigger"    binding:"required"`
	Secret    string            `json:"secret"`
	Enabled   bool              `json:"enabled"`
	Async     bool              `json:"async"`
	Priority  int               `json:"priority"`
	TimeoutMs int               `json:"timeout_ms"`
}

// UpdateHookRequest is the JSON body for PUT /hooks/:id.
type UpdateHookRequest struct {
	Name      *string            `json:"name"`
	URL       *string            `json:"url"`
	Trigger   *hooks.TriggerType `json:"trigger"`
	Secret    *string            `json:"secret"`
	Enabled   *bool              `json:"enabled"`
	Async     *bool              `json:"async"`
	Priority  *int               `json:"priority"`
	TimeoutMs *int               `json:"timeout_ms"`
}

// TestHookRequest is the JSON body for POST /hooks/:id/test.
type TestHookRequest struct {
	Data map[string]interface{} `json:"data"`
}

// HookResponse is the JSON representation of a HookConfig.
type HookResponse struct {
	ID        string            `json:"id"`
	TenantID  string            `json:"tenant_id"`
	Name      string            `json:"name"`
	URL       string            `json:"url"`
	Trigger   hooks.TriggerType `json:"trigger"`
	Enabled   bool              `json:"enabled"`
	Async     bool              `json:"async"`
	Priority  int               `json:"priority"`
	TimeoutMs int               `json:"timeout_ms"`
}

// TestHookResponse is returned by POST /hooks/:id/test.
type TestHookResponse struct {
	HookID     string                 `json:"hook_id"`
	Trigger    hooks.TriggerType      `json:"trigger"`
	Allow      bool                   `json:"allow"`
	Enrich     map[string]interface{} `json:"enrich,omitempty"`
	Message    string                 `json:"message,omitempty"`
	DurationMs int64                  `json:"duration_ms"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hookToResponse(h hooks.HookConfig) HookResponse {
	return HookResponse{
		ID:        h.ID,
		TenantID:  h.TenantID,
		Name:      h.Name,
		URL:       h.URL,
		Trigger:   h.Trigger,
		Enabled:   h.Enabled,
		Async:     h.Async,
		Priority:  h.Priority,
		TimeoutMs: h.TimeoutMs,
	}
}

func (h *HooksHandler) listHooks(tenantID string) []hooks.HookConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	list := h.tenantHooks[tenantID]
	out := make([]hooks.HookConfig, len(list))
	copy(out, list)
	return out
}

func (h *HooksHandler) setHooks(tenantID string, list []hooks.HookConfig) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tenantHooks[tenantID] = list
	h.engine.RegisterHooks(tenantID, list)
}

func currentHooksTenantID(c *gin.Context) string {
	if user := middleware.GetCurrentUser(c); user != nil {
		return user.TenantID.String()
	}
	return c.GetHeader("X-Tenant-ID")
}

// CreateHook is an exported identifier.
func (h *HooksHandler) CreateHook(c *gin.Context) {
	tenantID := currentHooksTenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgHooksTenantIDRequired})
		return
	}

	var req CreateHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.TimeoutMs <= 0 {
		req.TimeoutMs = 3000
	}

	hookID := "hook-" + time.Now().Format("20060102150405") + "-" + tenantID[:8]

	newHook := hooks.HookConfig{
		ID:        hookID,
		TenantID:  tenantID,
		Name:      req.Name,
		URL:       req.URL,
		Trigger:   req.Trigger,
		Secret:    req.Secret,
		Enabled:   req.Enabled,
		Async:     req.Async,
		Priority:  req.Priority,
		TimeoutMs: req.TimeoutMs,
	}

	existing := h.listHooks(tenantID)
	existing = append(existing, newHook)
	h.setHooks(tenantID, existing)

	h.logger.Info("hooks: created webhook",
		zap.String("hook_id", hookID),
		zap.String("tenant_id", tenantID),
		zap.String("trigger", string(req.Trigger)),
	)

	c.JSON(http.StatusCreated, hookToResponse(newHook))
}

// ListHooks is an exported function.
func (h *HooksHandler) ListHooks(c *gin.Context) {
	tenantID := currentHooksTenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgHooksTenantIDRequired})
		return
	}

	hooksForTenant := h.listHooks(tenantID)
	responses := make([]HookResponse, len(hooksForTenant))
	for i, hook := range hooksForTenant {
		responses[i] = hookToResponse(hook)
	}

	c.JSON(http.StatusOK, responses)
}

// GetHook is an exported function.
func (h *HooksHandler) GetHook(c *gin.Context) {
	tenantID := currentHooksTenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgHooksTenantIDRequired})
		return
	}

	hookID := c.Param("id")
	hooksForTenant := h.listHooks(tenantID)

	for _, hook := range hooksForTenant {
		if hook.ID == hookID {
			c.JSON(http.StatusOK, hookToResponse(hook))
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": msgHookNotFound})
}

// UpdateHook is an exported function.
func (h *HooksHandler) UpdateHook(c *gin.Context) {
	tenantID := currentHooksTenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgHooksTenantIDRequired})
		return
	}

	hookID := c.Param("id")

	var req UpdateHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existing := h.listHooks(tenantID)

	idx := findHookIndex(existing, hookID)
	if idx < 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": msgHookNotFound})
		return
	}

	applyHookUpdates(&existing[idx], &req)
	h.setHooks(tenantID, existing)

	h.logger.Info("hooks: updated webhook",
		zap.String("hook_id", hookID),
		zap.String("tenant_id", tenantID),
	)

	c.JSON(http.StatusOK, hookToResponse(existing[idx]))
}

// findHookIndex returns the slice index of the hook with the given ID, or -1 if not found.
func findHookIndex(hookList []hooks.HookConfig, hookID string) int {
	for i, h := range hookList {
		if h.ID == hookID {
			return i
		}
	}
	return -1
}

// applyHookUpdates merges the non-nil fields from req into the hook.
func applyHookUpdates(hook *hooks.HookConfig, req *UpdateHookRequest) {
	if req.Name != nil {
		hook.Name = *req.Name
	}
	if req.URL != nil {
		hook.URL = *req.URL
	}
	if req.Trigger != nil {
		hook.Trigger = *req.Trigger
	}
	if req.Secret != nil {
		hook.Secret = *req.Secret
	}
	if req.Enabled != nil {
		hook.Enabled = *req.Enabled
	}
	if req.Async != nil {
		hook.Async = *req.Async
	}
	if req.Priority != nil {
		hook.Priority = *req.Priority
	}
	if req.TimeoutMs != nil {
		hook.TimeoutMs = *req.TimeoutMs
	}
}

// DeleteHook is an exported function.
func (h *HooksHandler) DeleteHook(c *gin.Context) {
	tenantID := currentHooksTenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgHooksTenantIDRequired})
		return
	}

	hookID := c.Param("id")
	existing := h.listHooks(tenantID)

	filtered := existing[:0]
	found := false
	for _, hook := range existing {
		if hook.ID == hookID {
			found = true
			continue
		}
		filtered = append(filtered, hook)
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": msgHookNotFound})
		return
	}

	h.setHooks(tenantID, filtered)

	h.logger.Info("hooks: deleted webhook",
		zap.String("hook_id", hookID),
		zap.String("tenant_id", tenantID),
	)

	c.Status(http.StatusNoContent)
}

// TestHook is an exported function.
func (h *HooksHandler) TestHook(c *gin.Context) {
	tenantID := currentHooksTenantID(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgHooksTenantIDRequired})
		return
	}

	hookID := c.Param("id")

	existing := h.listHooks(tenantID)
	var targetHook *hooks.HookConfig
	for i := range existing {
		if existing[i].ID == hookID {
			targetHook = &existing[i]
			break
		}
	}

	if targetHook == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgHookNotFound})
		return
	}

	var req TestHookRequest
	_ = c.ShouldBindJSON(&req)
	if req.Data == nil {
		req.Data = map[string]interface{}{
			"test":    true,
			"hook_id": hookID,
		}
	}

	testHook := *targetHook
	testHook.Async = false

	// Use a temporary engine with only this one hook to isolate the test call.
	testEngine := hooks.NewHookEngine(h.logger)
	testEngine.RegisterHooks(tenantID, []hooks.HookConfig{testHook})

	start := time.Now()
	resp, err := testEngine.Execute(c.Request.Context(), testHook.Trigger, tenantID, req.Data)
	durationMs := time.Since(start).Milliseconds()

	if err != nil {
		c.JSON(http.StatusOK, TestHookResponse{
			HookID:     hookID,
			Trigger:    testHook.Trigger,
			Allow:      false,
			Message:    "hook execution error: " + err.Error(),
			DurationMs: durationMs,
		})
		return
	}

	c.JSON(http.StatusOK, TestHookResponse{
		HookID:     hookID,
		Trigger:    testHook.Trigger,
		Allow:      resp.Allow,
		Enrich:     resp.Enrich,
		Message:    resp.Message,
		DurationMs: durationMs,
	})
}

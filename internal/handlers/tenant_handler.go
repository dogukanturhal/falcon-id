// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"go.uber.org/zap"
)

const (
	msgTenantFailedGetTenant = "Failed to get tenant"
	planProfessional         = "professional"
	realmSlugDefault         = "default"
)

// TenantHandler handles tenant-related endpoints
type TenantHandler struct {
	tenantRepo *repositories.TenantRepository
	userRepo   *repositories.UserRepository
	realmRepo  *repositories.RealmRepository
	logger     *zap.Logger
}

// NewTenantHandler creates a new tenant handler
func NewTenantHandler(tenantRepo *repositories.TenantRepository, userRepo *repositories.UserRepository, logger *zap.Logger) *TenantHandler {
	return &TenantHandler{
		tenantRepo: tenantRepo,
		userRepo:   userRepo,
		logger:     logger,
	}
}

// SetRealmRepo sets the realm repository for realm-aware connection info
// This is called after realm initialization if realm support is enabled
func (h *TenantHandler) SetRealmRepo(realmRepo *repositories.RealmRepository) {
	h.realmRepo = realmRepo
}

// TenantResponse represents the tenant response
type TenantResponse struct {
	ID           uuid.UUID              `json:"id"`
	Name         string                 `json:"name"`
	Slug         string                 `json:"slug"`
	DisplayName  string                 `json:"display_name"`
	Domain       *string                `json:"domain,omitempty"`
	Status       string                 `json:"status"`
	Plan         string                 `json:"plan"`
	Settings     map[string]interface{} `json:"settings,omitempty"`
	BillingEmail *string                `json:"billing_email,omitempty"`
	MaxUsers     int                    `json:"max_users"`
	MaxStorage   int64                  `json:"max_storage"`
	TrialEndsAt  *time.Time             `json:"trial_ends_at,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	SuspendedAt  *time.Time             `json:"suspended_at,omitempty"`
	CancelledAt  *time.Time             `json:"cancelled_at,omitempty"`
}

// TenantUsageResponse represents tenant usage
type TenantUsageResponse struct {
	TenantID     uuid.UUID `json:"tenant_id"`
	UserCount    int       `json:"user_count"`
	StorageUsed  int64     `json:"storage_used"`
	APICallCount int64     `json:"api_call_count"`
	Month        string    `json:"month"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// PlanLimits represents plan limits
type PlanLimits struct {
	MaxUsers     int      `json:"max_users"`
	MaxStorage   int64    `json:"max_storage"`
	Modules      []string `json:"modules"`
	Features     []string `json:"features"`
	APIRateLimit int      `json:"api_rate_limit"`
}

// UpdateTenantSettingsRequest represents update request
type UpdateTenantSettingsRequest struct {
	DisplayName  *string                `json:"display_name,omitempty"`
	Domain       *string                `json:"domain,omitempty"`
	BillingEmail *string                `json:"billing_email,omitempty"`
	Settings     map[string]interface{} `json:"settings,omitempty"`
}

// TenantConnectionInfoResponse is returned to business modules for multi-tenant connection setup
// This matches the TenantConnectionInfo expected by the .NET middleware
type TenantConnectionInfoResponse struct {
	TenantID     uuid.UUID `json:"tenant_id"`
	Strategy     string    `json:"strategy"` // "shared", "schema", "database"
	DatabaseName string    `json:"database_name"`
	SchemaName   string    `json:"schema_name"`
	Host         string    `json:"host"`
	Port         int       `json:"port"`
	Status       string    `json:"status"`

	// Realm context fields
	RealmID   *uuid.UUID `json:"realm_id,omitempty"`
	RealmSlug string     `json:"realm_slug,omitempty"`
	RealmType string     `json:"realm_type,omitempty"` // platform, enterprise, shared, partner, sandbox
}

// CreateTenantRequest represents the request to create a tenant (service-to-service)
type CreateTenantRequest struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name" binding:"required"`
	Slug        string    `json:"slug" binding:"required"`
	DisplayName string    `json:"display_name"`
	Plan        string    `json:"plan"` // trial, professional, enterprise - determines isolation strategy
	MaxUsers    int       `json:"max_users"`
	MaxStorage  int64     `json:"max_storage"`
}

// CreateTenant creates a new tenant (service-to-service endpoint)
// This triggers the database provisioning based on the plan
// @Summary Create a tenant (service-to-service)
// @Tags Tenant
// @Security APIKeyAuth
// @Param request body CreateTenantRequest true "Tenant to create"
// @Success 201 {object} TenantResponse
// @Router /api/v1/tenants [post]
func (h *TenantHandler) CreateTenant(c *gin.Context) {
	var req CreateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Slug validation — same fail-closed policy as the public signup
	// adapter: format check + reserved-list check collapsed into one
	// generic 4xx so the response cannot be used to enumerate which
	// slugs exist vs. which are reserved (Push Security
	// slug-tenant-enumeration mitigation).
	if !models.IsValidSlug(req.Slug) || models.IsReservedSlug(req.Slug) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "slug unavailable"})
		return
	}

	// Set defaults
	if req.DisplayName == "" {
		req.DisplayName = req.Name
	}
	if req.Plan == "" {
		req.Plan = "trial" // Default to trial (shared isolation)
	}
	if req.MaxUsers == 0 {
		req.MaxUsers = 5 // Default trial limit
	}
	if req.MaxStorage == 0 {
		req.MaxStorage = 1073741824 // 1GB default
	}

	tenant := &models.Tenant{
		ID:          req.ID,
		Name:        req.Name,
		Slug:        req.Slug,
		DisplayName: req.DisplayName,
		Status:      "active",
		Plan:        req.Plan,
		MaxUsers:    req.MaxUsers,
		MaxStorage:  req.MaxStorage,
		Settings:    make(map[string]interface{}),
		Metadata:    make(map[string]interface{}),
	}

	if err := h.tenantRepo.Create(c.Request.Context(), tenant); err != nil {
		h.logger.Error("Failed to create tenant", zap.Error(err), zap.String("slug", req.Slug))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant"})
		return
	}

	h.logger.Info("Tenant created (provisioning will trigger based on plan)",
		zap.String("tenant_id", tenant.ID.String()),
		zap.String("plan", req.Plan))

	response := h.tenantToResponse(tenant)
	c.JSON(http.StatusCreated, response)
}

// GetCurrentTenant returns the current tenant info
// @Summary Get current tenant
// @Tags Tenant
// @Security BearerAuth
// @Success 200 {object} TenantResponse
// @Router /api/tenant [get]
func (h *TenantHandler) GetCurrentTenant(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	tenant, err := h.tenantRepo.GetByID(c.Request.Context(), user.TenantID)
	if err != nil {
		h.logger.Error(msgTenantFailedGetTenant, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get tenant"})
		return
	}
	if tenant == nil {
		// User's tenant_id points at a missing row — a FK-integrity bug,
		// not a normal "not found". Surface as 500 with a distinct
		// error so this is paged rather than served as a 404 mask.
		h.logger.Error("tenant row missing for authenticated user — FK integrity violation",
			zap.String("user_id", user.ID.String()),
			zap.String("tenant_id", user.TenantID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant integrity error"})
		return
	}

	response := h.tenantToResponse(tenant)
	c.JSON(http.StatusOK, response)
}

// UpdateTenantSettings updates the tenant settings
// @Summary Update tenant settings
// @Tags Tenant
// @Security BearerAuth
// @Param request body UpdateTenantSettingsRequest true "Update request"
// @Success 200 {object} TenantResponse
// @Router /api/tenant/settings [put]
func (h *TenantHandler) UpdateTenantSettings(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req UpdateTenantSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenant, err := h.tenantRepo.GetByID(c.Request.Context(), user.TenantID)
	if err != nil {
		h.logger.Error(msgTenantFailedGetTenant, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get tenant"})
		return
	}
	if tenant == nil {
		h.logger.Error("tenant row missing for authenticated user — FK integrity violation",
			zap.String("user_id", user.ID.String()),
			zap.String("tenant_id", user.TenantID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant integrity error"})
		return
	}

	// Update fields
	if req.DisplayName != nil {
		tenant.DisplayName = *req.DisplayName
	}
	if req.Domain != nil {
		tenant.Domain = req.Domain
	}
	if req.BillingEmail != nil {
		tenant.BillingEmail = req.BillingEmail
	}
	if req.Settings != nil {
		tenant.Settings = req.Settings
	}

	if err := h.tenantRepo.Update(c.Request.Context(), tenant); err != nil {
		h.logger.Error("Failed to update tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update tenant"})
		return
	}

	response := h.tenantToResponse(tenant)
	c.JSON(http.StatusOK, response)
}

// GetTenantUsage returns tenant usage statistics
// @Summary Get tenant usage
// @Tags Tenant
// @Security BearerAuth
// @Success 200 {object} TenantUsageResponse
// @Router /api/tenant/usage [get]
func (h *TenantHandler) GetTenantUsage(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Get user count
	userCount, err := h.userRepo.CountByTenant(c.Request.Context(), user.TenantID)
	if err != nil {
		h.logger.Error("Failed to get user count", zap.Error(err))
		userCount = 0
	}

	response := TenantUsageResponse{
		TenantID:     user.TenantID,
		UserCount:    userCount,
		StorageUsed:  0, // TODO: Implement storage tracking
		APICallCount: 0, // TODO: Implement API call tracking
		Month:        time.Now().Format("2006-01"),
		UpdatedAt:    time.Now(),
	}

	c.JSON(http.StatusOK, response)
}

// GetPlanLimits returns plan limits
// @Summary Get plan limits
// @Tags Tenant
// @Security BearerAuth
// @Param plan query string false "Plan name"
// @Success 200 {object} PlanLimits
// @Router /api/tenant/plan-limits [get]
func (h *TenantHandler) GetPlanLimits(c *gin.Context) {
	plan := c.Query("plan")
	if plan == "" {
		plan = planProfessional
	}

	limits := getPlanLimits(plan)
	c.JSON(http.StatusOK, limits)
}

// GetUsageHistory returns usage history
// @Summary Get usage history
// @Tags Tenant
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /api/tenant/usage/history [get]
func (h *TenantHandler) GetUsageHistory(c *gin.Context) {
	// Return empty history for now
	c.JSON(http.StatusOK, gin.H{"history": []interface{}{}})
}

// GetTenantFeatureFlags returns tenant feature flags
// @Summary Get tenant feature flags
// @Tags Tenant
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /api/tenant/feature-flags [get]
func (h *TenantHandler) GetTenantFeatureFlags(c *gin.Context) {
	// Return default feature flags
	flags := map[string]bool{
		"email_integration":  true,
		"ad_integration":     true,
		"mfa_enabled":        true,
		"sso_enabled":        true,
		"api_access":         true,
		"audit_logs":         true,
		"custom_branding":    false,
		"advanced_reporting": false,
	}
	c.JSON(http.StatusOK, gin.H{"flags": flags})
}

// GetTenantFeatureFlagOverrides returns tenant feature flag overrides
// @Summary Get tenant feature flag overrides
// @Tags Tenant
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /api/tenant/feature-flags/overrides [get]
func (h *TenantHandler) GetTenantFeatureFlagOverrides(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"overrides": []interface{}{}})
}

// GetTenantConnectionInfo returns tenant connection information with realm context
// This endpoint is called by business modules to get database connection info
// @Summary Get tenant connection info
// @Tags Tenant
// @Security BearerAuth
// @Param tenant_id query string false "Tenant ID (optional, defaults to current user's tenant)"
// @Success 200 {object} TenantConnectionInfoResponse
// @Router /api/tenant/connection-info [get]
func (h *TenantHandler) GetTenantConnectionInfo(c *gin.Context) {
	var tenantID uuid.UUID
	var err error

	// Check for tenant_id query parameter (for service-to-service calls)
	if tenantIDStr := c.Query("tenant_id"); tenantIDStr != "" {
		tenantID, err = uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id", "code": "INVALID_TENANT_ID"})
			return
		}
	} else {
		// Get from authenticated user
		user := middleware.GetCurrentUser(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		tenantID = user.TenantID
	}

	// Get tenant info
	tenant, err := h.tenantRepo.GetByID(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error(msgTenantFailedGetTenant, zap.Error(err), zap.String("tenant_id", tenantID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get tenant"})
		return
	}
	if tenant == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found", "code": "TENANT_NOT_FOUND"})
		return
	}

	// Get realm for tenant
	var realmID *uuid.UUID
	var realmSlug string
	var realmType string

	if h.realmRepo != nil {
		realm, err := h.realmRepo.GetTenantRealm(c.Request.Context(), tenantID)
		if err != nil {
			h.logger.Warn("Failed to get tenant realm, using default", zap.Error(err), zap.String("tenant_id", tenantID.String()))
			// Use default realm
			defaultRealmID := models.DefaultRealmID
			realmID = &defaultRealmID
			realmSlug = realmSlugDefault
			realmType = string(models.RealmTypeShared)
		} else {
			realmID = &realm.ID
			realmSlug = realm.Slug
			realmType = string(realm.Type)
		}
	} else {
		// Realm repo not available, use defaults
		defaultRealmID := models.DefaultRealmID
		realmID = &defaultRealmID
		realmSlug = realmSlugDefault
		realmType = string(models.RealmTypeShared)
	}

	// Determine isolation strategy based on plan
	strategy := getIsolationStrategy(tenant.Plan)

	// Build response - database connection info would typically come from subscription management
	// For now, we use sensible defaults based on the isolation strategy
	response := TenantConnectionInfoResponse{
		TenantID:     tenantID,
		Strategy:     strategy,
		DatabaseName: getDatabaseName(strategy, tenant.Slug),
		SchemaName:   getSchemaName(strategy, tenant.Slug),
		Host:         "postgres-master", // Would be configured externally
		Port:         5432,
		Status:       tenant.Status,

		// Realm context
		RealmID:   realmID,
		RealmSlug: realmSlug,
		RealmType: realmType,
	}

	c.JSON(http.StatusOK, response)
}

// GetTenantConnectionInfoByID returns connection info for a specific tenant
// This is a service-to-service endpoint with API key authentication
// @Summary Get tenant connection info by ID
// @Tags Internal
// @Security ApiKeyAuth
// @Param id path string true "Tenant ID"
// @Success 200 {object} TenantConnectionInfoResponse
// @Router /api/internal/tenants/{id}/connection-info [get]
func (h *TenantHandler) GetTenantConnectionInfoByID(c *gin.Context) {
	tenantIDStr := c.Param("id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id", "code": "INVALID_TENANT_ID"})
		return
	}

	// Get tenant info
	tenant, err := h.tenantRepo.GetByID(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error(msgTenantFailedGetTenant, zap.Error(err), zap.String("tenant_id", tenantID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get tenant"})
		return
	}
	if tenant == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found", "code": "TENANT_NOT_FOUND"})
		return
	}

	// Get realm for tenant
	var realmID *uuid.UUID
	var realmSlug string
	var realmType string

	if h.realmRepo != nil {
		realm, err := h.realmRepo.GetTenantRealm(c.Request.Context(), tenantID)
		if err != nil {
			h.logger.Warn("Failed to get tenant realm, using default", zap.Error(err), zap.String("tenant_id", tenantID.String()))
			defaultRealmID := models.DefaultRealmID
			realmID = &defaultRealmID
			realmSlug = realmSlugDefault
			realmType = string(models.RealmTypeShared)
		} else {
			realmID = &realm.ID
			realmSlug = realm.Slug
			realmType = string(realm.Type)
		}
	} else {
		defaultRealmID := models.DefaultRealmID
		realmID = &defaultRealmID
		realmSlug = realmSlugDefault
		realmType = string(models.RealmTypeShared)
	}

	strategy := getIsolationStrategy(tenant.Plan)

	response := TenantConnectionInfoResponse{
		TenantID:     tenantID,
		Strategy:     strategy,
		DatabaseName: getDatabaseName(strategy, tenant.Slug),
		SchemaName:   getSchemaName(strategy, tenant.Slug),
		Host:         "postgres-master",
		Port:         5432,
		Status:       tenant.Status,
		RealmID:      realmID,
		RealmSlug:    realmSlug,
		RealmType:    realmType,
	}

	c.JSON(http.StatusOK, response)
}

// tenantUserCountResponse is the body of GET /internal/v1/tenants/:id/users/count.
type tenantUserCountResponse struct {
	TenantID        string `json:"tenant_id"`
	ActiveUserCount int    `json:"active_user_count"`
}

// GetTenantUserCount returns the tenant's currently occupied seat count —
// active users (is_active = true) that are not in a pending-deletion grace
// period (deletion_scheduled_at IS NULL). This is the seat-usage source of
// truth for quota-service's users-resource backfill script: iam_users is
// the only live, authoritative tenant-user-count table on the platform.
//
// This is a service-to-service endpoint, mounted on the same
// serviceAuthMiddleware.ServiceAuth()-protected /internal/v1/tenants group
// as GetTenantConnectionInfoByID above (see cmd/routes_admin.go) — hence
// the same :id path param name (Gin panics at startup on two different
// wildcard names at the same position within one route group).
//
// @Summary Get tenant active user (seat) count
// @Tags Internal
// @Security ApiKeyAuth
// @Param id path string true "Tenant ID"
// @Success 200 {object} tenantUserCountResponse
// @Router /internal/v1/tenants/{id}/users/count [get]
func (h *TenantHandler) GetTenantUserCount(c *gin.Context) {
	tenantIDStr := c.Param("id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id", "code": "INVALID_TENANT_ID"})
		return
	}

	if h.userRepo == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user repository not configured"})
		return
	}

	count, err := h.userRepo.CountActiveByTenant(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("failed to count active users for tenant", zap.Error(err), zap.String("tenant_id", tenantID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to count tenant users"})
		return
	}

	c.JSON(http.StatusOK, tenantUserCountResponse{
		TenantID:        tenantID.String(),
		ActiveUserCount: count,
	})
}

// getIsolationStrategy returns the isolation strategy based on tenant plan
func getIsolationStrategy(plan string) string {
	switch plan {
	case "free", "starter":
		return "shared" // Shared database with RLS
	case planProfessional:
		return "schema" // Schema per tenant
	case "enterprise":
		return "database" // Database per tenant
	default:
		return "shared"
	}
}

// getDatabaseName returns the database name based on strategy
func getDatabaseName(strategy, slug string) string {
	switch strategy {
	case "database":
		return "hexxlock_" + slug
	default:
		return "hexxlock_master"
	}
}

// getSchemaName returns the schema name based on strategy
func getSchemaName(strategy, slug string) string {
	switch strategy {
	case "schema":
		return "tenant_" + slug
	default:
		return "public"
	}
}

func (h *TenantHandler) tenantToResponse(tenant *models.Tenant) TenantResponse {
	return TenantResponse{
		ID:           tenant.ID,
		Name:         tenant.Name,
		Slug:         tenant.Slug,
		DisplayName:  tenant.DisplayName,
		Domain:       tenant.Domain,
		Status:       tenant.Status,
		Plan:         tenant.Plan,
		Settings:     tenant.Settings,
		BillingEmail: tenant.BillingEmail,
		MaxUsers:     tenant.MaxUsers,
		MaxStorage:   tenant.MaxStorage,
		TrialEndsAt:  tenant.TrialEndsAt,
		CreatedAt:    tenant.CreatedAt,
		UpdatedAt:    tenant.UpdatedAt,
		SuspendedAt:  tenant.SuspendedAt,
		CancelledAt:  tenant.CancelledAt,
	}
}

func getPlanLimits(plan string) PlanLimits {
	switch plan {
	case "free":
		return PlanLimits{
			MaxUsers:     5,
			MaxStorage:   1073741824, // 1GB
			Modules:      []string{"core"},
			Features:     []string{"basic_auth"},
			APIRateLimit: 100,
		}
	case "starter":
		return PlanLimits{
			MaxUsers:     25,
			MaxStorage:   10737418240, // 10GB
			Modules:      []string{"core", "crm"},
			Features:     []string{"basic_auth", "mfa", "api_access"},
			APIRateLimit: 1000,
		}
	case planProfessional:
		return PlanLimits{
			MaxUsers:     100,
			MaxStorage:   107374182400, // 100GB
			Modules:      []string{"core", "crm", "invoicing", "hr"},
			Features:     []string{"basic_auth", "mfa", "api_access", "sso", "audit_logs"},
			APIRateLimit: 10000,
		}
	case "enterprise":
		return PlanLimits{
			MaxUsers:     -1,            // Unlimited
			MaxStorage:   1099511627776, // 1TB
			Modules:      []string{"core", "crm", "invoicing", "hr", "inventory", "accounting"},
			Features:     []string{"basic_auth", "mfa", "api_access", "sso", "audit_logs", "custom_branding", "advanced_reporting"},
			APIRateLimit: 100000,
		}
	default:
		return getPlanLimits(planProfessional)
	}
}

// tenantMemberResponse is the body of GET /internal/v1/tenants/:id/members/:userId.
// Intentionally a single boolean: no profile fields, no PII.
type tenantMemberResponse struct {
	Active bool `json:"active"`
}

// GetTenantMember answers "is user X an active member of tenant Y" for S2S callers
// (e.g. business validating a lead owner before core.users has synced). 404 when the
// user does not belong to the tenant (or does not exist — indistinguishable on purpose);
// 200 {"active":bool} otherwise. Point lookup only: there is no listing/enumeration.
//
// Mounted on the ServiceAuth()-gated /internal/v1/tenants group with
// RequireScope("iam:members:read"); :id and :userId are both taken from the path, never
// from X-Tenant-ID.
//
// @Summary Check active tenant membership
// @Tags Internal
// @Security ApiKeyAuth
// @Param id path string true "Tenant ID"
// @Param userId path string true "User ID"
// @Success 200 {object} tenantMemberResponse
// @Failure 404 {object} map[string]string
// @Router /internal/v1/tenants/{id}/members/{userId} [get]
func (h *TenantHandler) GetTenantMember(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id", "code": "INVALID_TENANT_ID"})
		return
	}
	userID, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id", "code": "INVALID_USER_ID"})
		return
	}
	if h.userRepo == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user repository not configured"})
		return
	}

	found, active, err := h.userRepo.GetMemberActiveState(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("failed to look up tenant member", zap.Error(err),
			zap.String("tenant_id", tenantID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to look up member"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "member not found", "code": "MEMBER_NOT_FOUND"})
		return
	}
	c.JSON(http.StatusOK, tenantMemberResponse{Active: active})
}

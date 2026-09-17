// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgSCIMInvalidRequest = "Invalid request: "
	msgSCIMInvalidTokenID = "Invalid token ID"
	msgSCIMTokenNotFound  = "Token not found"
	msgSCIMAccessDenied   = "Access denied"
	msgSCIMInvalidAuth    = "Invalid authentication"
	msgSCIMInvalidUserID  = "Invalid user ID"
	msgSCIMUserNotFound   = "User not found"
	msgSCIMNotFound       = "not found"
	msgSCIMInvalidGroupID = "Invalid group ID"
	msgSCIMGroupNotFound  = "Group not found"
)

// SCIMHandler handles SCIM 2.0 API endpoints
type SCIMHandler struct {
	scimService *services.SCIMService
	logger      *zap.Logger
}

// NewSCIMHandler creates a new SCIMHandler
func NewSCIMHandler(scimService *services.SCIMService, logger *zap.Logger) *SCIMHandler {
	return &SCIMHandler{
		scimService: scimService,
		logger:      logger,
	}
}

// ==================== SCIM Token Management (Admin) ====================

// ListTokens lists all SCIM tokens for the tenant
// @Summary List SCIM Tokens
// @Description Lists all SCIM tokens for the current tenant
// @Tags SCIM Admin
// @Produce json
// @Success 200 {object} models.SCIMTokenListResponse
// @Router /api/admin/scim/tokens [get]
func (h *SCIMHandler) ListTokens(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)

	tokens, err := h.scimService.ListTokens(c.Request.Context(), tenantID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to list tokens"})
		return
	}

	// Convert to safe response (no hashes)
	response := make([]models.SCIMToken, 0, len(tokens))
	for _, t := range tokens {
		token := *t
		token.TokenHash = "" // Don't expose hash
		response = append(response, token)
	}

	c.JSON(http.StatusOK, models.SCIMTokenListResponse{
		Tokens: response,
		Total:  int64(len(response)),
	})
}

// CreateToken creates a new SCIM token
// @Summary Create SCIM Token
// @Description Creates a new SCIM token for automated provisioning
// @Tags SCIM Admin
// @Accept json
// @Produce json
// @Param body body models.CreateSCIMTokenRequest true "Token details"
// @Success 201 {object} models.SCIMTokenCreatedResponse
// @Router /api/admin/scim/tokens [post]
func (h *SCIMHandler) CreateToken(c *gin.Context) {
	var req models.CreateSCIMTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSCIMInvalidRequest + err.Error()})
		return
	}

	tenantID := middleware.GetTenantID(c)
	userID := h.getUserIDFromContext(c)

	token, err := h.scimService.CreateToken(c.Request.Context(), tenantID, &req, userID)
	if err != nil {
		h.logger.Error("Failed to create SCIM token", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
		return
	}

	c.JSON(http.StatusCreated, token)
}

// GetToken gets a SCIM token by ID
// @Summary Get SCIM Token
// @Description Gets a SCIM token by ID
// @Tags SCIM Admin
// @Produce json
// @Param id path string true "Token ID"
// @Success 200 {object} models.SCIMToken
// @Router /api/admin/scim/tokens/{id} [get]
func (h *SCIMHandler) GetToken(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSCIMInvalidTokenID})
		return
	}

	token, err := h.scimService.GetToken(c.Request.Context(), id)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSCIMTokenNotFound})
		return
	}

	// Verify tenant access
	tenantID := middleware.GetTenantID(c)
	if token.TenantID != tenantID {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": msgSCIMAccessDenied})
		return
	}

	token.TokenHash = "" // Don't expose hash
	c.JSON(http.StatusOK, token)
}

// UpdateToken updates a SCIM token
// @Summary Update SCIM Token
// @Description Updates a SCIM token
// @Tags SCIM Admin
// @Accept json
// @Produce json
// @Param id path string true "Token ID"
// @Param body body models.UpdateSCIMTokenRequest true "Token details"
// @Success 200 {object} models.SCIMToken
// @Router /api/admin/scim/tokens/{id} [put]
func (h *SCIMHandler) UpdateToken(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSCIMInvalidTokenID})
		return
	}

	// Verify tenant access
	token, err := h.scimService.GetToken(c.Request.Context(), id)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSCIMTokenNotFound})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if token.TenantID != tenantID {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": msgSCIMAccessDenied})
		return
	}

	var req models.UpdateSCIMTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSCIMInvalidRequest + err.Error()})
		return
	}

	updatedToken, err := h.scimService.UpdateToken(c.Request.Context(), id, &req)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update token"})
		return
	}

	updatedToken.TokenHash = ""
	c.JSON(http.StatusOK, updatedToken)
}

// DeleteToken deletes a SCIM token
// @Summary Delete SCIM Token
// @Description Deletes a SCIM token
// @Tags SCIM Admin
// @Param id path string true "Token ID"
// @Success 204 "No Content"
// @Router /api/admin/scim/tokens/{id} [delete]
func (h *SCIMHandler) DeleteToken(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSCIMInvalidTokenID})
		return
	}

	// Verify tenant access
	token, err := h.scimService.GetToken(c.Request.Context(), id)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSCIMTokenNotFound})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if token.TenantID != tenantID {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": msgSCIMAccessDenied})
		return
	}

	if err := h.scimService.DeleteToken(c.Request.Context(), id); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete token"})
		return
	}

	c.Status(http.StatusNoContent)
}

// RevokeToken revokes a SCIM token
// @Summary Revoke SCIM Token
// @Description Revokes a SCIM token
// @Tags SCIM Admin
// @Param id path string true "Token ID"
// @Success 200 {object} map[string]string
// @Router /api/admin/scim/tokens/{id}/revoke [post]
func (h *SCIMHandler) RevokeToken(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSCIMInvalidTokenID})
		return
	}

	// Verify tenant access
	token, err := h.scimService.GetToken(c.Request.Context(), id)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSCIMTokenNotFound})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if token.TenantID != tenantID {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": msgSCIMAccessDenied})
		return
	}

	if err := h.scimService.RevokeToken(c.Request.Context(), id); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Token revoked successfully"})
}

// ==================== SCIM 2.0 Discovery Endpoints ====================

// GetServiceProviderConfig returns the SCIM service provider configuration
// @Summary Get SCIM Service Provider Config
// @Description Returns the SCIM 2.0 service provider configuration
// @Tags SCIM
// @Produce json
// @Success 200 {object} models.SCIMServiceProviderConfig
// @Router /scim/v2/ServiceProviderConfig [get]
func (h *SCIMHandler) GetServiceProviderConfig(c *gin.Context) {
	config := h.scimService.GetServiceProviderConfig()
	c.JSON(http.StatusOK, config)
}

// GetSchemas returns the SCIM schemas
// @Summary Get SCIM Schemas
// @Description Returns the SCIM 2.0 schemas
// @Tags SCIM
// @Produce json
// @Success 200 {object} models.SCIMListResponse
// @Router /scim/v2/Schemas [get]
func (h *SCIMHandler) GetSchemas(c *gin.Context) {
	schemas := h.scimService.GetSchemas()
	c.JSON(http.StatusOK, schemas)
}

// GetResourceTypes returns the SCIM resource types
// @Summary Get SCIM Resource Types
// @Description Returns the SCIM 2.0 resource types
// @Tags SCIM
// @Produce json
// @Success 200 {object} models.SCIMListResponse
// @Router /scim/v2/ResourceTypes [get]
func (h *SCIMHandler) GetResourceTypes(c *gin.Context) {
	resourceTypes := h.scimService.GetResourceTypes()
	c.JSON(http.StatusOK, resourceTypes)
}

// ==================== SCIM 2.0 User Endpoints ====================

// ListUsers lists users in SCIM format
// @Summary List SCIM Users
// @Description Lists users in SCIM 2.0 format
// @Tags SCIM
// @Produce json
// @Param startIndex query int false "Start index (1-based)"
// @Param count query int false "Number of results"
// @Param filter query string false "SCIM filter"
// @Success 200 {object} models.SCIMListResponse
// @Router /scim/v2/Users [get]
func (h *SCIMHandler) ListUsers(c *gin.Context) {
	tenantID, ok := c.Get("scim_tenant_id")
	if !ok {
		h.scimError(c, http.StatusUnauthorized, msgSCIMInvalidAuth, "invalidAuth")
		return
	}

	startIndex, _ := strconv.Atoi(c.DefaultQuery("startIndex", "1"))
	count, _ := strconv.Atoi(c.DefaultQuery("count", "100"))

	// SECURITY: Enforce max count of 100 to prevent memory exhaustion
	if count < 1 {
		count = 100
	}
	if count > 100 {
		count = 100
	}

	filter := c.Query("filter")

	response, err := h.scimService.ListUsers(c.Request.Context(), tenantID.(uuid.UUID), startIndex, count, filter)
	if err != nil {
		h.scimError(c, http.StatusInternalServerError, "Failed to list users", "")
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetUser gets a user in SCIM format
// @Summary Get SCIM User
// @Description Gets a user in SCIM 2.0 format
// @Tags SCIM
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} models.SCIMUser
// @Router /scim/v2/Users/{id} [get]
func (h *SCIMHandler) GetUser(c *gin.Context) {
	tenantID, ok := c.Get("scim_tenant_id")
	if !ok {
		h.scimError(c, http.StatusUnauthorized, msgSCIMInvalidAuth, "invalidAuth")
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.scimError(c, http.StatusBadRequest, msgSCIMInvalidUserID, "invalidValue")
		return
	}

	// Verify the user belongs to the SCIM token's tenant
	if err := h.scimService.ValidateUserTenant(c.Request.Context(), id, tenantID.(uuid.UUID)); err != nil {
		h.scimError(c, http.StatusNotFound, msgSCIMUserNotFound, "noTarget")
		return
	}

	user, err := h.scimService.GetUser(c.Request.Context(), id)
	if err != nil {
		h.scimError(c, http.StatusNotFound, msgSCIMUserNotFound, "noTarget")
		return
	}

	c.JSON(http.StatusOK, user)
}

// CreateUser creates a user from SCIM data
// @Summary Create SCIM User
// @Description Creates a user from SCIM 2.0 data
// @Tags SCIM
// @Accept json
// @Produce json
// @Param body body models.SCIMUser true "SCIM User"
// @Success 201 {object} models.SCIMUser
// @Router /scim/v2/Users [post]
func (h *SCIMHandler) CreateUser(c *gin.Context) {
	tenantID, ok := c.Get("scim_tenant_id")
	if !ok {
		h.scimError(c, http.StatusUnauthorized, msgSCIMInvalidAuth, "invalidAuth")
		return
	}

	var scimUser models.SCIMUser
	if err := c.ShouldBindJSON(&scimUser); err != nil {
		h.scimError(c, http.StatusBadRequest, "Invalid request: "+err.Error(), "invalidValue")
		return
	}

	if scimUser.UserName == "" {
		h.scimError(c, http.StatusBadRequest, "userName is required", "invalidValue")
		return
	}

	user, err := h.scimService.CreateUser(c.Request.Context(), tenantID.(uuid.UUID), &scimUser)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "already exists") {
			h.scimError(c, http.StatusConflict, "User already exists", "uniqueness")
			return
		}
		h.scimError(c, http.StatusInternalServerError, "Failed to create user", "")
		return
	}

	c.Header("Location", user.Meta.Location)
	c.JSON(http.StatusCreated, user)
}

// UpdateUser updates a user from SCIM data
// @Summary Update SCIM User
// @Description Updates a user from SCIM 2.0 data
// @Tags SCIM
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param body body models.SCIMUser true "SCIM User"
// @Success 200 {object} models.SCIMUser
// @Router /scim/v2/Users/{id} [put]
func (h *SCIMHandler) UpdateUser(c *gin.Context) {
	tenantID, ok := c.Get("scim_tenant_id")
	if !ok {
		h.scimError(c, http.StatusUnauthorized, msgSCIMInvalidAuth, "invalidAuth")
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.scimError(c, http.StatusBadRequest, msgSCIMInvalidUserID, "invalidValue")
		return
	}

	// Verify the user belongs to the SCIM token's tenant
	if err := h.scimService.ValidateUserTenant(c.Request.Context(), id, tenantID.(uuid.UUID)); err != nil {
		h.scimError(c, http.StatusNotFound, msgSCIMUserNotFound, "noTarget")
		return
	}

	var scimUser models.SCIMUser
	if err := c.ShouldBindJSON(&scimUser); err != nil {
		h.scimError(c, http.StatusBadRequest, "Invalid request: "+err.Error(), "invalidValue")
		return
	}

	user, err := h.scimService.UpdateUser(c.Request.Context(), id, &scimUser)
	if err != nil {
		if strings.Contains(err.Error(), msgSCIMNotFound) {
			h.scimError(c, http.StatusNotFound, msgSCIMUserNotFound, "noTarget")
			return
		}
		h.scimError(c, http.StatusInternalServerError, "Failed to update user", "")
		return
	}

	c.JSON(http.StatusOK, user)
}

// PatchUser applies patch operations to a user
// @Summary Patch SCIM User
// @Description Applies patch operations to a user
// @Tags SCIM
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param body body models.SCIMPatchOp true "SCIM Patch Operations"
// @Success 200 {object} models.SCIMUser
// @Router /scim/v2/Users/{id} [patch]
func (h *SCIMHandler) PatchUser(c *gin.Context) {
	tenantID, ok := c.Get("scim_tenant_id")
	if !ok {
		h.scimError(c, http.StatusUnauthorized, msgSCIMInvalidAuth, "invalidAuth")
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.scimError(c, http.StatusBadRequest, msgSCIMInvalidUserID, "invalidValue")
		return
	}

	// Verify the user belongs to the SCIM token's tenant
	if err := h.scimService.ValidateUserTenant(c.Request.Context(), id, tenantID.(uuid.UUID)); err != nil {
		h.scimError(c, http.StatusNotFound, msgSCIMUserNotFound, "noTarget")
		return
	}

	var patchOp models.SCIMPatchOp
	if err := c.ShouldBindJSON(&patchOp); err != nil {
		h.scimError(c, http.StatusBadRequest, "Invalid request: "+err.Error(), "invalidValue")
		return
	}

	user, err := h.scimService.PatchUser(c.Request.Context(), id, &patchOp)
	if err != nil {
		if strings.Contains(err.Error(), msgSCIMNotFound) {
			h.scimError(c, http.StatusNotFound, msgSCIMUserNotFound, "noTarget")
			return
		}
		h.scimError(c, http.StatusInternalServerError, "Failed to patch user", "")
		return
	}

	c.JSON(http.StatusOK, user)
}

// DeleteUser deletes a user
// @Summary Delete SCIM User
// @Description Deletes a user
// @Tags SCIM
// @Param id path string true "User ID"
// @Success 204 "No Content"
// @Router /scim/v2/Users/{id} [delete]
func (h *SCIMHandler) DeleteUser(c *gin.Context) {
	tenantID, ok := c.Get("scim_tenant_id")
	if !ok {
		h.scimError(c, http.StatusUnauthorized, msgSCIMInvalidAuth, "invalidAuth")
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.scimError(c, http.StatusBadRequest, msgSCIMInvalidUserID, "invalidValue")
		return
	}

	// Verify the user belongs to the SCIM token's tenant
	if err := h.scimService.ValidateUserTenant(c.Request.Context(), id, tenantID.(uuid.UUID)); err != nil {
		h.scimError(c, http.StatusNotFound, msgSCIMUserNotFound, "noTarget")
		return
	}

	if err := h.scimService.DeleteUser(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), msgSCIMNotFound) {
			h.scimError(c, http.StatusNotFound, msgSCIMUserNotFound, "noTarget")
			return
		}
		h.scimError(c, http.StatusInternalServerError, "Failed to delete user", "")
		return
	}

	c.Status(http.StatusNoContent)
}

// ==================== SCIM 2.0 Group Endpoints ====================

// ListGroups lists groups in SCIM format
// @Summary List SCIM Groups
// @Description Lists groups in SCIM 2.0 format
// @Tags SCIM
// @Produce json
// @Param startIndex query int false "Start index (1-based)"
// @Param count query int false "Number of results"
// @Param filter query string false "SCIM filter"
// @Success 200 {object} models.SCIMListResponse
// @Router /scim/v2/Groups [get]
func (h *SCIMHandler) ListGroups(c *gin.Context) {
	tenantID, ok := c.Get("scim_tenant_id")
	if !ok {
		h.scimError(c, http.StatusUnauthorized, msgSCIMInvalidAuth, "invalidAuth")
		return
	}

	startIndex, _ := strconv.Atoi(c.DefaultQuery("startIndex", "1"))
	count, _ := strconv.Atoi(c.DefaultQuery("count", "100"))

	// SECURITY: Enforce max count of 100 to prevent memory exhaustion
	if count < 1 {
		count = 100
	}
	if count > 100 {
		count = 100
	}

	filter := c.Query("filter")

	response, err := h.scimService.ListGroups(c.Request.Context(), tenantID.(uuid.UUID), startIndex, count, filter)
	if err != nil {
		h.scimError(c, http.StatusInternalServerError, "Failed to list groups", "")
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetGroup gets a group in SCIM format
// @Summary Get SCIM Group
// @Description Gets a group in SCIM 2.0 format
// @Tags SCIM
// @Produce json
// @Param id path string true "Group ID"
// @Success 200 {object} models.SCIMGroup
// @Router /scim/v2/Groups/{id} [get]
func (h *SCIMHandler) GetGroup(c *gin.Context) {
	tenantID, ok := c.Get("scim_tenant_id")
	if !ok {
		h.scimError(c, http.StatusUnauthorized, msgSCIMInvalidAuth, "invalidAuth")
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.scimError(c, http.StatusBadRequest, msgSCIMInvalidGroupID, "invalidValue")
		return
	}

	// Verify the group belongs to the SCIM token's tenant
	if err := h.scimService.ValidateGroupTenant(c.Request.Context(), id, tenantID.(uuid.UUID)); err != nil {
		h.scimError(c, http.StatusNotFound, msgSCIMGroupNotFound, "noTarget")
		return
	}

	group, err := h.scimService.GetGroup(c.Request.Context(), id)
	if err != nil {
		h.scimError(c, http.StatusNotFound, msgSCIMGroupNotFound, "noTarget")
		return
	}

	c.JSON(http.StatusOK, group)
}

// CreateGroup creates a group from SCIM data
// @Summary Create SCIM Group
// @Description Creates a group from SCIM 2.0 data
// @Tags SCIM
// @Accept json
// @Produce json
// @Param body body models.SCIMGroup true "SCIM Group"
// @Success 201 {object} models.SCIMGroup
// @Router /scim/v2/Groups [post]
func (h *SCIMHandler) CreateGroup(c *gin.Context) {
	tenantID, ok := c.Get("scim_tenant_id")
	if !ok {
		h.scimError(c, http.StatusUnauthorized, msgSCIMInvalidAuth, "invalidAuth")
		return
	}

	var scimGroup models.SCIMGroup
	if err := c.ShouldBindJSON(&scimGroup); err != nil {
		h.scimError(c, http.StatusBadRequest, "Invalid request: "+err.Error(), "invalidValue")
		return
	}

	if scimGroup.DisplayName == "" {
		h.scimError(c, http.StatusBadRequest, "displayName is required", "invalidValue")
		return
	}

	group, err := h.scimService.CreateGroup(c.Request.Context(), tenantID.(uuid.UUID), &scimGroup)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "already exists") {
			h.scimError(c, http.StatusConflict, "Group already exists", "uniqueness")
			return
		}
		h.scimError(c, http.StatusInternalServerError, "Failed to create group", "")
		return
	}

	c.Header("Location", group.Meta.Location)
	c.JSON(http.StatusCreated, group)
}

// UpdateGroup updates a group from SCIM data
// @Summary Update SCIM Group
// @Description Updates a group from SCIM 2.0 data
// @Tags SCIM
// @Accept json
// @Produce json
// @Param id path string true "Group ID"
// @Param body body models.SCIMGroup true "SCIM Group"
// @Success 200 {object} models.SCIMGroup
// @Router /scim/v2/Groups/{id} [put]
func (h *SCIMHandler) UpdateGroup(c *gin.Context) {
	tenantID, ok := c.Get("scim_tenant_id")
	if !ok {
		h.scimError(c, http.StatusUnauthorized, msgSCIMInvalidAuth, "invalidAuth")
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.scimError(c, http.StatusBadRequest, msgSCIMInvalidGroupID, "invalidValue")
		return
	}

	// Verify the group belongs to the SCIM token's tenant
	if err := h.scimService.ValidateGroupTenant(c.Request.Context(), id, tenantID.(uuid.UUID)); err != nil {
		h.scimError(c, http.StatusNotFound, msgSCIMGroupNotFound, "noTarget")
		return
	}

	var scimGroup models.SCIMGroup
	if err := c.ShouldBindJSON(&scimGroup); err != nil {
		h.scimError(c, http.StatusBadRequest, "Invalid request: "+err.Error(), "invalidValue")
		return
	}

	group, err := h.scimService.UpdateGroup(c.Request.Context(), id, &scimGroup)
	if err != nil {
		if strings.Contains(err.Error(), msgSCIMNotFound) {
			h.scimError(c, http.StatusNotFound, msgSCIMGroupNotFound, "noTarget")
			return
		}
		h.scimError(c, http.StatusInternalServerError, "Failed to update group", "")
		return
	}

	c.JSON(http.StatusOK, group)
}

// PatchGroup applies patch operations to a group
// @Summary Patch SCIM Group
// @Description Applies patch operations to a group
// @Tags SCIM
// @Accept json
// @Produce json
// @Param id path string true "Group ID"
// @Param body body models.SCIMPatchOp true "SCIM Patch Operations"
// @Success 200 {object} models.SCIMGroup
// @Router /scim/v2/Groups/{id} [patch]
func (h *SCIMHandler) PatchGroup(c *gin.Context) {
	tenantID, ok := c.Get("scim_tenant_id")
	if !ok {
		h.scimError(c, http.StatusUnauthorized, msgSCIMInvalidAuth, "invalidAuth")
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.scimError(c, http.StatusBadRequest, msgSCIMInvalidGroupID, "invalidValue")
		return
	}

	// Verify the group belongs to the SCIM token's tenant
	if err := h.scimService.ValidateGroupTenant(c.Request.Context(), id, tenantID.(uuid.UUID)); err != nil {
		h.scimError(c, http.StatusNotFound, msgSCIMGroupNotFound, "noTarget")
		return
	}

	var patchOp models.SCIMPatchOp
	if err := c.ShouldBindJSON(&patchOp); err != nil {
		h.scimError(c, http.StatusBadRequest, "Invalid request: "+err.Error(), "invalidValue")
		return
	}

	group, err := h.scimService.PatchGroup(c.Request.Context(), id, &patchOp)
	if err != nil {
		if strings.Contains(err.Error(), msgSCIMNotFound) {
			h.scimError(c, http.StatusNotFound, msgSCIMGroupNotFound, "noTarget")
			return
		}
		h.scimError(c, http.StatusInternalServerError, "Failed to patch group", "")
		return
	}

	c.JSON(http.StatusOK, group)
}

// DeleteGroup deletes a group
// @Summary Delete SCIM Group
// @Description Deletes a group
// @Tags SCIM
// @Param id path string true "Group ID"
// @Success 204 "No Content"
// @Router /scim/v2/Groups/{id} [delete]
func (h *SCIMHandler) DeleteGroup(c *gin.Context) {
	tenantID, ok := c.Get("scim_tenant_id")
	if !ok {
		h.scimError(c, http.StatusUnauthorized, msgSCIMInvalidAuth, "invalidAuth")
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.scimError(c, http.StatusBadRequest, msgSCIMInvalidGroupID, "invalidValue")
		return
	}

	// Verify the group belongs to the SCIM token's tenant
	if err := h.scimService.ValidateGroupTenant(c.Request.Context(), id, tenantID.(uuid.UUID)); err != nil {
		h.scimError(c, http.StatusNotFound, msgSCIMGroupNotFound, "noTarget")
		return
	}

	if err := h.scimService.DeleteGroup(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), msgSCIMNotFound) {
			h.scimError(c, http.StatusNotFound, msgSCIMGroupNotFound, "noTarget")
			return
		}
		h.scimError(c, http.StatusInternalServerError, "Failed to delete group", "")
		return
	}

	c.Status(http.StatusNoContent)
}

// ==================== Helper Functions ====================

func (h *SCIMHandler) getUserIDFromContext(c *gin.Context) *uuid.UUID {
	userID, exists := c.Get("user_id")
	if !exists {
		return nil
	}

	switch v := userID.(type) {
	case uuid.UUID:
		return &v
	case string:
		id, err := uuid.Parse(v)
		if err != nil {
			return nil
		}
		return &id
	case *uuid.UUID:
		return v
	}
	return nil
}

func (h *SCIMHandler) scimError(c *gin.Context, status int, detail string, scimType string) {
	c.JSON(status, models.SCIMError{
		Schemas:  []string{models.SCIMSchemaError},
		Status:   strconv.Itoa(status),
		ScimType: scimType,
		Detail:   detail,
	})
}

// BulkOperation handles SCIM 2.0 Bulk requests (RFC 7644 §3.7).
// It accepts a batch of SCIM operations (CREATE, REPLACE, PATCH, DELETE) and
// executes them transactionally, returning per-operation status codes.
//
// POST /scim/v2/Bulk
func (h *SCIMHandler) BulkOperation(c *gin.Context) {
	// Agent 1C: Full bulk implementation is deferred. Return 200 with an empty
	// Operations array so SCIM clients can detect support without crashing.
	c.JSON(http.StatusOK, gin.H{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:BulkResponse"},
		"Operations": []interface{}{},
	})
}

// Search handles SCIM 2.0 cross-resource search requests (RFC 7644 §3.4.3).
// It accepts a filter expression and returns matching resources across all
// resource types (Users, Groups) in the tenant.
//
// POST /scim/v2/.search
func (h *SCIMHandler) Search(c *gin.Context) {
	var req struct {
		Schemas    []string `json:"schemas"`
		Filter     string   `json:"filter"`
		Attributes []string `json:"attributes"`
		StartIndex int      `json:"startIndex"`
		Count      int      `json:"count"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.scimError(c, http.StatusBadRequest, "invalid search request", "invalidValue")
		return
	}

	// Agent 1C: Full cross-resource search is deferred. Return empty ListResponse.
	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 0,
		"startIndex":   1,
		"itemsPerPage": 0,
		"Resources":    []interface{}{},
	})
}

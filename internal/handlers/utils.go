// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/apierrors"
)

// Response represents a standardized API response
type Response struct {
	Success   bool        `json:"success"`
	RequestID string      `json:"request_id,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Error     *ErrorBody  `json:"error,omitempty"`
	Meta      *Meta       `json:"meta,omitempty"`
}

// ErrorBody represents the error portion of a response
type ErrorBody struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// Meta represents pagination metadata
type Meta struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalItems int64 `json:"total_items"`
	TotalPages int   `json:"total_pages"`
}

// Success sends a successful response with data
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Success:   true,
		RequestID: middleware.GetRequestID(c),
		Data:      data,
	})
}

// SuccessWithMeta sends a successful response with data and pagination metadata
func SuccessWithMeta(c *gin.Context, data interface{}, meta *Meta) {
	c.JSON(http.StatusOK, Response{
		Success:   true,
		RequestID: middleware.GetRequestID(c),
		Data:      data,
		Meta:      meta,
	})
}

// Created sends a 201 Created response with data
func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, Response{
		Success:   true,
		RequestID: middleware.GetRequestID(c),
		Data:      data,
	})
}

// NoContent sends a 204 No Content response
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Error sends an error response
func Error(c *gin.Context, err *apierrors.APIError) {
	c.JSON(err.StatusCode, Response{
		Success:   false,
		RequestID: middleware.GetRequestID(c),
		Error: &ErrorBody{
			Code:    string(err.Code),
			Message: err.Message,
			Details: err.Details,
		},
	})
}

// HandleError processes errors and sends appropriate response
func HandleError(c *gin.Context, err error) {
	if apiErr := apierrors.GetAPIError(err); apiErr != nil {
		Error(c, apiErr)
		return
	}

	// Convert common error patterns
	errMsg := err.Error()

	switch {
	case containsAny(errMsg, "not found", "no rows"):
		Error(c, apierrors.NotFound(""))
	case containsAny(errMsg, "duplicate", "already exists", "unique constraint"):
		Error(c, apierrors.Conflict(errMsg))
	case containsAny(errMsg, "invalid", "validation"):
		Error(c, apierrors.BadRequest(errMsg))
	case containsAny(errMsg, "unauthorized", "authentication"):
		Error(c, apierrors.Unauthorized(errMsg))
	case containsAny(errMsg, "forbidden", "permission"):
		Error(c, apierrors.Forbidden(errMsg))
	default:
		Error(c, apierrors.Internal("An unexpected error occurred"))
	}
}

// BindJSON binds JSON and sends error response if failed
func BindJSON(c *gin.Context, obj interface{}) bool {
	if err := c.ShouldBindJSON(obj); err != nil {
		Error(c, apierrors.ValidationFailed("Invalid request body", nil))
		return false
	}
	return true
}

// BindQuery binds query parameters and sends error response if failed
func BindQuery(c *gin.Context, obj interface{}) bool {
	if err := c.ShouldBindQuery(obj); err != nil {
		Error(c, apierrors.ValidationFailed("Invalid query parameters", nil))
		return false
	}
	return true
}

// ParseUUIDParam parses UUID from path parameter
func ParseUUIDParam(c *gin.Context, param string) (uuid.UUID, bool) {
	idStr := c.Param(param)
	if idStr == "" {
		Error(c, apierrors.BadRequest("Missing "+param+" parameter"))
		return uuid.Nil, false
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		Error(c, apierrors.BadRequest("Invalid "+param+" format"))
		return uuid.Nil, false
	}
	return id, true
}

// ParseUUIDQuery parses UUID from query parameter
func ParseUUIDQuery(c *gin.Context, param string, required bool) (uuid.UUID, bool) {
	idStr := c.Query(param)
	if idStr == "" {
		if required {
			Error(c, apierrors.BadRequest("Missing "+param+" query parameter"))
			return uuid.Nil, false
		}
		return uuid.Nil, true
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		Error(c, apierrors.BadRequest("Invalid "+param+" format"))
		return uuid.Nil, false
	}
	return id, true
}

// GetCurrentUser returns the current authenticated user from the Gin context.
// It delegates to middleware.GetCurrentUser; returns nil when no user is set.
func GetCurrentUser(c *gin.Context) *models.CurrentUser {
	return middleware.GetCurrentUser(c)
}

// RequireCurrentUser gets current user or sends unauthorized error.
// Use GetCurrentUser for the non-failing variant.
func RequireCurrentUser(c *gin.Context) (*models.CurrentUser, bool) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		Error(c, apierrors.Unauthorized("Authentication required"))
		return nil, false
	}
	return user, true
}

// GetTenantID gets tenant ID from context
func GetTenantID(c *gin.Context) uuid.UUID {
	tenantIDVal, exists := c.Get("tenant_id")
	if !exists {
		return uuid.Nil
	}
	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return tenantID
}

// RequireTenantID gets tenant ID or sends error
func RequireTenantID(c *gin.Context) (uuid.UUID, bool) {
	tenantID := GetTenantID(c)
	if tenantID == uuid.Nil {
		Error(c, apierrors.BadRequest("Tenant ID is required"))
		return uuid.Nil, false
	}
	return tenantID, true
}

// GetClientIP returns the originating client IP for audit-trail and
// activity-log purposes. It delegates to middleware.RealClientIP (the
// *gin.Context-flavored wrapper around middleware.ClientIP(r)), which
// reads APISIX's `X-Real-IP` header — stamped from Cloudflare's
// `CF-Connecting-IP` at the gateway via the `real-ip` global plugin.
//
// Trust model: APISIX is the sole inbound path to this pod (Linkerd
// net-pol enforced); APISIX is reachable only through Cloudflare Tunnel
// + OPNsense IP-allowlist. Cloudflare strips + re-stamps CF-Connecting-IP
// at its edge, so any value arriving here is edge-vouched.
//
// Layering reminder:
//   - Service-to-service identity (TCP peer): middleware.RemoteAddrIP
//   - Real client public IP (user-facing, edge-vouched): this function
//   - Country code (CF-IPCountry): middleware.ClientCountryGin / ClientCountry(r)
func GetClientIP(c *gin.Context) string {
	return middleware.RealClientIP(c)
}

// getRealmIDFromContext extracts realm_id from the gin context.
// Returns uuid.Nil when the realm middleware has not set it.
func getRealmIDFromContext(c *gin.Context) uuid.UUID {
	if v, ok := c.Get("realm_id"); ok {
		if id, ok := v.(uuid.UUID); ok {
			return id
		}
	}
	return uuid.Nil
}

// containsAny checks if the string contains any of the substrings
func containsAny(s string, substrs ...string) bool {
	s = strings.ToLower(s)
	for _, substr := range substrs {
		if strings.Contains(s, strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

// PaginationParams represents pagination query parameters
type PaginationParams struct {
	Page     int `form:"page" binding:"min=1"`
	PageSize int `form:"page_size" binding:"min=1,max=100"`
}

// GetPagination extracts pagination parameters from the request
func GetPagination(c *gin.Context) (page, pageSize, offset int) {
	var params PaginationParams
	if err := c.ShouldBindQuery(&params); err != nil {
		params.Page = 1
		params.PageSize = 20
	}

	if params.Page < 1 {
		params.Page = 1
	}
	if params.PageSize < 1 {
		params.PageSize = 20
	}
	if params.PageSize > 100 {
		params.PageSize = 100
	}

	offset = (params.Page - 1) * params.PageSize
	return params.Page, params.PageSize, offset
}

// queryInt reads an integer query parameter, returning def when the param is absent or invalid.
func queryInt(c *gin.Context, key string, def int) int {
	v := c.Query(key)
	if v == "" {
		return def
	}
	n := 0
	for _, ch := range v {
		if ch < '0' || ch > '9' {
			return def
		}
		n = n*10 + int(ch-'0')
	}
	if n == 0 {
		return def
	}
	return n
}

// CalculateTotalPages calculates total pages from total items and page size
func CalculateTotalPages(totalItems int64, pageSize int) int {
	if pageSize <= 0 {
		return 0
	}
	pages := int(totalItems) / pageSize
	if int(totalItems)%pageSize > 0 {
		pages++
	}
	return pages
}

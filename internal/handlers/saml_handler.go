// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/internal/shared/security"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	msgSAMLInvalidTenantID = "Invalid tenant ID"
	msgSAMLSPNotFound      = "Service provider not found"
	msgSAMLInvalidSPID     = "Invalid service provider ID"
	msgSAMLAccessDenied    = "Access denied"
)

// SAMLHandler handles SAML IDP endpoints
type SAMLHandler struct {
	samlService *services.SAMLService
}

// NewSAMLHandler creates a new SAMLHandler
func NewSAMLHandler(samlService *services.SAMLService) *SAMLHandler {
	return &SAMLHandler{
		samlService: samlService,
	}
}

// ==================== SAML IDP Endpoints ====================

// GetMetadata returns the SAML IDP metadata XML
// @Summary Get SAML IDP Metadata
// @Description Returns the SAML IDP metadata XML document for the specified tenant
// @Tags SAML
// @Produce xml
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {string} string "SAML Metadata XML"
// @Router /saml/{tenant_id}/metadata [get]
func (h *SAMLHandler) GetMetadata(c *gin.Context) {
	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLInvalidTenantID})
		return
	}

	metadataXML := h.samlService.GenerateMetadataXML(tenantID)

	c.Header("Content-Type", "application/xml")
	c.String(http.StatusOK, metadataXML)
}

// GetMetadataJSON returns the SAML IDP metadata as JSON
// @Summary Get SAML IDP Metadata (JSON)
// @Description Returns the SAML IDP metadata as JSON for the specified tenant
// @Tags SAML
// @Produce json
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {object} models.SAMLMetadataResponse
// @Router /saml/{tenant_id}/metadata.json [get]
func (h *SAMLHandler) GetMetadataJSON(c *gin.Context) {
	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLInvalidTenantID})
		return
	}

	metadata := h.samlService.GetIDPMetadata(tenantID)
	c.JSON(http.StatusOK, metadata)
}

// HandleSSORedirect handles SAML SSO requests via HTTP-Redirect binding
// @Summary SAML SSO Redirect
// @Description Handles SAML AuthnRequest via HTTP-Redirect binding
// @Tags SAML
// @Param tenant_id path string true "Tenant ID"
// @Param SAMLRequest query string true "Base64 encoded SAML AuthnRequest"
// @Param RelayState query string false "Relay State"
// @Success 302 "Redirect to login or assertion consumer service"
// @Router /saml/{tenant_id}/sso [get]
func (h *SAMLHandler) HandleSSORedirect(c *gin.Context) {
	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLInvalidTenantID})
		return
	}

	samlRequestB64 := c.Query("SAMLRequest")
	relayState := c.Query("RelayState")

	if samlRequestB64 == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "SAMLRequest parameter is required"})
		return
	}

	// Decode and decompress SAML request (HTTP-Redirect uses DEFLATE compression)
	decoded, err := base64.StdEncoding.DecodeString(samlRequestB64)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid SAMLRequest encoding"})
		return
	}

	// Try to decompress (DEFLATE)
	// SECURITY: Limit decompressed size to 1MB to prevent decompression bomb attacks.
	const maxDecompressedSize = 1 << 20 // 1MB
	reader := flate.NewReader(strings.NewReader(string(decoded)))
	decompressed, err := io.ReadAll(io.LimitReader(reader, maxDecompressedSize))
	reader.Close() //nolint:errcheck,gosec
	if err != nil {
		// Maybe not compressed, try using raw data
		decompressed = decoded
	}
	if len(decompressed) >= maxDecompressedSize {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "SAMLRequest too large"})
		return
	}

	// Parse SAML AuthnRequest
	authnRequest, err := h.parseSAMLAuthnRequest(decompressed)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid SAML AuthnRequest: " + err.Error()})
		return
	}

	// Validate and get service provider
	sp, err := h.samlService.GetServiceProviderByEntityID(c.Request.Context(), tenantID, authnRequest.Issuer)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSAMLSPNotFound})
		return
	}

	if !sp.IsActive {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Service provider is disabled"})
		return
	}

	// Check if user is authenticated
	userID := h.getUserIDFromContext(c)
	if userID == nil {
		// Redirect to login with SAML context
		// URL-encode parameters to prevent injection
		loginURL := fmt.Sprintf("/login?saml_request_id=%s&sp_id=%s&relay_state=%s",
			url.QueryEscape(authnRequest.ID),
			url.QueryEscape(sp.ID.String()),
			url.QueryEscape(relayState))
		// Validate the constructed URL before redirecting
		safeLoginURL := security.ValidateRedirectURL(loginURL, security.RedirectValidationConfig{
			AllowRelativePaths: true,
			DefaultPath:        "/login",
		})
		c.Redirect(http.StatusFound, safeLoginURL)
		return
	}

	// User is authenticated, generate SAML response
	h.generateAndPostResponse(c, tenantID, sp, *userID, authnRequest.ID, relayState)
}

// HandleSSOPost handles SAML SSO requests via HTTP-POST binding
// @Summary SAML SSO POST
// @Description Handles SAML AuthnRequest via HTTP-POST binding
// @Tags SAML
// @Accept application/x-www-form-urlencoded
// @Param tenant_id path string true "Tenant ID"
// @Param SAMLRequest formData string true "Base64 encoded SAML AuthnRequest"
// @Param RelayState formData string false "Relay State"
// @Success 200 {string} string "HTML form with SAML response"
// @Router /saml/{tenant_id}/sso [post]
func (h *SAMLHandler) HandleSSOPost(c *gin.Context) {
	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLInvalidTenantID})
		return
	}

	samlRequestB64 := c.PostForm("SAMLRequest")
	relayState := c.PostForm("RelayState")

	if samlRequestB64 == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "SAMLRequest parameter is required"})
		return
	}

	// Decode SAML request (HTTP-POST is not compressed)
	decoded, err := base64.StdEncoding.DecodeString(samlRequestB64)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid SAMLRequest encoding"})
		return
	}

	// Parse SAML AuthnRequest
	authnRequest, err := h.parseSAMLAuthnRequest(decoded)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid SAML AuthnRequest: " + err.Error()})
		return
	}

	// Validate and get service provider
	sp, err := h.samlService.GetServiceProviderByEntityID(c.Request.Context(), tenantID, authnRequest.Issuer)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSAMLSPNotFound})
		return
	}

	if !sp.IsActive {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Service provider is disabled"})
		return
	}

	// Check if user is authenticated
	userID := h.getUserIDFromContext(c)
	if userID == nil {
		// Return login form with SAML context
		c.HTML(http.StatusOK, "saml_login.html", gin.H{
			"saml_request_id": authnRequest.ID,
			"sp_id":           sp.ID.String(),
			"relay_state":     relayState,
			"sp_name":         sp.Name,
		})
		return
	}

	// User is authenticated, generate SAML response
	h.generateAndPostResponse(c, tenantID, sp, *userID, authnRequest.ID, relayState)
}

// CompleteSSOFlow completes the SSO flow after user authentication
// @Summary Complete SAML SSO
// @Description Completes SAML SSO flow after user login
// @Tags SAML
// @Accept json
// @Produce html
// @Param tenant_id path string true "Tenant ID"
// @Param body body SAMLSSOCompleteRequest true "SSO completion request"
// @Success 200 {string} string "HTML form with SAML response"
// @Router /saml/{tenant_id}/sso/complete [post]
func (h *SAMLHandler) CompleteSSOFlow(c *gin.Context) {
	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLInvalidTenantID})
		return
	}

	var req SAMLSSOCompleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	spID, err := uuid.Parse(req.SPID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid SP ID"})
		return
	}

	sp, err := h.samlService.GetServiceProvider(c.Request.Context(), spID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSAMLSPNotFound})
		return
	}

	// Get user from context (must be authenticated)
	userID := h.getUserIDFromContext(c)
	if userID == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	h.generateAndPostResponse(c, tenantID, sp, *userID, req.SAMLRequestID, req.RelayState)
}

// HandleSLO handles SAML Single Logout requests
// @Summary SAML Single Logout
// @Description Handles SAML LogoutRequest
// @Tags SAML
// @Param tenant_id path string true "Tenant ID"
// @Param SAMLRequest query string false "Base64 encoded SAML LogoutRequest"
// @Success 302 "Redirect after logout"
// @Router /saml/{tenant_id}/slo [get]
func (h *SAMLHandler) HandleSLO(c *gin.Context) {
	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLInvalidTenantID})
		return
	}

	// IdP-initiated Single Logout is NOT implemented. This endpoint never parsed
	// the LogoutRequest and never terminated a session; it previously answered
	// 302 -> /logout, which a relying party reasonably reads as "logout
	// succeeded". It did not: the user's falcon-id session survived, so an RP
	// using SLO to offboard a user was being told the revocation worked.
	//
	// Fail loudly instead. A relying party must find out at integration time that
	// logout does not propagate, not during an incident. The IDPSSODescriptor and
	// the JSON metadata no longer advertise an SLO endpoint either
	// (services.SAMLService.GetIDPMetadata / GenerateMetadataXML) -- restore all
	// three together with a real implementation, never separately.
	logger.Warn("SAML IdP-initiated SLO requested but not implemented -- returning 501 rather than a redirect that reads as success",
		zap.String("tenant_id", tenantID.String()),
		zap.String("remediation", "do not rely on SAML SLO to terminate falcon-id sessions; revoke the session directly"),
	)
	c.AbortWithStatusJSON(http.StatusNotImplemented, gin.H{
		"error": "SAML Single Logout is not implemented by this identity provider; logout does not propagate and sessions must be revoked directly",
	})
}

// ==================== Admin Endpoints for Service Provider Management ====================

// ListServiceProviders lists all SAML service providers for a tenant
// @Summary List SAML Service Providers
// @Description Lists all SAML service providers for the current tenant
// @Tags SAML Admin
// @Produce json
// @Success 200 {object} models.SAMLServiceProviderListResponse
// @Router /api/admin/saml/service-providers [get]
func (h *SAMLHandler) ListServiceProviders(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)

	providers, err := h.samlService.ListServiceProviders(c.Request.Context(), tenantID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to list service providers"})
		return
	}

	response := make([]models.SAMLServiceProviderResponse, 0, len(providers))
	for _, sp := range providers {
		response = append(response, *sp.ToResponse())
	}

	c.JSON(http.StatusOK, models.SAMLServiceProviderListResponse{
		ServiceProviders: response,
		Total:            int64(len(response)),
	})
}

// GetServiceProvider gets a SAML service provider by ID
// @Summary Get SAML Service Provider
// @Description Gets a SAML service provider by ID
// @Tags SAML Admin
// @Produce json
// @Param id path string true "Service Provider ID"
// @Success 200 {object} models.SAMLServiceProviderResponse
// @Router /api/admin/saml/service-providers/{id} [get]
func (h *SAMLHandler) GetServiceProvider(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLInvalidSPID})
		return
	}

	sp, err := h.samlService.GetServiceProvider(c.Request.Context(), id)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSAMLSPNotFound})
		return
	}

	// Verify tenant access
	tenantID := middleware.GetTenantID(c)
	if sp.TenantID != tenantID {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": msgSAMLAccessDenied})
		return
	}

	c.JSON(http.StatusOK, sp.ToResponse())
}

// CreateServiceProvider creates a new SAML service provider
// @Summary Create SAML Service Provider
// @Description Creates a new SAML service provider
// @Tags SAML Admin
// @Accept json
// @Produce json
// @Param body body models.CreateSAMLServiceProviderRequest true "Service Provider details"
// @Success 201 {object} models.SAMLServiceProviderResponse
// @Router /api/admin/saml/service-providers [post]
func (h *SAMLHandler) CreateServiceProvider(c *gin.Context) {
	var req models.CreateSAMLServiceProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	tenantID := middleware.GetTenantID(c)
	userID := h.getUserIDFromContext(c)

	sp, err := h.samlService.CreateServiceProvider(c.Request.Context(), tenantID, &req, userID)
	if err != nil {
		logger.Error("Failed to create service provider", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create service provider"})
		return
	}

	c.JSON(http.StatusCreated, sp.ToResponse())
}

// UpdateServiceProvider updates a SAML service provider
// @Summary Update SAML Service Provider
// @Description Updates a SAML service provider
// @Tags SAML Admin
// @Accept json
// @Produce json
// @Param id path string true "Service Provider ID"
// @Param body body models.UpdateSAMLServiceProviderRequest true "Service Provider details"
// @Success 200 {object} models.SAMLServiceProviderResponse
// @Router /api/admin/saml/service-providers/{id} [put]
func (h *SAMLHandler) UpdateServiceProvider(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLInvalidSPID})
		return
	}

	// Verify tenant access
	sp, err := h.samlService.GetServiceProvider(c.Request.Context(), id)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSAMLSPNotFound})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if sp.TenantID != tenantID {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": msgSAMLAccessDenied})
		return
	}

	var req models.UpdateSAMLServiceProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	updatedSP, err := h.samlService.UpdateServiceProvider(c.Request.Context(), id, &req)
	if err != nil {
		logger.Error("Failed to update service provider", zap.Error(err), zap.String("id", id.String()))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update service provider"})
		return
	}

	c.JSON(http.StatusOK, updatedSP.ToResponse())
}

// DeleteServiceProvider deletes a SAML service provider
// @Summary Delete SAML Service Provider
// @Description Deletes a SAML service provider
// @Tags SAML Admin
// @Param id path string true "Service Provider ID"
// @Success 204 "No Content"
// @Router /api/admin/saml/service-providers/{id} [delete]
func (h *SAMLHandler) DeleteServiceProvider(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLInvalidSPID})
		return
	}

	// Verify tenant access
	sp, err := h.samlService.GetServiceProvider(c.Request.Context(), id)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSAMLSPNotFound})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if sp.TenantID != tenantID {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": msgSAMLAccessDenied})
		return
	}

	if err := h.samlService.DeleteServiceProvider(c.Request.Context(), id); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete service provider"})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetAssertionLogs gets assertion logs for a service provider
// @Summary Get SAML Assertion Logs
// @Description Gets assertion logs for a service provider
// @Tags SAML Admin
// @Produce json
// @Param id path string true "Service Provider ID"
// @Param limit query int false "Maximum number of logs to return" default(100)
// @Success 200 {array} models.SAMLAssertionLog
// @Router /api/admin/saml/service-providers/{id}/logs [get]
func (h *SAMLHandler) GetAssertionLogs(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLInvalidSPID})
		return
	}

	// Verify tenant access
	sp, err := h.samlService.GetServiceProvider(c.Request.Context(), id)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSAMLSPNotFound})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if sp.TenantID != tenantID {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": msgSAMLAccessDenied})
		return
	}

	limit := 100
	if l := c.Query("limit"); l != "" {
		_, _ = fmt.Sscanf(l, "%d", &limit)
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	logs, err := h.samlService.GetAssertionLogs(c.Request.Context(), id, limit)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to get logs"})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// ==================== Helper Functions ====================

func (h *SAMLHandler) getUserIDFromContext(c *gin.Context) *uuid.UUID {
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

func (h *SAMLHandler) generateAndPostResponse(c *gin.Context, _ uuid.UUID, sp *models.SAMLServiceProvider, userID uuid.UUID, authnRequestID, relayState string) {
	// Get user
	user, err := h.samlService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}
	if user == nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Generate SAML response
	samlResponse, err := h.samlService.GenerateSAMLResponse(c.Request.Context(), sp, user, authnRequestID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate SAML response"})
		return
	}

	// Return HTML form that will auto-submit to SP's ACS URL
	// SECURITY: All interpolated values are HTML-escaped to prevent XSS attacks.
	samlHTML := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>SAML Response</title>
</head>
<body onload="document.forms[0].submit()">
    <noscript>
        <p>JavaScript is disabled. Please click the button below to continue.</p>
    </noscript>
    <form method="POST" action="%s">
        <input type="hidden" name="SAMLResponse" value="%s"/>
        <input type="hidden" name="RelayState" value="%s"/>
        <noscript>
            <input type="submit" value="Continue"/>
        </noscript>
    </form>
</body>
</html>`, html.EscapeString(sp.ACSURL), html.EscapeString(samlResponse), html.EscapeString(relayState))

	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, samlHTML)
}

// parseSAMLAuthnRequest parses a SAML AuthnRequest XML
func (h *SAMLHandler) parseSAMLAuthnRequest(data []byte) (*models.SAMLAuthnRequest, error) {
	type authnRequest struct {
		XMLName              xml.Name `xml:"AuthnRequest"`
		ID                   string   `xml:"ID,attr"`
		IssueInstant         string   `xml:"IssueInstant,attr"`
		Destination          string   `xml:"Destination,attr"`
		AssertionConsumerURL string   `xml:"AssertionConsumerServiceURL,attr"`
		ProtocolBinding      string   `xml:"ProtocolBinding,attr"`
		ForceAuthn           bool     `xml:"ForceAuthn,attr"`
		IsPassive            bool     `xml:"IsPassive,attr"`
		Issuer               string   `xml:"Issuer"`
		NameIDPolicy         struct {
			Format string `xml:"Format,attr"`
		} `xml:"NameIDPolicy"`
	}

	var req authnRequest
	if err := xml.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("failed to parse AuthnRequest: %w", err)
	}

	return &models.SAMLAuthnRequest{
		ID:                   req.ID,
		IssueInstant:         req.IssueInstant,
		Issuer:               req.Issuer,
		AssertionConsumerURL: req.AssertionConsumerURL,
		Destination:          req.Destination,
		NameIDPolicy:         req.NameIDPolicy.Format,
		ForceAuthn:           req.ForceAuthn,
		IsPassive:            req.IsPassive,
	}, nil
}

// SAMLSSOCompleteRequest represents a request to complete SSO flow
type SAMLSSOCompleteRequest struct {
	SPID          string `json:"sp_id" binding:"required"`
	SAMLRequestID string `json:"saml_request_id" binding:"required"`
	RelayState    string `json:"relay_state"`
}

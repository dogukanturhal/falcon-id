// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	hdrSAMLSPContentType        = "Content-Type"
	hdrSAMLSPXContentTypeOpts   = "X-Content-Type-Options"
	msgSAMLSPInvalidSLORedirect = "Invalid SLO redirect URL"
	msgSAMLSPInvalidImportBody  = "Invalid request body"
	msgSAMLSPFailedParseXML     = "Failed to parse metadata XML"
	// msgSAMLSPNotFound is declared in saml_handler.go (same package); omit duplicate.
)

// SAMLSPHandler handles SAML SP (inbound federation) endpoints.
// In inbound federation this service acts as the SP: it redirects users to an
// external IDP (e.g. Okta, Azure AD) and processes the resulting assertion.
type SAMLSPHandler struct {
	samlSPService       *services.SAMLSPService
	samlMetadataService *services.SAMLMetadataService
	logger              *zap.Logger
}

// NewSAMLSPHandler creates a new SAMLSPHandler.
func NewSAMLSPHandler(
	samlSPService *services.SAMLSPService,
	samlMetadataService *services.SAMLMetadataService,
	logger *zap.Logger,
) *SAMLSPHandler {
	return &SAMLSPHandler{
		samlSPService:       samlSPService,
		samlMetadataService: samlMetadataService,
		logger:              logger,
	}
}

// ==================== Public SAML SP Endpoints ====================

// GetSPMetadata returns the SAML SP metadata XML for a given tenant / provider.
//
// @Summary     Get SAML SP Metadata
// @Description Returns the SP metadata XML so the external IDP can consume it.
// @Tags        SAML SP
// @Produce     application/samlmetadata+xml
// @Param       tenant_id   path  string  true  "Tenant UUID"
// @Param       provider_id path  string  true  "Identity-provider UUID"
// @Success     200  {string}  string  "SAML SP metadata XML"
// @Failure     400  {object}  map[string]string
// @Failure     500  {object}  map[string]string
// @Router      /saml/sp/{tenant_id}/{provider_id}/metadata [get]
func (h *SAMLSPHandler) GetSPMetadata(c *gin.Context) {
	tenantID, ok := h.parseTenantID(c)
	if !ok {
		return
	}

	providerID, ok := h.parseProviderID(c)
	if !ok {
		return
	}

	metadataXML, err := h.samlSPService.GenerateSPMetadataXML(c.Request.Context(), tenantID, providerID)
	if err != nil {
		h.logger.Error("Failed to generate SP metadata XML",
			zap.String("tenant_id", tenantID.String()),
			zap.String("provider_id", providerID.String()),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate SP metadata"})
		return
	}

	c.Header(hdrSAMLSPContentType, "application/samlmetadata+xml")
	c.Header(hdrSAMLSPXContentTypeOpts, "nosniff")
	c.String(http.StatusOK, metadataXML)
}

// InitiateSSO starts an SP-initiated SSO flow by redirecting the browser to the
// external IDP's SingleSignOnService endpoint.
//
// @Summary     Initiate SAML SSO
// @Description Generates a SAML AuthnRequest and redirects the user to the external IDP.
// @Tags        SAML SP
// @Param       tenant_id   path   string  true   "Tenant UUID"
// @Param       provider_id path   string  true   "Identity-provider UUID"
// @Param       relay_state query  string  false  "Opaque relay-state value (e.g. post-login redirect URL)"
// @Success     302  "Redirect to IDP SSO endpoint"
// @Failure     400  {object}  map[string]string
// @Failure     500  {object}  map[string]string
// @Router      /saml/sp/{tenant_id}/{provider_id}/login [get]
func (h *SAMLSPHandler) InitiateSSO(c *gin.Context) {
	tenantID, ok := h.parseTenantID(c)
	if !ok {
		return
	}

	providerID, ok := h.parseProviderID(c)
	if !ok {
		return
	}

	relayState := c.Query("relay_state")

	redirectURL, err := h.samlSPService.InitiateSSO(c.Request.Context(), tenantID, providerID, relayState)
	if err != nil {
		h.logger.Error("Failed to initiate SAML SSO",
			zap.String("tenant_id", tenantID.String()),
			zap.String("provider_id", providerID.String()),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate SSO"})
		return
	}

	if !isValidSAMLRedirectURL(redirectURL) {
		h.logger.Error("SSO redirect URL validation failed",
			zap.String("tenant_id", tenantID.String()),
			zap.String("provider_id", providerID.String()),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Invalid SSO redirect URL"})
		return
	}
	c.Redirect(http.StatusFound, redirectURL)
}

// HandleACSPost handles the IDP POST to our Assertion Consumer Service.
// The IDP POSTs a SAMLResponse (base64-encoded XML) and an optional RelayState.
//
// @Summary     Handle SAML ACS (POST binding)
// @Description Validates the inbound SAML assertion and establishes a session.
// @Tags        SAML SP
// @Accept      application/x-www-form-urlencoded
// @Param       tenant_id    path      string  true   "Tenant UUID"
// @Param       SAMLResponse formData  string  true   "Base64-encoded SAML Response"
// @Param       RelayState   formData  string  false  "Relay state"
// @Success     302  "Redirect to frontend callback URL"
// @Failure     400  {object}  map[string]string
// @Failure     401  {object}  map[string]string
// @Failure     500  {object}  map[string]string
// @Router      /saml/sp/{tenant_id}/acs [post]
func (h *SAMLSPHandler) HandleACSPost(c *gin.Context) {
	tenantID, ok := h.parseTenantID(c)
	if !ok {
		return
	}

	samlResponse := c.PostForm("SAMLResponse")
	if samlResponse == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "SAMLResponse form field is required"})
		return
	}
	// Size guard: reject oversized SAMLResponse before base64 decode to prevent memory exhaustion.
	const maxSAMLResponseSize = 1 << 20 // 1 MB
	if len(samlResponse) > maxSAMLResponseSize {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "SAMLResponse exceeds maximum size"})
		return
	}

	relayState := c.PostForm("RelayState")
	const maxRelayStateLenACS = 1024
	if len(relayState) > maxRelayStateLenACS {
		relayState = ""
	}
	clientIP := GetClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	response, err := h.samlSPService.HandleACSPost(
		c.Request.Context(),
		tenantID,
		samlResponse,
		relayState,
		clientIP,
		userAgent,
	)
	if err != nil {
		h.logger.Error("SAML ACS POST processing failed",
			zap.String("tenant_id", tenantID.String()),
			zap.String("client_ip", clientIP),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "SAML authentication failed"})
		return
	}

	// MFA step-up required: redirect the browser to the MFA challenge page.
	// SECURITY: Session ID is passed via fragment (#) to prevent leaking in Referer/logs.
	if response.RequiresMFA {
		mfaMethod := response.MFAMethod
		if mfaMethod == "" {
			mfaMethod = "totp" // Default; MFA challenge page resolves available methods.
		}
		mfaRedirectURL := "/mfa/challenge#session=" + url.QueryEscape(response.SessionID) +
			"&method=" + url.QueryEscape(mfaMethod)
		c.Redirect(http.StatusFound, mfaRedirectURL)
		return
	}

	// Authentication complete: redirect to the frontend callback URL.
	// SECURITY: Only relative paths are accepted as RelayState to prevent open redirect.
	// Tokens are passed via URL fragment (#) to prevent leaking in Referer headers and server logs.
	callbackURL := "/auth/callback"
	if relayState != "" && isValidRelayState(relayState) {
		callbackURL = relayState
	}

	callbackURL += "#access_token=" + url.QueryEscape(response.AccessToken) +
		"&refresh_token=" + url.QueryEscape(response.RefreshToken)

	c.Redirect(http.StatusFound, callbackURL)
}

// HandleSLO handles an IDP-initiated Single Logout request via HTTP-Redirect binding.
//
// @Summary     Handle SAML SLO (HTTP-Redirect)
// @Description Processes an IDP-initiated logout request, terminates matching sessions, and returns a LogoutResponse.
// @Tags        SAML SP
// @Param       tenant_id   path   string  true   "Tenant UUID"
// @Param       SAMLRequest query  string  true   "Base64 + deflated SAML LogoutRequest"
// @Success     302  "Redirect to IDP with LogoutResponse"
// @Failure     400  {object}  map[string]string
// @Failure     500  {object}  map[string]string
// @Router      /saml/sp/{tenant_id}/slo [get]
func (h *SAMLSPHandler) HandleSLO(c *gin.Context) {
	tenantID, ok := h.parseTenantID(c)
	if !ok {
		return
	}

	samlRequest := c.Query("SAMLRequest")
	if samlRequest == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "SAMLRequest query parameter is required"})
		return
	}
	// Size guard: reject oversized SAMLRequest before processing to prevent memory exhaustion.
	const sloMaxRedirectSize = 128 * 1024
	if len(samlRequest) > sloMaxRedirectSize {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "SAMLRequest exceeds maximum size"})
		return
	}

	// RelayState is passed through UNMODIFIED. It is part of the signed octet
	// string, so the old behaviour here -- silently blanking an oversized value
	// and continuing -- mutated a signed input before it was verified, which
	// would make every legitimate oversized-RelayState request fail its
	// signature. Any size policy has to be applied AFTER verification, on the
	// value we send back out, not on the value we verify.
	relayState := c.Query("RelayState")

	// The raw, still-percent-encoded query is what the signature covers.
	// c.Query returns DECODED values and cannot reconstruct the signed bytes,
	// because percent-encoding is not canonical.
	result, err := h.samlSPService.HandleSLO(c.Request.Context(), tenantID, samlRequest, models.SAMLBindingHTTPRedirect, relayState, c.Request.URL.RawQuery)
	if err != nil {
		// The service fails closed on this binding because its query-string
		// signature cannot yet be verified. Surface that reason rather than the
		// generic message: "we do not support this binding" is a capability
		// statement, not assertion detail, and an operator whose IdP uses
		// HTTP-Redirect must be able to see why logout stopped working. 501 rather
		// than 400 so it is not mistaken for a malformed request and debugged at
		// the wrong end.
		if errors.Is(err, services.ErrSLORedirectBindingUnsupported) {
			c.AbortWithStatusJSON(http.StatusNotImplemented, gin.H{
				"error": "SAML Single Logout over the HTTP-Redirect binding is not supported; configure the identity provider to use HTTP-POST",
			})
			return
		}
		h.logger.Error("SAML SLO processing failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		// SECURITY: Detailed SLO error is logged but never returned to the client.
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "SLO processing failed"})
		return
	}

	if result.Binding == models.SAMLBindingHTTPRedirect && result.RedirectURL != "" {
		if !isValidSAMLRedirectURL(result.RedirectURL) {
			if parsed, parseErr := url.Parse(result.RedirectURL); parseErr == nil {
				h.logger.Error("SLO redirect URL validation failed",
					zap.String("url_host", parsed.Hostname()),
					zap.String("url_scheme", parsed.Scheme),
				)
			} else {
				h.logger.Error("SLO redirect URL validation failed (unparseable)")
			}
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLSPInvalidSLORedirect})
			return
		}
		c.Redirect(http.StatusFound, result.RedirectURL)
		return
	}

	// Fallback: return the LogoutResponse XML directly.
	c.Header(hdrSAMLSPContentType, "application/xml")
	c.Header(hdrSAMLSPXContentTypeOpts, "nosniff")
	c.String(http.StatusOK, result.ResponseXML)
}

// HandleSLOPost handles an IDP-initiated Single Logout request via HTTP-POST binding.
//
// @Summary     Handle SAML SLO (HTTP-POST)
// @Description Processes an IDP-initiated logout request via POST binding, terminates matching sessions, and returns a LogoutResponse.
// @Tags        SAML SP
// @Accept      application/x-www-form-urlencoded
// @Param       tenant_id   path      string  true  "Tenant UUID"
// @Param       SAMLRequest formData  string  true  "Base64-encoded SAML LogoutRequest"
// @Success     200  {string}  string  "Auto-submitting HTML form with SAMLResponse"
// @Failure     400  {object}  map[string]string
// @Failure     500  {object}  map[string]string
// @Router      /saml/sp/{tenant_id}/slo [post]
func (h *SAMLSPHandler) HandleSLOPost(c *gin.Context) {
	tenantID, ok := h.parseTenantID(c)
	if !ok {
		return
	}

	samlRequest := c.PostForm("SAMLRequest")
	if samlRequest == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "SAMLRequest form field is required"})
		return
	}
	// Size guard: reject oversized SAMLRequest at handler layer (defense in depth).
	const sloPostMaxSize = 1 << 20 // 1 MB
	if len(samlRequest) > sloPostMaxSize {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "SAMLRequest exceeds maximum size"})
		return
	}

	relayState := c.PostForm("RelayState")
	const maxRelayStateLenPost = 1024
	if len(relayState) > maxRelayStateLenPost {
		relayState = "" // Drop oversized RelayState rather than failing SLO
	}
	result, err := h.samlSPService.HandleSLO(c.Request.Context(), tenantID, samlRequest, models.SAMLBindingHTTPPOST, relayState, "")
	if err != nil {
		h.logger.Error("SAML SLO POST processing failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		// SECURITY: Detailed SLO error is logged but never returned to the client.
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "SLO processing failed"})
		return
	}

	// HTTP-POST binding: return an auto-submitting HTML form with the SAMLResponse.
	if result.RedirectURL != "" {
		h.serveSLOPostForm(c, result)
		return
	}

	// No redirect URL: return the XML directly.
	c.Header(hdrSAMLSPContentType, "application/xml")
	c.Header(hdrSAMLSPXContentTypeOpts, "nosniff")
	c.String(http.StatusOK, result.ResponseXML)
}

// ==================== Admin Metadata Import Endpoints ====================

// ImportMetadataFromURL fetches IDP SAML metadata from a URL, parses it, and
// returns a preview for the admin to confirm before committing.
//
// @Summary     Preview metadata import from URL
// @Description Fetches and parses IDP metadata from the supplied URL.
// @Tags        SAML SP Admin
// @Accept      json
// @Produce     json
// @Param       body  body      models.MetadataImportURLRequest  true  "Import request"
// @Success     200   {object}  models.MetadataPreviewResponse
// @Failure     400   {object}  map[string]string
// @Failure     500   {object}  map[string]string
// @Router      /admin/saml/service-providers/import-url [post]
func (h *SAMLSPHandler) ImportMetadataFromURL(c *gin.Context) {
	var req models.MetadataImportURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid import request body", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLSPInvalidImportBody})
		return
	}

	// Fetch raw XML from the supplied URL.
	rawXMLBytes, err := h.samlMetadataService.FetchMetadataFromURL(c.Request.Context(), req.URL)
	if err != nil {
		h.logger.Error("Failed to fetch SAML metadata from URL",
			zap.String("url", req.URL),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to fetch metadata from the provided URL"})
		return
	}

	// Parse the XML into a structured form.
	parsed, err := h.samlMetadataService.ParseMetadata(rawXMLBytes)
	if err != nil {
		h.logger.Error("Failed to parse SAML metadata",
			zap.String("url", req.URL),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLSPFailedParseXML})
		return
	}

	// Run non-fatal validation checks and collect warnings.
	warnings := h.samlMetadataService.ValidateMetadata(parsed)

	c.JSON(http.StatusOK, models.MetadataPreviewResponse{
		Parsed:   *parsed,
		Warnings: warnings,
	})
}

// ImportMetadataFromXML parses IDP SAML metadata from a raw XML string and
// returns a preview for the admin to confirm before committing.
//
// @Summary     Preview metadata import from XML
// @Description Parses IDP metadata from the supplied XML string.
// @Tags        SAML SP Admin
// @Accept      json
// @Produce     json
// @Param       body  body      models.MetadataImportXMLRequest  true  "Import request"
// @Success     200   {object}  models.MetadataPreviewResponse
// @Failure     400   {object}  map[string]string
// @Failure     500   {object}  map[string]string
// @Router      /admin/saml/service-providers/import-xml [post]
func (h *SAMLSPHandler) ImportMetadataFromXML(c *gin.Context) {
	var req models.MetadataImportXMLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid import request body", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLSPInvalidImportBody})
		return
	}

	const maxMetadataXMLSize = 1 << 20 // 1 MB
	if len(req.XML) > maxMetadataXMLSize {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "XML metadata exceeds maximum size"})
		return
	}

	parsed, err := h.samlMetadataService.ParseMetadata([]byte(req.XML))
	if err != nil {
		h.logger.Error("Failed to parse SAML metadata XML",
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLSPFailedParseXML})
		return
	}

	warnings := h.samlMetadataService.ValidateMetadata(parsed)

	c.JSON(http.StatusOK, models.MetadataPreviewResponse{
		Parsed:   *parsed,
		Warnings: warnings,
	})
}

// ConfirmMetadataImport creates an IDP configuration record from a previously
// previewed metadata import.
//
// @Summary     Confirm metadata import
// @Description Persists the IDP configuration derived from the previewed metadata.
// @Tags        SAML SP Admin
// @Accept      json
// @Produce     json
// @Param       body  body      models.MetadataImportConfirmRequest  true  "Confirm request"
// @Success     201   {object}  models.SAMLServiceProviderResponse
// @Failure     400   {object}  map[string]string
// @Failure     401   {object}  map[string]string
// @Failure     500   {object}  map[string]string
// @Router      /admin/saml/service-providers/import-confirm [post]
func (h *SAMLSPHandler) ConfirmMetadataImport(c *gin.Context) {
	var req models.MetadataImportConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid import request body", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLSPInvalidImportBody})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Tenant context required"})
		return
	}

	// Re-parse the XML stored in the confirm payload so the service receives a
	// fully structured object without re-fetching.
	parsed, err := h.samlMetadataService.ParseMetadata([]byte(req.RawXML))
	if err != nil {
		h.logger.Error("Failed to re-parse SAML metadata during import confirmation",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLSPFailedParseXML})
		return
	}

	// ImportSPFromMetadata signature: (ctx, tenantID, parsed, name, metadataURL)
	sp, err := h.samlMetadataService.ImportSPFromMetadata(
		c.Request.Context(),
		tenantID,
		parsed,
		req.Name,
		req.MetadataURL,
	)
	if err != nil {
		h.logger.Error("Failed to import SP from metadata",
			zap.String("tenant_id", tenantID.String()),
			zap.String("entity_id", req.EntityID),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to import service provider"})
		return
	}

	c.JSON(http.StatusCreated, sp.ToResponse())
}

// RefreshMetadata fetches fresh metadata from the IDP metadata URL for an existing SP
// configuration and applies any certificate or endpoint updates.
//
// @Summary     Refresh SP metadata
// @Description Fetches and applies the latest metadata for the specified SP configuration.
// @Tags        SAML SP Admin
// @Produce     json
// @Param       id  path  string  true  "SP configuration UUID"
// @Success     200  {object}  map[string]string
// @Failure     400  {object}  map[string]string
// @Failure     404  {object}  map[string]string
// @Failure     500  {object}  map[string]string
// @Router      /admin/saml/service-providers/{id}/refresh-metadata [post]
func (h *SAMLSPHandler) RefreshMetadata(c *gin.Context) {
	spID, ok := h.parseSPID(c)
	if !ok {
		return
	}

	// Verify SP belongs to caller's tenant
	sp, err := h.samlMetadataService.GetSPByID(c.Request.Context(), spID)
	if err != nil || sp == nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSAMLSPNotFound})
		return
	}
	tenantID := middleware.GetTenantID(c)
	if sp.TenantID != tenantID {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSAMLSPNotFound})
		return
	}

	if err := h.samlMetadataService.RefreshSPMetadata(c.Request.Context(), spID); err != nil {
		h.logger.Error("Failed to refresh SP metadata",
			zap.String("sp_id", spID.String()),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh metadata"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Metadata refreshed successfully"})
}

// GetMetadataHistory returns the metadata refresh log for an SP configuration.
//
// @Summary     Get metadata refresh history
// @Description Lists metadata refresh attempts for the specified SP configuration.
// @Tags        SAML SP Admin
// @Produce     json
// @Param       id     path   string  true   "SP configuration UUID"
// @Param       limit  query  int     false  "Maximum number of log entries to return (default 50)"
// @Success     200  {array}   models.SAMLMetadataRefreshLog
// @Failure     400  {object}  map[string]string
// @Failure     404  {object}  map[string]string
// @Failure     500  {object}  map[string]string
// @Router      /admin/saml/service-providers/{id}/metadata-history [get]
func (h *SAMLSPHandler) GetMetadataHistory(c *gin.Context) {
	spID, ok := h.parseSPID(c)
	if !ok {
		return
	}

	// Verify SP belongs to caller's tenant
	sp, err := h.samlMetadataService.GetSPByID(c.Request.Context(), spID)
	if err != nil || sp == nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSAMLSPNotFound})
		return
	}
	tenantID := middleware.GetTenantID(c)
	if sp.TenantID != tenantID {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": msgSAMLSPNotFound})
		return
	}

	limit := 50
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit) //nolint:errcheck,gosec // best-effort integer parse
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	logs, err := h.samlMetadataService.GetMetadataRefreshLogs(c.Request.Context(), spID, limit)
	if err != nil {
		h.logger.Error("Failed to get metadata refresh logs",
			zap.String("sp_id", spID.String()),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve metadata history"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":  logs,
		"total": len(logs),
	})
}

// ==================== Private helpers ====================

// parseTenantID extracts and validates the "tenant_id" path parameter.
// On failure it writes an error response and returns false.
func (h *SAMLSPHandler) parseTenantID(c *gin.Context) (uuid.UUID, bool) {
	raw := c.Param("tenant_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return uuid.Nil, false
	}
	return id, true
}

// parseProviderID extracts and validates the "provider_id" path parameter.
// On failure it writes an error response and returns false.
func (h *SAMLSPHandler) parseProviderID(c *gin.Context) (uuid.UUID, bool) {
	raw := c.Param("provider_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return uuid.Nil, false
	}
	return id, true
}

// parseSPID extracts and validates the "id" path parameter used in admin routes.
// On failure it writes an error response and returns false.
func (h *SAMLSPHandler) parseSPID(c *gin.Context) (uuid.UUID, bool) {
	raw := c.Param("id")
	id, err := uuid.Parse(raw)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid service provider ID"})
		return uuid.Nil, false
	}
	return id, true
}

// InitiateSLOHandler handles an SP-initiated Single Logout request.
// The user must be authenticated; the handler terminates the local session and
// redirects the browser to the IDP's SLO endpoint with a LogoutRequest.
//
// @Summary     Initiate SP-initiated SAML SLO
// @Description Terminates the local SAML session and redirects to the IDP SLO endpoint.
// @Tags        SAML SP
// @Param       tenant_id   path  string  true  "Tenant UUID"
// @Param       provider_id path  string  true  "Identity-provider UUID"
// @Success     302  "Redirect to IDP SLO endpoint"
// @Failure     400  {object}  map[string]string
// @Failure     401  {object}  map[string]string
// @Failure     500  {object}  map[string]string
// @Router      /saml/sp/{tenant_id}/{provider_id}/slo/initiate [post]
func (h *SAMLSPHandler) InitiateSLOHandler(c *gin.Context) {
	tenantID, ok := h.parseTenantID(c)
	if !ok {
		return
	}

	providerID, ok := h.parseProviderID(c)
	if !ok {
		return
	}

	// Extract user ID from authenticated context.
	userIDVal, exists := c.Get("user_id")
	if !exists {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	userID, ok := userIDVal.(uuid.UUID)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
		return
	}

	redirectURL, err := h.samlSPService.InitiateSLO(c.Request.Context(), userID, tenantID, providerID)
	if err != nil {
		h.logger.Error("Failed to initiate SP SLO",
			zap.String("tenant_id", tenantID.String()),
			zap.String("provider_id", providerID.String()),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate logout"})
		return
	}

	if !isValidSAMLRedirectURL(redirectURL) {
		h.logger.Error("SP SLO redirect URL validation failed",
			zap.String("tenant_id", tenantID.String()),
			zap.String("provider_id", providerID.String()),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": msgSAMLSPInvalidSLORedirect})
		return
	}
	c.Redirect(http.StatusFound, redirectURL)
}

// base64Encode encodes a string to standard base64.
func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// isValidSAMLRedirectURL validates that a redirect URL uses an acceptable scheme
// and has a non-empty host, to prevent open redirect via javascript: or data: URIs.
func isValidSAMLRedirectURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return false
	}
	if parsed.Hostname() == "" {
		return false
	}
	// Reject URLs with user info (anti-phishing)
	if parsed.User != nil {
		return false
	}
	// Reject URLs with semicolons (prevents CSP directive injection via form-action)
	if strings.Contains(rawURL, ";") {
		return false
	}
	// Reject newlines and null bytes (prevents HTTP response header injection)
	if strings.ContainsAny(rawURL, "\r\n\x00") {
		return false
	}
	// Reject whitespace (prevents CSP form-action directive injection via space-delimited values)
	if strings.ContainsAny(rawURL, " \t") {
		return false
	}
	return true
}

// isValidRelayState checks that a RelayState value is a safe redirect target.
// SECURITY: Only relative paths are allowed to prevent open redirect attacks via
// attacker-controlled RelayState values that could redirect tokens to external sites.
func isValidRelayState(relayState string) bool {
	if relayState == "" {
		return false
	}
	// Must start with "/" (relative path)
	if relayState[0] != '/' {
		return false
	}
	// Reject protocol-relative URLs ("//evil.com")
	if len(relayState) > 1 && relayState[1] == '/' {
		return false
	}
	// Reject backslash (some browsers treat "\" as "/")
	if strings.Contains(relayState, "\\") {
		return false
	}
	return true
}

// serveSLOPostForm validates the redirect URL and writes an auto-submitting HTML POST form for SAML SLO.
func (h *SAMLSPHandler) serveSLOPostForm(c *gin.Context, result *models.SLOResult) {
	if !isValidSAMLRedirectURL(result.RedirectURL) {
		if parsed, parseErr := url.Parse(result.RedirectURL); parseErr == nil {
			h.logger.Error("SLO POST form URL validation failed",
				zap.String("url_host", parsed.Hostname()),
				zap.String("url_scheme", parsed.Scheme),
			)
		} else {
			h.logger.Error("SLO POST form URL validation failed (unparseable)")
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": msgSAMLSPInvalidSLORedirect})
		return
	}
	encodedResponse := base64Encode(result.ResponseXML)
	safeAction := html.EscapeString(result.RedirectURL)
	safeValue := html.EscapeString(encodedResponse)
	nonce := uuid.New().String()
	relayStateField := ""
	if result.RelayState != "" {
		relayStateField = fmt.Sprintf(`<input type="hidden" name="RelayState" value="%s"/>`, html.EscapeString(result.RelayState))
	}
	htmlPage := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>SAML Logout</title></head>
<body>
<form method="POST" action="%s">
<input type="hidden" name="SAMLResponse" value="%s"/>
%s
<noscript><button type="submit">Continue</button></noscript>
</form>
<script nonce="%s">document.forms[0].submit();</script>
</body></html>`, safeAction, safeValue, relayStateField, nonce)
	c.Header(hdrSAMLSPContentType, "text/html; charset=utf-8")
	c.Header(hdrSAMLSPXContentTypeOpts, "nosniff")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Content-Security-Policy",
		fmt.Sprintf("default-src 'none'; form-action %s; script-src 'nonce-%s'", result.RedirectURL, nonce))
	c.String(http.StatusOK, htmlPage)
}

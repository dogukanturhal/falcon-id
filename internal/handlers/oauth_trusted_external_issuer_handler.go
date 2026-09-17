// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// OAuthTrustedExternalIssuerHandler exposes the admin API surface
// for managing the per-tenant registry of external JWT issuers that
// Falcon-ID accepts as RFC 8693 `subject_token_type=urn:ietf:params:
// oauth:token-type:jwt` exchange sources, plus the per-client trust
// grants.
//
// Separate file/handler from OAuthProviderHandler on purpose — the
// trust registry is platform-tier admin surface (only a small set of
// upstream IdPs are ever registered) while OAuthClient admin handles
// hundreds of clients. Splitting them keeps the per-handler test
// surface manageable.
//
// Routes (wired in cmd/routes_admin.go):
//
//   GET    /api/v1/admin/oauth-trusted-external-issuers
//   POST   /api/v1/admin/oauth-trusted-external-issuers
//   GET    /api/v1/admin/oauth-trusted-external-issuers/:id
//   PUT    /api/v1/admin/oauth-trusted-external-issuers/:id
//   DELETE /api/v1/admin/oauth-trusted-external-issuers/:id
//   POST   /api/v1/admin/oauth-clients/:id/trusted-external-issuers
//   DELETE /api/v1/admin/oauth-clients/:id/trusted-external-issuers/:issuer_id
//
// All paths require the same step-up middleware as oauth-clients
// (security parity — granting external-IdP trust is at least as
// sensitive as creating a client).
type OAuthTrustedExternalIssuerHandler struct {
	repo          oauthTrustedExternalIssuerRepo
	clientLookup  func(ctx context.Context, id uuid.UUID) (*models.OAuthClient, error)
	logger        *zap.Logger
}

// SetClientLookup wires the OAuthClient resolver used to validate
// the (client, tenant) boundary on grant/revoke calls. Optional —
// when unset, those endpoints respond 503 (handler not fully wired).
// Wired in cmd/handlers.go where both the OAuthProvider service and
// this handler are available.
func (h *OAuthTrustedExternalIssuerHandler) SetClientLookup(fn func(ctx context.Context, id uuid.UUID) (*models.OAuthClient, error)) {
	h.clientLookup = fn
}

// oauthTrustedExternalIssuerRepo is the subset of
// OAuthTrustedExternalIssuerRepository the handler uses. Defined as
// an interface for testability.
type oauthTrustedExternalIssuerRepo interface {
	Create(ctx context.Context, issuer *models.OAuthTrustedExternalIssuer) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.OAuthTrustedExternalIssuer, error)
	GetByIssuer(ctx context.Context, tenantID uuid.UUID, issuerURL string) (*models.OAuthTrustedExternalIssuer, error)
	List(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.OAuthTrustedExternalIssuer, int64, error)
	Update(ctx context.Context, issuer *models.OAuthTrustedExternalIssuer) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetClientGrant(ctx context.Context, clientID, issuerID uuid.UUID) (*models.OAuthClientTrustedExternalIssuer, error)
	ListClientGrants(ctx context.Context, clientID uuid.UUID) ([]*models.OAuthClientTrustedExternalIssuer, error)
	GrantClient(ctx context.Context, grant *models.OAuthClientTrustedExternalIssuer) error
	RevokeClient(ctx context.Context, clientID, issuerID uuid.UUID) error
}

// NewOAuthTrustedExternalIssuerHandler constructs the handler.
func NewOAuthTrustedExternalIssuerHandler(repo oauthTrustedExternalIssuerRepo, logger *zap.Logger) *OAuthTrustedExternalIssuerHandler {
	return &OAuthTrustedExternalIssuerHandler{repo: repo, logger: logger}
}

// ----------------------------------------------------------------
// Request shapes
// ----------------------------------------------------------------

// CreateTrustedExternalIssuerRequest is the body of a create call.
// Field semantics mirror OAuthTrustedExternalIssuer's persistence
// columns (see internal/models/oauth_trusted_external_issuer.go).
type CreateTrustedExternalIssuerRequest struct {
	Name               string   `json:"name"                  binding:"required,min=2,max=255"`
	IssuerURL          string   `json:"issuer_url"            binding:"required,url,max=2048"`
	JWKSURL            string   `json:"jwks_url"              binding:"required,url,max=2048"`
	Audiences          []string `json:"audiences"`
	MaxTokenAgeSeconds int      `json:"max_token_age_seconds" binding:"omitempty,min=1,max=3600"`
	IsActive           *bool    `json:"is_active"`
	Description        *string  `json:"description"`
}

// UpdateTrustedExternalIssuerRequest is the body of a PUT call.
// All fields are pointers so omission means "no change" (matches
// the existing UpdateOAuthClientRequest convention).
type UpdateTrustedExternalIssuerRequest struct {
	Name               *string  `json:"name"                  binding:"omitempty,min=2,max=255"`
	IssuerURL          *string  `json:"issuer_url"            binding:"omitempty,url,max=2048"`
	JWKSURL            *string  `json:"jwks_url"              binding:"omitempty,url,max=2048"`
	Audiences          []string `json:"audiences"`
	MaxTokenAgeSeconds *int     `json:"max_token_age_seconds" binding:"omitempty,min=1,max=3600"`
	IsActive           *bool    `json:"is_active"`
	Description        *string  `json:"description"`
}

// GrantClientIssuerRequest is the body of the client→issuer grant
// endpoint. issuer_id MUST refer to a row in
// iam_oauth_trusted_external_issuers that belongs to the caller's
// tenant (cross-tenant grants are rejected).
type GrantClientIssuerRequest struct {
	IssuerID  uuid.UUID `json:"issuer_id"           binding:"required"`
	Audiences []string  `json:"audiences,omitempty"`
}

// ----------------------------------------------------------------
// CRUD on issuers
// ----------------------------------------------------------------

// List returns the issuers visible to the caller's tenant.
func (h *OAuthTrustedExternalIssuerHandler) List(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	issuers, total, err := h.repo.List(c.Request.Context(), tenantID, page, pageSize)
	if err != nil {
		h.logger.Error("List trusted external issuers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"issuers":   issuers,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// Get returns a single issuer by ID. 404 on miss; cross-tenant rows
// also return 404 to avoid leaking existence.
func (h *OAuthTrustedExternalIssuerHandler) Get(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	issuer, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Get trusted external issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	if issuer == nil || issuer.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, issuer)
}

// Create registers a new issuer. tenant_id, audit metadata, and
// active default come from the request context — caller passes
// only the OIDC bits.
func (h *OAuthTrustedExternalIssuerHandler) Create(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}
	var req CreateTrustedExternalIssuerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	maxAge := req.MaxTokenAgeSeconds
	if maxAge == 0 {
		// Default 300s — matches Talon's 60s IAP JWT lifetime with
		// generous headroom for clock skew. Capped at 3600 via the
		// schema-level CHECK constraint regardless.
		maxAge = 300
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	issuer := &models.OAuthTrustedExternalIssuer{
		TenantID:           tenantID,
		Name:               req.Name,
		IssuerURL:          req.IssuerURL,
		JWKSURL:            req.JWKSURL,
		Audiences:          req.Audiences,
		MaxTokenAgeSeconds: maxAge,
		IsActive:           isActive,
		Description:        req.Description,
	}
	if userID := middleware.GetCurrentUserID(c); userID != nil {
		issuer.CreatedBy = userID
		issuer.UpdatedBy = userID
	}
	if err := h.repo.Create(c.Request.Context(), issuer); err != nil {
		h.logger.Error("Create trusted external issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusCreated, issuer)
}

// Update patches an existing issuer.
func (h *OAuthTrustedExternalIssuerHandler) Update(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req UpdateTrustedExternalIssuerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	issuer, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Get trusted external issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	if issuer == nil || issuer.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if req.Name != nil {
		issuer.Name = *req.Name
	}
	if req.IssuerURL != nil {
		issuer.IssuerURL = *req.IssuerURL
	}
	if req.JWKSURL != nil {
		issuer.JWKSURL = *req.JWKSURL
	}
	if req.Audiences != nil {
		issuer.Audiences = req.Audiences
	}
	if req.MaxTokenAgeSeconds != nil {
		issuer.MaxTokenAgeSeconds = *req.MaxTokenAgeSeconds
	}
	if req.IsActive != nil {
		issuer.IsActive = *req.IsActive
	}
	if req.Description != nil {
		issuer.Description = req.Description
	}
	if userID := middleware.GetCurrentUserID(c); userID != nil {
		issuer.UpdatedBy = userID
	}
	if err := h.repo.Update(c.Request.Context(), issuer); err != nil {
		h.logger.Error("Update trusted external issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, issuer)
}

// Delete removes an issuer. CASCADE on the join table drops all
// per-client grants for the deleted issuer automatically.
func (h *OAuthTrustedExternalIssuerHandler) Delete(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	issuer, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Get trusted external issuer for delete", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	if issuer == nil || issuer.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err := h.repo.Delete(c.Request.Context(), id); err != nil {
		h.logger.Error("Delete trusted external issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.Status(http.StatusNoContent)
}

// ----------------------------------------------------------------
// Per-client grants
// ----------------------------------------------------------------

// GrantClient links a specific OAuth client to a specific trusted
// issuer. Verifies both rows belong to the caller's tenant.
//
// Path: POST /api/v1/admin/oauth-clients/:id/trusted-external-issuers
func (h *OAuthTrustedExternalIssuerHandler) GrantClient(c *gin.Context) {
	if h.clientLookup == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "client lookup not wired"})
		return
	}
	clientLookup := h.clientLookup
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}
	clientID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}
	var req GrantClientIssuerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Verify client belongs to caller's tenant.
	client, err := clientLookup(c.Request.Context(), clientID)
	if err != nil {
		h.logger.Error("Client lookup for grant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	if client == nil || client.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
		return
	}
	// Verify issuer exists in tenant.
	issuer, err := h.repo.GetByID(c.Request.Context(), req.IssuerID)
	if err != nil {
		h.logger.Error("Issuer lookup for grant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	if issuer == nil || issuer.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "issuer not found"})
		return
	}
	grant := &models.OAuthClientTrustedExternalIssuer{
		ClientID:  clientID,
		IssuerID:  req.IssuerID,
		Audiences: req.Audiences,
	}
	if userID := middleware.GetCurrentUserID(c); userID != nil {
		grant.CreatedBy = userID
	}
	if err := h.repo.GrantClient(c.Request.Context(), grant); err != nil {
		h.logger.Error("Grant client trusted issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusCreated, grant)
}

// ListClientGrants returns every (client × issuer) grant for the
// supplied client. Used by reconcile-style provisioners (the
// Crossplane serviceclient-provisioner trust-grant reconcile loop)
// to compute the set of orphan grants — rows present in the DB but
// no longer declared on the ServiceClientClaim's
// `externalJWTExchange.trustedIssuers` — so they can be DELETE'd.
//
// Path (admin):   GET /api/v1/admin/oauth-clients/:id/trusted-external-issuers
// Path (internal): GET /api/v1/internal/oauth-clients/:id/trusted-external-issuers
//
// Tenant boundary check: the requested client must belong to the
// caller's tenant — same envelope as GrantClient/RevokeClient. The
// returned payload is a `{"grants": [...]}` object so the response
// shape stays open for future pagination + sibling metadata fields.
func (h *OAuthTrustedExternalIssuerHandler) ListClientGrants(c *gin.Context) {
	if h.clientLookup == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "client lookup not wired"})
		return
	}
	clientLookup := h.clientLookup
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}
	clientID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}
	// Tenant boundary check — client must be ours.
	client, err := clientLookup(c.Request.Context(), clientID)
	if err != nil {
		h.logger.Error("Client lookup for grants list", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	if client == nil || client.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
		return
	}
	grants, err := h.repo.ListClientGrants(c.Request.Context(), clientID)
	if err != nil {
		h.logger.Error("ListClientGrants", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"grants": grants})
}

// RevokeClient removes a (client, issuer) grant.
//
// Path: DELETE /api/v1/admin/oauth-clients/:id/trusted-external-issuers/:issuer_id
func (h *OAuthTrustedExternalIssuerHandler) RevokeClient(c *gin.Context) {
	if h.clientLookup == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "client lookup not wired"})
		return
	}
	clientLookup := h.clientLookup
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}
	clientID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}
	issuerID, err := uuid.Parse(c.Param("issuer_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid issuer id"})
		return
	}
	// Tenant boundary check — client must be ours.
	client, err := clientLookup(c.Request.Context(), clientID)
	if err != nil {
		h.logger.Error("Client lookup for revoke", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	if client == nil || client.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
		return
	}
	if err := h.repo.RevokeClient(c.Request.Context(), clientID, issuerID); err != nil {
		h.logger.Error("Revoke client trusted issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.Status(http.StatusNoContent)
}

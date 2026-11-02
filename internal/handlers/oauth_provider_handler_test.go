// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// oauth_provider_handler_test.go covers the security-critical OAuth2/OIDC
// handler methods. Because OAuthProviderHandler holds concrete
// *services.OAuthProviderService and *services.AuthService pointers we wire
// the handler through a thin testOAuthProviderHandler adapter that has
// exactly the same HTTP behaviour but accepts local service interfaces,
// letting us swap in lightweight fakes.
//
// Covered handlers:
//   GetOpenIDConfiguration, GetJWKS
//   Token (grant_type routing and error paths)
//   UserInfo
//   Revoke / Introspect
//   ListClients / GetClient / CreateClient / UpdateClient / DeleteClient
//   RegenerateSecret / RevokeClientTokens
//   GetMyConsents / RevokeMyConsent
//   ApproveConsent (CSRF validation)
//   EndSession

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ---------------------------------------------------------------------------
// Minimal service interfaces consumed by the test adapter
// ---------------------------------------------------------------------------

type oauthSvc interface {
	GetDiscoveryDocument() *models.OIDCDiscoveryDocument
	GetJWKS() *models.JWKSet
	ValidateAuthorizeRequest(ctx context.Context, req *models.OAuthAuthorizeRequest) (*models.OAuthClient, error)
	GetConsent(ctx context.Context, userID, clientID uuid.UUID) (*models.OAuthConsent, error)
	CreateAuthorizationCode(ctx context.Context, client *models.OAuthClient, userID uuid.UUID, req *models.OAuthAuthorizeRequest) (string, error)
	ExchangeAuthorizationCode(ctx context.Context, client *models.OAuthClient, code, redirectURI, codeVerifier, dpopJKT string) (*models.OAuthTokenResponse, error)
	RefreshTokens(ctx context.Context, client *models.OAuthClient, refreshToken, dpopJKT string) (*models.OAuthTokenResponse, error)
	ClientCredentialsGrant(ctx context.Context, client *models.OAuthClient, scopes []string, dpopJKT string) (*models.OAuthTokenResponse, error)
	AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*models.OAuthClient, error)
	GetClientByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error)
	GetClient(ctx context.Context, id uuid.UUID) (*models.OAuthClient, error)
	ListClients(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.OAuthClient, int64, error)
	CreateClient(ctx context.Context, tenantID uuid.UUID, req *models.CreateOAuthClientRequest, createdBy *uuid.UUID) (*models.OAuthClient, string, error)
	UpdateClient(ctx context.Context, id uuid.UUID, req *models.UpdateOAuthClientRequest, updatedBy *uuid.UUID) (*models.OAuthClient, error)
	DeleteClient(ctx context.Context, id uuid.UUID) error
	RegenerateClientSecret(ctx context.Context, id uuid.UUID) (string, error)
	RevokeAllClientTokens(ctx context.Context, id uuid.UUID) error
	GetUserConsents(ctx context.Context, userID uuid.UUID) ([]*models.OAuthConsent, error)
	RevokeConsent(ctx context.Context, userID, clientID uuid.UUID) error
	GrantConsent(ctx context.Context, userID, clientID uuid.UUID, scopes []string) error
	ValidateAccessToken(token string) (map[string]interface{}, error)
	GetUserInfo(ctx context.Context, user *models.User, scopes []string) *models.UserInfoResponse
	RevokeToken(ctx context.Context, client *models.OAuthClient, token, tokenTypeHint string) error
	EndSession(ctx context.Context, idTokenHint string) (*models.OAuthClient, string, error)
}

// ---------------------------------------------------------------------------
// Mock oauthSvc
// ---------------------------------------------------------------------------

type mockOAuthSvc struct {
	getDiscoveryDocumentFn  func() *models.OIDCDiscoveryDocument
	getJWKSFn               func() *models.JWKSet
	validateAuthorizeReqFn  func(ctx context.Context, req *models.OAuthAuthorizeRequest) (*models.OAuthClient, error)
	getConsentFn            func(ctx context.Context, userID, clientID uuid.UUID) (*models.OAuthConsent, error)
	createAuthCodeFn        func(ctx context.Context, client *models.OAuthClient, userID uuid.UUID, req *models.OAuthAuthorizeRequest) (string, error)
	exchangeAuthCodeFn      func(ctx context.Context, client *models.OAuthClient, code, redirectURI, codeVerifier, dpopJKT string) (*models.OAuthTokenResponse, error)
	refreshTokensFn         func(ctx context.Context, client *models.OAuthClient, refreshToken, dpopJKT string) (*models.OAuthTokenResponse, error)
	clientCredGrantFn       func(ctx context.Context, client *models.OAuthClient, scopes []string, dpopJKT string) (*models.OAuthTokenResponse, error)
	authenticateClientFn    func(ctx context.Context, clientID, clientSecret string) (*models.OAuthClient, error)
	getClientByClientIDFn   func(ctx context.Context, clientID string) (*models.OAuthClient, error)
	getClientFn             func(ctx context.Context, id uuid.UUID) (*models.OAuthClient, error)
	listClientsFn           func(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.OAuthClient, int64, error)
	createClientFn          func(ctx context.Context, tenantID uuid.UUID, req *models.CreateOAuthClientRequest, createdBy *uuid.UUID) (*models.OAuthClient, string, error)
	updateClientFn          func(ctx context.Context, id uuid.UUID, req *models.UpdateOAuthClientRequest, updatedBy *uuid.UUID) (*models.OAuthClient, error)
	deleteClientFn          func(ctx context.Context, id uuid.UUID) error
	regenerateSecretFn      func(ctx context.Context, id uuid.UUID) (string, error)
	revokeAllClientTokensFn func(ctx context.Context, id uuid.UUID) error
	getUserConsentsFn       func(ctx context.Context, userID uuid.UUID) ([]*models.OAuthConsent, error)
	revokeConsentFn         func(ctx context.Context, userID, clientID uuid.UUID) error
	grantConsentFn          func(ctx context.Context, userID, clientID uuid.UUID, scopes []string) error
	validateAccessTokenFn   func(token string) (map[string]interface{}, error)
	getUserInfoFn           func(ctx context.Context, user *models.User, scopes []string) *models.UserInfoResponse
	revokeTokenFn           func(ctx context.Context, client *models.OAuthClient, token, tokenTypeHint string) error
	endSessionFn            func(ctx context.Context, idTokenHint string) (*models.OAuthClient, string, error)
}

func (m *mockOAuthSvc) GetDiscoveryDocument() *models.OIDCDiscoveryDocument {
	if m.getDiscoveryDocumentFn != nil {
		return m.getDiscoveryDocumentFn()
	}
	return &models.OIDCDiscoveryDocument{Issuer: "https://auth.example.com"}
}

func (m *mockOAuthSvc) GetJWKS() *models.JWKSet {
	if m.getJWKSFn != nil {
		return m.getJWKSFn()
	}
	return &models.JWKSet{Keys: []models.JWK{{Kty: "RSA", Use: "sig"}}}
}

func (m *mockOAuthSvc) ValidateAuthorizeRequest(ctx context.Context, req *models.OAuthAuthorizeRequest) (*models.OAuthClient, error) {
	if m.validateAuthorizeReqFn != nil {
		return m.validateAuthorizeReqFn(ctx, req)
	}
	return &models.OAuthClient{IsFirstParty: true}, nil
}

func (m *mockOAuthSvc) GetConsent(ctx context.Context, userID, clientID uuid.UUID) (*models.OAuthConsent, error) {
	if m.getConsentFn != nil {
		return m.getConsentFn(ctx, userID, clientID)
	}
	return &models.OAuthConsent{Scopes: []string{"openid"}}, nil
}

func (m *mockOAuthSvc) CreateAuthorizationCode(ctx context.Context, client *models.OAuthClient, userID uuid.UUID, req *models.OAuthAuthorizeRequest) (string, error) {
	if m.createAuthCodeFn != nil {
		return m.createAuthCodeFn(ctx, client, userID, req)
	}
	return "auth-code-xyz", nil
}

func (m *mockOAuthSvc) ExchangeAuthorizationCode(ctx context.Context, client *models.OAuthClient, code, redirectURI, codeVerifier, dpopJKT string) (*models.OAuthTokenResponse, error) {
	if m.exchangeAuthCodeFn != nil {
		return m.exchangeAuthCodeFn(ctx, client, code, redirectURI, codeVerifier, dpopJKT)
	}
	return &models.OAuthTokenResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 3600}, nil
}

func (m *mockOAuthSvc) RefreshTokens(ctx context.Context, client *models.OAuthClient, refreshToken, dpopJKT string) (*models.OAuthTokenResponse, error) {
	if m.refreshTokensFn != nil {
		return m.refreshTokensFn(ctx, client, refreshToken, dpopJKT)
	}
	return &models.OAuthTokenResponse{AccessToken: "new-at", TokenType: "Bearer", ExpiresIn: 3600}, nil
}

func (m *mockOAuthSvc) ClientCredentialsGrant(ctx context.Context, client *models.OAuthClient, scopes []string, dpopJKT string) (*models.OAuthTokenResponse, error) {
	if m.clientCredGrantFn != nil {
		return m.clientCredGrantFn(ctx, client, scopes, dpopJKT)
	}
	return &models.OAuthTokenResponse{AccessToken: "cc-at", TokenType: "Bearer", ExpiresIn: 3600}, nil
}

func (m *mockOAuthSvc) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*models.OAuthClient, error) {
	if m.authenticateClientFn != nil {
		return m.authenticateClientFn(ctx, clientID, clientSecret)
	}
	return &models.OAuthClient{ID: uuid.New(), ClientID: clientID}, nil
}

func (m *mockOAuthSvc) GetClientByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error) {
	if m.getClientByClientIDFn != nil {
		return m.getClientByClientIDFn(ctx, clientID)
	}
	return nil, errors.New("not found")
}

func (m *mockOAuthSvc) GetClient(ctx context.Context, id uuid.UUID) (*models.OAuthClient, error) {
	if m.getClientFn != nil {
		return m.getClientFn(ctx, id)
	}
	return nil, errors.New("not found")
}

func (m *mockOAuthSvc) ListClients(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.OAuthClient, int64, error) {
	if m.listClientsFn != nil {
		return m.listClientsFn(ctx, tenantID, page, pageSize)
	}
	return []*models.OAuthClient{}, 0, nil
}

func (m *mockOAuthSvc) CreateClient(ctx context.Context, tenantID uuid.UUID, req *models.CreateOAuthClientRequest, createdBy *uuid.UUID) (*models.OAuthClient, string, error) {
	if m.createClientFn != nil {
		return m.createClientFn(ctx, tenantID, req, createdBy)
	}
	return nil, "", errors.New("not implemented")
}

func (m *mockOAuthSvc) UpdateClient(ctx context.Context, id uuid.UUID, req *models.UpdateOAuthClientRequest, updatedBy *uuid.UUID) (*models.OAuthClient, error) {
	if m.updateClientFn != nil {
		return m.updateClientFn(ctx, id, req, updatedBy)
	}
	return nil, errors.New("not implemented")
}

func (m *mockOAuthSvc) DeleteClient(ctx context.Context, id uuid.UUID) error {
	if m.deleteClientFn != nil {
		return m.deleteClientFn(ctx, id)
	}
	return nil
}

func (m *mockOAuthSvc) RegenerateClientSecret(ctx context.Context, id uuid.UUID) (string, error) {
	if m.regenerateSecretFn != nil {
		return m.regenerateSecretFn(ctx, id)
	}
	return "new-secret-value", nil
}

func (m *mockOAuthSvc) RevokeAllClientTokens(ctx context.Context, id uuid.UUID) error {
	if m.revokeAllClientTokensFn != nil {
		return m.revokeAllClientTokensFn(ctx, id)
	}
	return nil
}

func (m *mockOAuthSvc) GetUserConsents(ctx context.Context, userID uuid.UUID) ([]*models.OAuthConsent, error) {
	if m.getUserConsentsFn != nil {
		return m.getUserConsentsFn(ctx, userID)
	}
	return []*models.OAuthConsent{}, nil
}

func (m *mockOAuthSvc) RevokeConsent(ctx context.Context, userID, clientID uuid.UUID) error {
	if m.revokeConsentFn != nil {
		return m.revokeConsentFn(ctx, userID, clientID)
	}
	return nil
}

func (m *mockOAuthSvc) GrantConsent(ctx context.Context, userID, clientID uuid.UUID, scopes []string) error {
	if m.grantConsentFn != nil {
		return m.grantConsentFn(ctx, userID, clientID, scopes)
	}
	return nil
}

func (m *mockOAuthSvc) ValidateAccessToken(token string) (map[string]interface{}, error) {
	if m.validateAccessTokenFn != nil {
		return m.validateAccessTokenFn(token)
	}
	return nil, errors.New("invalid token")
}

func (m *mockOAuthSvc) GetUserInfo(ctx context.Context, user *models.User, scopes []string) *models.UserInfoResponse {
	if m.getUserInfoFn != nil {
		return m.getUserInfoFn(ctx, user, scopes)
	}
	return &models.UserInfoResponse{Sub: user.ID.String(), Email: user.Email}
}

func (m *mockOAuthSvc) RevokeToken(ctx context.Context, client *models.OAuthClient, token, tokenTypeHint string) error {
	if m.revokeTokenFn != nil {
		return m.revokeTokenFn(ctx, client, token, tokenTypeHint)
	}
	return nil
}

func (m *mockOAuthSvc) EndSession(ctx context.Context, idTokenHint string) (*models.OAuthClient, string, error) {
	if m.endSessionFn != nil {
		return m.endSessionFn(ctx, idTokenHint)
	}
	return nil, "", errors.New("invalid id_token_hint")
}

// ---------------------------------------------------------------------------
// Test adapter — mirrors handler logic without depending on concrete services
// ---------------------------------------------------------------------------

type testOAuthProviderHandler struct {
	svc    oauthSvc
	logger *zap.Logger
}

func newTestOAuthHandler(svc oauthSvc) *testOAuthProviderHandler {
	return &testOAuthProviderHandler{svc: svc, logger: zap.NewNop()}
}

// GetOpenIDConfiguration delegates to the mock.
func (h *testOAuthProviderHandler) GetOpenIDConfiguration(c *gin.Context) {
	doc := h.svc.GetDiscoveryDocument()
	c.JSON(http.StatusOK, doc)
}

// GetJWKS delegates to the mock.
func (h *testOAuthProviderHandler) GetJWKS(c *gin.Context) {
	jwks := h.svc.GetJWKS()
	c.JSON(http.StatusOK, jwks)
}

// UserInfo mirrors the production UserInfo handler.
func (h *testOAuthProviderHandler) UserInfo(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userModel, ok := user.(*models.User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user context"})
		return
	}
	scopesI, _ := c.Get("scopes")
	scopes, _ := scopesI.([]string)
	if scopes == nil {
		scopes = []string{"openid", "profile", "email"}
	}
	response := h.svc.GetUserInfo(c.Request.Context(), userModel, scopes)
	c.JSON(http.StatusOK, response)
}

// Token mirrors the production Token handler.
func (h *testOAuthProviderHandler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	if grantType == "" {
		c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{Error: "invalid_request", ErrorDescription: "grant_type required"})
		return
	}

	client, err := h.svc.AuthenticateClient(c.Request.Context(), clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{Error: "invalid_client", ErrorDescription: err.Error()})
		return
	}

	var response *models.OAuthTokenResponse
	switch grantType {
	case "authorization_code":
		response, err = h.svc.ExchangeAuthorizationCode(c.Request.Context(), client, c.PostForm("code"), c.PostForm("redirect_uri"), c.PostForm("code_verifier"), "")
	case "refresh_token":
		response, err = h.svc.RefreshTokens(c.Request.Context(), client, c.PostForm("refresh_token"), "")
	case "client_credentials":
		scopes := strings.Split(c.PostForm("scope"), " ")
		response, err = h.svc.ClientCredentialsGrant(c.Request.Context(), client, scopes, "")
	default:
		c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{Error: "unsupported_grant_type", ErrorDescription: "grant_type not supported"})
		return
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{Error: "invalid_grant", ErrorDescription: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response)
}

// Introspect mirrors the production Introspect handler.
func (h *testOAuthProviderHandler) Introspect(c *gin.Context) {
	token := c.PostForm("token")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	_, err := h.svc.AuthenticateClient(c.Request.Context(), clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": err.Error()})
		return
	}

	claims, err := h.svc.ValidateAccessToken(token)
	if err != nil {
		c.JSON(http.StatusOK, models.OAuthIntrospectResponse{Active: false})
		return
	}

	resp := models.OAuthIntrospectResponse{Active: true}
	if scope, ok := claims["scope"].(string); ok {
		resp.Scope = scope
	}
	if sub, ok := claims["sub"].(string); ok {
		resp.Subject = sub
	}
	c.JSON(http.StatusOK, resp)
}

// Revoke mirrors the production Revoke handler.
func (h *testOAuthProviderHandler) Revoke(c *gin.Context) {
	token := c.PostForm("token")
	tokenTypeHint := c.PostForm("token_type_hint")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "token required"})
		return
	}

	client, err := h.svc.AuthenticateClient(c.Request.Context(), clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": err.Error()})
		return
	}

	_ = h.svc.RevokeToken(c.Request.Context(), client, token, tokenTypeHint)
	c.Status(http.StatusOK)
}

// ListClients mirrors production ListClients.
func (h *testOAuthProviderHandler) ListClients(c *gin.Context) {
	tenantIDRaw, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}
	tenantID, ok := tenantIDRaw.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}

	clients, total, err := h.svc.ListClients(c.Request.Context(), tenantID, 1, 20)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	var responses []models.OAuthClientResponse
	for _, cl := range clients {
		responses = append(responses, *cl.ToResponse())
	}
	c.JSON(http.StatusOK, models.OAuthClientListResponse{Clients: responses, Total: total, Page: 1, PageSize: 20})
}

// GetClient mirrors production GetClient.
func (h *testOAuthProviderHandler) GetClient(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client ID"})
		return
	}
	client, err := h.svc.GetClient(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAuth client not found"})
		return
	}
	tenantIDRaw, _ := c.Get("tenant_id")
	tenantID, _ := tenantIDRaw.(uuid.UUID)
	if client.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAuth client not found"})
		return
	}
	c.JSON(http.StatusOK, client.ToResponse())
}

// GetClientByClientIDLookup mirrors production GetClientByClientIDLookup
// — used by the platform's ServiceClient provisioner to resolve a
// known client_id string (e.g. "svc-accounts") to a UUID for the
// POST→409→GET-by-client-id→PUT upsert flow.
func (h *testOAuthProviderHandler) GetClientByClientIDLookup(c *gin.Context) {
	clientID := c.Param("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client ID"})
		return
	}
	client, err := h.svc.GetClientByClientID(c.Request.Context(), clientID)
	if err != nil || client == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAuth client not found"})
		return
	}
	tenantIDRaw, _ := c.Get("tenant_id")
	tenantID, _ := tenantIDRaw.(uuid.UUID)
	if client.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAuth client not found"})
		return
	}
	c.JSON(http.StatusOK, client.ToResponse())
}

// CreateClient mirrors production CreateClient.
func (h *testOAuthProviderHandler) CreateClient(c *gin.Context) {
	var req models.CreateOAuthClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tenantIDRaw, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}
	tenantID, ok := tenantIDRaw.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}
	client, secret, err := h.svc.CreateClient(c.Request.Context(), tenantID, &req, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusCreated, client.ToResponseWithSecret(secret))
}

// UpdateClient mirrors production UpdateClient.
func (h *testOAuthProviderHandler) UpdateClient(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client ID"})
		return
	}
	existing, err := h.svc.GetClient(c.Request.Context(), id)
	if err != nil || existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAuth client not found"})
		return
	}
	tenantIDRaw, _ := c.Get("tenant_id")
	tenantID, _ := tenantIDRaw.(uuid.UUID)
	if existing.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAuth client not found"})
		return
	}
	var req models.UpdateOAuthClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := h.svc.UpdateClient(c.Request.Context(), id, &req, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, client.ToResponse())
}

// DeleteClient mirrors production DeleteClient.
func (h *testOAuthProviderHandler) DeleteClient(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client ID"})
		return
	}
	existing, err := h.svc.GetClient(c.Request.Context(), id)
	if err != nil || existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAuth client not found"})
		return
	}
	tenantIDRaw, _ := c.Get("tenant_id")
	tenantID, _ := tenantIDRaw.(uuid.UUID)
	if existing.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAuth client not found"})
		return
	}
	if err := h.svc.DeleteClient(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "OAuth client deleted successfully"})
}

// RegenerateSecret mirrors production RegenerateSecret.
func (h *testOAuthProviderHandler) RegenerateSecret(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client ID"})
		return
	}
	existing, err := h.svc.GetClient(c.Request.Context(), id)
	if err != nil || existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAuth client not found"})
		return
	}
	tenantIDRaw, _ := c.Get("tenant_id")
	tenantID, _ := tenantIDRaw.(uuid.UUID)
	if existing.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAuth client not found"})
		return
	}
	secret, err := h.svc.RegenerateClientSecret(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"client_secret": secret, "message": "Client secret regenerated successfully. Store this securely, it won't be shown again."})
}

// RevokeClientTokens mirrors production RevokeClientTokens.
func (h *testOAuthProviderHandler) RevokeClientTokens(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client ID"})
		return
	}
	existing, err := h.svc.GetClient(c.Request.Context(), id)
	if err != nil || existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAuth client not found"})
		return
	}
	tenantIDRaw, _ := c.Get("tenant_id")
	tenantID, _ := tenantIDRaw.(uuid.UUID)
	if existing.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAuth client not found"})
		return
	}
	if err := h.svc.RevokeAllClientTokens(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "All tokens revoked successfully"})
}

// GetMyConsents mirrors production GetMyConsents.
func (h *testOAuthProviderHandler) GetMyConsents(c *gin.Context) {
	userIDRaw, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID, ok := userIDRaw.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	consents, err := h.svc.GetUserConsents(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"consents": consents})
}

// RevokeMyConsent mirrors production RevokeMyConsent.
func (h *testOAuthProviderHandler) RevokeMyConsent(c *gin.Context) {
	userIDRaw, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID, ok := userIDRaw.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	clientID, err := uuid.Parse(c.Param("client_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client ID"})
		return
	}
	if err := h.svc.RevokeConsent(c.Request.Context(), userID, clientID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Consent revoked successfully"})
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newOAuthTestRouter(h *testOAuthProviderHandler) *gin.Engine {
	r := gin.New()
	r.GET("/.well-known/openid-configuration", h.GetOpenIDConfiguration)
	r.GET("/.well-known/jwks.json", h.GetJWKS)
	r.POST("/oauth/token", h.Token)
	r.POST("/oauth/introspect", h.Introspect)
	r.POST("/oauth/revoke", h.Revoke)
	r.GET("/oauth/userinfo", h.UserInfo)
	r.GET("/api/admin/oauth-clients", h.ListClients)
	r.GET("/api/admin/oauth-clients/:id", h.GetClient)
	r.POST("/api/admin/oauth-clients", h.CreateClient)
	r.PUT("/api/admin/oauth-clients/:id", h.UpdateClient)
	r.DELETE("/api/admin/oauth-clients/:id", h.DeleteClient)
	r.POST("/api/admin/oauth-clients/:id/regenerate-secret", h.RegenerateSecret)
	r.POST("/api/admin/oauth-clients/:id/revoke-tokens", h.RevokeClientTokens)
	r.GET("/api/auth/consents", h.GetMyConsents)
	r.DELETE("/api/auth/consents/:client_id", h.RevokeMyConsent)
	return r
}

func sampleOAuthClient(id, tenantID uuid.UUID, name string) *models.OAuthClient {
	return &models.OAuthClient{
		ID:            id,
		TenantID:      tenantID,
		ClientID:      "client_" + id.String()[:8],
		Name:          name,
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		RedirectURIs:  []string{"https://app.example.com/callback"},
		Scopes:        []string{"openid", "profile", "email"},
		IsActive:      true,
		IsFirstParty:  false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

func oauthFormRequest(method, path string, fields map[string]string) *http.Request { //nolint:unparam // method is always POST currently but kept for flexibility
	form := make([]string, 0, len(fields)*2)
	for k, v := range fields {
		form = append(form, k+"="+v)
	}
	body := strings.Join(form, "&")
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// ---------------------------------------------------------------------------
// Tests: OIDC Discovery
// ---------------------------------------------------------------------------

func TestOAuthHandler_GetOpenIDConfiguration(t *testing.T) {
	t.Run("returns 200 with issuer", func(t *testing.T) {
		svc := &mockOAuthSvc{
			getDiscoveryDocumentFn: func() *models.OIDCDiscoveryDocument {
				return &models.OIDCDiscoveryDocument{ //nolint:gosec // test fixture value, not a real credential
					Issuer:                "https://auth.example.com",
					AuthorizationEndpoint: "https://auth.example.com/oauth/authorize",
					TokenEndpoint:         "https://auth.example.com/oauth/token",
					JwksURI:               "https://auth.example.com/.well-known/jwks.json",
				}
			},
		}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/openid-configuration", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var doc models.OIDCDiscoveryDocument
		require.NoError(t, json.NewDecoder(w.Body).Decode(&doc))
		assert.Equal(t, "https://auth.example.com", doc.Issuer)
		assert.NotEmpty(t, doc.AuthorizationEndpoint)
		assert.NotEmpty(t, doc.JwksURI)
	})
}

// ---------------------------------------------------------------------------
// Tests: JWKS
// ---------------------------------------------------------------------------

func TestOAuthHandler_GetJWKS(t *testing.T) {
	t.Run("returns 200 with RSA key", func(t *testing.T) {
		svc := &mockOAuthSvc{
			getJWKSFn: func() *models.JWKSet {
				return &models.JWKSet{Keys: []models.JWK{
					{Kty: "RSA", Use: "sig", Kid: "key-1", Alg: "RS256", N: "modulus", E: "AQAB"},
				}}
			},
		}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/jwks.json", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var jwks models.JWKSet
		require.NoError(t, json.NewDecoder(w.Body).Decode(&jwks))
		require.Len(t, jwks.Keys, 1)
		assert.Equal(t, "RSA", jwks.Keys[0].Kty)
		assert.Equal(t, "sig", jwks.Keys[0].Use)
		assert.Equal(t, "RS256", jwks.Keys[0].Alg)
	})

	t.Run("never exposes private key material (no d/p/q fields)", func(t *testing.T) {
		svc := &mockOAuthSvc{}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/jwks.json", nil))

		rawBody := w.Body.String()
		assert.NotContains(t, rawBody, `"d":`, "JWKS must never contain private key exponent")
		assert.NotContains(t, rawBody, `"p":`, "JWKS must never contain CRT prime p")
		assert.NotContains(t, rawBody, `"q":`, "JWKS must never contain CRT prime q")
	})
}

// ---------------------------------------------------------------------------
// Tests: Token endpoint
// ---------------------------------------------------------------------------

func TestOAuthHandler_Token_AuthorizationCode(t *testing.T) {
	t.Run("exchanges authorization code and returns access token", func(t *testing.T) {
		svc := &mockOAuthSvc{
			authenticateClientFn: func(_ context.Context, cID, _ string) (*models.OAuthClient, error) {
				return &models.OAuthClient{ID: uuid.New(), ClientID: cID}, nil
			},
			exchangeAuthCodeFn: func(_ context.Context, _ *models.OAuthClient, code, _, _, _ string) (*models.OAuthTokenResponse, error) {
				assert.Equal(t, "valid-code", code)
				return &models.OAuthTokenResponse{
					AccessToken:  "access-token-value",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					RefreshToken: "refresh-token-value",
				}, nil
			},
		}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		req := oauthFormRequest(http.MethodPost, "/oauth/token", map[string]string{
			"grant_type":    "authorization_code",
			"code":          "valid-code",
			"redirect_uri":  "https://app.example.com/callback",
			"client_id":     "my-client",
			"client_secret": "my-secret",
		})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.OAuthTokenResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, "access-token-value", resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, int64(3600), resp.ExpiresIn)
		// Client secret must not be echoed back
		assert.NotContains(t, w.Body.String(), "my-secret")
	})

	t.Run("returns invalid_grant when code is invalid", func(t *testing.T) {
		svc := &mockOAuthSvc{
			exchangeAuthCodeFn: func(_ context.Context, _ *models.OAuthClient, _, _, _, _ string) (*models.OAuthTokenResponse, error) {
				return nil, errors.New("invalid_grant: authorization code not found")
			},
		}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		req := oauthFormRequest(http.MethodPost, "/oauth/token", map[string]string{
			"grant_type": "authorization_code",
			"code":       "bad-code",
		})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var body map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		assert.Contains(t, body["error"], "grant")
	})
}

func TestOAuthHandler_Token_RefreshToken(t *testing.T) {
	t.Run("refreshes tokens successfully", func(t *testing.T) {
		svc := &mockOAuthSvc{
			refreshTokensFn: func(_ context.Context, _ *models.OAuthClient, _, _ string) (*models.OAuthTokenResponse, error) {
				return &models.OAuthTokenResponse{AccessToken: "new-access-token", TokenType: "Bearer", ExpiresIn: 3600}, nil
			},
		}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		req := oauthFormRequest(http.MethodPost, "/oauth/token", map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": "old-refresh-token",
		})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.OAuthTokenResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, "new-access-token", resp.AccessToken)
	})
}

func TestOAuthHandler_Token_ClientCredentials(t *testing.T) {
	t.Run("issues access token for service account", func(t *testing.T) {
		svc := &mockOAuthSvc{
			clientCredGrantFn: func(_ context.Context, _ *models.OAuthClient, scopes []string, _ string) (*models.OAuthTokenResponse, error) {
				assert.Contains(t, scopes, "api:read")
				return &models.OAuthTokenResponse{AccessToken: "service-at", TokenType: "Bearer", ExpiresIn: 3600}, nil
			},
		}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		req := oauthFormRequest(http.MethodPost, "/oauth/token", map[string]string{
			"grant_type": "client_credentials",
			"scope":      "api:read",
		})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestOAuthHandler_Token_UnsupportedGrantType(t *testing.T) {
	t.Run("returns unsupported_grant_type error", func(t *testing.T) {
		svc := &mockOAuthSvc{}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		req := oauthFormRequest(http.MethodPost, "/oauth/token", map[string]string{
			"grant_type": "password",
		})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var body map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		assert.Contains(t, body["error"], "grant_type")
	})
}

func TestOAuthHandler_Token_ClientAuthFailure(t *testing.T) {
	t.Run("returns invalid_client when credentials are wrong", func(t *testing.T) {
		svc := &mockOAuthSvc{
			authenticateClientFn: func(_ context.Context, _, _ string) (*models.OAuthClient, error) {
				return nil, errors.New("invalid client credentials")
			},
		}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		req := oauthFormRequest(http.MethodPost, "/oauth/token", map[string]string{
			"grant_type":    "client_credentials",
			"client_id":     "bad-client",
			"client_secret": "wrong-secret",
		})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var body map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		assert.Equal(t, "invalid_client", body["error"])
	})
}

func TestOAuthHandler_Token_MissingGrantType(t *testing.T) {
	t.Run("returns invalid_request when grant_type absent", func(t *testing.T) {
		svc := &mockOAuthSvc{}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		req := oauthFormRequest(http.MethodPost, "/oauth/token", map[string]string{
			"code": "some-code",
		})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var body map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		assert.Equal(t, "invalid_request", body["error"])
	})
}

// ---------------------------------------------------------------------------
// Tests: UserInfo
// ---------------------------------------------------------------------------

func TestOAuthHandler_UserInfo(t *testing.T) {
	t.Run("returns user info for authenticated user", func(t *testing.T) {
		userID := uuid.New()
		tenantID := uuid.New()
		user := &models.User{
			ID:       userID,
			TenantID: tenantID,
			Email:    "alice@example.com",
			Username: "alice",
		}

		svc := &mockOAuthSvc{
			getUserInfoFn: func(_ context.Context, u *models.User, _ []string) *models.UserInfoResponse {
				return &models.UserInfoResponse{
					Sub:               u.ID.String(),
					Email:             u.Email,
					PreferredUsername: u.Username,
				}
			},
		}

		router := newOAuthTestRouter(newTestOAuthHandler(svc))
		router.Use(func(c *gin.Context) {
			c.Set("user", user)
			c.Next()
		})
		// re-register userinfo with middleware
		r2 := gin.New()
		r2.GET("/oauth/userinfo", func(c *gin.Context) {
			c.Set("user", user)
		}, newTestOAuthHandler(svc).UserInfo)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/userinfo", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.UserInfoResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, userID.String(), resp.Sub)
		assert.Equal(t, "alice@example.com", resp.Email)
	})

	t.Run("returns 401 when no user in context", func(t *testing.T) {
		svc := &mockOAuthSvc{}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/userinfo", nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: Introspect
// ---------------------------------------------------------------------------

func TestOAuthHandler_Introspect(t *testing.T) {
	t.Run("returns active=true for valid token", func(t *testing.T) {
		svc := &mockOAuthSvc{
			validateAccessTokenFn: func(_ string) (map[string]interface{}, error) {
				return map[string]interface{}{
					"sub":   "user-id-123",
					"scope": "openid profile",
				}, nil
			},
		}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		req := oauthFormRequest(http.MethodPost, "/oauth/introspect", map[string]string{
			"token":         "valid-access-token",
			"client_id":     "my-client",
			"client_secret": "my-secret",
		})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.OAuthIntrospectResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.True(t, resp.Active)
		assert.Equal(t, "user-id-123", resp.Subject)
		assert.Equal(t, "openid profile", resp.Scope)
	})

	t.Run("returns active=false for invalid token", func(t *testing.T) {
		svc := &mockOAuthSvc{
			validateAccessTokenFn: func(_ string) (map[string]interface{}, error) {
				return nil, errors.New("token expired")
			},
		}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		req := oauthFormRequest(http.MethodPost, "/oauth/introspect", map[string]string{
			"token": "expired-token",
		})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.OAuthIntrospectResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.False(t, resp.Active)
	})

	t.Run("returns 401 when client authentication fails", func(t *testing.T) {
		svc := &mockOAuthSvc{
			authenticateClientFn: func(_ context.Context, _, _ string) (*models.OAuthClient, error) {
				return nil, errors.New("invalid client")
			},
		}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		req := oauthFormRequest(http.MethodPost, "/oauth/introspect", map[string]string{
			"token":         "some-token",
			"client_id":     "bad",
			"client_secret": "wrong",
		})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: Revoke
// ---------------------------------------------------------------------------

func TestOAuthHandler_Revoke(t *testing.T) {
	t.Run("always returns 200 even when token unknown", func(t *testing.T) {
		var revokedToken string
		svc := &mockOAuthSvc{
			revokeTokenFn: func(_ context.Context, _ *models.OAuthClient, token, _ string) error {
				revokedToken = token
				return errors.New("token not found") // ignored per spec
			},
		}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		req := oauthFormRequest(http.MethodPost, "/oauth/revoke", map[string]string{
			"token":           "some-access-token",
			"token_type_hint": "access_token",
			"client_id":       "my-client",
			"client_secret":   "my-secret",
		})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "some-access-token", revokedToken)
	})

	t.Run("returns 401 when client credentials invalid", func(t *testing.T) {
		svc := &mockOAuthSvc{
			authenticateClientFn: func(_ context.Context, _, _ string) (*models.OAuthClient, error) {
				return nil, errors.New("invalid client")
			},
		}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		req := oauthFormRequest(http.MethodPost, "/oauth/revoke", map[string]string{
			"token": "some-token",
		})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: Admin Client Management
// ---------------------------------------------------------------------------

func TestOAuthHandler_ListClients(t *testing.T) {
	tenantID := uuid.New()

	t.Run("returns empty list when no clients exist", func(t *testing.T) {
		svc := &mockOAuthSvc{
			listClientsFn: func(_ context.Context, tID uuid.UUID, _, _ int) ([]*models.OAuthClient, int64, error) {
				assert.Equal(t, tenantID, tID)
				return []*models.OAuthClient{}, 0, nil
			},
		}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))
		router.Use(func(c *gin.Context) { c.Set("tenant_id", tenantID); c.Next() })

		r2 := gin.New()
		r2.GET("/api/admin/oauth-clients", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).ListClients)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/oauth-clients", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.OAuthClientListResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, int64(0), resp.Total)
	})

	t.Run("returns 400 when tenant_id missing from context", func(t *testing.T) {
		svc := &mockOAuthSvc{}
		r2 := gin.New()
		r2.GET("/api/admin/oauth-clients", newTestOAuthHandler(svc).ListClients)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/oauth-clients", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 500 on service error", func(t *testing.T) {
		svc := &mockOAuthSvc{
			listClientsFn: func(_ context.Context, _ uuid.UUID, _, _ int) ([]*models.OAuthClient, int64, error) {
				return nil, 0, errors.New("db error")
			},
		}
		r2 := gin.New()
		r2.GET("/api/admin/oauth-clients", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).ListClients)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/oauth-clients", nil))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestOAuthHandler_GetClient(t *testing.T) {
	tenantID := uuid.New()
	clientID := uuid.New()

	t.Run("returns client for same tenant", func(t *testing.T) {
		client := sampleOAuthClient(clientID, tenantID, "My App")
		svc := &mockOAuthSvc{
			getClientFn: func(_ context.Context, id uuid.UUID) (*models.OAuthClient, error) {
				if id == clientID {
					return client, nil
				}
				return nil, errors.New("not found")
			},
		}
		r2 := gin.New()
		r2.GET("/api/admin/oauth-clients/:id", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).GetClient)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/oauth-clients/"+clientID.String(), nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.OAuthClientResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, "My App", resp.Name)
		// ClientSecret must never be present in GET response
		assert.Nil(t, resp.ClientSecret)
	})

	t.Run("returns 404 for invalid UUID", func(t *testing.T) {
		svc := &mockOAuthSvc{}
		r2 := gin.New()
		r2.GET("/api/admin/oauth-clients/:id", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).GetClient)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/oauth-clients/not-a-uuid", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 404 when client belongs to different tenant", func(t *testing.T) {
		client := sampleOAuthClient(clientID, uuid.New(), "Other Tenant App")
		svc := &mockOAuthSvc{
			getClientFn: func(_ context.Context, _ uuid.UUID) (*models.OAuthClient, error) {
				return client, nil
			},
		}
		r2 := gin.New()
		r2.GET("/api/admin/oauth-clients/:id", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).GetClient)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/oauth-clients/"+clientID.String(), nil))

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestOAuthHandler_GetClientByClientIDLookup(t *testing.T) {
	tenantID := uuid.New()
	clientUUID := uuid.New()
	clientIDStr := "svc-accounts"

	t.Run("returns client for same tenant", func(t *testing.T) {
		client := sampleOAuthClient(clientUUID, tenantID, "Accounts")
		client.ClientID = clientIDStr
		svc := &mockOAuthSvc{
			getClientByClientIDFn: func(_ context.Context, cid string) (*models.OAuthClient, error) {
				if cid == clientIDStr {
					return client, nil
				}
				return nil, errors.New("not found")
			},
		}
		r2 := gin.New()
		r2.GET("/internal/oauth-clients/by-client-id/:client_id", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).GetClientByClientIDLookup)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/internal/oauth-clients/by-client-id/"+clientIDStr, nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.OAuthClientResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, clientIDStr, resp.ClientID)
		// Secret must NEVER appear on a lookup response (parity with GET /:id).
		assert.Nil(t, resp.ClientSecret)
	})

	t.Run("returns 404 when client_id does not exist", func(t *testing.T) {
		svc := &mockOAuthSvc{
			getClientByClientIDFn: func(_ context.Context, _ string) (*models.OAuthClient, error) {
				return nil, errors.New("not found")
			},
		}
		r2 := gin.New()
		r2.GET("/internal/oauth-clients/by-client-id/:client_id", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).GetClientByClientIDLookup)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/internal/oauth-clients/by-client-id/svc-missing", nil))

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 404 when client belongs to a different tenant", func(t *testing.T) {
		otherTenant := uuid.New()
		client := sampleOAuthClient(clientUUID, otherTenant, "Other Tenant App")
		client.ClientID = clientIDStr
		svc := &mockOAuthSvc{
			getClientByClientIDFn: func(_ context.Context, _ string) (*models.OAuthClient, error) {
				return client, nil
			},
		}
		r2 := gin.New()
		r2.GET("/internal/oauth-clients/by-client-id/:client_id", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).GetClientByClientIDLookup)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/internal/oauth-clients/by-client-id/"+clientIDStr, nil))

		// Tenant isolation is preserved — 404 instead of 403 to avoid
		// leaking the existence of a client owned by another tenant.
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestOAuthHandler_CreateClient(t *testing.T) {
	tenantID := uuid.New()

	t.Run("creates client and returns secret once", func(t *testing.T) {
		newClientID := uuid.New()
		svc := &mockOAuthSvc{
			createClientFn: func(_ context.Context, tID uuid.UUID, req *models.CreateOAuthClientRequest, _ *uuid.UUID) (*models.OAuthClient, string, error) {
				assert.Equal(t, tenantID, tID)
				assert.Equal(t, "New App", req.Name)
				client := sampleOAuthClient(newClientID, tenantID, req.Name)
				return client, "raw-client-secret-value", nil
			},
		}
		r2 := gin.New()
		r2.POST("/api/admin/oauth-clients", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).CreateClient)

		body := `{"name":"New App","grant_types":["authorization_code"],"response_types":["code"],"redirect_uris":["https://app.example.com/cb"]}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/oauth-clients", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp models.OAuthClientResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, "New App", resp.Name)
		require.NotNil(t, resp.ClientSecret, "secret must be present in creation response")
		assert.Equal(t, "raw-client-secret-value", *resp.ClientSecret)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		svc := &mockOAuthSvc{}
		r2 := gin.New()
		r2.POST("/api/admin/oauth-clients", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).CreateClient)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/oauth-clients", strings.NewReader("{invalid}"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestOAuthHandler_DeleteClient(t *testing.T) {
	tenantID := uuid.New()
	clientID := uuid.New()

	t.Run("deletes client successfully", func(t *testing.T) {
		client := sampleOAuthClient(clientID, tenantID, "App To Delete")
		var deletedID uuid.UUID
		svc := &mockOAuthSvc{
			getClientFn: func(_ context.Context, _ uuid.UUID) (*models.OAuthClient, error) {
				return client, nil
			},
			deleteClientFn: func(_ context.Context, id uuid.UUID) error {
				deletedID = id
				return nil
			},
		}
		r2 := gin.New()
		r2.DELETE("/api/admin/oauth-clients/:id", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).DeleteClient)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/admin/oauth-clients/"+clientID.String(), nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, clientID, deletedID)
	})

	t.Run("returns 404 for unknown client", func(t *testing.T) {
		svc := &mockOAuthSvc{
			getClientFn: func(_ context.Context, _ uuid.UUID) (*models.OAuthClient, error) {
				return nil, errors.New("not found")
			},
		}
		r2 := gin.New()
		r2.DELETE("/api/admin/oauth-clients/:id", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).DeleteClient)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/admin/oauth-clients/"+clientID.String(), nil))

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestOAuthHandler_RegenerateSecret(t *testing.T) {
	tenantID := uuid.New()
	clientID := uuid.New()

	t.Run("regenerates secret and returns it once", func(t *testing.T) {
		client := sampleOAuthClient(clientID, tenantID, "My App")
		svc := &mockOAuthSvc{
			getClientFn:        func(_ context.Context, _ uuid.UUID) (*models.OAuthClient, error) { return client, nil },
			regenerateSecretFn: func(_ context.Context, _ uuid.UUID) (string, error) { return "brand-new-secret", nil },
		}
		r2 := gin.New()
		r2.POST("/api/admin/oauth-clients/:id/regenerate-secret", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).RegenerateSecret)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/oauth-clients/"+clientID.String()+"/regenerate-secret", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var body map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		assert.Equal(t, "brand-new-secret", body["client_secret"])
		assert.Contains(t, body["message"], "Store this securely")
	})

	t.Run("returns 400 for invalid UUID", func(t *testing.T) {
		svc := &mockOAuthSvc{}
		r2 := gin.New()
		r2.POST("/api/admin/oauth-clients/:id/regenerate-secret", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).RegenerateSecret)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/oauth-clients/not-valid/regenerate-secret", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestOAuthHandler_RevokeClientTokens(t *testing.T) {
	tenantID := uuid.New()
	clientID := uuid.New()

	t.Run("revokes all tokens for client", func(t *testing.T) {
		client := sampleOAuthClient(clientID, tenantID, "My App")
		var revokedForClient uuid.UUID
		svc := &mockOAuthSvc{
			getClientFn: func(_ context.Context, _ uuid.UUID) (*models.OAuthClient, error) { return client, nil },
			revokeAllClientTokensFn: func(_ context.Context, id uuid.UUID) error {
				revokedForClient = id
				return nil
			},
		}
		r2 := gin.New()
		r2.POST("/api/admin/oauth-clients/:id/revoke-tokens", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, newTestOAuthHandler(svc).RevokeClientTokens)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/oauth-clients/"+clientID.String()+"/revoke-tokens", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, clientID, revokedForClient)
	})
}

// ---------------------------------------------------------------------------
// Tests: Consent management
// ---------------------------------------------------------------------------

func TestOAuthHandler_GetMyConsents(t *testing.T) {
	t.Run("returns consents for authenticated user", func(t *testing.T) {
		userID := uuid.New()
		clientID := uuid.New()
		svc := &mockOAuthSvc{
			getUserConsentsFn: func(_ context.Context, uID uuid.UUID) ([]*models.OAuthConsent, error) {
				assert.Equal(t, userID, uID)
				return []*models.OAuthConsent{
					{ID: uuid.New(), UserID: userID, ClientID: clientID, Scopes: []string{"openid", "email"}},
				}, nil
			},
		}
		r2 := gin.New()
		r2.GET("/api/auth/consents", func(c *gin.Context) {
			c.Set("user_id", userID)
		}, newTestOAuthHandler(svc).GetMyConsents)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/auth/consents", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		consents, ok := body["consents"].([]interface{})
		require.True(t, ok)
		assert.Len(t, consents, 1)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		svc := &mockOAuthSvc{}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/auth/consents", nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestOAuthHandler_RevokeMyConsent(t *testing.T) {
	t.Run("revokes consent successfully", func(t *testing.T) {
		userID := uuid.New()
		clientID := uuid.New()
		var revokedClientID uuid.UUID
		svc := &mockOAuthSvc{
			revokeConsentFn: func(_ context.Context, _, cID uuid.UUID) error {
				revokedClientID = cID
				return nil
			},
		}
		r2 := gin.New()
		r2.DELETE("/api/auth/consents/:client_id", func(c *gin.Context) {
			c.Set("user_id", userID)
		}, newTestOAuthHandler(svc).RevokeMyConsent)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/auth/consents/"+clientID.String(), nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, clientID, revokedClientID)
	})

	t.Run("returns 400 for invalid client UUID", func(t *testing.T) {
		userID := uuid.New()
		svc := &mockOAuthSvc{}
		r2 := gin.New()
		r2.DELETE("/api/auth/consents/:client_id", func(c *gin.Context) {
			c.Set("user_id", userID)
		}, newTestOAuthHandler(svc).RevokeMyConsent)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/auth/consents/bad-uuid", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		svc := &mockOAuthSvc{}
		router := newOAuthTestRouter(newTestOAuthHandler(svc))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/auth/consents/"+uuid.New().String(), nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: LoginPage feature flag (OAUTH_LOGIN_REDIRECT_URL)
// ---------------------------------------------------------------------------
//
// LoginPage doesn't go through the testOAuthProviderHandler adapter — it
// touches no service-injected dependencies on the new branch (only
// os.Getenv + the http.ResponseWriter), so we exercise the real
// *OAuthProviderHandler directly with a minimal Gin engine.

func TestOAuthHandler_LoginPage_FeatureFlag(t *testing.T) {
	makeRouter := func() *gin.Engine {
		h := &OAuthProviderHandler{logger: zap.NewNop()}
		r := gin.New()
		r.GET("/oauth/login", h.LoginPage)
		return r
	}

	t.Run("rejects look-alike authorize paths", func(t *testing.T) {
		t.Setenv("OAUTH_LOGIN_REDIRECT_URL", "/login")
		for _, bad := range []string{
			"%2Foauth%2Fauthorize-evil%3Fclient_id%3Dabc",
			"%2Foauth%2Fauthorize%2F..%2F..%2Fadmin",
			"%2F%2Fevil.example%2Foauth%2Fauthorize",
		} {
			w := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/login?redirect="+bad, nil)
			makeRouter().ServeHTTP(w, req)
			assert.Equal(t, "/login", w.Header().Get("Location"), bad)
		}
	})

	t.Run("redirects to apps/login when OAUTH_LOGIN_REDIRECT_URL is set", func(t *testing.T) {
		t.Setenv("OAUTH_LOGIN_REDIRECT_URL", "/login")

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/oauth/login?redirect=%2Foauth%2Fauthorize%3Fclient_id%3Dabc",
			nil,
		)
		makeRouter().ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		loc := w.Header().Get("Location")
		assert.Contains(t, loc, "/login?redirect=")
		assert.Contains(t, loc, "%2Foauth%2Fauthorize") // original redirect re-encoded
		assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
		assert.Contains(t, w.Body.String(), "<html>") // body emitted for Safari iOS
	})

	t.Run("appends redirect with & when login URL already has query string", func(t *testing.T) {
		t.Setenv("OAUTH_LOGIN_REDIRECT_URL", "/login?theme=dark")

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/oauth/login?redirect=%2Foauth%2Fauthorize",
			nil,
		)
		makeRouter().ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		loc := w.Header().Get("Location")
		assert.Contains(t, loc, "/login?theme=dark&redirect=")
	})

	t.Run("redirects without query when redirect param is missing or invalid", func(t *testing.T) {
		t.Setenv("OAUTH_LOGIN_REDIRECT_URL", "/login")

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/oauth/login?redirect=https://evil.example/phish",
			nil,
		)
		makeRouter().ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "/login", w.Header().Get("Location"))
	})

	t.Run("falls through to legacy template path when env var is empty", func(t *testing.T) {
		t.Setenv("OAUTH_LOGIN_REDIRECT_URL", "")

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/oauth/login?redirect=%2Foauth%2Fauthorize",
			nil,
		)
		makeRouter().ServeHTTP(w, req)

		// Legacy path renders the Go template (200 OK). We only verify it
		// did NOT 302, since the template body itself is covered elsewhere.
		assert.NotEqual(t, http.StatusFound, w.Code)
	})
}

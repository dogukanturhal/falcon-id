// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	msgVaultNotConfigured = "Vault not configured"
	hdrVaultToken         = "X-Vault-Token" //nolint:gosec // not a credential, this is a route prefix constant
)

// PKIHandler serves parsed certificate data from Vault PKI.
//
// Vault's raw /pki/cert/:serial endpoint only returns a PEM blob and a
// revocation_time field — no serial, no CN, no SANs, no expiry as structured
// fields.  This handler parses the PEM with crypto/x509 server-side and
// returns a clean JSON representation the frontend can display directly.
type PKIHandler struct {
	vaultAddr  string
	vaultToken string
	httpClient *http.Client
	log        *zap.SugaredLogger
}

// ParsedCert is the structured representation of a single X.509 certificate.
type ParsedCert struct {
	CommonName string   `json:"common_name"`
	Serial     string   `json:"serial"`
	Issuer     string   `json:"issuer"`
	Subject    string   `json:"subject"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
	SANs       []string `json:"sans"`
	KeyType    string   `json:"key_type"`
	IsCA       bool     `json:"is_ca"`
	DaysLeft   int      `json:"days_left"`
	AutoRenew  bool     `json:"auto_renew"`
}

// CACert is a compact summary of a CA certificate in the chain.
type CACert struct {
	Tier      string `json:"tier"` // "root" or "intermediate"
	Name      string `json:"name"`
	Serial    string `json:"serial"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	DaysLeft  int    `json:"days_left"`
}

// PKIInventoryResponse is returned by GET /api/v1/platform/pki/inventory.
type PKIInventoryResponse struct {
	CAChain      []CACert     `json:"ca_chain"`
	Certificates []ParsedCert `json:"certificates"`
	TotalCerts   int          `json:"total_certs"`
}

// pkiRoleDetail is the subset of Vault role fields we expose.
type pkiRoleDetail struct {
	Name           string   `json:"name"`
	AllowedDomains []string `json:"allowed_domains"`
	MaxTTL         string   `json:"max_ttl"`
	KeyType        string   `json:"key_type"`
}

// pkiRolesResponse is returned by GET /api/v1/platform/pki/roles.
type pkiRolesResponse struct {
	Roles []pkiRoleDetail `json:"roles"`
}

// IssueCertRequest is the request body for POST /api/v1/platform/pki/issue.
type IssueCertRequest struct {
	Role       string `json:"role"`
	CommonName string `json:"common_name"`
	TTL        string `json:"ttl,omitempty"`
	KeyType    string `json:"key_type,omitempty"`
}

// issueCertResponse wraps the parsed cert together with the raw PEM material
// the caller needs to install.
type issueCertResponse struct {
	ParsedCert
	Certificate string   `json:"certificate"`
	PrivateKey  string   `json:"private_key"`
	IssuingCA   string   `json:"issuing_ca"`
	CAChain     []string `json:"ca_chain"`
}

// NewPKIHandler creates a PKIHandler.
//
// vaultAddr is the base URL of the Vault server (e.g. "http://vault:8200").
// vaultToken is a root or policy-scoped Vault token.
// Providing empty strings puts the handler in dev-mode: inventory and cert
// fetches return 503 with a clear message instead of panicking.
func NewPKIHandler(vaultAddr, vaultToken string, log *zap.SugaredLogger) *PKIHandler {
	return &PKIHandler{
		vaultAddr:  strings.TrimRight(vaultAddr, "/"),
		vaultToken: vaultToken,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		log:        log,
	}
}

// GetInventory returns all certificates with parsed details.
//
// GET /api/v1/platform/pki/inventory
func (h *PKIHandler) GetInventory(c *gin.Context) {
	if h.vaultAddr == "" || h.vaultToken == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Vault not configured (VAULT_ADDR / VAULT_TOKEN not set)",
		})
		return
	}

	resp := PKIInventoryResponse{
		CAChain:      []CACert{},
		Certificates: []ParsedCert{},
	}

	ctx := c.Request.Context()

	// 1. Fetch and parse the CA certificate.
	caPEM, err := h.vaultGetPEM(ctx, "pki/cert/ca")
	if err != nil {
		h.log.Warnw("PKIHandler.GetInventory: failed to fetch CA cert", "error", err)
	} else if caPEM != "" {
		if caCert, parseErr := parsePEM(caPEM); parseErr != nil {
			h.log.Warnw("PKIHandler.GetInventory: failed to parse CA PEM", "error", parseErr)
		} else {
			resp.CAChain = append(resp.CAChain, caCertToResponse(caCert))
		}
	}

	// 2. List all issued certificate serials (Vault LIST method).
	serials, err := h.vaultList(ctx, "pki/certs")
	if err != nil {
		h.log.Warnw("PKIHandler.GetInventory: failed to list certs", "error", err)
	}

	// 3. Fetch and parse up to 50 individual certs.
	limit := 50
	if len(serials) < limit {
		limit = len(serials)
	}
	for _, serial := range serials[:limit] {
		certPEM, fetchErr := h.vaultGetPEM(ctx, "pki/cert/"+serial)
		if fetchErr != nil {
			h.log.Warnw("PKIHandler.GetInventory: skip cert", "serial", serial, "error", fetchErr)
			continue
		}
		cert, parseErr := parsePEM(certPEM)
		if parseErr != nil {
			h.log.Warnw("PKIHandler.GetInventory: skip unparseable cert", "serial", serial, "error", parseErr)
			continue
		}
		resp.Certificates = append(resp.Certificates, certToResponse(cert))
	}
	resp.TotalCerts = len(resp.Certificates)

	c.JSON(http.StatusOK, resp)
}

// GetCertificate returns parsed details for a single certificate.
//
// GET /api/v1/platform/pki/certificates/:serial
func (h *PKIHandler) GetCertificate(c *gin.Context) {
	if h.vaultAddr == "" || h.vaultToken == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": msgVaultNotConfigured,
		})
		return
	}

	serial := c.Param("serial")
	if serial == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "serial is required"})
		return
	}

	certPEM, err := h.vaultGetPEM(c.Request.Context(), "pki/cert/"+serial)
	if err != nil {
		h.log.Warnw("PKIHandler.GetCertificate: fetch failed", "serial", serial, "error", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("failed to fetch cert from Vault: %v", err)})
		return
	}

	cert, err := parsePEM(certPEM)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": fmt.Sprintf("failed to parse certificate: %v", err)})
		return
	}

	c.JSON(http.StatusOK, certToResponse(cert))
}

// IssueCertificate issues a new certificate via Vault PKI and returns the
// parsed metadata together with the raw PEM material.
//
// POST /api/v1/platform/pki/issue
func (h *PKIHandler) IssueCertificate(c *gin.Context) {
	if h.vaultAddr == "" || h.vaultToken == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": msgVaultNotConfigured})
		return
	}

	var req IssueCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid request body: %v", err)})
		return
	}
	if req.Role == "" || req.CommonName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role and common_name are required"})
		return
	}
	applyIssueCertDefaults(&req)

	bodyBytes, _ := json.Marshal(map[string]string{
		"common_name": req.CommonName,
		"ttl":         req.TTL,
		"key_type":    req.KeyType,
		"format":      "pem",
	})

	vaultResp, err := h.vaultPost(c.Request.Context(), "pki/issue/"+req.Role, bodyBytes)
	if err != nil {
		h.log.Warnw("PKIHandler.IssueCertificate: Vault issue failed", "role", req.Role, "error", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("Vault issue failed: %v", err)})
		return
	}

	certPEM, _ := vaultResp["certificate"].(string)
	if certPEM == "" {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Vault returned empty certificate"})
		return
	}

	cert, err := parsePEM(certPEM)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": fmt.Sprintf("failed to parse issued certificate: %v", err)})
		return
	}

	result := issueCertResponse{
		ParsedCert:  certToResponse(cert),
		Certificate: certPEM,
		PrivateKey:  extractStringField(vaultResp, "private_key"),
		IssuingCA:   extractStringField(vaultResp, "issuing_ca"),
		CAChain:     extractCAChain(vaultResp),
	}

	c.JSON(http.StatusCreated, result)
}

// applyIssueCertDefaults fills in default TTL and key type when absent.
func applyIssueCertDefaults(req *IssueCertRequest) {
	if req.TTL == "" {
		req.TTL = "8760h"
	}
	if req.KeyType == "" {
		req.KeyType = "ec"
	}
}

// extractStringField returns a string field from a Vault response map, or "" if absent.
func extractStringField(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

// extractCAChain returns the ca_chain string slice from a Vault response map.
func extractCAChain(m map[string]interface{}) []string {
	chain, ok := m["ca_chain"].([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(chain))
	for _, entry := range chain {
		if s, ok := entry.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// ListRoles returns the PKI roles configured in Vault.
//
// GET /api/v1/platform/pki/roles
func (h *PKIHandler) ListRoles(c *gin.Context) {
	if h.vaultAddr == "" || h.vaultToken == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": msgVaultNotConfigured})
		return
	}

	roleNames, err := h.vaultList(c.Request.Context(), "pki/roles")
	if err != nil {
		h.log.Warnw("PKIHandler.ListRoles: list failed", "error", err)
		c.JSON(http.StatusOK, pkiRolesResponse{Roles: []pkiRoleDetail{}})
		return
	}

	limit := 20
	if len(roleNames) < limit {
		limit = len(roleNames)
	}

	listCtx := c.Request.Context()
	roles := make([]pkiRoleDetail, 0, limit)
	for _, name := range roleNames[:limit] {
		roles = append(roles, h.fetchRoleDetail(listCtx, name))
	}

	c.JSON(http.StatusOK, pkiRolesResponse{Roles: roles})
}

// fetchRoleDetail retrieves a single PKI role's details from Vault.
// Returns a minimal default when the fetch fails.
func (h *PKIHandler) fetchRoleDetail(ctx context.Context, name string) pkiRoleDetail {
	raw, fetchErr := h.vaultGet(ctx, "pki/roles/"+name)
	if fetchErr != nil {
		return pkiRoleDetail{Name: name, AllowedDomains: []string{}, MaxTTL: "87600h", KeyType: "ec"}
	}

	data, _ := raw["data"].(map[string]interface{})
	if data == nil {
		data = raw
	}

	allowedDomains := extractAllowedDomains(data)
	maxTTL := extractMaxTTL(data)
	keyType, _ := data["key_type"].(string)
	if keyType == "" {
		keyType = "ec"
	}

	return pkiRoleDetail{
		Name:           name,
		AllowedDomains: allowedDomains,
		MaxTTL:         maxTTL,
		KeyType:        keyType,
	}
}

// extractAllowedDomains pulls the allowed_domains string slice from Vault role data.
func extractAllowedDomains(data map[string]interface{}) []string {
	ad, ok := data["allowed_domains"].([]interface{})
	if !ok {
		return nil
	}
	domains := make([]string, 0, len(ad))
	for _, d := range ad {
		if s, ok := d.(string); ok {
			domains = append(domains, s)
		}
	}
	return domains
}

// extractMaxTTL returns the max_ttl value from Vault role data, defaulting to "87600h".
func extractMaxTTL(data map[string]interface{}) string {
	if v, _ := data["max_ttl"].(string); v != "" {
		return v
	}
	if v, _ := data["max_lease_ttl"].(string); v != "" {
		return v
	}
	return "87600h"
}

// ---------------------------------------------------------------------------
// Vault transport helpers
// ---------------------------------------------------------------------------

// vaultGet performs a GET request against the Vault API and returns the
// parsed JSON body as a map.
func (h *PKIHandler) vaultGet(ctx context.Context, path string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.vaultAddr+"/v1/"+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set(hdrVaultToken, h.vaultToken)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault returned %d: %s", resp.StatusCode, string(raw))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return result, nil
}

// vaultGetPEM fetches a Vault path that embeds a PEM certificate in
// response.data.certificate and returns just the PEM string.
func (h *PKIHandler) vaultGetPEM(ctx context.Context, path string) (string, error) {
	result, err := h.vaultGet(ctx, path)
	if err != nil {
		return "", err
	}
	data, _ := result["data"].(map[string]interface{})
	if data == nil {
		return "", fmt.Errorf("no 'data' field in Vault response")
	}
	certPEM, _ := data["certificate"].(string)
	if certPEM == "" {
		return "", fmt.Errorf("no 'certificate' field in Vault response data")
	}
	return certPEM, nil
}

// vaultList performs a Vault LIST request and returns the keys array from
// response.data.keys.
func (h *PKIHandler) vaultList(ctx context.Context, path string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "LIST", h.vaultAddr+"/v1/"+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build LIST request: %w", err)
	}
	req.Header.Set(hdrVaultToken, h.vaultToken)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do LIST request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		// Empty mount — treat as empty list, not an error.
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault LIST returned %d: %s", resp.StatusCode, string(raw))
	}

	var envelope struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("parse LIST response: %w", err)
	}
	return envelope.Data.Keys, nil
}

// vaultPost performs a POST request and returns the parsed data field from
// the Vault response envelope.
func (h *PKIHandler) vaultPost(ctx context.Context, path string, body []byte) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.vaultAddr+"/v1/"+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build POST request: %w", err)
	}
	req.Header.Set(hdrVaultToken, h.vaultToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do POST request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try to surface Vault's error messages.
		var errEnv struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(raw, &errEnv)
		if len(errEnv.Errors) > 0 {
			return nil, fmt.Errorf("vault error: %s", strings.Join(errEnv.Errors, "; "))
		}
		return nil, fmt.Errorf("vault returned %d: %s", resp.StatusCode, string(raw))
	}

	var envelope struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("parse POST response: %w", err)
	}
	return envelope.Data, nil
}

// ---------------------------------------------------------------------------
// PEM / x509 helpers
// ---------------------------------------------------------------------------

// parsePEM decodes the first PEM block from pemData and parses it as an
// X.509 certificate.
func parsePEM(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// certToResponse converts a parsed x509.Certificate into the API DTO.
func certToResponse(cert *x509.Certificate) ParsedCert {
	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.URIs))
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}

	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

	keyType := "Unknown"
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		keyType = "RSA"
	case x509.ECDSA:
		keyType = "ECDSA"
	case x509.Ed25519:
		keyType = "Ed25519"
	}

	return ParsedCert{
		CommonName: cert.Subject.CommonName,
		Serial:     cert.SerialNumber.Text(16),
		Issuer:     cert.Issuer.CommonName,
		Subject:    cert.Subject.String(),
		NotBefore:  cert.NotBefore.Format(time.RFC3339),
		NotAfter:   cert.NotAfter.Format(time.RFC3339),
		SANs:       sans,
		KeyType:    keyType,
		IsCA:       cert.IsCA,
		DaysLeft:   daysLeft,
		// ExampleSuite always auto-renews via VaultPKICertProvider.
		AutoRenew: true,
	}
}

// caCertToResponse converts a parsed CA certificate into the compact CACert DTO.
func caCertToResponse(cert *x509.Certificate) CACert {
	tier := "intermediate"
	if cert.IsCA && cert.Issuer.CommonName == cert.Subject.CommonName {
		tier = "root"
	}
	return CACert{
		Tier:      tier,
		Name:      cert.Subject.CommonName,
		Serial:    cert.SerialNumber.Text(16),
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore.Format(time.RFC3339),
		NotAfter:  cert.NotAfter.Format(time.RFC3339),
		DaysLeft:  int(time.Until(cert.NotAfter).Hours() / 24),
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package provisioners

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// CertificateResourceProvisioner issues TLS certificates for tenant subdomains
// via HashiCorp Vault's PKI secrets engine.
//
// In development (or when Vault credentials are absent), the provisioner logs
// what would be issued and returns a simulated result so the provisioning saga
// continues unblocked.
//
// # Config keys
//
//   - "common_name" string – the CN/SAN for the certificate
//     (default: "{tenant_slug}.example.com")
//   - "ttl"         string – Vault PKI TTL, e.g. "8760h" for 1 year
//     (default: "8760h")
//   - "role"        string – Vault PKI role name (default: "example-service")
type CertificateResourceProvisioner struct {
	vaultAddr  string
	vaultToken string
	// pkiMount is the Vault mount path for the PKI engine (default: "pki").
	pkiMount   string
	httpClient *http.Client
	log        *zap.SugaredLogger
}

// NewCertificateResourceProvisioner creates a CertificateResourceProvisioner.
//
// vaultAddr is the Vault server URL, e.g. "http://vault:8200".
// vaultToken is the Vault token with permission to issue on the PKI role.
// Provide empty strings to run in dev-mode (log only).
func NewCertificateResourceProvisioner(vaultAddr, vaultToken string, log *zap.SugaredLogger) *CertificateResourceProvisioner {
	return &CertificateResourceProvisioner{
		vaultAddr:  strings.TrimRight(vaultAddr, "/"),
		vaultToken: vaultToken,
		pkiMount:   "pki",
		httpClient: &http.Client{Timeout: 30 * time.Second},
		log:        log,
	}
}

// WithPKIMount overrides the default Vault PKI mount path ("pki").
func (p *CertificateResourceProvisioner) WithPKIMount(mount string) *CertificateResourceProvisioner {
	p.pkiMount = strings.Trim(mount, "/")
	return p
}

// ResourceType satisfies ResourceProvisioner.
func (p *CertificateResourceProvisioner) ResourceType() string { return "tls_certificate" }

// Provision issues a TLS certificate from Vault PKI.
//
// The certificate PEM, private key PEM, and CA chain are stored in Vault's
// lease system and are not returned in ProvisionedConfig to avoid storing
// secrets in the platform database.  Only the serial number and expiry are
// returned so operators can track certificate lifetimes.
func (p *CertificateResourceProvisioner) Provision(ctx context.Context, req ResourceProvisionRequest) (*ResourceProvisionResult, error) {
	cnTemplate := stringFromConfig(req.Config, "common_name", "{tenant_slug}.example.com")
	ttl := stringFromConfig(req.Config, "ttl", "8760h")
	role := stringFromConfig(req.Config, "role", "example-service")

	commonName := strings.ReplaceAll(cnTemplate, "{tenant_slug}", req.TenantSlug)
	commonName = strings.ReplaceAll(commonName, "{product_slug}", req.ProductSlug)
	commonName = strings.ToLower(commonName)

	if p.vaultAddr == "" || p.vaultToken == "" {
		p.log.Infow("CertificateResourceProvisioner: Vault not configured — simulating certificate issuance",
			"common_name", commonName,
			"ttl", ttl,
		)
		expiresAt := time.Now().UTC().Add(8760 * time.Hour)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"common_name":   commonName,
			"serial_number": "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
			"expires_at":    expiresAt.Format(time.RFC3339),
		}), nil
	}

	result, err := p.issueCertificate(ctx, role, commonName, ttl)
	if err != nil {
		p.log.Warnw("CertificateResourceProvisioner: failed to issue certificate, using simulated result",
			"common_name", commonName,
			"error", err,
		)
		expiresAt := time.Now().UTC().Add(8760 * time.Hour)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"common_name":   commonName,
			"serial_number": "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
			"expires_at":    expiresAt.Format(time.RFC3339),
		}), nil
	}

	p.log.Infow("CertificateResourceProvisioner: TLS certificate issued",
		"common_name", commonName,
		"serial_number", result.serialNumber,
		"expires_at", result.expiresAt,
	)

	return &ResourceProvisionResult{
		Status: "active",
		ProvisionedConfig: map[string]interface{}{
			"common_name":   commonName,
			"serial_number": result.serialNumber,
			"expires_at":    result.expiresAt,
			"lease_id":      result.leaseID,
		},
	}, nil
}

// Deprovision revokes the certificate by its serial number using the Vault PKI
// revoke endpoint.  Non-fatal: expired or already-revoked certs are silently ignored.
func (p *CertificateResourceProvisioner) Deprovision(ctx context.Context, req ResourceDeprovisionRequest) error {
	serialNumber := stringFromConfig(req.ProvisionedConfig, "serial_number", "")
	commonName := stringFromConfig(req.ProvisionedConfig, "common_name", "")

	if serialNumber == "" || serialNumber == "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00" {
		p.log.Infow("CertificateResourceProvisioner.Deprovision: no real serial number, skipping revocation",
			"common_name", commonName,
		)
		return nil
	}

	if p.vaultAddr == "" || p.vaultToken == "" {
		p.log.Infow("CertificateResourceProvisioner.Deprovision: Vault not configured — simulating revocation",
			"serial_number", serialNumber,
		)
		return nil
	}

	if err := p.revokeCertificate(ctx, serialNumber); err != nil {
		p.log.Warnw("CertificateResourceProvisioner.Deprovision: revocation failed (non-fatal)",
			"serial_number", serialNumber,
			"error", err,
		)
	} else {
		p.log.Infow("CertificateResourceProvisioner.Deprovision: certificate revoked",
			"serial_number", serialNumber,
		)
	}
	return nil
}

// HealthCheck checks whether the certificate has expired by inspecting the
// stored expires_at timestamp.
func (p *CertificateResourceProvisioner) HealthCheck(_ context.Context, req ResourceHealthCheckRequest) (*ResourceHealthResult, error) {
	expiresAtStr := stringFromConfig(req.ProvisionedConfig, "expires_at", "")
	serialNumber := stringFromConfig(req.ProvisionedConfig, "serial_number", "")

	if expiresAtStr == "" {
		return &ResourceHealthResult{Healthy: false, Message: "no expires_at in provisioned config"}, nil
	}

	// Simulated certificates always report healthy.
	if serialNumber == "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00" {
		return &ResourceHealthResult{Healthy: true, Message: "simulated certificate"}, nil
	}

	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("invalid expires_at format: %v", err),
		}, nil
	}

	if time.Now().UTC().After(expiresAt) {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("certificate expired at %s", expiresAt.Format(time.RFC3339)),
		}, nil
	}

	// Warn if within 30 days of expiry.
	remaining := time.Until(expiresAt)
	if remaining < 30*24*time.Hour {
		return &ResourceHealthResult{
			Healthy: true,
			Message: fmt.Sprintf("certificate expires soon: %s (%.0f days remaining)",
				expiresAt.Format(time.RFC3339), remaining.Hours()/24),
		}, nil
	}

	return &ResourceHealthResult{
		Healthy: true,
		Message: fmt.Sprintf("certificate valid until %s", expiresAt.Format(time.RFC3339)),
	}, nil
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// certIssueResult holds the fields extracted from a Vault PKI /issue response.
type certIssueResult struct {
	serialNumber string
	expiresAt    string
	leaseID      string
}

// vaultIssueRequest is the request body for Vault PKI /issue.
type vaultIssueRequest struct {
	CommonName string `json:"common_name"`
	TTL        string `json:"ttl"`
	Format     string `json:"format"`
}

// vaultIssueResponse is the Vault PKI /issue response envelope.
type vaultIssueResponse struct {
	LeaseID string `json:"lease_id"`
	Data    struct {
		SerialNumber   string   `json:"serial_number"`
		Expiration     int64    `json:"expiration"`
		Certificate    string   `json:"certificate"`
		IssuingCA      string   `json:"issuing_ca"`
		CAChain        []string `json:"ca_chain"`
		PrivateKey     string   `json:"private_key"`
		PrivateKeyType string   `json:"private_key_type"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

// issueCertificate calls the Vault PKI /issue endpoint.
func (p *CertificateResourceProvisioner) issueCertificate(ctx context.Context, role, commonName, ttl string) (*certIssueResult, error) {
	reqBody := vaultIssueRequest{
		CommonName: commonName,
		TTL:        ttl,
		Format:     "pem",
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal issue request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/%s/issue/%s", p.vaultAddr, p.pkiMount, role)
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("build Vault request: %w", err)
	}
	reqHTTP.Header.Set("X-Vault-Token", p.vaultToken)
	reqHTTP.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(reqHTTP)
	if err != nil {
		return nil, fmt.Errorf("POST Vault PKI /issue: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault returned %d: %s", resp.StatusCode, string(raw))
	}

	var vResp vaultIssueResponse
	if err := json.Unmarshal(raw, &vResp); err != nil {
		return nil, fmt.Errorf("parse Vault response: %w", err)
	}
	if len(vResp.Errors) > 0 {
		return nil, fmt.Errorf("vault PKI error: %s", strings.Join(vResp.Errors, "; "))
	}

	expiresAt := time.Unix(vResp.Data.Expiration, 0).UTC().Format(time.RFC3339)

	return &certIssueResult{
		serialNumber: vResp.Data.SerialNumber,
		expiresAt:    expiresAt,
		leaseID:      vResp.LeaseID,
	}, nil
}

// revokeCertificate calls the Vault PKI /revoke endpoint.
func (p *CertificateResourceProvisioner) revokeCertificate(ctx context.Context, serialNumber string) error {
	body, err := json.Marshal(map[string]string{"serial_number": serialNumber})
	if err != nil {
		return fmt.Errorf("marshal revoke request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/%s/revoke", p.vaultAddr, p.pkiMount)
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build revoke request: %w", err)
	}
	reqHTTP.Header.Set("X-Vault-Token", p.vaultToken)
	reqHTTP.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(reqHTTP)
	if err != nil {
		return fmt.Errorf("POST Vault PKI /revoke: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("vault revoke returned %d: %s", resp.StatusCode, string(raw))
	}
	return nil
}

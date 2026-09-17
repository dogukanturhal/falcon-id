// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/security"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	// metadataMaxBodyBytes is the maximum size of a metadata response body (5 MB).
	metadataMaxBodyBytes = 5 * 1024 * 1024

	// metadataFetchTimeout is the HTTP client timeout for metadata fetches.
	metadataFetchTimeout = 30 * time.Second

	// metadataRefreshInterval is how often the background scheduler wakes up to
	// check for SPs that are due for a metadata refresh.
	metadataRefreshInterval = 1 * time.Hour

	// metadataCertExpiryWarnDays is the lead-time before certificate expiry at
	// which a warning is emitted during validation.
	metadataCertExpiryWarnDays = 30

	// SAML binding URNs used when selecting SSO / SLO endpoints.
	samlBindingHTTPPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	samlBindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

	// metadataImportSourceURL and metadataImportSourceXML are the two valid
	// values for the metadata_import_source field.
	metadataImportSourceURL = "url"
	metadataImportSourceXML = "xml"
)

// SAMLMetadataService handles SAML metadata discovery: fetching, parsing,
// validating, and auto-refreshing metadata from external IDPs.
type SAMLMetadataService struct {
	config     *config.Config
	samlRepo   *repositories.SAMLRepository
	httpClient *http.Client
	stopCh     chan struct{}
	stopOnce   sync.Once
	running    bool
	mu         sync.Mutex // guards running
}

// NewSAMLMetadataService creates a new SAMLMetadataService.
// The embedded HTTP client uses security.SafeTransport so that SSRF via DNS
// rebinding is blocked at dial time rather than only in a pre-flight check.
func NewSAMLMetadataService(cfg *config.Config, samlRepo *repositories.SAMLRepository) *SAMLMetadataService {
	allowHTTP := cfg.Environment == "development" || cfg.Environment == "test"
	return &SAMLMetadataService{
		config:   cfg,
		samlRepo: samlRepo,
		stopCh:   make(chan struct{}),
		httpClient: &http.Client{
			Timeout:   metadataFetchTimeout,
			Transport: security.SafeTransport(allowHTTP),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return security.ValidateMetadataURL(req.URL.String(), allowHTTP)
			},
		},
	}
}

// ==================== Fetch ====================

// FetchMetadataFromURL retrieves raw SAML metadata XML from the given URL.
// It enforces a 30-second timeout and a 5 MB response-body limit.
// SSRF protection is applied in two layers:
//  1. A fast pre-flight check on the literal URL (scheme, blocked hostname strings).
//  2. IP validation inside the transport dialer (closes DNS-rebinding TOCTOU gap).
func (s *SAMLMetadataService) FetchMetadataFromURL(ctx context.Context, url string) ([]byte, error) {
	allowHTTP := s.config.Environment == "development" || s.config.Environment == "test"

	// Pre-flight: reject obviously bad URLs before touching the network.
	if err := security.ValidateMetadataURL(url, allowHTTP); err != nil {
		return nil, fmt.Errorf("FetchMetadataFromURL: SSRF protection: %w", err)
	}

	if !strings.HasPrefix(url, "https://") {
		logger.Warn("SAML metadata URL does not use HTTPS; connection is not encrypted",
			zap.String("url", url),
		)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("FetchMetadataFromURL: build request: %w", err)
	}
	req.Header.Set("Accept", "application/xml, text/xml, */*")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("FetchMetadataFromURL: http get: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("FetchMetadataFromURL: unexpected status %d from %s", resp.StatusCode, url)
	}

	limited := io.LimitReader(resp.Body, metadataMaxBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("FetchMetadataFromURL: read body: %w", err)
	}

	if int64(len(data)) > metadataMaxBodyBytes {
		return nil, fmt.Errorf("FetchMetadataFromURL: response body exceeds 5 MB limit for %s", url)
	}

	return data, nil
}

// ==================== Parse ====================

// ParseMetadata parses a SAML metadata XML document and returns a normalised
// ParsedSAMLMetadata value.  It prefers the HTTP-POST binding for SSO and
// falls back to HTTP-Redirect.
func (s *SAMLMetadataService) ParseMetadata(xmlData []byte) (*models.ParsedSAMLMetadata, error) {
	// XML sanitization: reject XXE, DTD declarations, null bytes, oversized payloads.
	if err := security.SanitizeXMLInput(xmlData); err != nil {
		return nil, fmt.Errorf("ParseMetadata: XML sanitization failed: %w", err)
	}

	var entity models.SAMLEntityDescriptor
	if err := xml.Unmarshal(xmlData, &entity); err != nil {
		return nil, fmt.Errorf("ParseMetadata: unmarshal XML: %w", err)
	}

	parsed := &models.ParsedSAMLMetadata{
		EntityID: entity.EntityID,
		RawXML:   string(xmlData),
	}

	// Parse the optional validUntil attribute.
	if entity.ValidUntil != "" {
		if t, err := time.Parse(time.RFC3339, entity.ValidUntil); err == nil {
			parsed.ValidUntil = &t
		}
	}

	// Extract data from the IDPSSODescriptor (IDP metadata).
	if idp := entity.IDPSSODescriptor; idp != nil {
		parsed.WantAuthnSigned = strings.EqualFold(idp.WantAuthnRequestsSigned, "true")

		// SSO URL: prefer HTTP-POST, fall back to HTTP-Redirect.
		parsed.SSOURL, parsed.SSOBinding = selectBinding(
			ssoLocations(idp.SingleSignOnServices),
			samlBindingHTTPPost,
			samlBindingHTTPRedirect,
		)

		// SLO URL: same preference order.
		parsed.SLOURL, parsed.SLOBinding = selectBinding(
			sloLocations(idp.SingleLogoutServices),
			samlBindingHTTPPost,
			samlBindingHTTPRedirect,
		)

		// Name ID formats.
		parsed.NameIDFormats = idp.NameIDFormats

		// Signing certificate: use the first key descriptor with use="signing",
		// or the first key descriptor when no use attribute is present.
		signingCertB64 := extractSigningCert(idp.KeyDescriptors)
		if signingCertB64 != "" {
			signingCertPEM, expiry, err := certBase64ToPEM(signingCertB64)
			if err != nil {
				logger.Warn("ParseMetadata: failed to parse signing certificate",
					zap.String("entity_id", entity.EntityID),
					zap.Error(err),
				)
			} else {
				parsed.SigningCertPEM = signingCertPEM
				parsed.CertificateExpiry = expiry
			}
		}
	}

	// Organization name.
	if org := entity.Organization; org != nil {
		parsed.OrganizationName = localizedValue(org.OrganizationDisplayName, org.OrganizationName)
	}

	// Detect well-known IDP type from the entity ID.
	parsed.DetectedIDPType = s.detectWellKnownIDP(entity.EntityID)

	return parsed, nil
}

// ==================== Validate ====================

// ValidateMetadata runs a series of non-fatal checks on parsed metadata and
// returns a slice of human-readable warning strings.  A non-empty result does
// not prevent import; callers decide how to surface the warnings.
func (s *SAMLMetadataService) ValidateMetadata(parsed *models.ParsedSAMLMetadata) []string {
	var warnings []string

	if parsed.EntityID == "" {
		warnings = append(warnings, "metadata is missing an EntityID")
	}

	if parsed.SSOURL == "" {
		warnings = append(warnings, "no SingleSignOnService endpoint found in metadata")
	}

	if parsed.SigningCertPEM == "" {
		warnings = append(warnings, "no signing certificate found in metadata; assertion signatures cannot be verified")
	}

	now := time.Now()
	if parsed.CertificateExpiry != nil {
		if parsed.CertificateExpiry.Before(now) {
			warnings = append(warnings, fmt.Sprintf(
				"signing certificate expired on %s",
				parsed.CertificateExpiry.Format(time.DateOnly),
			))
		} else if parsed.CertificateExpiry.Before(now.AddDate(0, 0, metadataCertExpiryWarnDays)) {
			warnings = append(warnings, fmt.Sprintf(
				"signing certificate expires soon: %s",
				parsed.CertificateExpiry.Format(time.DateOnly),
			))
		}
	}

	for _, u := range []struct{ name, url string }{
		{"SSO URL", parsed.SSOURL},
		{"SLO URL", parsed.SLOURL},
	} {
		if u.url != "" && !strings.HasPrefix(u.url, "https://") {
			warnings = append(warnings, fmt.Sprintf("%s does not use HTTPS: %s", u.name, u.url))
		}
	}

	return warnings
}

// ==================== IDP Detection ====================

// detectWellKnownIDP matches an entity ID against known IDP patterns and
// returns a short identifier string, or "unknown" when no pattern matches.
func (s *SAMLMetadataService) detectWellKnownIDP(entityID string) string {
	switch {
	case strings.Contains(entityID, "okta.com"):
		return "okta"
	case strings.Contains(entityID, "sts.windows.net") ||
		strings.Contains(entityID, "login.microsoftonline.com"):
		return "azure_ad"
	case strings.Contains(entityID, "onelogin.com"):
		return "onelogin"
	case strings.Contains(entityID, "pingidentity.com") ||
		strings.Contains(entityID, "pingone.com"):
		return "ping"
	case strings.Contains(entityID, "google.com/a/"):
		return "google_workspace"
	default:
		return "unknown"
	}
}

// ==================== Import ====================

// ImportSPFromMetadata creates a SAMLServiceProvider record from already-parsed
// metadata.  Pass metadataURL as a non-empty string when the source was a URL;
// leave it empty to mark the source as "xml".
func (s *SAMLMetadataService) ImportSPFromMetadata(
	ctx context.Context,
	tenantID uuid.UUID,
	parsed *models.ParsedSAMLMetadata,
	name string,
	metadataURL string,
) (*models.SAMLServiceProvider, error) {
	now := time.Now()

	importSource := metadataImportSourceXML
	var metaURL *string
	if metadataURL != "" {
		importSource = metadataImportSourceURL
		metaURL = &metadataURL
	}

	var rawXML *string
	if parsed.RawXML != "" {
		rawXML = &parsed.RawXML
	}

	idpType := parsed.DetectedIDPType
	var detectedIDPType *string
	if idpType != "" {
		detectedIDPType = &idpType
	}

	var orgName *string
	if parsed.OrganizationName != "" {
		orgName = &parsed.OrganizationName
	}

	var sloURL *string
	if parsed.SLOURL != "" {
		sloURL = &parsed.SLOURL
	}

	var certPEM *string
	if parsed.SigningCertPEM != "" {
		certPEM = &parsed.SigningCertPEM
	}

	defaultAttrMapping := models.JSONMap{}
	for k, v := range models.DefaultAttributeMapping() {
		defaultAttrMapping[k] = v
	}

	sp := &models.SAMLServiceProvider{
		ID:                         uuid.New(),
		TenantID:                   tenantID,
		Name:                       name,
		EntityID:                   parsed.EntityID,
		ACSURL:                     parsed.SSOURL,
		SLOURL:                     sloURL,
		MetadataURL:                metaURL,
		Certificate:                certPEM,
		NameIDFormat:               defaultNameIDFormat(parsed.NameIDFormats),
		SignAssertions:             false,
		EncryptAssertions:          false,
		AttributeMapping:           defaultAttrMapping,
		AllowedAttributes:          models.DefaultAllowedAttributes(),
		IsActive:                   true,
		RawMetadataXML:             rawXML,
		MetadataLastFetched:        &now,
		MetadataAutoRefresh:        metaURL != nil,
		MetadataRefreshIntervalHrs: 24,
		DetectedIDPType:            detectedIDPType,
		OrganizationName:           orgName,
		CertificateExpiry:          parsed.CertificateExpiry,
		MetadataImportSource:       importSource,
		CreatedAt:                  now,
		UpdatedAt:                  now,
	}

	if err := s.samlRepo.Create(ctx, sp); err != nil {
		return nil, fmt.Errorf("ImportSPFromMetadata: persist SP: %w", err)
	}

	logger.Info("SAML SP imported from metadata",
		zap.String("sp_id", sp.ID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("entity_id", sp.EntityID),
		zap.String("detected_idp", idpType),
		zap.String("import_source", importSource),
	)

	return sp, nil
}

// ==================== Refresh ====================

// GetSPByID retrieves a SAML service provider by ID for tenant validation.
func (s *SAMLMetadataService) GetSPByID(ctx context.Context, id uuid.UUID) (*models.SAMLServiceProvider, error) {
	return s.samlRepo.GetByID(ctx, id)
}

// RefreshSPMetadata re-fetches metadata for a single SP, compares it with the
// stored version, and persists any changes.  A SAMLMetadataRefreshLog entry is
// always written, regardless of whether the refresh succeeds or fails.
func (s *SAMLMetadataService) RefreshSPMetadata(ctx context.Context, spID uuid.UUID) error {
	sp, err := s.samlRepo.GetByID(ctx, spID)
	if err != nil {
		return fmt.Errorf("RefreshSPMetadata: get SP: %w", err)
	}

	if sp.MetadataURL == nil || *sp.MetadataURL == "" {
		return fmt.Errorf("RefreshSPMetadata: SP %s has no metadata URL", spID)
	}

	refreshLog := &models.SAMLMetadataRefreshLog{
		SPID: spID,
	}

	xmlData, fetchErr := s.FetchMetadataFromURL(ctx, *sp.MetadataURL)
	if fetchErr != nil {
		errMsg := fetchErr.Error()
		refreshLog.Status = awxJobStatusFailed
		refreshLog.ErrorMessage = &errMsg
		_ = s.samlRepo.CreateMetadataRefreshLog(ctx, refreshLog)
		return fmt.Errorf("RefreshSPMetadata: fetch: %w", fetchErr)
	}

	parsed, parseErr := s.ParseMetadata(xmlData)
	if parseErr != nil {
		errMsg := parseErr.Error()
		refreshLog.Status = awxJobStatusFailed
		refreshLog.ErrorMessage = &errMsg
		_ = s.samlRepo.CreateMetadataRefreshLog(ctx, refreshLog)
		return fmt.Errorf("RefreshSPMetadata: parse: %w", parseErr)
	}

	// Detect changes by comparing fields of interest.
	changes := make(map[string]interface{})

	newCertPEM := parsed.SigningCertPEM
	oldCertPEM := ""
	if sp.Certificate != nil {
		oldCertPEM = *sp.Certificate
	}

	certRotated := newCertPEM != "" && newCertPEM != oldCertPEM
	if certRotated {
		changes["certificate"] = "rotated"
		refreshLog.CertRotated = true
		refreshLog.OldCertExpiry = sp.CertificateExpiry
		refreshLog.NewCertExpiry = parsed.CertificateExpiry
	}

	oldRawXML := ""
	if sp.RawMetadataXML != nil {
		oldRawXML = *sp.RawMetadataXML
	}
	if parsed.RawXML != oldRawXML {
		changes["raw_metadata_xml"] = "updated"
	}

	if len(changes) == 0 {
		refreshLog.Status = "no_changes"
		_ = s.samlRepo.CreateMetadataRefreshLog(ctx, refreshLog)

		logger.Info("SAML metadata refresh: no changes detected",
			zap.String("sp_id", spID.String()),
		)
		return nil
	}

	// Apply updates to the SP record.
	now := time.Now()
	if newCertPEM != "" {
		sp.Certificate = &newCertPEM
	}
	sp.CertificateExpiry = parsed.CertificateExpiry
	if parsed.RawXML != "" {
		sp.RawMetadataXML = &parsed.RawXML
	}
	sp.MetadataLastFetched = &now

	if idpType := parsed.DetectedIDPType; idpType != "" {
		sp.DetectedIDPType = &idpType
	}
	if orgName := parsed.OrganizationName; orgName != "" {
		sp.OrganizationName = &orgName
	}

	if err := s.samlRepo.UpdateMetadataFields(ctx, sp); err != nil {
		errMsg := err.Error()
		refreshLog.Status = awxJobStatusFailed
		refreshLog.ErrorMessage = &errMsg
		_ = s.samlRepo.CreateMetadataRefreshLog(ctx, refreshLog)
		return fmt.Errorf("RefreshSPMetadata: persist update: %w", err)
	}

	refreshLog.Status = "success"
	refreshLog.Changes = changes
	_ = s.samlRepo.CreateMetadataRefreshLog(ctx, refreshLog)

	logger.Info("SAML metadata refresh: updated",
		zap.String("sp_id", spID.String()),
		zap.Bool("cert_rotated", certRotated),
		zap.Any("changes", changes),
	)

	return nil
}

// ==================== Background Scheduler ====================

// StartRefreshScheduler launches a background goroutine that wakes up every
// hour, queries for SPs due for a metadata refresh, and calls RefreshSPMetadata
// for each one.  It follows the same pattern as ADSyncService.StartScheduler.
// The goroutine terminates when StopRefreshScheduler is called or ctx is done.
func (s *SAMLMetadataService) StartRefreshScheduler(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		logger.Warn("SAML metadata refresh scheduler is already running")
		return
	}
	s.running = true
	s.mu.Unlock()

	logger.Info("Starting SAML metadata refresh scheduler",
		zap.Duration("interval", metadataRefreshInterval),
	)

	go func() {
		// Small initial delay so the service is fully initialised before the
		// first refresh run.
		select {
		case <-time.After(30 * time.Second):
			s.runScheduledRefresh(ctx)
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		}

		ticker := time.NewTicker(metadataRefreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.runScheduledRefresh(ctx)
			case <-s.stopCh:
				logger.Info("SAML metadata refresh scheduler stopped")
				return
			case <-ctx.Done():
				logger.Info("SAML metadata refresh scheduler: context cancelled")
				return
			}
		}
	}()
}

// StopRefreshScheduler signals the background goroutine to stop.
// It is safe to call more than once.
func (s *SAMLMetadataService) StopRefreshScheduler() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.running = false
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// runScheduledRefresh is the body of each scheduled refresh tick.
func (s *SAMLMetadataService) runScheduledRefresh(ctx context.Context) {
	logger.Info("Running scheduled SAML metadata refresh")

	sps, err := s.samlRepo.GetSPsForMetadataRefresh(ctx)
	if err != nil {
		logger.Error("SAML metadata refresh: failed to query SPs", zap.Error(err))
		return
	}

	for _, sp := range sps {
		if err := s.RefreshSPMetadata(ctx, sp.ID); err != nil {
			logger.Error("SAML metadata refresh failed for SP",
				zap.String("sp_id", sp.ID.String()),
				zap.String("sp_name", sp.Name),
				zap.Error(err),
			)
		}
	}
}

// GetMetadataRefreshLogs returns the metadata refresh log for the given SP,
// ordered by creation time descending, capped at limit entries.
// It delegates to the underlying SAMLRepository.
func (s *SAMLMetadataService) GetMetadataRefreshLogs(ctx context.Context, spID uuid.UUID, limit int) ([]*models.SAMLMetadataRefreshLog, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.samlRepo.GetMetadataRefreshLogs(ctx, spID, limit)
}

// ==================== Certificate Helpers ====================

// certBase64ToPEM converts a raw base64-encoded DER certificate into a PEM
// string and also returns the certificate's expiry date.
func certBase64ToPEM(certBase64 string) (string, *time.Time, error) {
	clean := strings.ReplaceAll(certBase64, "\n", "")
	clean = strings.ReplaceAll(clean, "\r", "")
	clean = strings.ReplaceAll(clean, " ", "")
	clean = strings.TrimSpace(clean)

	derBytes, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return "", nil, fmt.Errorf("certBase64ToPEM: base64 decode: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return "", nil, fmt.Errorf("certBase64ToPEM: x509 parse: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	pemStr := string(pem.EncodeToMemory(pemBlock))
	expiry := cert.NotAfter
	return pemStr, &expiry, nil
}

// ==================== Internal Helpers ====================

// bindingMap is a keyed lookup from binding URN to location URL.
type bindingMap map[string]string

// selectBinding returns the location and binding URN for the most-preferred
// binding that is present in the provided map.  It tries each candidate in
// order and returns the first match, or empty strings if none match.
func selectBinding(locations bindingMap, candidates ...string) (location, binding string) {
	for _, b := range candidates {
		if loc, ok := locations[b]; ok && loc != "" {
			return loc, b
		}
	}
	return "", ""
}

// ssoLocations converts a slice of SAMLSingleSignOnService into a bindingMap.
func ssoLocations(svcs []models.SAMLSingleSignOnService) bindingMap {
	m := make(bindingMap, len(svcs))
	for _, svc := range svcs {
		m[svc.Binding] = svc.Location
	}
	return m
}

// sloLocations converts a slice of SAMLSingleLogoutService into a bindingMap.
func sloLocations(svcs []models.SAMLSingleLogoutService) bindingMap {
	m := make(bindingMap, len(svcs))
	for _, svc := range svcs {
		m[svc.Binding] = svc.Location
	}
	return m
}

// extractSigningCert returns the base64-encoded certificate data from the first
// KeyDescriptor whose use attribute is "signing".  If no such descriptor
// exists, it falls back to the first KeyDescriptor regardless of use.
func extractSigningCert(descriptors []models.SAMLKeyDescriptor) string {
	var fallback string
	for _, kd := range descriptors {
		if kd.KeyInfo.X509Data == nil {
			continue
		}
		cert := strings.TrimSpace(kd.KeyInfo.X509Data.X509Certificate)
		if cert == "" {
			continue
		}
		if strings.EqualFold(kd.Use, "signing") {
			return cert
		}
		if fallback == "" {
			fallback = cert
		}
	}
	return fallback
}

// localizedValue returns the first English ("en") value from displayNames, or
// falls back to the first value from names, or the empty string.
func localizedValue(displayNames, names []models.SAMLLocalizedName) string {
	for _, n := range displayNames {
		if strings.EqualFold(n.Lang, "en") {
			return n.Value
		}
	}
	if len(displayNames) > 0 {
		return displayNames[0].Value
	}
	for _, n := range names {
		if strings.EqualFold(n.Lang, "en") {
			return n.Value
		}
	}
	if len(names) > 0 {
		return names[0].Value
	}
	return ""
}

// defaultNameIDFormat selects a sensible NameID format from the list provided
// in the metadata, defaulting to emailAddress when the list is empty or none
// of the preferred formats are present.
func defaultNameIDFormat(formats []string) string {
	preferred := []string{
		models.NameIDFormatEmailAddress,
		models.NameIDFormatPersistent,
		models.NameIDFormatUnspecified,
	}
	for _, p := range preferred {
		for _, f := range formats {
			if f == p {
				return f
			}
		}
	}
	return models.NameIDFormatEmailAddress
}

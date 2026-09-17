// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/security"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// samlServiceSAMLRepo defines the SAML repository methods needed by SAMLService.
type samlServiceSAMLRepo interface {
	Create(ctx context.Context, sp *models.SAMLServiceProvider) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.SAMLServiceProvider, error)
	GetByEntityID(ctx context.Context, tenantID uuid.UUID, entityID string) (*models.SAMLServiceProvider, error)
	GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.SAMLServiceProvider, error)
	Update(ctx context.Context, sp *models.SAMLServiceProvider) error
	Delete(ctx context.Context, id uuid.UUID) error
	CreateAssertionLog(ctx context.Context, log *models.SAMLAssertionLog) error
	GetAssertionLogs(ctx context.Context, spID uuid.UUID, limit int) ([]*models.SAMLAssertionLog, error)
}

// samlServiceUserRepo defines the user repository methods needed by SAMLService.
type samlServiceUserRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
}

// SAMLService handles SAML IDP operations
type SAMLService struct {
	samlRepo   samlServiceSAMLRepo
	userRepo   samlServiceUserRepo
	cfg        *config.Config
	privateKey *rsa.PrivateKey
	cert       *x509.Certificate
	certPEM    string
	certB64    string
	signer     security.Signer
}

// NewSAMLService creates a new SAMLService
func NewSAMLService(
	samlRepo samlServiceSAMLRepo,
	userRepo samlServiceUserRepo,
	cfg *config.Config,
) (*SAMLService, error) {
	svc := &SAMLService{
		samlRepo: samlRepo,
		userRepo: userRepo,
		cfg:      cfg,
	}

	// Load or generate SAML signing key and certificate
	if err := svc.loadOrGenerateKeyAndCert(); err != nil {
		return nil, fmt.Errorf("failed to load SAML keys: %w", err)
	}

	// Initialize the XML-DSig signer for assertion/response signing.
	signer, err := security.NewSAMLSigner(svc.privateKey, svc.certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create SAML signer: %w", err)
	}
	svc.signer = signer

	return svc, nil
}

func (s *SAMLService) loadOrGenerateKeyAndCert() error {
	// Try to load from environment
	privateKeyPEM := os.Getenv("SAML_PRIVATE_KEY")
	certPEM := os.Getenv("SAML_CERTIFICATE")

	if privateKeyPEM != "" && certPEM != "" {
		key, err := parseSAMLPrivateKey(privateKeyPEM)
		if err != nil {
			return err
		}
		if key != nil {
			s.privateKey = key
		}
		cert, certB64, err := parseSAMLCertificate(certPEM)
		if err != nil {
			return err
		}
		if cert != nil {
			s.cert = cert
			s.certPEM = certPEM
			s.certB64 = certB64
		}
	}

	// Generate if not loaded
	if s.privateKey == nil || s.cert == nil {
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return fmt.Errorf("failed to generate RSA key: %w", err)
		}
		s.privateKey = key

		// Generate self-signed certificate
		serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return fmt.Errorf("failed to generate certificate serial number: %w", err)
		}
		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{"Hexxlock"},
				CommonName:   "Hexxlock SAML IdP",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			return fmt.Errorf("failed to create certificate: %w", err)
		}

		s.cert, err = x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		s.certPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		}))
		s.certB64 = base64.StdEncoding.EncodeToString(certDER)
	}

	return nil
}

// parseSAMLPrivateKey parses a PEM-encoded RSA private key (PKCS1 or PKCS8).
func parseSAMLPrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, nil
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	rsaKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return rsaKey, nil
}

// parseSAMLCertificate parses a PEM-encoded X.509 certificate and returns the cert, base64 DER, and any error.
func parseSAMLCertificate(certPEM string) (*x509.Certificate, string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, "", nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, base64.StdEncoding.EncodeToString(block.Bytes), nil
}

// ==================== Service Provider Management ====================

// CreateServiceProvider creates a new SAML service provider
func (s *SAMLService) CreateServiceProvider(ctx context.Context, tenantID uuid.UUID, req *models.CreateSAMLServiceProviderRequest, createdBy *uuid.UUID) (*models.SAMLServiceProvider, error) {
	// Set defaults
	nameIDFormat := req.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = models.NameIDFormatEmailAddress
	}

	signAssertions := true
	if req.SignAssertions != nil {
		signAssertions = *req.SignAssertions
	}

	encryptAssertions := false
	if req.EncryptAssertions != nil {
		encryptAssertions = *req.EncryptAssertions
	}

	attrMapping := models.JSONMap{}
	if req.AttributeMapping != nil {
		for k, v := range req.AttributeMapping {
			attrMapping[k] = v
		}
	} else {
		for k, v := range models.DefaultAttributeMapping() {
			attrMapping[k] = v
		}
	}

	allowedAttrs := req.AllowedAttributes
	if len(allowedAttrs) == 0 {
		allowedAttrs = models.DefaultAllowedAttributes()
	}

	now := time.Now()
	sp := &models.SAMLServiceProvider{
		ID:                uuid.New(),
		TenantID:          tenantID,
		Name:              req.Name,
		EntityID:          req.EntityID,
		ACSURL:            req.ACSURL,
		SLOURL:            req.SLOURL,
		MetadataURL:       req.MetadataURL,
		Certificate:       req.Certificate,
		NameIDFormat:      nameIDFormat,
		SignAssertions:    signAssertions,
		EncryptAssertions: encryptAssertions,
		AttributeMapping:  attrMapping,
		AllowedAttributes: allowedAttrs,
		IsActive:          true,
		CreatedAt:         now,
		UpdatedAt:         now,
		CreatedBy:         createdBy,
	}

	if err := s.samlRepo.Create(ctx, sp); err != nil {
		return nil, fmt.Errorf("CreateServiceProvider: %w", err)
	}

	return sp, nil
}

// GetServiceProvider retrieves a SAML service provider by ID
func (s *SAMLService) GetServiceProvider(ctx context.Context, id uuid.UUID) (*models.SAMLServiceProvider, error) {
	return s.samlRepo.GetByID(ctx, id)
}

// GetServiceProviderByEntityID retrieves a SAML service provider by entity ID
func (s *SAMLService) GetServiceProviderByEntityID(ctx context.Context, tenantID uuid.UUID, entityID string) (*models.SAMLServiceProvider, error) {
	return s.samlRepo.GetByEntityID(ctx, tenantID, entityID)
}

// ListServiceProviders lists all SAML service providers for a tenant
func (s *SAMLService) ListServiceProviders(ctx context.Context, tenantID uuid.UUID) ([]*models.SAMLServiceProvider, error) {
	return s.samlRepo.GetByTenantID(ctx, tenantID)
}

// UpdateServiceProvider updates a SAML service provider
func (s *SAMLService) UpdateServiceProvider(ctx context.Context, id uuid.UUID, req *models.UpdateSAMLServiceProviderRequest) (*models.SAMLServiceProvider, error) {
	sp, err := s.samlRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("UpdateServiceProvider: %w", err)
	}

	if req.Name != nil {
		sp.Name = *req.Name
	}
	if req.EntityID != nil {
		sp.EntityID = *req.EntityID
	}
	if req.ACSURL != nil {
		sp.ACSURL = *req.ACSURL
	}
	if req.SLOURL != nil {
		sp.SLOURL = req.SLOURL
	}
	if req.MetadataURL != nil {
		sp.MetadataURL = req.MetadataURL
	}
	if req.Certificate != nil {
		sp.Certificate = req.Certificate
	}
	if req.NameIDFormat != nil {
		sp.NameIDFormat = *req.NameIDFormat
	}
	if req.SignAssertions != nil {
		sp.SignAssertions = *req.SignAssertions
	}
	if req.EncryptAssertions != nil {
		sp.EncryptAssertions = *req.EncryptAssertions
	}
	if req.AttributeMapping != nil {
		sp.AttributeMapping = models.JSONMap{}
		for k, v := range req.AttributeMapping {
			sp.AttributeMapping[k] = v
		}
	}
	if len(req.AllowedAttributes) > 0 {
		sp.AllowedAttributes = req.AllowedAttributes
	}
	if req.IsActive != nil {
		sp.IsActive = *req.IsActive
	}

	sp.UpdatedAt = time.Now()

	if err := s.samlRepo.Update(ctx, sp); err != nil {
		return nil, fmt.Errorf("UpdateServiceProvider: %w", err)
	}

	return sp, nil
}

// DeleteServiceProvider deletes a SAML service provider
func (s *SAMLService) DeleteServiceProvider(ctx context.Context, id uuid.UUID) error {
	return s.samlRepo.Delete(ctx, id)
}

// ==================== SAML IDP Metadata ====================

// GetIDPMetadata returns the SAML IDP metadata
func (s *SAMLService) GetIDPMetadata(tenantID uuid.UUID) *models.SAMLMetadataResponse {
	baseURL := s.getBaseURL()

	return &models.SAMLMetadataResponse{
		EntityID: fmt.Sprintf("%s/saml/%s/metadata", baseURL, tenantID.String()),
		SSOURL:   fmt.Sprintf("%s/saml/%s/sso", baseURL, tenantID.String()),
		// No SLO URL is published. The /saml/<tenant>/slo endpoint does not
		// perform Single Logout -- it never parses the LogoutRequest and never
		// terminates a session (handlers.SAMLHandler.HandleSLO) -- so advertising
		// it here or in the IDPSSODescriptor would tell relying parties that
		// logout propagates when it does not. Restore both together with a real
		// implementation, never before.
		SLOURL:      "",
		Certificate: s.getCertificateBase64(),
		NameIDFormats: []string{
			models.NameIDFormatEmailAddress,
			models.NameIDFormatPersistent,
			models.NameIDFormatTransient,
			models.NameIDFormatUnspecified,
		},
	}
}

// GenerateMetadataXML generates the SAML IDP metadata XML
func (s *SAMLService) GenerateMetadataXML(tenantID uuid.UUID) string {
	meta := s.GetIDPMetadata(tenantID)

	// Generate metadata XML
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="%s">
    <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
                         protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>%s</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>%s</md:NameIDFormat>
        <md:NameIDFormat>%s</md:NameIDFormat>
        <md:NameIDFormat>%s</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="%s"/>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                Location="%s"/>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>`,
		meta.EntityID,
		meta.Certificate,
		models.NameIDFormatEmailAddress,
		models.NameIDFormatPersistent,
		models.NameIDFormatTransient,
		meta.SSOURL,
		meta.SSOURL,
	)
}

// ==================== SAML Assertion Generation ====================

// GenerateAssertion generates a SAML assertion for a user
func (s *SAMLService) GenerateAssertion(
	_ context.Context,
	sp *models.SAMLServiceProvider,
	user *models.User,
	authnRequestID string,
) (*models.SAMLAssertion, error) {
	now := time.Now().UTC()
	aid, err := generateSAMLID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate assertion ID: %w", err)
	}
	assertionID := "_" + aid
	sid, err := generateSAMLID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session index: %w", err)
	}
	sessionIndex := "_" + sid

	// Determine Name ID value based on format
	var nameID string
	switch sp.NameIDFormat {
	case models.NameIDFormatEmailAddress:
		nameID = user.Email
	case models.NameIDFormatPersistent, models.NameIDFormatTransient:
		nameID = user.ID.String()
	default:
		nameID = user.Username
	}

	// Build attributes based on attribute mapping
	attributes := make(map[string][]string)
	for attrName, userField := range sp.AttributeMapping {
		if !s.isAllowedAttribute(attrName, sp.AllowedAttributes) {
			continue
		}
		fieldName, ok := userField.(string)
		if !ok {
			continue
		}
		value := s.getUserAttributeValue(user, fieldName)
		if value != "" {
			attributes[attrName] = []string{value}
		}
	}

	assertion := &models.SAMLAssertion{
		ID:                  assertionID,
		IssueInstant:        now,
		Issuer:              s.GetIDPMetadata(sp.TenantID).EntityID,
		Subject:             nameID,
		SubjectNameIDFormat: sp.NameIDFormat,
		Audience:            sp.EntityID,
		Recipient:           sp.ACSURL,
		SessionIndex:        sessionIndex,
		SessionNotOnOrAfter: now.Add(8 * time.Hour),
		NotBefore:           now.Add(-5 * time.Minute), // 5 minute clock skew tolerance
		NotOnOrAfter:        now.Add(5 * time.Minute),
		Attributes:          attributes,
		InResponseTo:        authnRequestID,
	}

	return assertion, nil
}

// GenerateAssertionXML generates the SAML assertion XML
func (s *SAMLService) GenerateAssertionXML(assertion *models.SAMLAssertion) (string, error) {
	// Build attribute statements
	var attrStatements strings.Builder
	for name, values := range assertion.Attributes {
		fmt.Fprintf(&attrStatements, `
            <saml:Attribute Name="%s" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">`, xmlEscape(name))
		for _, value := range values {
			fmt.Fprintf(&attrStatements, `
                <saml:AttributeValue xsi:type="xs:string">%s</saml:AttributeValue>`, xmlEscape(value))
		}
		attrStatements.WriteString(`
            </saml:Attribute>`)
	}

	assertionXML := fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                    xmlns:xs="http://www.w3.org/2001/XMLSchema"
                    ID="%s"
                    IssueInstant="%s"
                    Version="2.0">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
        <saml:NameID Format="%s">%s</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData InResponseTo="%s"
                                          NotOnOrAfter="%s"
                                          Recipient="%s"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
        <saml:AudienceRestriction>
            <saml:Audience>%s</saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="%s" SessionIndex="%s" SessionNotOnOrAfter="%s">
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
        </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>%s
    </saml:AttributeStatement>
</saml:Assertion>`,
		assertion.ID,
		security.FormatSAMLTime(assertion.IssueInstant),
		xmlEscape(assertion.Issuer),
		assertion.SubjectNameIDFormat,
		xmlEscape(assertion.Subject),
		xmlEscape(assertion.InResponseTo),
		security.FormatSAMLTime(assertion.NotOnOrAfter),
		xmlEscape(assertion.Recipient),
		security.FormatSAMLTime(assertion.NotBefore),
		security.FormatSAMLTime(assertion.NotOnOrAfter),
		xmlEscape(assertion.Audience),
		security.FormatSAMLTime(assertion.IssueInstant),
		assertion.SessionIndex,
		security.FormatSAMLTime(assertion.SessionNotOnOrAfter),
		attrStatements.String(),
	)

	return assertionXML, nil
}

// GenerateSAMLResponse generates a complete SAML response with assertion.
// When sp.SignAssertions is true (default), the assertion is signed with an
// RSA-SHA256 enveloped signature. The response envelope is always signed.
func (s *SAMLService) GenerateSAMLResponse(
	ctx context.Context,
	sp *models.SAMLServiceProvider,
	user *models.User,
	authnRequestID string,
) (string, error) {
	assertion, err := s.GenerateAssertion(ctx, sp, user, authnRequestID)
	if err != nil {
		return "", fmt.Errorf("failed to generate assertion: %w", err)
	}

	assertionXML, err := s.GenerateAssertionXML(assertion)
	if err != nil {
		return "", fmt.Errorf("failed to generate assertion XML: %w", err)
	}

	// Sign the assertion if required by the SP configuration.
	if sp.SignAssertions {
		if s.signer == nil {
			return "", fmt.Errorf("assertion signing required but signer not initialized")
		}
		signedAssertion, signErr := s.signAssertionXML(assertion.ID, assertionXML)
		if signErr != nil {
			return "", fmt.Errorf("failed to sign assertion: %w", signErr)
		}
		assertionXML = signedAssertion
	}

	responseID := security.GenerateResponseID()
	now := time.Now().UTC()

	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="%s"
                InResponseTo="%s"
                IssueInstant="%s"
                Destination="%s"
                Version="2.0">
    <saml:Issuer>%s</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    %s
</samlp:Response>`,
		responseID,
		xmlEscape(authnRequestID),
		security.FormatSAMLTime(now),
		xmlEscape(sp.ACSURL),
		xmlEscape(assertion.Issuer),
		assertionXML,
	)

	// Sign the response envelope.
	if s.signer != nil {
		signedResponse, signErr := s.signResponseXML(responseID, responseXML)
		if signErr != nil {
			return "", fmt.Errorf("failed to sign response: %w", signErr)
		}
		responseXML = signedResponse
	}

	// Log the assertion
	s.logAssertion(ctx, sp.ID, user.ID, assertion.ID, assertion.Subject, "", "", "success", nil)

	return base64.StdEncoding.EncodeToString([]byte(responseXML)), nil
}

// signAssertionXML inserts an enveloped XML-DSig signature into the assertion XML.
// The signature is placed immediately after the <saml:Issuer> element.
func (s *SAMLService) signAssertionXML(assertionID, assertionXML string) (string, error) {
	sigBlock, err := s.signer.GenerateSignatureBlock(assertionID, []byte(assertionXML))
	if err != nil {
		return "", fmt.Errorf("sign assertion: %w", err)
	}

	// Insert signature after the closing </saml:Issuer> tag.
	issuerClose := "</saml:Issuer>"
	idx := strings.Index(assertionXML, issuerClose)
	if idx < 0 {
		return "", fmt.Errorf("sign assertion: could not find </saml:Issuer> in assertion XML")
	}
	insertPos := idx + len(issuerClose)
	signed := assertionXML[:insertPos] + "\n    " + sigBlock + assertionXML[insertPos:]
	return signed, nil
}

// signResponseXML inserts an enveloped XML-DSig signature into the response XML.
// The signature is placed immediately after the <saml:Issuer> element in the response.
func (s *SAMLService) signResponseXML(responseID, responseXML string) (string, error) {
	sigBlock, err := s.signer.GenerateSignatureBlock(responseID, []byte(responseXML))
	if err != nil {
		return "", fmt.Errorf("sign response: %w", err)
	}

	// Insert signature after the first closing </saml:Issuer> tag in the response.
	issuerClose := "</saml:Issuer>"
	idx := strings.Index(responseXML, issuerClose)
	if idx < 0 {
		return "", fmt.Errorf("sign response: could not find </saml:Issuer> in response XML")
	}
	insertPos := idx + len(issuerClose)
	signed := responseXML[:insertPos] + "\n    " + sigBlock + responseXML[insertPos:]
	return signed, nil
}

// ==================== Logging ====================

func (s *SAMLService) logAssertion(ctx context.Context, spID, userID uuid.UUID, assertionID, nameID, ipAddress, userAgent, status string, errMsg *string) {
	log := &models.SAMLAssertionLog{
		ID:           uuid.New(),
		SPID:         spID,
		UserID:       &userID,
		AssertionID:  assertionID,
		NameID:       nameID,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		Status:       status,
		ErrorMessage: errMsg,
		CreatedAt:    time.Now(),
	}
	_ = s.samlRepo.CreateAssertionLog(ctx, log)
}

// GetAssertionLogs retrieves assertion logs for a service provider
func (s *SAMLService) GetAssertionLogs(ctx context.Context, spID uuid.UUID, limit int) ([]*models.SAMLAssertionLog, error) {
	if limit <= 0 {
		limit = 100
	}
	return s.samlRepo.GetAssertionLogs(ctx, spID, limit)
}

// GetUserByID retrieves a user by ID for SAML assertions
func (s *SAMLService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	return s.userRepo.GetByID(ctx, userID)
}

// ==================== Helper Functions ====================

func (s *SAMLService) getBaseURL() string {
	baseURL := os.Getenv("SAML_BASE_URL")
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%s", s.cfg.ServicePort)
	}
	return baseURL
}

func (s *SAMLService) getCertificateBase64() string {
	return s.certB64
}

func (s *SAMLService) isAllowedAttribute(attrName string, allowedAttrs []string) bool {
	for _, a := range allowedAttrs {
		if a == attrName {
			return true
		}
	}
	return false
}

func (s *SAMLService) getUserAttributeValue(user *models.User, fieldName string) string {
	switch fieldName {
	case authMethodEmail:
		return user.Email
	case "first_name":
		if user.FirstName != nil {
			return *user.FirstName
		}
	case "last_name":
		if user.LastName != nil {
			return *user.LastName
		}
	case "display_name":
		if user.DisplayName != nil {
			return *user.DisplayName
		}
	case scimAttrUsername:
		return user.Username
	case "id":
		return user.ID.String()
	}
	return ""
}

func generateSAMLID() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func xmlEscape(s string) string {
	var buf strings.Builder
	_ = xml.EscapeText(&buf, []byte(s)) //nolint:errcheck
	return buf.String()
}

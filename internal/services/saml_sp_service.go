// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// saml_sp_service.go implements inbound SAML federation (SP-initiated SSO).
// Tenants configure external IDPs (Okta, Azure AD, etc.) and users authenticate
// through those IDPs, receiving Hexxlock JWTs upon successful assertion validation.
//
// Flow:
//   1. GenerateSPMetadataXML  — publish SP metadata so the IDP can configure the trust.
//   2. InitiateSSO            — build and redirect with a signed/unsigned AuthnRequest.
//   3. HandleACSPost          — validate the IDP SAMLResponse, provision user, issue JWTs.
//   4. HandleSLO              — receive IDP-initiated logout notification.
//
// NOTE: XML-DSig signature validation uses a structural best-effort approach.
// For production deployments requiring strict XML canonicalization and signature
// chain validation, replace the validateSAMLResponse helper with a certified library
// (e.g., github.com/russellhaering/gosaml2 or github.com/crewjam/saml).

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/security"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// clockSkewDefault is the tolerance applied to NotBefore/NotOnOrAfter checks
// when neither the provider nor the config has set an explicit clock-skew value.
const clockSkewDefault = 5 * time.Minute

// samlMFASessionTTL matches the TTL used by AuthService for MFA challenge sessions.
const samlMFASessionTTL = 5 * time.Minute

// certCacheTTL is how long a validated IDP certificate result is considered fresh.
const certCacheTTL = 5 * time.Minute

// maxCertCacheEntries prevents unbounded growth of the certificate validation cache.
const maxCertCacheEntries = 1000

// ============================================================
// certCacheEntry holds a validated IDP certificate and when it was validated.
//
// It used to hold only the timestamp, which was a fair summary of the old
// behaviour: the certificate was parsed, expiry-checked and thrown away, because
// nothing verified a signature with it. Signature verification needs the key, so
// the parsed certificate is now cached alongside the timestamp.
// ============================================================

type certCacheEntry struct {
	validatedAt time.Time
	cert        *x509.Certificate
}

// ============================================================
// SAMLSPService struct and constructor
// ============================================================

// samlSPServiceIDPRepo defines the identity provider repository methods needed by SAMLSPService.
type samlSPServiceIDPRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.IdentityProvider, error)
	GetByTenantAndType(ctx context.Context, tenantID uuid.UUID, providerType string) ([]*models.IdentityProvider, error)
}

// samlSPServiceSAMLSPRepo defines the SAML SP repository methods needed by SAMLSPService.
type samlSPServiceSAMLSPRepo interface {
	CreateAuthnRequest(ctx context.Context, req *models.SAMLSPAuthnRequest) error
	GetAuthnRequestByRequestID(ctx context.Context, requestID string) (*models.SAMLSPAuthnRequest, error)
	ConsumeAuthnRequest(ctx context.Context, requestID string) error
	CreateAssertionLog(ctx context.Context, log *models.SAMLSPAssertionLog) error
}

// samlSPServiceUserRepo defines the user repository methods needed by SAMLSPService.
type samlSPServiceUserRepo interface {
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error)
	Create(ctx context.Context, user *models.User) error
	AssignRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error)
	Update(ctx context.Context, user *models.User) error
	HasAnyMFAFactor(ctx context.Context, userID uuid.UUID) (bool, error)
}

// samlSPServiceRoleRepo defines the role repository methods needed by SAMLSPService.
type samlSPServiceRoleRepo interface {
	GetDefaultRoles(ctx context.Context, tenantID uuid.UUID) ([]models.Role, error)
}

// samlSPServiceFedAccountRepo defines the federated account repository methods needed by SAMLSPService.
type samlSPServiceFedAccountRepo interface {
	Create(ctx context.Context, account *models.FederatedAccount) error
}

// samlSPServiceSessionRepo defines the session repository methods needed by SAMLSPService.
type samlSPServiceSessionRepo interface {
	Create(ctx context.Context, session *models.Session) error
	GetBySAMLMetadata(ctx context.Context, providerID uuid.UUID, nameID string, sessionIndex *string) ([]models.Session, error)
	GetSAMLSessionForUser(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) (*models.Session, error)
	EndSession(ctx context.Context, id uuid.UUID, reason string) error
}

// SAMLSPService handles inbound SAML federation.  Tenants register an external
// IDP (Okta, Azure AD, Google Workspace…) and this service acts as the SAML SP.
type SAMLSPService struct {
	config         *config.Config
	idpRepo        samlSPServiceIDPRepo
	samlSPRepo     samlSPServiceSAMLSPRepo
	userRepo       samlSPServiceUserRepo
	roleRepo       samlSPServiceRoleRepo
	fedAccountRepo samlSPServiceFedAccountRepo
	tokenService   *TokenService
	auditService   *AuditService

	// Optional — injected after construction to avoid circular dependencies.
	riskService   *RiskService
	mfaService    *MFAService
	deviceService *DeviceService

	// Session repository and token blacklist for SAML SLO.
	sessionRepo    samlSPServiceSessionRepo
	tokenBlacklist interface {
		BlacklistSession(ctx context.Context, sessionID uuid.UUID, reason string, ttl time.Duration) error
	}

	// replayStore tracks consumed assertion IDs to prevent replay attacks.
	replayStore security.AssertionReplayStore

	// sessionCache stores short-lived MFA challenge sessions.
	// The interface mirrors redis.Client.Set so the concrete redis type can be
	// injected without importing the redis package here.
	sessionCache interface {
		Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	}

	// baseURL is the SP base URL, resolved once at construction time.
	baseURL string

	// signingCertBase64 is the SP signing certificate, resolved once at construction time.
	signingCertBase64 string

	// certCache caches IDP certificate validation results to avoid re-parsing on
	// every ACS request.  Keyed by provider ID.
	certCache   map[uuid.UUID]*certCacheEntry
	certCacheMu sync.RWMutex
}

// NewSAMLSPService creates a SAMLSPService with its required dependencies.
func NewSAMLSPService(
	cfg *config.Config,
	idpRepo samlSPServiceIDPRepo,
	samlSPRepo samlSPServiceSAMLSPRepo,
	userRepo samlSPServiceUserRepo,
	roleRepo samlSPServiceRoleRepo,
	fedAccountRepo samlSPServiceFedAccountRepo,
	tokenService *TokenService,
	auditService *AuditService,
) *SAMLSPService {
	svc := &SAMLSPService{
		config:         cfg,
		idpRepo:        idpRepo,
		samlSPRepo:     samlSPRepo,
		userRepo:       userRepo,
		roleRepo:       roleRepo,
		fedAccountRepo: fedAccountRepo,
		tokenService:   tokenService,
		auditService:   auditService,
		certCache:      make(map[uuid.UUID]*certCacheEntry),
	}
	svc.baseURL = svc.resolveBaseURL()
	svc.signingCertBase64 = svc.resolveSigningCert()
	return svc
}

// SetMFAService injects the MFA service (called after construction).
func (s *SAMLSPService) SetMFAService(svc *MFAService) {
	s.mfaService = svc
}

// SetRiskService injects the risk assessment service (called after construction).
func (s *SAMLSPService) SetRiskService(svc *RiskService) {
	s.riskService = svc
}

// SetDeviceService injects the device trust service (called after construction).
func (s *SAMLSPService) SetDeviceService(svc *DeviceService) {
	s.deviceService = svc
}

// SetReplayStore injects the assertion replay store (called after construction).
func (s *SAMLSPService) SetReplayStore(store security.AssertionReplayStore) {
	s.replayStore = store
}

// SetSessionCache injects the Redis-backed client used to store MFA challenge state.
func (s *SAMLSPService) SetSessionCache(cache interface {
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
},
) {
	s.sessionCache = cache
}

// SetSessionRepository injects the session repository for SAML SLO session management.
func (s *SAMLSPService) SetSessionRepository(repo samlSPServiceSessionRepo) {
	s.sessionRepo = repo
}

// SetTokenBlacklist injects the token blacklist for SAML SLO session invalidation.
func (s *SAMLSPService) SetTokenBlacklist(bl interface {
	BlacklistSession(ctx context.Context, sessionID uuid.UUID, reason string, ttl time.Duration) error
},
) {
	s.tokenBlacklist = bl
}

// Validate checks that all critical SLO dependencies have been wired.
// Call this after construction and all Set* calls, before serving traffic.
func (s *SAMLSPService) Validate() error {
	if s.sessionRepo == nil {
		return fmt.Errorf("SAMLSPService: sessionRepo is required for SLO")
	}
	if s.replayStore == nil {
		return fmt.Errorf("SAMLSPService: replayStore is required for replay prevention")
	}
	if s.tokenBlacklist == nil {
		return fmt.Errorf("SAMLSPService: tokenBlacklist is required for session invalidation")
	}
	return nil
}

// ============================================================
// 1. SP Metadata
// ============================================================

// spMetadataXML is the Go struct representation of a SAML 2.0 SP EntityDescriptor.
type spMetadataXML struct {
	XMLName  xml.Name           `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID string             `xml:"entityID,attr"`
	SPDesc   spSSODescriptorXML `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
}

type spSSODescriptorXML struct {
	AuthnRequestsSigned        bool               `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       bool               `xml:"WantAssertionsSigned,attr"`
	ProtocolSupportEnumeration string             `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors             []keyDescriptorXML `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor,omitempty"`
	NameIDFormats              []nameIDFormatXML  `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat"`
	ACSServices                []acsServiceXML    `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
	SLOServices                []sloServiceXML    `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService,omitempty"`
}

type keyDescriptorXML struct {
	Use     string     `xml:"use,attr"`
	KeyInfo keyInfoXML `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type keyInfoXML struct {
	X509Data x509DataXML `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type x509DataXML struct {
	X509Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

type nameIDFormatXML struct {
	Value string `xml:",chardata"`
}

type acsServiceXML struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    int    `xml:"index,attr"`
}

type sloServiceXML struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// GenerateSPMetadataXML returns the SAML SP metadata XML for the given tenant and
// provider.  The IDP administrator imports this document to configure the trust
// relationship on their side.
func (s *SAMLSPService) GenerateSPMetadataXML(ctx context.Context, tenantID, providerID uuid.UUID) (string, error) {
	provider, err := s.idpRepo.GetByID(ctx, providerID)
	if err != nil {
		return "", fmt.Errorf("GenerateSPMetadataXML: get provider: %w", err)
	}
	if provider == nil {
		return "", fmt.Errorf("GenerateSPMetadataXML: provider not found")
	}
	if provider.TenantID != tenantID {
		return "", fmt.Errorf("GenerateSPMetadataXML: provider does not belong to tenant")
	}

	baseURL := s.spBaseURL()
	acsURL := fmt.Sprintf("%s/saml/sp/%s/acs", baseURL, tenantID.String())
	sloURL := fmt.Sprintf("%s/saml/sp/%s/slo", baseURL, tenantID.String())

	entityID := fmt.Sprintf("%s/saml/sp/%s/metadata", baseURL, tenantID.String())
	if provider.SAMLSPConfig != nil && provider.SAMLSPConfig.SPEntityID != "" {
		entityID = provider.SAMLSPConfig.SPEntityID
	}

	meta := spMetadataXML{
		EntityID: entityID,
		SPDesc: spSSODescriptorXML{
			AuthnRequestsSigned:        false,
			WantAssertionsSigned:       true,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			NameIDFormats: []nameIDFormatXML{
				{Value: models.NameIDFormatEmailAddress},
				{Value: models.NameIDFormatPersistent},
				{Value: models.NameIDFormatTransient},
			},
			ACSServices: []acsServiceXML{
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: acsURL,
					Index:    0,
				},
			},
			// Both bindings are advertised again: each is now cryptographically
			// verified before any session is terminated -- HTTP-Redirect against
			// the query-string octet string, HTTP-POST against the enveloped
			// XML-DSig on the LogoutRequest.
			SLOServices: []sloServiceXML{
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
					Location: sloURL,
				},
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: sloURL,
				},
			},
		},
	}

	// Include the SP signing certificate when one is configured so the IDP can
	// verify signed AuthnRequests.
	spCert := s.spSigningCertBase64()
	if spCert != "" {
		meta.SPDesc.KeyDescriptors = []keyDescriptorXML{
			{
				Use: "signing",
				KeyInfo: keyInfoXML{
					X509Data: x509DataXML{X509Certificate: spCert},
				},
			},
		}
		meta.SPDesc.AuthnRequestsSigned = true
	}

	out, err := xml.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", fmt.Errorf("GenerateSPMetadataXML: marshal: %w", err)
	}

	return xml.Header + string(out), nil
}

// ============================================================
// 2. Initiate SSO (SP-initiated)
// ============================================================

// InitiateSSO creates a SAML AuthnRequest, persists it for replay prevention, and
// returns the IDP redirect URL with the SAMLRequest parameter encoded per the
// HTTP-Redirect binding (DEFLATE-compressed, then base64-encoded).
func (s *SAMLSPService) InitiateSSO(ctx context.Context, tenantID, providerID uuid.UUID, relayState string) (string, error) {
	provider, err := s.idpRepo.GetByID(ctx, providerID)
	if err != nil {
		return "", fmt.Errorf("InitiateSSO: get provider: %w", err)
	}
	if provider == nil {
		return "", fmt.Errorf("InitiateSSO: provider not found")
	}
	if provider.TenantID != tenantID {
		return "", fmt.Errorf("InitiateSSO: provider does not belong to tenant")
	}
	if !provider.IsEnabled {
		return "", fmt.Errorf("InitiateSSO: provider is disabled")
	}
	if provider.SAMLSPConfig == nil {
		return "", fmt.Errorf("InitiateSSO: provider has no SAML SP configuration")
	}
	if provider.SAMLSPConfig.IDPSSOURL == "" {
		return "", fmt.Errorf("InitiateSSO: IdP SSO URL not configured")
	}

	rid, err := generateSAMLID()
	if err != nil {
		return "", fmt.Errorf("InitiateSSO: failed to generate request ID: %w", err)
	}
	requestID := "_" + rid
	now := time.Now().UTC()

	baseURL := s.spBaseURL()
	acsURL := fmt.Sprintf("%s/saml/sp/%s/acs", baseURL, tenantID.String())
	entityID := fmt.Sprintf("%s/saml/sp/%s/metadata", baseURL, tenantID.String())
	if provider.SAMLSPConfig.SPEntityID != "" {
		entityID = provider.SAMLSPConfig.SPEntityID
	}

	nameIDFormat := provider.SAMLSPConfig.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = models.NameIDFormatEmailAddress
	}

	authnRequestXML := fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8"?>`+
			`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`+
			` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`+
			` ID="%s"`+
			` Version="2.0"`+
			` IssueInstant="%s"`+
			` AssertionConsumerServiceURL="%s"`+
			` Destination="%s">`+
			`<saml:Issuer>%s</saml:Issuer>`+
			`<samlp:NameIDPolicy Format="%s" AllowCreate="true"/>`+
			`</samlp:AuthnRequest>`,
		requestID,
		now.Format(time.RFC3339),
		xmlEscape(acsURL),
		xmlEscape(provider.SAMLSPConfig.IDPSSOURL),
		xmlEscape(entityID),
		xmlEscape(nameIDFormat),
	)

	// HTTP-Redirect binding: DEFLATE compress then base64-encode the XML.
	deflated, err := samlDeflateCompress([]byte(authnRequestXML))
	if err != nil {
		return "", fmt.Errorf("InitiateSSO: compress authn request: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(deflated)

	// Persist the request so we can validate InResponseTo and detect replays.
	var relayStatePtr *string
	if relayState != "" {
		relayStatePtr = &relayState
	}
	authnReq := &models.SAMLSPAuthnRequest{
		TenantID:   tenantID,
		ProviderID: providerID,
		RequestID:  requestID,
		RelayState: relayStatePtr,
		ACSURL:     acsURL,
		ExpiresAt:  now.Add(10 * time.Minute),
	}
	if err := s.samlSPRepo.CreateAuthnRequest(ctx, authnReq); err != nil {
		return "", fmt.Errorf("InitiateSSO: persist authn request: %w", err)
	}

	// Build the redirect URL.
	params := url.Values{}
	params.Set("SAMLRequest", encoded)
	if relayState != "" {
		params.Set("RelayState", relayState)
	}

	ssoURL := provider.SAMLSPConfig.IDPSSOURL
	if strings.Contains(ssoURL, "?") {
		ssoURL += "&" + params.Encode()
	} else {
		ssoURL += "?" + params.Encode()
	}

	logger.Info("SAMLSPService: SSO initiated",
		zap.String("tenant_id", tenantID.String()),
		zap.String("provider_id", providerID.String()),
		zap.String("request_id", requestID),
	)

	return ssoURL, nil
}

// ============================================================
// 3. ACS — Assertion Consumer Service (HTTP-POST binding)
// ============================================================

// Minimal XML structs for parsing the inbound SAML Response.

type samlSPResponseEnvelope struct {
	XMLName      xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string              `xml:"ID,attr"`
	InResponseTo string              `xml:"InResponseTo,attr"`
	Destination  string              `xml:"Destination,attr"`
	IssueInstant string              `xml:"IssueInstant,attr"`
	Status       samlSPStatusXML     `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion    *samlSPAssertionXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

type samlSPStatusXML struct {
	StatusCode samlSPStatusCodeXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

type samlSPStatusCodeXML struct {
	Value string `xml:"Value,attr"`
}

type samlSPAssertionXML struct {
	ID           string                        `xml:"ID,attr"`
	IssueInstant string                        `xml:"IssueInstant,attr"`
	Issuer       string                        `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject      samlSPSubjectXML              `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions   samlSPConditionsXML           `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AuthnStmt    *samlSPAuthnStatementXML      `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AttrStmts    []samlSPAttributeStatementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

type samlSPSubjectXML struct {
	NameID              samlSPNameIDXML              `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SubjectConfirmation samlSPSubjectConfirmationXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
}

type samlSPNameIDXML struct {
	Format string `xml:"Format,attr"`
	Value  string `xml:",chardata"`
}

type samlSPSubjectConfirmationXML struct {
	Method string                           `xml:"Method,attr"`
	Data   samlSPSubjectConfirmationDataXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
}

type samlSPSubjectConfirmationDataXML struct {
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	Recipient    string `xml:"Recipient,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`
}

type samlSPAudienceRestrictionXML struct {
	Audiences []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

type samlSPConditionsXML struct {
	NotBefore            string                         `xml:"NotBefore,attr"`
	NotOnOrAfter         string                         `xml:"NotOnOrAfter,attr"`
	AudienceRestrictions []samlSPAudienceRestrictionXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
}

type samlSPAuthnStatementXML struct {
	SessionIndex string `xml:"SessionIndex,attr"`
}

type samlSPAttributeStatementXML struct {
	Attributes []samlSPAttributeXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

type samlSPAttributeXML struct {
	Name   string                 `xml:"Name,attr"`
	Values []samlSPAttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

type samlSPAttributeValue struct {
	Value string `xml:",chardata"`
}

// HandleACSPost processes an inbound SAML Response posted to our ACS endpoint.
// It decodes and validates the response, provisions or locates the user, optionally
// applies risk and MFA checks, and finally issues Hexxlock JWTs.
func (s *SAMLSPService) HandleACSPost(
	ctx context.Context,
	tenantID uuid.UUID,
	samlResponse, _, ipAddress, userAgent string,
) (*models.LoginResponse, error) {
	rawXML, _, envelope, err := s.decodeSAMLResponse(samlResponse)
	if err != nil {
		return nil, err
	}

	// envelope is UNVERIFIED at this point. It is used for exactly two things
	// before verification, both safe:
	//   - the Issuer, as a lookup key to choose WHICH certificate to trust. A
	//     forged Issuer selects the wrong provider, whose certificate then fails
	//     to verify the signature, so it cannot be used to gain trust.
	//   - the top-level Status, a cheap early reject inside decodeSAMLResponse.
	// Nothing else may be read from it. In particular the identity claims below
	// come from the VERIFIED assertion, never from envelope.Assertion.
	unverifiedAssertion := envelope.Assertion

	provider, err := s.resolveProvider(ctx, tenantID, unverifiedAssertion.Issuer)
	if err != nil {
		return nil, fmt.Errorf("HandleACSPost: %w", err)
	}

	// From here on `assertion` is the cryptographically verified one.
	assertion, err := s.verifySAMLSignature(ctx, tenantID, provider, rawXML, unverifiedAssertion, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	expectedACSURL, expectedEntityID, clockSkew := s.buildSAMLValidationParams(tenantID, provider)

	if err := s.validateAssertionSemantics(ctx, tenantID, provider, envelope, assertion, expectedACSURL, expectedEntityID, clockSkew, ipAddress, userAgent); err != nil {
		return nil, err
	}

	attributes := samlExtractAttributes(assertion)
	if assertion.Subject.NameID.Value != "" {
		attributes["nameID"] = assertion.Subject.NameID.Value
	}

	if err := s.validateAndConsumeAuthnRequest(ctx, provider, envelope.InResponseTo); err != nil {
		return nil, err
	}

	user, err := s.findOrCreateUser(ctx, provider, attributes)
	if err != nil {
		s.logSPAssertionFailure(ctx, tenantID, provider.ID, assertion, ipAddress, userAgent, err.Error())
		return nil, fmt.Errorf("HandleACSPost: %w", err)
	}

	if !user.IsActive {
		s.auditService.LogLogin(ctx, tenantID, &user.ID, ipAddress, userAgent, false, "account disabled")
		return nil, fmt.Errorf("HandleACSPost: account is disabled")
	}

	riskAssessment, err := s.assessSAMLRisk(ctx, tenantID, user, provider, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	// Source-of-truth factor inventory check (companion to auth_service +
	// OAuth /authorize gate): user.MFAEnabled is denormalized and may
	// drift. HasAnyMFAFactor reads from iam_users + iam_webauthn_credentials
	// + iam_push_mfa_devices in a single query.
	hasFactor, factorErr := s.userRepo.HasAnyMFAFactor(ctx, user.ID)
	if factorErr != nil {
		return nil, fmt.Errorf("SAML ACS: check MFA factor inventory: %w", factorErr)
	}
	mfaRequired := hasFactor || (riskAssessment != nil && riskAssessment.RequiresMFA)
	if mfaRequired && s.mfaService != nil {
		if resp := s.handleSAMLMFAChallenge(ctx, user, provider, ipAddress, userAgent); resp != nil {
			return resp, nil
		}
	}

	return s.issueSAMLTokensAndSession(ctx, tenantID, user, provider, assertion, attributes, ipAddress, userAgent)
}

// decodeSAMLResponse decodes, sanitizes and parses a base64-encoded SAML Response.
func (s *SAMLSPService) decodeSAMLResponse(samlResponse string) ([]byte, *security.SAMLSignatureValidationResult, *samlSPResponseEnvelope, error) {
	rawXML, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("HandleACSPost: decode SAMLResponse: %w", err)
	}
	if err := security.SanitizeXMLInput(rawXML); err != nil {
		return nil, nil, nil, fmt.Errorf("HandleACSPost: XML sanitization failed: %w", err)
	}
	sigResult, err := security.ValidateSAMLResponseSignatureStructure(rawXML)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("HandleACSPost: signature validation failed: %w", err)
	}
	var envelope samlSPResponseEnvelope
	if err := xml.Unmarshal(rawXML, &envelope); err != nil {
		return nil, nil, nil, fmt.Errorf("HandleACSPost: parse SAMLResponse XML: %w", err)
	}
	const samlSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
	if envelope.Status.StatusCode.Value != samlSuccess {
		return nil, nil, nil, fmt.Errorf("HandleACSPost: IdP returned non-success status: %s",
			envelope.Status.StatusCode.Value)
	}
	if envelope.Assertion == nil {
		return nil, nil, nil, fmt.Errorf("HandleACSPost: SAML Response contains no Assertion")
	}
	return rawXML, sigResult, &envelope, nil
}

// verifySAMLSignature cryptographically verifies the SAML Response and returns
// the assertion that was ACTUALLY SIGNED, parsed from the verified bytes alone.
//
// The returned assertion is the only one any caller may act on. It is decoded
// from security.VerifiedAssertion.XML, which goxmldsig reconstructed from the
// canonical bytes whose digest matched the signature -- not from the response
// document. Parsing the response document instead would re-open XML Signature
// Wrapping, because encoding/xml and etree can disagree about the same bytes
// (c-085).
//
// This fails closed in every direction, and there is no configuration that
// disables it. SPWantSigned used to gate whether a signature was even looked
// for, and it defaulted to FALSE because it is a plain bool in the
// saml_sp_config jsonb -- so the default posture required nothing at all. An
// unsigned or unverifiable assertion is now rejected regardless of provider
// configuration; the flag can no longer weaken this path.
func (s *SAMLSPService) verifySAMLSignature(ctx context.Context, tenantID uuid.UUID, provider *models.IdentityProvider, rawXML []byte, unverified *samlSPAssertionXML, ipAddress, userAgent string) (*samlSPAssertionXML, error) {
	if provider.SAMLSPConfig == nil || provider.SAMLSPConfig.IDPCertificate == "" {
		s.logSPAssertionFailure(ctx, tenantID, provider.ID, unverified, ipAddress, userAgent, "no IdP certificate configured; cannot verify assertion signature")
		return nil, fmt.Errorf("HandleACSPost: no IdP certificate configured for provider %s; refusing an unverifiable assertion", provider.ID)
	}

	cert, err := s.idpCertWithCache(ctx, tenantID, provider, unverified, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	verified, err := security.VerifySAMLResponseSignature(rawXML, cert)
	if err != nil {
		s.logSPAssertionFailure(ctx, tenantID, provider.ID, unverified, ipAddress, userAgent, "assertion signature verification failed: "+err.Error())
		return nil, fmt.Errorf("HandleACSPost: %w", err)
	}

	// Re-parse the VERIFIED subtree in isolation. This is what makes the
	// guarantee real rather than nominal.
	var signedAssertion samlSPAssertionXML
	if err := xml.Unmarshal(verified.XML, &signedAssertion); err != nil {
		s.logSPAssertionFailure(ctx, tenantID, provider.ID, unverified, ipAddress, userAgent, "verified assertion could not be parsed: "+err.Error())
		return nil, fmt.Errorf("HandleACSPost: parse verified assertion: %w", err)
	}

	logger.Info("SAMLSPService: SAML signature verified",
		zap.String("tenant_id", tenantID.String()),
		zap.String("provider_id", provider.ID.String()),
		zap.String("signature_placement", string(verified.Placement)),
		zap.String("signature_algorithm", verified.SignatureAlgorithm),
		zap.String("assertion_id", signedAssertion.ID),
	)
	return &signedAssertion, nil
}

// idpCertWithCache returns the provider's validated IDP certificate, using a
// short-lived in-memory cache to avoid re-parsing the PEM on every assertion.
//
// This returns the certificate rather than discarding it. The previous version
// dropped it into `_`, which is why the IdP public key never met a signature.
func (s *SAMLSPService) idpCertWithCache(ctx context.Context, tenantID uuid.UUID, provider *models.IdentityProvider, assertion *samlSPAssertionXML, ipAddress, userAgent string) (*x509.Certificate, error) {
	s.certCacheMu.RLock()
	entry, ok := s.certCache[provider.ID]
	fresh := ok && entry.cert != nil && time.Since(entry.validatedAt) < certCacheTTL
	s.certCacheMu.RUnlock()

	if fresh {
		return entry.cert, nil
	}
	cert, err := security.ValidateIDPCertificateForSAML(provider.SAMLSPConfig.IDPCertificate, "")
	if err != nil {
		s.logSPAssertionFailure(ctx, tenantID, provider.ID, assertion, ipAddress, userAgent, "IdP certificate validation failed: "+err.Error())
		return nil, fmt.Errorf("HandleACSPost: IdP certificate validation failed: %w", err)
	}
	s.certCacheMu.Lock()
	if len(s.certCache) >= maxCertCacheEntries {
		s.certCache = make(map[uuid.UUID]*certCacheEntry)
	}
	s.certCache[provider.ID] = &certCacheEntry{validatedAt: time.Now(), cert: cert}
	s.certCacheMu.Unlock()
	return cert, nil
}

// buildSAMLValidationParams derives the expected ACS URL, entity ID, and clock skew for assertion validation.
func (s *SAMLSPService) buildSAMLValidationParams(tenantID uuid.UUID, provider *models.IdentityProvider) (expectedACSURL, expectedEntityID string, clockSkew time.Duration) {
	baseURL := s.spBaseURL()
	expectedACSURL = fmt.Sprintf("%s/saml/sp/%s/acs", baseURL, tenantID.String())
	expectedEntityID = fmt.Sprintf("%s/saml/sp/%s/metadata", baseURL, tenantID.String())
	if provider.SAMLSPConfig != nil && provider.SAMLSPConfig.SPEntityID != "" {
		expectedEntityID = provider.SAMLSPConfig.SPEntityID
	}
	clockSkew = s.config.SAMLSPClockSkew
	if clockSkew == 0 {
		clockSkew = clockSkewDefault
	}
	if provider.SAMLSPConfig != nil && provider.SAMLSPConfig.ClockSkewSeconds > 0 {
		clockSkew = time.Duration(provider.SAMLSPConfig.ClockSkewSeconds) * time.Second
		if clockSkew > 10*time.Minute {
			clockSkew = 10 * time.Minute
		}
	}
	return expectedACSURL, expectedEntityID, clockSkew
}

// validateAssertionSemantics validates assertion time conditions, audience, destination and SC expiry.
func (s *SAMLSPService) validateAssertionSemantics(ctx context.Context, tenantID uuid.UUID, provider *models.IdentityProvider, envelope *samlSPResponseEnvelope, assertion *samlSPAssertionXML, expectedACSURL, expectedEntityID string, clockSkew time.Duration, ipAddress, userAgent string) error {
	var audience string
	if len(assertion.Conditions.AudienceRestrictions) > 0 &&
		len(assertion.Conditions.AudienceRestrictions[0].Audiences) > 0 {
		audience = assertion.Conditions.AudienceRestrictions[0].Audiences[0]
	}
	parsedAssertion := &security.ParsedAssertion{
		ID:                        assertion.ID,
		IssueInstant:              parseSAMLTime(assertion.IssueInstant),
		Issuer:                    assertion.Issuer,
		Audience:                  audience,
		ResponseDestination:       envelope.Destination,
		Recipient:                 assertion.Subject.SubjectConfirmation.Data.Recipient,
		SubjectConfirmationMethod: assertion.Subject.SubjectConfirmation.Method,
		NotBefore:                 parseSAMLTime(assertion.Conditions.NotBefore),
		NotOnOrAfter:              parseSAMLTime(assertion.Conditions.NotOnOrAfter),
		NameID:                    assertion.Subject.NameID.Value,
		NameIDFormat:              assertion.Subject.NameID.Format,
		// Sourced from the VERIFIED assertion. envelope.InResponseTo sits on the
		// Response, which carries no signature when the IdP signs only the
		// assertion -- taking it from there would let an attacker rebind a
		// captured assertion to a different AuthnRequest.
		InResponseTo: assertion.Subject.SubjectConfirmation.Data.InResponseTo,
	}
	if assertion.AuthnStmt != nil {
		parsedAssertion.SessionIndex = assertion.AuthnStmt.SessionIndex
	}
	validationConfig := &security.AssertionValidationConfig{
		ExpectedAudience:    expectedEntityID,
		ExpectedDestination: expectedACSURL,
		ExpectedRecipient:   expectedACSURL,
		ClockSkew:           clockSkew,
		MaxAssertionAge:     10 * time.Minute,
	}
	if err := security.ValidateAssertionSemantics(ctx, parsedAssertion, validationConfig, s.replayStore); err != nil {
		s.logSPAssertionFailure(ctx, tenantID, provider.ID, assertion, ipAddress, userAgent, err.Error())
		return fmt.Errorf("HandleACSPost: assertion validation failed: %w", err)
	}
	if scNotOnOrAfter := assertion.Subject.SubjectConfirmation.Data.NotOnOrAfter; scNotOnOrAfter != "" {
		scTime := parseSAMLTime(scNotOnOrAfter)
		if !scTime.IsZero() && time.Now().UTC().After(scTime.Add(clockSkew)) {
			s.logSPAssertionFailure(ctx, tenantID, provider.ID, assertion, ipAddress, userAgent, "SubjectConfirmationData has expired")
			return fmt.Errorf("HandleACSPost: SubjectConfirmationData has expired (NotOnOrAfter)")
		}
	}
	return nil
}

// validateAndConsumeAuthnRequest validates and consumes the originating AuthnRequest if present.
func (s *SAMLSPService) validateAndConsumeAuthnRequest(ctx context.Context, provider *models.IdentityProvider, inResponseTo string) error {
	if inResponseTo == "" {
		// UNSOLICITED assertion: it carries no InResponseTo, so it cannot be bound
		// to an AuthnRequest we issued. This used to return nil and accept it
		// silently, which meant IdP-initiated SSO was always on and no deployment
		// could turn it off. It is now opt-in per provider.
		//
		// Replay of an accepted unsolicited assertion remains bounded by the
		// assertion-ID replay store in security.ValidateAssertionSemantics; what
		// this flag governs is whether we accept an assertion we never asked for.
		if provider != nil && provider.SAMLSPConfig != nil && provider.SAMLSPConfig.SPAllowIdPInitiated {
			return nil
		}
		return fmt.Errorf("HandleACSPost: unsolicited assertion refused (no InResponseTo); enable sp_allow_idp_initiated on this provider to permit IdP-initiated SSO")
	}
	authnReq, err := s.samlSPRepo.GetAuthnRequestByRequestID(ctx, inResponseTo)
	if err != nil {
		return fmt.Errorf("HandleACSPost: look up authn request: %w", err)
	}
	if authnReq == nil {
		return fmt.Errorf("HandleACSPost: no pending authn request for InResponseTo=%q (possible replay)", inResponseTo)
	}
	if authnReq.ConsumedAt != nil {
		return fmt.Errorf("HandleACSPost: authn request already consumed (replay attack?)")
	}
	if time.Now().After(authnReq.ExpiresAt) {
		return fmt.Errorf("HandleACSPost: authn request has expired")
	}
	if err := s.samlSPRepo.ConsumeAuthnRequest(ctx, inResponseTo); err != nil {
		return fmt.Errorf("HandleACSPost: consume authn request: %w", err)
	}
	return nil
}

// assessSAMLRisk runs optional risk assessment for a SAML login.
func (s *SAMLSPService) assessSAMLRisk(ctx context.Context, tenantID uuid.UUID, user *models.User, provider *models.IdentityProvider, ipAddress, userAgent string) (*models.RiskAssessment, error) {
	if s.riskService == nil {
		return nil, nil
	}
	riskCtx := &models.RiskContext{
		UserID:      user.ID,
		TenantID:    tenantID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		LoginTime:   time.Now(),
		AuthMethod:  "saml",
		SSOProvider: provider.Name,
	}
	ra, err := s.riskService.AssessLoginRisk(ctx, riskCtx)
	if err != nil {
		logger.Warn("SAMLSPService: risk assessment error, continuing",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		return nil, nil
	}
	if ra != nil && ra.Blocked {
		s.auditService.LogLogin(ctx, tenantID, &user.ID, ipAddress, userAgent, false, "blocked by risk assessment")
		return nil, fmt.Errorf("HandleACSPost: login blocked by risk policy: %s", ra.BlockReason)
	}
	return ra, nil
}

// handleSAMLMFAChallenge stores an MFA challenge session and returns a LoginResponse requiring MFA,
// or nil if the device is already trusted.
func (s *SAMLSPService) handleSAMLMFAChallenge(ctx context.Context, user *models.User, provider *models.IdentityProvider, ipAddress, userAgent string) *models.LoginResponse {
	if s.deviceService != nil {
		trusted, trustErr := s.deviceService.IsTrustedDevice(ctx, user.ID, userAgent, ipAddress, nil)
		if trustErr == nil && trusted {
			return nil
		}
	}
	sessionID := uuid.New().String()
	mfaData := &models.MFASessionData{
		UserID:     user.ID.String(),
		TenantID:   provider.TenantID.String(),
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		AuthMethod: "saml",
		CreatedAt:  time.Now().Unix(),
	}
	if s.sessionCache != nil {
		sessionJSON, marshalErr := json.Marshal(mfaData)
		if marshalErr == nil {
			redisKey := "mfa:session:" + sessionID
			if setErr := s.sessionCache.Set(ctx, redisKey, string(sessionJSON), samlMFASessionTTL); setErr != nil {
				logger.Warn("SAMLSPService: failed to store MFA session in Redis",
					zap.String("user_id", user.ID.String()),
					zap.Error(setErr),
				)
			}
		}
	}
	logger.Info("SAMLSPService: MFA required for SAML login",
		zap.String("user_id", user.ID.String()),
		zap.String("session_id", sessionID),
	)
	return &models.LoginResponse{RequiresMFA: true, SessionID: sessionID}
}

// issueSAMLTokensAndSession issues JWTs, creates a DB session record, and emits audit events.
func (s *SAMLSPService) issueSAMLTokensAndSession(ctx context.Context, tenantID uuid.UUID, user *models.User, provider *models.IdentityProvider, assertion *samlSPAssertionXML, attributes map[string]string, ipAddress, userAgent string) (*models.LoginResponse, error) {
	roles, err := s.userRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("HandleACSPost: get user roles: %w", err)
	}
	permissions, err := s.userRepo.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("HandleACSPost: get user permissions: %w", err)
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	permNames := make([]string, len(permissions))
	for i, p := range permissions {
		permNames[i] = p.Name
	}
	jwtSessionID := uuid.New()
	accessToken, err := s.tokenService.GenerateAccessToken(ctx, user, jwtSessionID, roleNames, permNames)
	if err != nil {
		return nil, fmt.Errorf("HandleACSPost: generate access token: %w", err)
	}
	loginTime := time.Now()
	user.LastLoginAt = &loginTime
	if updateErr := s.userRepo.Update(ctx, user); updateErr != nil {
		logger.Error("SAMLSPService: failed to update last login", zap.Error(updateErr))
	}
	if err := s.createSAMLSession(ctx, user, provider, assertion, jwtSessionID, ipAddress, userAgent); err != nil {
		return nil, err
	}
	s.auditService.LogLogin(ctx, tenantID, &user.ID, ipAddress, userAgent, true, "")
	s.writeSPAssertionLog(ctx, tenantID, provider.ID, user.ID, assertion, attributes, ipAddress, userAgent, "success", nil)
	user.Roles = roles
	user.Permissions = permissions
	logger.Info("SAMLSPService: SAML login successful",
		zap.String("user_id", user.ID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("provider", provider.Name),
	)
	// Phase 3 (mig 233): RefreshToken left empty — iam_refresh_tokens is
	// dropped, BFF runs the OAuth dance after redirect for the rotatable
	// token pair.
	return &models.LoginResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.config.AccessTokenExpiry.Seconds()),
		User:        user.ToResponse(),
	}, nil
}

// assignDefaultRolesToUser assigns provider-level or tenant-level default roles to a new SAML user.
func (s *SAMLSPService) assignDefaultRolesToUser(ctx context.Context, userID uuid.UUID, provider *models.IdentityProvider) {
	if len(provider.DefaultRoleIDs) > 0 {
		if assignErr := s.userRepo.AssignRoles(ctx, userID, provider.DefaultRoleIDs, nil); assignErr != nil {
			logger.Error("SAMLSPService: failed to assign provider default roles",
				zap.String("user_id", userID.String()),
				zap.Error(assignErr),
			)
		}
		return
	}
	defaultRoles, rolesErr := s.roleRepo.GetDefaultRoles(ctx, provider.TenantID)
	if rolesErr != nil || len(defaultRoles) == 0 {
		return
	}
	roleIDs := make([]uuid.UUID, len(defaultRoles))
	for i, r := range defaultRoles {
		roleIDs[i] = r.ID
	}
	if assignErr := s.userRepo.AssignRoles(ctx, userID, roleIDs, nil); assignErr != nil {
		logger.Error("SAMLSPService: failed to assign tenant default roles",
			zap.String("user_id", userID.String()),
			zap.Error(assignErr),
		)
	}
}

// createSAMLSession persists a DB session record so SAML SLO can find and terminate it.
func (s *SAMLSPService) createSAMLSession(ctx context.Context, user *models.User, provider *models.IdentityProvider, assertion *samlSPAssertionXML, jwtSessionID uuid.UUID, ipAddress, userAgent string) error {
	if s.sessionRepo == nil {
		return nil
	}
	nameIDValue := assertion.Subject.NameID.Value
	var sessionIdx *string
	if assertion.AuthnStmt != nil && assertion.AuthnStmt.SessionIndex != "" {
		idx := assertion.AuthnStmt.SessionIndex
		sessionIdx = &idx
	}
	sessionExpiry := s.config.SessionExpiry
	if sessionExpiry <= 0 {
		sessionExpiry = 24 * time.Hour
	}
	tokenHash := sha256.Sum256([]byte(jwtSessionID.String()))
	samlSession := &models.Session{
		ID:               jwtSessionID,
		UserID:           user.ID,
		SessionTokenHash: hex.EncodeToString(tokenHash[:]),
		DeviceInfo:       strPtr("SAML SSO"),
		IPAddress:        &ipAddress,
		UserAgent:        &userAgent,
		ExpiresAt:        time.Now().Add(sessionExpiry),
		SAMLProviderID:   &provider.ID,
		SAMLNameID:       &nameIDValue,
		SAMLSessionIndex: sessionIdx,
	}
	if createErr := s.sessionRepo.Create(ctx, samlSession); createErr != nil {
		logger.Error("SAMLSPService: failed to create SAML session record (SLO will be unavailable for this session)",
			zap.String("user_id", user.ID.String()),
			zap.Error(createErr),
		)
		return fmt.Errorf("HandleACSPost: failed to persist SAML session: %w", createErr)
	}
	return nil
}

// parseSAMLTime parses a SAML timestamp string, supporting both RFC3339 and sub-second variants.
func parseSAMLTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05.999Z07:00", s)
	}
	if err != nil {
		logger.Warn("SAMLSPService: unparseable SAML timestamp", zap.String("value", s))
	}
	return t
}

// ============================================================
// 4. findOrCreateUser
// ============================================================

// findOrCreateUser locates an existing user by the email extracted from the SAML
// assertion attributes, or creates a new one if the provider has AutoProvisionUsers
// enabled.
func (s *SAMLSPService) findOrCreateUser(
	ctx context.Context,
	provider *models.IdentityProvider,
	attributes map[string]string,
) (*models.User, error) {
	// Determine which attribute key holds the email.
	emailAttrKey := authMethodEmail
	if provider.SAMLSPConfig != nil {
		if mapped, ok := provider.SAMLSPConfig.AttributeMapping[authMethodEmail]; ok && mapped != "" {
			emailAttrKey = mapped
		}
	}
	if provider.AttributeMapping != nil {
		if mapped, ok := provider.AttributeMapping[authMethodEmail]; ok && mapped != "" {
			emailAttrKey = mapped
		}
	}

	email := attributes[emailAttrKey]
	if email == "" {
		// Fallback to well-known SAML attribute URIs used by common IDPs.
		for _, candidate := range []string{
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
			"urn:oid:1.2.840.113549.1.9.1",
			"nameID",
		} {
			if v := attributes[candidate]; v != "" && strings.Contains(v, "@") {
				email = v
				break
			}
		}
	}
	if email == "" {
		return nil, fmt.Errorf("findOrCreateUser: email not found in SAML attributes")
	}

	// Try to find the user by email within the tenant.
	user, err := s.userRepo.GetByEmail(ctx, provider.TenantID, email)
	if err != nil {
		return nil, fmt.Errorf("findOrCreateUser: lookup user by email: %w", err)
	}
	if user != nil {
		return user, nil
	}

	// AutoProvisionUsers gates CREATION ONLY, and deliberately sits below the
	// lookup above. Turning it off does NOT stop SAML logins for accounts that
	// already exist -- an existing account is resolved by email at :1102 and
	// returned before this line is reached.
	//
	// That is the opposite of what an admin toggling "auto-provision users" off
	// would assume, so it is stated rather than left to be discovered. Moving the
	// gate above the lookup was considered and REJECTED: it would break the
	// legitimate enterprise pattern of pre-provisioning users (SCIM, or by an
	// admin) and then letting them sign in via SAML with JIT creation disabled.
	//
	// What an admin actually wants -- "no SAML assertion may reach an account
	// that was not deliberately linked to this provider" -- is NOT this flag and
	// does not exist yet. Resolution here is by EMAIL ALONE, with no check that
	// the account was ever associated with this IdP. See the linking proposal.
	if !provider.AutoProvisionUsers {
		return nil, fmt.Errorf("findOrCreateUser: user %q does not exist and auto-provisioning is disabled", email)
	}

	firstName := s.samlExtractAttr(provider, attributes, "first_name",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
		"urn:oid:2.5.4.42",
		"given_name",
	)
	lastName := s.samlExtractAttr(provider, attributes, "last_name",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
		"urn:oid:2.5.4.4",
		"family_name",
	)
	displayName := s.samlExtractAttr(provider, attributes, "display_name",
		"http://schemas.microsoft.com/identity/claims/displayname",
		"name",
	)

	username := strings.Split(email, "@")[0]
	now := time.Now()
	fedType := "saml"
	providerName := provider.Name
	nameID := attributes["nameID"]

	newUser := &models.User{
		TenantID: provider.TenantID,
		Username: username,
		Email:    email,
		IsActive: true,
		// NOT "trust the IdP's verified email claim" -- SAML has no such claim to
		// trust. A verified signature proves this assertion came FROM the
		// configured IdP; it says nothing about whether that IdP checked the
		// address. Treated as verified only where the tenant's admin has explicitly
		// said this IdP verifies addresses, and only when one was actually
		// asserted. Flows into the OIDC email_verified claim
		// (oauth_provider_service_tokens.go), so an assumption here is re-asserted
		// to every downstream relying party as fact.
		IsEmailVerified:  provider.SAMLSPConfig.TrustsAssertedEmail(email),
		FederationType:   &fedType,
		FederationID:     &nameID,
		FederationSource: &providerName,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if firstName != "" {
		newUser.FirstName = &firstName
	}
	if lastName != "" {
		newUser.LastName = &lastName
	}
	if displayName != "" {
		newUser.DisplayName = &displayName
	}

	if err := s.userRepo.Create(ctx, newUser); err != nil {
		return nil, fmt.Errorf("findOrCreateUser: create user: %w", err)
	}

	// Assign default roles (provider-level first, then tenant-level defaults).
	s.assignDefaultRolesToUser(ctx, newUser.ID, provider)

	// Create the federated account link record.
	providerEmail := email
	fedAccount := &models.FederatedAccount{
		UserID:         newUser.ID,
		ProviderID:     provider.ID,
		ProviderUserID: nameID,
		ProviderEmail:  &providerEmail,
		FirstLinkedAt:  now,
		LastUsedAt:     &now,
	}
	if createErr := s.fedAccountRepo.Create(ctx, fedAccount); createErr != nil {
		logger.Error("SAMLSPService: failed to create federated account link",
			zap.String("user_id", newUser.ID.String()),
			zap.Error(createErr),
		)
	}

	logger.Info("SAMLSPService: auto-provisioned user via SAML",
		zap.String("user_id", newUser.ID.String()),
		zap.String(authMethodEmail, email),
		zap.String("provider", provider.Name),
	)

	return newUser, nil
}

// ============================================================
// 5. SLO — Single Logout
// ============================================================

// SLO input validation limits.
const (
	sloMaxNameIDLength       = 512
	sloMaxSessionIndexLength = 255
	sloMaxIssuerLength       = 1024
	sloMaxSessionIndexCount  = 10
	sloMaxRequestAge         = 10 * time.Minute
	sloReplayTTL             = 10 * time.Minute
)

// allowedNameIDFormats is the set of SAML NameID formats accepted in LogoutRequests.
var allowedNameIDFormats = map[string]bool{
	"": true,
	"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress": true,
	"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent":   true,
	"urn:oasis:names:tc:SAML:2.0:nameid-format:transient":    true,
	"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified":  true,
	"urn:oasis:names:tc:SAML:2.0:nameid-format:entity":       true,
}

// ErrSLORedirectBindingUnsupported is retained so callers that still branch on
// it keep compiling. It is no longer returned: HTTP-Redirect is verified rather
// than refused (t-083 Part 2).
var ErrSLORedirectBindingUnsupported = errors.New("SAML HTTP-Redirect binding is not supported: its signature cannot be verified")

// HandleSLO processes an IDP-initiated Single Logout Request.
// It decodes the SAMLRequest, validates signature/replay/timing, finds matching
// sessions, terminates them, blacklists their tokens, and returns a LogoutResponse.
func (s *SAMLSPService) HandleSLO(ctx context.Context, tenantID uuid.UUID, samlRequest string, binding string, relayState string, rawQuery string) (*models.SLOResult, error) {
	logger.Info("SAMLSPService: received SLO request",
		zap.String("tenant_id", tenantID.String()),
		zap.String("binding", binding),
	)

	if samlRequest == "" {
		return nil, fmt.Errorf("HandleSLO: SAMLRequest is empty")
	}
	if s.sessionRepo == nil {
		return nil, fmt.Errorf("HandleSLO: session repository unavailable, cannot terminate sessions")
	}
	if s.replayStore == nil {
		return nil, fmt.Errorf("HandleSLO: replay store unavailable, cannot process LogoutRequest safely")
	}

	// The structural result is deliberately discarded: it proves only that a
	// Signature element was present and well-formed, which is what made this path
	// look protected while accepting forged LogoutRequests. Real verification
	// happens below, after the provider (and therefore the trust anchor) is known.
	rawXML, _, _, err := s.decodeSLORequest(tenantID, samlRequest, binding)
	if err != nil {
		return nil, err
	}

	var logoutReq models.SAMLLogoutRequest
	if err := xml.Unmarshal(rawXML, &logoutReq); err != nil {
		return nil, fmt.Errorf("HandleSLO: parse LogoutRequest XML: %w", err)
	}

	expectedSLOURL := fmt.Sprintf("%s/saml/sp/%s/slo", s.spBaseURL(), tenantID.String())
	if err := validateSLOLogoutRequest(&logoutReq, binding, expectedSLOURL); err != nil {
		return nil, err
	}

	provider, err := s.resolveProvider(ctx, tenantID, logoutReq.Issuer)
	if err != nil {
		return nil, fmt.Errorf("HandleSLO: %w", err)
	}

	// VERIFY BEFORE ACTING. Everything below this point terminates sessions, so
	// nothing above it may have side effects. Both bindings are verified against
	// the stored IdP certificate and neither is optional: SPWantSigned used to
	// gate whether a signature was even looked for and defaults to false, so it
	// can no longer weaken this path.
	if provider.SAMLSPConfig == nil || provider.SAMLSPConfig.IDPCertificate == "" {
		return nil, fmt.Errorf("HandleSLO: no IdP certificate configured for provider %s; refusing an unverifiable LogoutRequest", provider.ID)
	}
	sloCert, certErr := security.ValidateIDPCertificateForSAML(provider.SAMLSPConfig.IDPCertificate, "")
	if certErr != nil {
		return nil, fmt.Errorf("HandleSLO: IdP certificate validation failed: %w", certErr)
	}

	switch binding {
	case models.SAMLBindingHTTPRedirect:
		// Signature lives in the SigAlg/Signature QUERY PARAMETERS over an octet
		// string that must be rebuilt from the raw, still-encoded query.
		if err := security.VerifyRedirectSignature(rawQuery, "SAMLRequest", sloCert); err != nil {
			logger.Warn("SAMLSPService: SLO signature verification failed",
				zap.String("tenant_id", tenantID.String()),
				zap.String("binding", binding),
				zap.Error(err),
			)
			return nil, fmt.Errorf("HandleSLO: %w", err)
		}
	case models.SAMLBindingHTTPPOST:
		// Enveloped XML-DSig over the LogoutRequest root.
		if _, err := security.VerifySignedRootElement(rawXML, sloCert, "LogoutRequest"); err != nil {
			logger.Warn("SAMLSPService: SLO signature verification failed",
				zap.String("tenant_id", tenantID.String()),
				zap.String("binding", binding),
				zap.Error(err),
			)
			return nil, fmt.Errorf("HandleSLO: %w", err)
		}
	default:
		return nil, fmt.Errorf("HandleSLO: unsupported binding %q", binding)
	}

	clockSkew := clockSkewDefault
	if provider.SAMLSPConfig != nil && provider.SAMLSPConfig.ClockSkewSeconds > 0 {
		clockSkew = time.Duration(provider.SAMLSPConfig.ClockSkewSeconds) * time.Second
		if clockSkew > 10*time.Minute {
			clockSkew = 10 * time.Minute
		}
	}

	if err := validateSLOTimestamps(&logoutReq, clockSkew); err != nil {
		return nil, err
	}

	replayKey := fmt.Sprintf("slo:%s:%s", provider.ID.String(), logoutReq.ID)
	isNew, err := s.replayStore.MarkAssertionConsumed(ctx, replayKey, sloReplayTTL)
	if err != nil {
		return nil, fmt.Errorf("HandleSLO: replay store error: %w", err)
	}
	if !isNew {
		return nil, fmt.Errorf("HandleSLO: LogoutRequest already processed (replay)")
	}

	logger.Debug("SAMLSPService: parsed SLO LogoutRequest",
		zap.String("tenant_id", tenantID.String()),
		zap.String("request_id", logoutReq.ID),
		zap.String("issuer", logoutReq.Issuer),
		zap.String("name_id_masked", maskPII(logoutReq.NameID.Value)),
		zap.Int("session_indexes", len(logoutReq.SessionIndex)),
	)

	uniqueSessions, err := s.lookupSLOSessions(ctx, tenantID, provider, logoutReq.NameID.Value, logoutReq.SessionIndex)
	if err != nil {
		return nil, err
	}

	sessionsTerminated := 0
	for _, session := range uniqueSessions {
		if err := s.terminateSession(ctx, session, "saml_slo"); err != nil {
			logger.Error("SAMLSPService: failed to terminate session during SLO",
				zap.String("session_id", session.ID.String()),
				zap.Error(err),
			)
			continue
		}
		sessionsTerminated++
	}

	logger.Info("SAMLSPService: SLO sessions terminated",
		zap.String("tenant_id", tenantID.String()),
		zap.String("provider_id", provider.ID.String()),
		zap.Int("sessions_terminated", sessionsTerminated),
		zap.Int("sessions_found", len(uniqueSessions)),
	)

	s.auditService.LogLogin(ctx, tenantID, nil, "", "", false,
		fmt.Sprintf("saml_slo: terminated=%d found=%d provider=%s request_id=%s",
			sessionsTerminated, len(uniqueSessions), provider.ID.String(), logoutReq.ID))

	responseXML, err := s.buildLogoutResponseXML(tenantID, provider, logoutReq.ID, sessionsTerminated, len(uniqueSessions))
	if err != nil {
		return nil, fmt.Errorf("HandleIdPSLO: %w", err)
	}

	return s.buildSLOResult(provider, responseXML, binding, relayState)
}

// decodeSLORequest decodes, sanitizes and performs structural signature validation on a SAMLRequest.
func (s *SAMLSPService) decodeSLORequest(tenantID uuid.UUID, samlRequest, binding string) ([]byte, *security.SAMLSignatureValidationResult, error, error) {
	rawXML, decErr := decodeSLOBinding(samlRequest, binding)
	if decErr != nil {
		return nil, nil, nil, decErr
	}
	if err := security.SanitizeXMLInput(rawXML); err != nil {
		return nil, nil, nil, fmt.Errorf("HandleSLO: XML sanitization failed: %w", err)
	}
	sigResult, sigErr := security.ValidateSAMLResponseSignatureStructure(rawXML)
	if sigErr != nil {
		logger.Warn("SAMLSPService: SLO LogoutRequest signature structure validation failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(sigErr),
		)
	}
	return rawXML, sigResult, sigErr, nil
}

// decodeSLOBinding decodes a SAMLRequest based on the binding type (POST or Redirect).
func decodeSLOBinding(samlRequest, binding string) ([]byte, error) {
	if binding == models.SAMLBindingHTTPPOST {
		const sloMaxBase64Length = 1 << 20
		if len(samlRequest) > sloMaxBase64Length {
			return nil, fmt.Errorf("HandleSLO: SAMLRequest exceeds maximum size (%d bytes)", len(samlRequest))
		}
		decoded, err := base64.StdEncoding.DecodeString(samlRequest)
		if err != nil {
			return nil, fmt.Errorf("HandleSLO: decode POST SAMLRequest: %w", err)
		}
		return decoded, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(samlRequest)
		if err != nil {
			return nil, fmt.Errorf("HandleSLO: decode Redirect SAMLRequest: %w", err)
		}
	}
	inflated, err := samlDeflateDecompress(decoded)
	if err != nil {
		return nil, fmt.Errorf("HandleSLO: decompress SAMLRequest: %w", err)
	}
	return inflated, nil
}

// validateSLOLogoutRequest validates protocol fields in the LogoutRequest.
func validateSLOLogoutRequest(logoutReq *models.SAMLLogoutRequest, binding, expectedSLOURL string) error {
	if logoutReq.Version != "2.0" {
		return fmt.Errorf("HandleSLO: unsupported SAML version")
	}
	if logoutReq.ID == "" {
		return fmt.Errorf("HandleSLO: LogoutRequest ID is empty")
	}
	if logoutReq.Issuer == "" {
		return fmt.Errorf("HandleSLO: Issuer is empty")
	}
	if len(logoutReq.Issuer) > sloMaxIssuerLength {
		return fmt.Errorf("HandleSLO: Issuer exceeds maximum length")
	}
	if logoutReq.NameID.Value == "" {
		return fmt.Errorf("HandleSLO: NameID value is empty")
	}
	if len(logoutReq.NameID.Value) > sloMaxNameIDLength {
		return fmt.Errorf("HandleSLO: NameID value exceeds maximum length")
	}
	if !allowedNameIDFormats[logoutReq.NameID.Format] {
		return fmt.Errorf("HandleSLO: unsupported NameID Format")
	}
	if len(logoutReq.SessionIndex) > sloMaxSessionIndexCount {
		return fmt.Errorf("HandleSLO: too many SessionIndex elements (%d)", len(logoutReq.SessionIndex))
	}
	for _, idx := range logoutReq.SessionIndex {
		if len(idx) > sloMaxSessionIndexLength {
			return fmt.Errorf("HandleSLO: SessionIndex exceeds maximum length")
		}
	}
	if logoutReq.IssueInstant == "" {
		return fmt.Errorf("HandleSLO: IssueInstant is required")
	}
	if binding == models.SAMLBindingHTTPPOST && logoutReq.Destination == "" {
		return fmt.Errorf("HandleSLO: Destination is required for HTTP-POST binding")
	}
	if logoutReq.Destination != "" && logoutReq.Destination != expectedSLOURL {
		return fmt.Errorf("HandleSLO: Destination mismatch")
	}
	return nil
}

// validateSLOTimestamps validates IssueInstant and NotOnOrAfter fields of a LogoutRequest.
func validateSLOTimestamps(logoutReq *models.SAMLLogoutRequest, clockSkew time.Duration) error {
	issueTime, err := time.Parse(time.RFC3339, logoutReq.IssueInstant)
	if err != nil {
		issueTime, err = time.Parse("2006-01-02T15:04:05.999Z07:00", logoutReq.IssueInstant)
		if err != nil {
			return fmt.Errorf("HandleSLO: invalid IssueInstant format")
		}
	}
	now := time.Now().UTC()
	if now.Add(clockSkew).Before(issueTime) {
		return fmt.Errorf("HandleSLO: LogoutRequest IssueInstant is in the future")
	}
	if now.Sub(issueTime) > sloMaxRequestAge+clockSkew {
		return fmt.Errorf("HandleSLO: LogoutRequest is too old")
	}
	if logoutReq.NotOnOrAfter == "" {
		return nil
	}
	notOnOrAfter, notErr := time.Parse(time.RFC3339, logoutReq.NotOnOrAfter)
	if notErr != nil {
		notOnOrAfter, notErr = time.Parse("2006-01-02T15:04:05.999Z07:00", logoutReq.NotOnOrAfter)
	}
	if notErr != nil {
		return fmt.Errorf("HandleSLO: invalid NotOnOrAfter format")
	}
	if now.After(notOnOrAfter.Add(clockSkew)) {
		return fmt.Errorf("HandleSLO: LogoutRequest has expired (NotOnOrAfter)")
	}
	return nil
}

// lookupSLOSessions retrieves and deduplicates sessions matching the logout request.
func (s *SAMLSPService) lookupSLOSessions(ctx context.Context, tenantID uuid.UUID, provider *models.IdentityProvider, nameID string, sessionIndexes []string) ([]models.Session, error) {
	allSessions, err := s.fetchSLOSessions(ctx, tenantID, provider, nameID, sessionIndexes)
	if err != nil {
		return nil, err
	}
	seen := make(map[uuid.UUID]struct{})
	var uniqueSessions []models.Session
	for _, session := range allSessions {
		if _, exists := seen[session.ID]; !exists {
			seen[session.ID] = struct{}{}
			uniqueSessions = append(uniqueSessions, session)
		}
	}
	return uniqueSessions, nil
}

// fetchSLOSessions retrieves all sessions for a SAML SLO request, either by session indexes or by nameID alone.
func (s *SAMLSPService) fetchSLOSessions(ctx context.Context, tenantID uuid.UUID, provider *models.IdentityProvider, nameID string, sessionIndexes []string) ([]models.Session, error) {
	if len(sessionIndexes) == 0 {
		sessions, err := s.sessionRepo.GetBySAMLMetadata(ctx, provider.ID, nameID, nil)
		if err != nil {
			return nil, fmt.Errorf("HandleSLO: failed to look up SAML sessions: %w", err)
		}
		return sessions, nil
	}
	var allSessions []models.Session
	var lookupErrors int
	for _, idx := range sessionIndexes {
		if idx == "" {
			continue
		}
		idxCopy := idx
		sessions, lookupErr := s.sessionRepo.GetBySAMLMetadata(ctx, provider.ID, nameID, &idxCopy)
		if lookupErr != nil {
			logger.Error("SAMLSPService: failed to look up SAML sessions for SLO",
				zap.String("tenant_id", tenantID.String()),
				zap.Error(lookupErr),
			)
			lookupErrors++
			continue
		}
		allSessions = append(allSessions, sessions...)
	}
	if lookupErrors > 0 && len(allSessions) == 0 {
		return nil, fmt.Errorf("HandleSLO: all session lookups failed (%d errors)", lookupErrors)
	}
	return allSessions, nil
}

// buildSLOResult constructs the SLOResult with proper binding and redirect URL.
func (s *SAMLSPService) buildSLOResult(provider *models.IdentityProvider, responseXML, binding, relayState string) (*models.SLOResult, error) {
	sloResponseURL := ""
	if provider.SAMLSPConfig != nil {
		sloResponseURL = provider.SAMLSPConfig.IDPSLOURL
	}
	if sloResponseURL == "" {
		return &models.SLOResult{ResponseXML: responseXML, Binding: models.SAMLBindingHTTPPOST}, nil
	}
	responseBinding := binding
	if provider.SAMLSPConfig != nil && provider.SAMLSPConfig.SLOBinding != "" {
		responseBinding = provider.SAMLSPConfig.SLOBinding
	}
	if responseBinding == models.SAMLBindingHTTPPOST {
		return &models.SLOResult{
			ResponseXML: responseXML,
			RedirectURL: sloResponseURL,
			RelayState:  relayState,
			Binding:     models.SAMLBindingHTTPPOST,
		}, nil
	}
	deflated, err := samlDeflateCompress([]byte(responseXML))
	if err != nil {
		return nil, fmt.Errorf("HandleSLO: compress LogoutResponse: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(deflated)
	params := url.Values{}
	params.Set("SAMLResponse", encoded)
	if relayState != "" {
		params.Set("RelayState", relayState)
	}
	redirectURL := sloResponseURL
	if strings.Contains(redirectURL, "?") {
		redirectURL += "&" + params.Encode()
	} else {
		redirectURL += "?" + params.Encode()
	}
	return &models.SLOResult{
		RedirectURL: redirectURL,
		RelayState:  relayState,
		Binding:     models.SAMLBindingHTTPRedirect,
	}, nil
}

// terminateSession blacklists the session token first (to immediately invalidate
// JWTs), then marks the session as ended in the database.
// SECURITY: If blacklisting fails, we do NOT proceed with the DB update to avoid
// an inconsistent state where the DB shows "ended" but the JWT remains valid.
func (s *SAMLSPService) terminateSession(ctx context.Context, session models.Session, reason string) error {
	// Blacklist FIRST so existing JWTs are rejected immediately.
	if s.tokenBlacklist != nil {
		ttl := time.Until(session.ExpiresAt)
		if ttl <= 0 {
			ttl = 1 * time.Hour // Short fallback for already-expired sessions.
		}
		if blErr := s.tokenBlacklist.BlacklistSession(ctx, session.ID, reason, ttl); blErr != nil {
			return fmt.Errorf("blacklist session %s failed (tokens remain valid): %w", session.ID.String(), blErr)
		}
	} else {
		return fmt.Errorf("blacklist session %s failed: token blacklist not configured", session.ID.String())
	}

	// Then mark session inactive in DB.
	if err := s.sessionRepo.EndSession(ctx, session.ID, reason); err != nil {
		return fmt.Errorf("end session %s: %w", session.ID.String(), err)
	}
	return nil
}

// maskPII masks personally identifiable information for safe logging.
func maskPII(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}

// buildLogoutResponseXML generates a SAML 2.0 LogoutResponse XML document.
// Per SAML Core 3.7.3.2, the response includes PartialLogout sub-status when
// some (but not all) sessions were terminated.
func (s *SAMLSPService) buildLogoutResponseXML(tenantID uuid.UUID, provider *models.IdentityProvider, inResponseTo string, sessionsTerminated, totalFound int) (string, error) {
	baseURL := s.spBaseURL()
	entityID := fmt.Sprintf("%s/saml/sp/%s/metadata", baseURL, tenantID.String())
	if provider.SAMLSPConfig != nil && provider.SAMLSPConfig.SPEntityID != "" {
		entityID = provider.SAMLSPConfig.SPEntityID
	}

	// Only include Destination attribute when a SLO URL is configured (avoid empty Destination="").
	destinationAttr := ""
	if provider.SAMLSPConfig != nil && provider.SAMLSPConfig.IDPSLOURL != "" {
		destinationAttr = fmt.Sprintf(` Destination="%s"`, xmlEscape(provider.SAMLSPConfig.IDPSLOURL))
	}

	// Determine SAML status codes based on termination results.
	statusValue := "urn:oasis:names:tc:SAML:2.0:status:Success"
	subStatusXML := ""
	if totalFound == 0 {
		// No sessions found for the NameID/SessionIndex — indicate requester error.
		statusValue = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	} else if sessionsTerminated < totalFound {
		statusValue = "urn:oasis:names:tc:SAML:2.0:status:Responder"
		if sessionsTerminated > 0 {
			// Partial success: some sessions terminated, some failed.
			subStatusXML = `<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:PartialLogout"/>`
		}
	}

	rid, err := generateSAMLID()
	if err != nil {
		return "", fmt.Errorf("buildLogoutResponseXML: failed to generate response ID: %w", err)
	}
	responseID := "_" + rid
	now := time.Now().UTC().Format(time.RFC3339)

	return fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8"?>`+
			`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`+
			` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`+
			` ID="%s"`+
			` Version="2.0"`+
			` IssueInstant="%s"`+
			`%s`+
			` InResponseTo="%s">`+
			`<saml:Issuer>%s</saml:Issuer>`+
			`<samlp:Status>`+
			`<samlp:StatusCode Value="%s">%s</samlp:StatusCode>`+
			`</samlp:Status>`+
			`</samlp:LogoutResponse>`,
		responseID,
		now,
		destinationAttr,
		xmlEscape(inResponseTo),
		xmlEscape(entityID),
		statusValue,
		subStatusXML,
	), nil
}

// InitiateSLO starts an SP-initiated Single Logout by building a LogoutRequest
// and returning a redirect URL to the IDP's SLO endpoint.
func (s *SAMLSPService) InitiateSLO(ctx context.Context, userID, tenantID, providerID uuid.UUID) (string, error) {
	provider, err := s.idpRepo.GetByID(ctx, providerID)
	if err != nil {
		return "", fmt.Errorf("InitiateSLO: get provider: %w", err)
	}
	if provider == nil {
		return "", fmt.Errorf("InitiateSLO: provider not found")
	}
	if provider.TenantID != tenantID {
		return "", fmt.Errorf("InitiateSLO: provider does not belong to tenant")
	}
	if !provider.IsEnabled {
		return "", fmt.Errorf("InitiateSLO: provider is disabled")
	}
	if provider.SAMLSPConfig == nil || provider.SAMLSPConfig.IDPSLOURL == "" {
		return "", fmt.Errorf("InitiateSLO: IdP SLO URL not configured")
	}

	// Find the user's active SAML session to extract NameID and SessionIndex.
	if s.sessionRepo == nil {
		return "", fmt.Errorf("InitiateSLO: session repository not available")
	}

	session, err := s.sessionRepo.GetSAMLSessionForUser(ctx, userID, providerID)
	if err != nil {
		return "", fmt.Errorf("InitiateSLO: lookup SAML session: %w", err)
	}
	if session == nil {
		return "", fmt.Errorf("InitiateSLO: no active SAML session found for user")
	}

	// Build the LogoutRequest XML.
	baseURL := s.spBaseURL()
	entityID := fmt.Sprintf("%s/saml/sp/%s/metadata", baseURL, tenantID.String())
	if provider.SAMLSPConfig.SPEntityID != "" {
		entityID = provider.SAMLSPConfig.SPEntityID
	}

	rid, err := generateSAMLID()
	if err != nil {
		return "", fmt.Errorf("InitiateSLO: failed to generate request ID: %w", err)
	}
	requestID := "_" + rid
	now := time.Now().UTC().Format(time.RFC3339)

	nameID := ""
	if session.SAMLNameID != nil {
		nameID = *session.SAMLNameID
	}

	nameIDFormat := models.NameIDFormatEmailAddress
	if provider.SAMLSPConfig.NameIDFormat != "" {
		nameIDFormat = provider.SAMLSPConfig.NameIDFormat
	}

	sessionIndexXML := ""
	if session.SAMLSessionIndex != nil && *session.SAMLSessionIndex != "" {
		sessionIndexXML = fmt.Sprintf(`<samlp:SessionIndex>%s</samlp:SessionIndex>`, xmlEscape(*session.SAMLSessionIndex))
	}

	logoutRequestXML := fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8"?>`+
			`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`+
			` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`+
			` ID="%s"`+
			` Version="2.0"`+
			` IssueInstant="%s"`+
			` Destination="%s">`+
			`<saml:Issuer>%s</saml:Issuer>`+
			`<saml:NameID Format="%s">%s</saml:NameID>`+
			`%s`+
			`</samlp:LogoutRequest>`,
		requestID,
		now,
		xmlEscape(provider.SAMLSPConfig.IDPSLOURL),
		xmlEscape(entityID),
		xmlEscape(nameIDFormat),
		xmlEscape(nameID),
		sessionIndexXML,
	)

	// DEFLATE + base64 encode for HTTP-Redirect binding.
	deflated, err := samlDeflateCompress([]byte(logoutRequestXML))
	if err != nil {
		return "", fmt.Errorf("InitiateSLO: compress LogoutRequest: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(deflated)

	// Terminate ALL matching SAML sessions for this user/provider/NameID, not just one.
	// SECURITY: Do not redirect to the IDP until local sessions are confirmed terminated.
	allSessions, allErr := s.sessionRepo.GetBySAMLMetadata(ctx, providerID, nameID, nil)
	if allErr != nil {
		logger.Warn("SAMLSPService: SP-SLO could not fetch all sessions, terminating primary only",
			zap.Error(allErr),
		)
		allSessions = []models.Session{*session}
	}
	for _, sess := range allSessions {
		if err := s.terminateSession(ctx, sess, "sp_initiated_slo"); err != nil {
			return "", fmt.Errorf("InitiateSLO: failed to terminate local session %s: %w", sess.ID.String(), err)
		}
	}

	// Audit log for SP-initiated SLO.
	s.auditService.LogLogin(ctx, tenantID, &userID, "", "", false,
		fmt.Sprintf("sp_initiated_slo: sessions_terminated=%d provider=%s request_id=%s",
			len(allSessions), provider.ID.String(), requestID))

	// Build redirect URL.
	params := url.Values{}
	params.Set("SAMLRequest", encoded)

	sloURL := provider.SAMLSPConfig.IDPSLOURL
	if strings.Contains(sloURL, "?") {
		sloURL += "&" + params.Encode()
	} else {
		sloURL += "?" + params.Encode()
	}

	logger.Info("SAMLSPService: SP-initiated SLO initiated",
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("provider", provider.Name),
		zap.String("request_id", requestID),
	)

	return sloURL, nil
}

// ============================================================
// Internal helpers
// ============================================================

// resolveProvider finds the SAML provider for the tenant whose IDPEntityID matches
// the assertion issuer.  Returns an error when no matching provider is found.
func (s *SAMLSPService) resolveProvider(ctx context.Context, tenantID uuid.UUID, issuer string) (*models.IdentityProvider, error) {
	providers, err := s.idpRepo.GetByTenantAndType(ctx, tenantID, "saml")
	if err != nil {
		return nil, fmt.Errorf("resolveProvider: load SAML providers: %w", err)
	}

	for _, p := range providers {
		if p.SAMLSPConfig != nil && p.SAMLSPConfig.IDPEntityID == issuer {
			if !p.IsEnabled {
				return nil, fmt.Errorf("resolveProvider: SAML provider for issuer %q is disabled", issuer)
			}
			return p, nil
		}
	}

	return nil, fmt.Errorf("resolveProvider: no SAML provider found for issuer %q in tenant %s",
		issuer, tenantID.String())
}

// resolveBaseURL computes the base URL for SAML SP endpoints from config and
// environment variables.  It is called once at construction time.
// Precedence: config.SAMLSPBaseURL > SAML_SP_BASE_URL env > SAML_BASE_URL env > derived from service port.
func (s *SAMLSPService) resolveBaseURL() string {
	if s.config.SAMLSPBaseURL != "" {
		return s.config.SAMLSPBaseURL
	}
	if v := os.Getenv("SAML_SP_BASE_URL"); v != "" {
		return v
	}
	if v := os.Getenv("SAML_BASE_URL"); v != "" {
		return v
	}
	return fmt.Sprintf("http://localhost:%s", s.config.ServicePort)
}

// spBaseURL returns the cached base URL for SAML SP endpoints.
func (s *SAMLSPService) spBaseURL() string {
	return s.baseURL
}

// spSigningCertBase64 returns the base64-encoded DER bytes of the SP signing
// certificate read from the SAML_CERTIFICATE environment variable.
// resolveSigningCert reads the SAML signing certificate from the environment once
// at construction time, decodes PEM, and returns the base64 DER form.
func (s *SAMLSPService) resolveSigningCert() string {
	certPEM := os.Getenv("SAML_CERTIFICATE")
	if certPEM == "" {
		return ""
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

func (s *SAMLSPService) spSigningCertBase64() string {
	return s.signingCertBase64
}

// samlExtractAttributes flattens all AttributeStatement attributes into a single
// string map keyed by the SAML attribute Name.  Only the first value is kept.
func samlExtractAttributes(assertion *samlSPAssertionXML) map[string]string {
	out := make(map[string]string)
	for _, stmt := range assertion.AttrStmts {
		for _, attr := range stmt.Attributes {
			if attr.Name != "" && len(attr.Values) > 0 {
				out[attr.Name] = attr.Values[0].Value
			}
		}
	}
	return out
}

// samlExtractAttr resolves a user profile field from the SAML attribute map.
// It first checks the provider's configured attribute mapping, then tries each
// fallback attribute name in order.
func (s *SAMLSPService) samlExtractAttr(
	provider *models.IdentityProvider,
	attributes map[string]string,
	fieldName string,
	fallbacks ...string,
) string {
	if provider.SAMLSPConfig != nil {
		if mapped, ok := provider.SAMLSPConfig.AttributeMapping[fieldName]; ok && mapped != "" {
			if v := attributes[mapped]; v != "" {
				return v
			}
		}
	}
	if provider.AttributeMapping != nil {
		if mapped, ok := provider.AttributeMapping[fieldName]; ok && mapped != "" {
			if v := attributes[mapped]; v != "" {
				return v
			}
		}
	}
	for _, fb := range fallbacks {
		if v := attributes[fb]; v != "" {
			return v
		}
	}
	return ""
}

// writeSPAssertionLog persists a SAML SP assertion audit log entry.
func (s *SAMLSPService) writeSPAssertionLog(
	ctx context.Context,
	tenantID, providerID, userID uuid.UUID,
	assertion *samlSPAssertionXML,
	attributes map[string]string,
	ipAddress, userAgent, status string,
	errMsg *string,
) {
	assertionID := assertion.ID
	nameID := assertion.Subject.NameID.Value
	issuer := assertion.Issuer

	attrMap := make(map[string]interface{}, len(attributes))
	for k, v := range attributes {
		attrMap[k] = v
	}

	var sessionIdx *string
	if assertion.AuthnStmt != nil {
		idx := assertion.AuthnStmt.SessionIndex
		sessionIdx = &idx
	}

	logEntry := &models.SAMLSPAssertionLog{
		TenantID:     tenantID,
		ProviderID:   providerID,
		UserID:       &userID,
		AssertionID:  &assertionID,
		NameID:       &nameID,
		SessionIndex: sessionIdx,
		Issuer:       &issuer,
		IPAddress:    &ipAddress,
		UserAgent:    &userAgent,
		Status:       status,
		ErrorMessage: errMsg,
		Attributes:   attrMap,
	}
	if err := s.samlSPRepo.CreateAssertionLog(ctx, logEntry); err != nil {
		logger.Error("SAMLSPService: failed to write assertion log", zap.Error(err))
	}
}

// logSPAssertionFailure writes a failed assertion audit log entry without a user ID.
func (s *SAMLSPService) logSPAssertionFailure(
	ctx context.Context,
	tenantID, providerID uuid.UUID,
	assertion *samlSPAssertionXML,
	ipAddress, userAgent, reason string,
) {
	var assertionIDPtr, nameIDPtr, issuerPtr *string
	if assertion != nil {
		assertionIDPtr = &assertion.ID
		nameIDValue := assertion.Subject.NameID.Value
		nameIDPtr = &nameIDValue
		issuerPtr = &assertion.Issuer
	}

	logEntry := &models.SAMLSPAssertionLog{
		TenantID:     tenantID,
		ProviderID:   providerID,
		AssertionID:  assertionIDPtr,
		NameID:       nameIDPtr,
		Issuer:       issuerPtr,
		IPAddress:    &ipAddress,
		UserAgent:    &userAgent,
		Status:       "failed",
		ErrorMessage: &reason,
	}
	if err := s.samlSPRepo.CreateAssertionLog(ctx, logEntry); err != nil {
		logger.Error("SAMLSPService: failed to write assertion failure log", zap.Error(err))
	}
}

// strPtr returns a pointer to the given string.
func strPtr(s string) *string {
	return &s
}

// samlDeflateCompress compresses data with raw DEFLATE (RFC 1951) as required
// by the SAML HTTP-Redirect binding.
func samlDeflateCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("samlDeflateCompress: new writer: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("samlDeflateCompress: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("samlDeflateCompress: close: %w", err)
	}
	return buf.Bytes(), nil
}

// samlDeflateDecompress decompresses raw DEFLATE data.  A 1 MB size limit is
// enforced to prevent decompression-bomb attacks.
func samlDeflateDecompress(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()                       //nolint:errcheck
	limited := io.LimitReader(r, 1<<20+1) // 1 MB + 1 byte sentinel
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(limited); err != nil {
		return nil, fmt.Errorf("samlDeflateDecompress: %w", err)
	}
	if buf.Len() > 1<<20 {
		return nil, fmt.Errorf("samlDeflateDecompress: decompressed data exceeds 1 MB limit")
	}
	return buf.Bytes(), nil
}

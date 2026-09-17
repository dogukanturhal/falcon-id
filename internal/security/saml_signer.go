// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Signer is the interface for SAML XML-DSig signing operations.
type Signer interface {
	GenerateSignatureBlock(elementID string, canonicalContent []byte) (string, error)
}

// SAMLSigner signs SAML Assertion and Response XML documents using
// RSA-SHA256 with enveloped signatures. It uses Go's standard crypto
// library rather than goxmldsig for signing (output direction), since
// we control the XML generation and do not need to handle arbitrary
// input canonicalization.
type SAMLSigner struct {
	privateKey *rsa.PrivateKey
	certPEM    string // base64 DER (inner content without PEM headers)
}

// NewSAMLSigner creates a signer using the IDP's private key and PEM certificate.
func NewSAMLSigner(privateKey *rsa.PrivateKey, certPEM string) (*SAMLSigner, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	// Extract the base64 DER from the PEM certificate for embedding in KeyInfo.
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}
	certB64 := base64.StdEncoding.EncodeToString(block.Bytes)

	return &SAMLSigner{
		privateKey: privateKey,
		certPEM:    certB64,
	}, nil
}

// signatureTemplate returns the XML Signature block with a placeholder for
// the actual SignatureValue and DigestValue. The caller must replace these
// placeholders after computing the actual values.
const signatureTemplate = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
	`<ds:SignedInfo>` +
	`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
	`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
	`<ds:Reference URI="#%s">` +
	`<ds:Transforms>` +
	`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>` +
	`<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
	`</ds:Transforms>` +
	`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
	`<ds:DigestValue>%s</ds:DigestValue>` +
	`</ds:Reference>` +
	`</ds:SignedInfo>` +
	`<ds:SignatureValue>%s</ds:SignatureValue>` +
	`<ds:KeyInfo>` +
	`<ds:X509Data>` +
	`<ds:X509Certificate>%s</ds:X509Certificate>` +
	`</ds:X509Data>` +
	`</ds:KeyInfo>` +
	`</ds:Signature>`

// GenerateSignatureBlock creates a complete XML Signature block for the given
// element content. The content should be the canonical form of the element
// being signed (with the Signature placeholder removed).
//
// Returns the complete <ds:Signature> XML string ready for insertion.
func (s *SAMLSigner) GenerateSignatureBlock(elementID string, canonicalContent []byte) (string, error) {
	// Step 1: Compute DigestValue (SHA-256 of the canonical content).
	digestHash := sha256.Sum256(canonicalContent)
	digestB64 := base64.StdEncoding.EncodeToString(digestHash[:])

	// Step 2: Build SignedInfo with the real DigestValue.
	signedInfo := fmt.Sprintf(
		`<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`+
			`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
			`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>`+
			`<ds:Reference URI="#%s">`+
			`<ds:Transforms>`+
			`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>`+
			`<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
			`</ds:Transforms>`+
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
			`<ds:DigestValue>%s</ds:DigestValue>`+
			`</ds:Reference>`+
			`</ds:SignedInfo>`,
		elementID, digestB64,
	)

	// Step 3: Sign the SignedInfo with RSA-SHA256.
	signedInfoHash := sha256.Sum256([]byte(signedInfo))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, signedInfoHash[:])
	if err != nil {
		return "", fmt.Errorf("RSA sign: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// Step 4: Assemble the complete Signature block.
	return fmt.Sprintf(signatureTemplate, elementID, digestB64, sigB64, s.certPEM), nil
}

// GenerateAssertionID creates a new SAML-compliant assertion ID.
func GenerateAssertionID() string {
	return "_" + uuid.New().String()
}

// GenerateResponseID creates a new SAML-compliant response ID.
func GenerateResponseID() string {
	return "_" + uuid.New().String()
}

// FormatSAMLTime formats a time.Time in the SAML-required format (RFC3339 with milliseconds).
func FormatSAMLTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

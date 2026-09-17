// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// Rejected signature/digest algorithms.
var rejectedAlgorithms = map[string]bool{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":         true,
	"http://www.w3.org/2000/09/xmldsig#dsa-sha1":         true,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-md5":     true,
	"http://www.w3.org/2000/09/xmldsig#hmac-sha1":        true, // key confusion
	"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256": true, // key confusion
	"http://www.w3.org/2001/04/xmldsig-more#hmac-sha384": true,
	"http://www.w3.org/2001/04/xmldsig-more#hmac-sha512": true,
}

// Allowed digest algorithms (SHA-256+).
var allowedDigestAlgorithms = map[string]bool{
	"http://www.w3.org/2001/04/xmlenc#sha256":       true,
	"http://www.w3.org/2001/04/xmldsig-more#sha384": true,
	"http://www.w3.org/2001/04/xmlenc#sha512":       true,
}

// Allowed signature algorithms (SHA-256+).
var allowedSignatureAlgorithms = map[string]bool{
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   true,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   true,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   true,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": true,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": true,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": true,
}

// Minimal XML structs for extracting signature metadata from a SAML Response.
// These are used for algorithm checking and structural validation only.

type xmlSignedInfo struct {
	SignatureMethod xmlAlgorithm   `xml:"SignatureMethod"`
	References      []xmlReference `xml:"Reference"`
}

type xmlAlgorithm struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type xmlReference struct {
	URI          string       `xml:"URI,attr"`
	DigestMethod xmlAlgorithm `xml:"DigestMethod"`
}

type xmlSignature struct {
	XMLName    xml.Name      `xml:"Signature"`
	SignedInfo xmlSignedInfo `xml:"SignedInfo"`
}

// xmlResponseForSigCheck is a minimal struct used only to locate Signature
// elements within a SAML Response. Does not parse the full assertion.
type xmlResponseForSigCheck struct {
	XMLName    xml.Name       `xml:"Response"`
	ID         string         `xml:"ID,attr"`
	Signature  *xmlSignature  `xml:"Signature"`
	Assertions []xmlAssertion `xml:"Assertion"`
}

type xmlAssertion struct {
	ID        string        `xml:"ID,attr"`
	Signature *xmlSignature `xml:"Signature"`
}

// SAMLSignatureValidationResult captures the outcome of STRUCTURAL signature
// checks only. Nothing in this struct means a signature verified.
//
// These fields were previously documented as "has a valid signature", which is
// how the total absence of cryptographic verification survived review: a caller
// reading ResponseSigned==true reasonably concluded the signature had been
// checked against a key. It never was. Cryptographic verification lives in
// VerifySAMLResponseSignature (saml_signature_verify.go); trust only that.
type SAMLSignatureValidationResult struct {
	// ResponseSignaturePresent is true if the Response element carries a
	// Signature whose declared algorithms are allow-listed and whose Reference
	// URI matches the Response ID. It says nothing about whether that signature
	// verifies against any key.
	ResponseSignaturePresent bool
	// AssertionSignaturePresent is the same statement about the Assertion
	// element: present and well-formed, NOT verified.
	AssertionSignaturePresent bool
	// SignatureAlgorithm is the algorithm DECLARED by the signature that passed
	// the allow-list. Reported for audit; it is not evidence of verification.
	SignatureAlgorithm string
	// SignedAssertionID is the ID attribute of the signed assertion.
	SignedAssertionID string
}

// ValidateSAMLResponseSignatureStructure performs structural and algorithmic
// validation of a SAML Response's signature elements. It checks:
//   - At least one Signature element exists (on Response or Assertion)
//   - Signature algorithms are not in the rejected list
//   - Signature algorithms are in the allowed list
//   - No more than one Assertion element exists (XSW basic protection)
//   - The Signature Reference URI matches the signed element's ID
//
// This does NOT perform cryptographic signature verification (that requires
// goxmldsig). It is a pre-check to reject obviously bad responses early.
func ValidateSAMLResponseSignatureStructure(rawXML []byte) (*SAMLSignatureValidationResult, error) {
	var resp xmlResponseForSigCheck
	if err := xml.Unmarshal(rawXML, &resp); err != nil {
		return nil, fmt.Errorf("parse SAML Response for signature check: %w", err)
	}

	result := &SAMLSignatureValidationResult{}

	// XSW basic protection: reject multiple assertions.
	if len(resp.Assertions) > 1 {
		return nil, fmt.Errorf("SAML Response contains %d Assertion elements; expected at most 1 (possible XSW attack)", len(resp.Assertions))
	}

	// Check Response-level signature.
	if resp.Signature != nil {
		if err := validateSignatureAlgorithms(resp.Signature); err != nil {
			return nil, fmt.Errorf("response signature: %w", err)
		}
		if err := validateReferenceURI(resp.Signature, resp.ID); err != nil {
			return nil, fmt.Errorf("response signature reference URI: %w", err)
		}
		result.ResponseSignaturePresent = true
		result.SignatureAlgorithm = resp.Signature.SignedInfo.SignatureMethod.Algorithm
	}

	// Check Assertion-level signature.
	if len(resp.Assertions) == 1 && resp.Assertions[0].Signature != nil {
		sig := resp.Assertions[0].Signature
		if err := validateSignatureAlgorithms(sig); err != nil {
			return nil, fmt.Errorf("assertion signature: %w", err)
		}
		if err := validateReferenceURI(sig, resp.Assertions[0].ID); err != nil {
			return nil, fmt.Errorf("assertion signature reference URI: %w", err)
		}
		result.AssertionSignaturePresent = true
		result.SignedAssertionID = resp.Assertions[0].ID
		if result.SignatureAlgorithm == "" {
			result.SignatureAlgorithm = sig.SignedInfo.SignatureMethod.Algorithm
		}
	}

	if !result.ResponseSignaturePresent && !result.AssertionSignaturePresent {
		return nil, fmt.Errorf("SAML Response has no signature on either Response or Assertion element")
	}

	return result, nil
}

// validateSignatureAlgorithms checks the SignatureMethod and DigestMethod
// against the allowed/rejected lists.
func validateSignatureAlgorithms(sig *xmlSignature) error {
	alg := sig.SignedInfo.SignatureMethod.Algorithm
	if rejectedAlgorithms[alg] {
		return fmt.Errorf("rejected signature algorithm: %s", alg)
	}
	if !allowedSignatureAlgorithms[alg] {
		return fmt.Errorf("unsupported signature algorithm: %s", alg)
	}

	for _, ref := range sig.SignedInfo.References {
		digestAlg := ref.DigestMethod.Algorithm
		if rejectedAlgorithms[digestAlg] {
			return fmt.Errorf("rejected digest algorithm: %s", digestAlg)
		}
		if !allowedDigestAlgorithms[digestAlg] {
			return fmt.Errorf("unsupported digest algorithm: %s", digestAlg)
		}
	}

	return nil
}

// validateReferenceURI checks that the Signature's Reference URI points to the
// expected element ID (either empty, or "#<id>").
func validateReferenceURI(sig *xmlSignature, expectedID string) error {
	for _, ref := range sig.SignedInfo.References {
		uri := ref.URI
		if uri == "" {
			// Empty URI means the entire document is signed — acceptable.
			continue
		}
		if !strings.HasPrefix(uri, "#") {
			return fmt.Errorf("reference URI %q does not start with '#'", uri)
		}
		refID := uri[1:]
		if refID != expectedID {
			return fmt.Errorf("reference URI points to %q but expected %q", refID, expectedID)
		}
	}
	return nil
}

// ValidateIDPCertificateForSAML is an exported identifier.
// ValidateIDPCertificateForSAML validates that the IDP certificate is usable for
// SAML signature verification: not expired, structurally valid, and optionally
// fingerprint-pinned.
func ValidateIDPCertificateForSAML(certPEM string, pinnedFingerprint string) (*x509.Certificate, error) {
	cert, err := ParsePEMOrDERCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse IdP certificate: %w", err)
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("IdP certificate not yet valid (NotBefore=%s)", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("IdP certificate expired (NotAfter=%s)", cert.NotAfter.Format(time.RFC3339))
	}

	if pinnedFingerprint != "" {
		fp := CertFingerprint(cert)
		if fp != pinnedFingerprint {
			return nil, fmt.Errorf("IdP certificate fingerprint mismatch: got %s, expected %s", fp, pinnedFingerprint)
		}
	}

	return cert, nil
}

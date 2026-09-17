// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ──────────────────────────────────────────────────────────────────

const (
	sigAlgRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	sigAlgRSASHA384   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	sigAlgRSASHA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	sigAlgECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"

	sigAlgRSASHA1    = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	sigAlgDSASHA1    = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
	sigAlgRSAMD5     = "http://www.w3.org/2001/04/xmldsig-more#rsa-md5"
	sigAlgHMACSHA1   = "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
	sigAlgHMACSHA256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"

	digestAlgSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	digestAlgSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	digestAlgSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
)

// buildSignature builds a minimal <Signature> XML block with explicit alg & digest.
func buildSignature(sigAlg, digestAlg, refURI string) string {
	return fmt.Sprintf(`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">`+
		`<SignedInfo>`+
		`<SignatureMethod Algorithm="%s"/>`+
		`<Reference URI="%s">`+
		`<DigestMethod Algorithm="%s"/>`+
		`<DigestValue>dummydigest</DigestValue>`+
		`</Reference>`+
		`</SignedInfo>`+
		`<SignatureValue>dummysig</SignatureValue>`+
		`</Signature>`,
		sigAlg, refURI, digestAlg)
}

// buildResponse builds a minimal SAML Response XML.  When responseSignature is
// non-empty it is embedded directly in the Response element.  When
// assertionSignature is non-empty it is embedded inside the single Assertion.
func buildResponse(responseID, assertionID, responseSignature, assertionSignature string) []byte { //nolint:unparam // responseID is always "resp1" currently but kept for flexibility
	assertionBody := ""
	if assertionID != "" {
		assertionBody = fmt.Sprintf(`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s">%s</Assertion>`,
			assertionID, assertionSignature)
	}
	return []byte(fmt.Sprintf(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="%s">%s%s</samlp:Response>`,
		responseID, responseSignature, assertionBody,
	))
}

// buildMultiAssertionResponse builds a response with two assertions (XSW).
func buildMultiAssertionResponse(responseID string) []byte {
	return []byte(fmt.Sprintf(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="%s">`+
			`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"></Assertion>`+
			`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a2"></Assertion>`+
			`</samlp:Response>`,
		responseID,
	))
}

// ── table-driven tests ────────────────────────────────────────────────────────

func TestValidateSAMLResponseSignatureStructure(t *testing.T) {
	type tc struct {
		name        string
		xml         []byte
		wantErr     bool
		errContains string
		// optional assertions on the result
		wantResponseSigned  bool
		wantAssertionSigned bool
		wantSigAlg          string
	}

	respSig := buildSignature(sigAlgRSASHA256, digestAlgSHA256, "#resp1")
	assertSig := buildSignature(sigAlgRSASHA256, digestAlgSHA256, "#assert1")

	tests := []tc{
		{
			name:               "ResponseSignedOnly",
			xml:                buildResponse("resp1", "", respSig, ""),
			wantErr:            false,
			wantResponseSigned: true,
			wantSigAlg:         sigAlgRSASHA256,
		},
		{
			name:                "AssertionSignedOnly",
			xml:                 buildResponse("resp1", "assert1", "", assertSig),
			wantErr:             false,
			wantAssertionSigned: true,
			wantSigAlg:          sigAlgRSASHA256,
		},
		{
			name:                "BothSigned",
			xml:                 buildResponse("resp1", "assert1", respSig, assertSig),
			wantErr:             false,
			wantResponseSigned:  true,
			wantAssertionSigned: true,
		},
		{
			name:        "NoSignatureAtAll",
			xml:         buildResponse("resp1", "assert1", "", ""),
			wantErr:     true,
			errContains: "no signature",
		},
		{
			name:        "MultipleAssertions_XSWAttack",
			xml:         buildMultiAssertionResponse("resp1"),
			wantErr:     true,
			errContains: "XSW",
		},
		{
			name:        "RejectsRSASHA1",
			xml:         buildResponse("resp1", "", buildSignature(sigAlgRSASHA1, digestAlgSHA256, "#resp1"), ""),
			wantErr:     true,
			errContains: "rejected",
		},
		{
			name:        "RejectsDSASHA1",
			xml:         buildResponse("resp1", "", buildSignature(sigAlgDSASHA1, digestAlgSHA256, "#resp1"), ""),
			wantErr:     true,
			errContains: "rejected",
		},
		{
			name:        "RejectsMD5",
			xml:         buildResponse("resp1", "", buildSignature(sigAlgRSAMD5, digestAlgSHA256, "#resp1"), ""),
			wantErr:     true,
			errContains: "rejected",
		},
		{
			name:        "RejectsHMACSHA1_KeyConfusion",
			xml:         buildResponse("resp1", "", buildSignature(sigAlgHMACSHA1, digestAlgSHA256, "#resp1"), ""),
			wantErr:     true,
			errContains: "rejected",
		},
		{
			name:        "RejectsHMACSHA256",
			xml:         buildResponse("resp1", "", buildSignature(sigAlgHMACSHA256, digestAlgSHA256, "#resp1"), ""),
			wantErr:     true,
			errContains: "rejected",
		},
		{
			name:               "AcceptsRSASHA256",
			xml:                buildResponse("resp1", "", buildSignature(sigAlgRSASHA256, digestAlgSHA256, "#resp1"), ""),
			wantErr:            false,
			wantResponseSigned: true,
		},
		{
			name:               "AcceptsRSASHA384",
			xml:                buildResponse("resp1", "", buildSignature(sigAlgRSASHA384, digestAlgSHA384, "#resp1"), ""),
			wantErr:            false,
			wantResponseSigned: true,
		},
		{
			name:               "AcceptsRSASHA512",
			xml:                buildResponse("resp1", "", buildSignature(sigAlgRSASHA512, digestAlgSHA512, "#resp1"), ""),
			wantErr:            false,
			wantResponseSigned: true,
		},
		{
			name:               "AcceptsECDSASHA256",
			xml:                buildResponse("resp1", "", buildSignature(sigAlgECDSASHA256, digestAlgSHA256, "#resp1"), ""),
			wantErr:            false,
			wantResponseSigned: true,
		},
		{
			name:        "RejectsUnknownAlgorithm",
			xml:         buildResponse("resp1", "", buildSignature("http://example.com/custom-alg", digestAlgSHA256, "#resp1"), ""),
			wantErr:     true,
			errContains: "unsupported",
		},
		{
			name:               "ReferenceURIMatchesID",
			xml:                buildResponse("resp1", "", buildSignature(sigAlgRSASHA256, digestAlgSHA256, "#resp1"), ""),
			wantErr:            false,
			wantResponseSigned: true,
		},
		{
			name:        "ReferenceURIMismatch",
			xml:         buildResponse("resp1", "", buildSignature(sigAlgRSASHA256, digestAlgSHA256, "#wrongID"), ""),
			wantErr:     true,
			errContains: "expected",
		},
		{
			name: "EmptyReferenceURIAccepted",
			// Empty URI means "whole document is signed" — must be accepted.
			xml:                buildResponse("resp1", "", buildSignature(sigAlgRSASHA256, digestAlgSHA256, ""), ""),
			wantErr:            false,
			wantResponseSigned: true,
		},
		{
			name:        "ParseError_MalformedXML",
			xml:         []byte(`<not valid xml`),
			wantErr:     true,
			errContains: "parse",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateSAMLResponseSignatureStructure(tt.xml)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, result)
			// These assert PRESENCE of a well-formed, allow-listed signature
			// element -- not that it verifies. Cryptographic verification is
			// covered by VerifySAMLResponseSignature, not by this function.
			if tt.wantResponseSigned {
				assert.True(t, result.ResponseSignaturePresent, "expected ResponseSignaturePresent=true")
			}
			if tt.wantAssertionSigned {
				assert.True(t, result.AssertionSignaturePresent, "expected AssertionSignaturePresent=true")
			}
			if tt.wantSigAlg != "" {
				assert.Equal(t, tt.wantSigAlg, result.SignatureAlgorithm)
			}
		})
	}
}

// ── edge cases for validateReferenceURI ──────────────────────────────────────

func TestValidateReferenceURI_NoHashPrefix(t *testing.T) {
	// A reference URI that doesn't start with "#" should be an error.
	xml := buildResponse(
		"resp1", "",
		buildSignature(sigAlgRSASHA256, digestAlgSHA256, "resp1"), // no '#'
		"",
	)
	_, err := ValidateSAMLResponseSignatureStructure(xml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "#")
}

// ── SignedAssertionID propagation ─────────────────────────────────────────────

func TestValidateSAMLResponseSignatureStructure_AssertionIDPropagated(t *testing.T) {
	assertSig := buildSignature(sigAlgRSASHA256, digestAlgSHA256, "#myAssertID")
	xml := buildResponse("resp1", "myAssertID", "", assertSig)
	result, err := ValidateSAMLResponseSignatureStructure(xml)
	require.NoError(t, err)
	assert.Equal(t, "myAssertID", result.SignedAssertionID)
}

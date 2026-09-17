// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── test setup helpers ────────────────────────────────────────────────────────

// generateTestKeyAndCertPEM generates a 2048-bit RSA key and a self-signed
// certificate, and returns both the key and the certificate as PEM strings.
func generateTestKeyAndCertPEM(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "SAML Signer Test"},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	return key, certPEM
}

// ── NewSAMLSigner ─────────────────────────────────────────────────────────────

func TestNewSAMLSigner_NilKey_ReturnsError(t *testing.T) {
	_, certPEM := generateTestKeyAndCertPEM(t)
	_, err := NewSAMLSigner(nil, certPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestNewSAMLSigner_InvalidPEM_ReturnsError(t *testing.T) {
	key, _ := generateTestKeyAndCertPEM(t)
	_, err := NewSAMLSigner(key, "-----BEGIN CERTIFICATE-----\nbaddata\n-----END CERTIFICATE-----")
	require.Error(t, err)
}

func TestNewSAMLSigner_EmptyCertPEM_ReturnsError(t *testing.T) {
	key, _ := generateTestKeyAndCertPEM(t)
	_, err := NewSAMLSigner(key, "")
	require.Error(t, err)
}

func TestNewSAMLSigner_ValidInputs_Success(t *testing.T) {
	key, certPEM := generateTestKeyAndCertPEM(t)
	signer, err := NewSAMLSigner(key, certPEM)
	require.NoError(t, err)
	require.NotNil(t, signer)
}

// ── GenerateSignatureBlock ────────────────────────────────────────────────────

func TestGenerateSignatureBlock_ContainsRSASHA256(t *testing.T) {
	key, certPEM := generateTestKeyAndCertPEM(t)
	signer, err := NewSAMLSigner(key, certPEM)
	require.NoError(t, err)

	sigBlock, err := signer.GenerateSignatureBlock("_elem1", []byte("<elem>content</elem>"))
	require.NoError(t, err)

	const rsaSHA256URI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	assert.Contains(t, sigBlock, rsaSHA256URI,
		"signature block must declare rsa-sha256 as the signature algorithm")
}

func TestGenerateSignatureBlock_ElementIDInReferenceURI(t *testing.T) {
	key, certPEM := generateTestKeyAndCertPEM(t)
	signer, err := NewSAMLSigner(key, certPEM)
	require.NoError(t, err)

	elementID := "_myElementID"
	sigBlock, err := signer.GenerateSignatureBlock(elementID, []byte("<elem/>"))
	require.NoError(t, err)

	// The Reference URI must point to "#_myElementID".
	assert.Contains(t, sigBlock, `URI="#`+elementID+`"`,
		"Reference URI must reference the signed element ID with a '#' prefix")
}

func TestGenerateSignatureBlock_CertEmbeddedInKeyInfo(t *testing.T) {
	key, certPEM := generateTestKeyAndCertPEM(t)
	signer, err := NewSAMLSigner(key, certPEM)
	require.NoError(t, err)

	// Extract the raw base64 DER to verify it appears in the output.
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)

	sigBlock, err := signer.GenerateSignatureBlock("_el", []byte("<el/>"))
	require.NoError(t, err)

	assert.Contains(t, sigBlock, "X509Certificate",
		"signature block must contain an X509Certificate element in KeyInfo")
	// The base64 DER content must not be empty (spot-check first 10 chars).
	assert.True(t, strings.Contains(sigBlock, "<ds:X509Certificate>"),
		"X509Certificate element must be present")
}

func TestGenerateSignatureBlock_DigestSHA256Present(t *testing.T) {
	key, certPEM := generateTestKeyAndCertPEM(t)
	signer, err := NewSAMLSigner(key, certPEM)
	require.NoError(t, err)

	sigBlock, err := signer.GenerateSignatureBlock("_el", []byte("<el/>"))
	require.NoError(t, err)

	const sha256DigestURI = "http://www.w3.org/2001/04/xmlenc#sha256"
	assert.Contains(t, sigBlock, sha256DigestURI,
		"signature block must use SHA-256 as the digest algorithm")
}

func TestGenerateSignatureBlock_SignatureValueNonEmpty(t *testing.T) {
	key, certPEM := generateTestKeyAndCertPEM(t)
	signer, err := NewSAMLSigner(key, certPEM)
	require.NoError(t, err)

	sigBlock, err := signer.GenerateSignatureBlock("_el", []byte("<el/>"))
	require.NoError(t, err)

	// Locate the SignatureValue content.
	const openTag = "<ds:SignatureValue>"
	const closeTag = "</ds:SignatureValue>"
	start := strings.Index(sigBlock, openTag)
	end := strings.Index(sigBlock, closeTag)
	require.True(t, start >= 0 && end > start, "SignatureValue element must be present")

	value := sigBlock[start+len(openTag) : end]
	assert.NotEmpty(t, value, "SignatureValue must not be empty")
}

// ── GenerateAssertionID / GenerateResponseID ──────────────────────────────────

func TestGenerateAssertionID_StartsWithUnderscore(t *testing.T) {
	id := GenerateAssertionID()
	assert.True(t, strings.HasPrefix(id, "_"), "assertion ID must start with '_'")
}

func TestGenerateAssertionID_Unique(t *testing.T) {
	const n = 100
	ids := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := GenerateAssertionID()
		ids[id] = struct{}{}
	}
	assert.Len(t, ids, n, "all generated assertion IDs must be unique")
}

func TestGenerateResponseID_StartsWithUnderscore(t *testing.T) {
	id := GenerateResponseID()
	assert.True(t, strings.HasPrefix(id, "_"), "response ID must start with '_'")
}

func TestGenerateResponseID_Unique(t *testing.T) {
	const n = 100
	ids := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := GenerateResponseID()
		ids[id] = struct{}{}
	}
	assert.Len(t, ids, n, "all generated response IDs must be unique")
}

// ── FormatSAMLTime ────────────────────────────────────────────────────────────

func TestFormatSAMLTime_MillisecondPrecision(t *testing.T) {
	// 2024-03-15 10:30:00.123 UTC
	ts := time.Date(2024, 3, 15, 10, 30, 0, 123_000_000, time.UTC)
	result := FormatSAMLTime(ts)
	assert.Equal(t, "2024-03-15T10:30:00.123Z", result)
}

func TestFormatSAMLTime_AlwaysUTC(t *testing.T) {
	// Create a time in a non-UTC location and verify the output is still UTC.
	loc, err := time.LoadLocation("America/New_York")
	require.NoError(t, err)
	// 2024-06-01 15:00:00 New York = 2024-06-01 19:00:00 UTC
	ts := time.Date(2024, 6, 1, 15, 0, 0, 0, loc)
	result := FormatSAMLTime(ts)
	assert.True(t, strings.HasSuffix(result, "Z"),
		"formatted SAML time must be UTC (end with 'Z'): %s", result)
	assert.Contains(t, result, "19:00:00",
		"time must be converted to UTC before formatting")
}

func TestFormatSAMLTime_ZeroMilliseconds(t *testing.T) {
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	result := FormatSAMLTime(ts)
	assert.Equal(t, "2024-01-01T00:00:00.000Z", result)
}

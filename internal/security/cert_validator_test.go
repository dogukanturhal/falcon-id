// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── test certificate generator ────────────────────────────────────────────────

// generateTestCert creates a self-signed RSA certificate valid in the window
// [notBefore, notAfter] and returns the PEM string and the parsed *x509.Certificate.
func generateTestCert(t *testing.T, notBefore, notAfter time.Time) (certPEM string, cert *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generate RSA key")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err, "create certificate")

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certPEM = string(pemBlock)

	cert, err = x509.ParseCertificate(derBytes)
	require.NoError(t, err, "parse certificate")

	return certPEM, cert
}

// ── ValidateIDPCertificateForSAML ────────────────────────────────────────────

func TestValidateIDPCertificateForSAML_ValidCert(t *testing.T) {
	now := time.Now()
	certPEM, _ := generateTestCert(t, now.Add(-1*time.Hour), now.Add(24*time.Hour))

	got, err := ValidateIDPCertificateForSAML(certPEM, "")
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestValidateIDPCertificateForSAML_ExpiredCert(t *testing.T) {
	past := time.Now().Add(-48 * time.Hour)
	certPEM, _ := generateTestCert(t, past.Add(-1*time.Hour), past)

	_, err := ValidateIDPCertificateForSAML(certPEM, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestValidateIDPCertificateForSAML_NotYetValidCert(t *testing.T) {
	future := time.Now().Add(48 * time.Hour)
	certPEM, _ := generateTestCert(t, future, future.Add(24*time.Hour))

	_, err := ValidateIDPCertificateForSAML(certPEM, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet valid")
}

func TestValidateIDPCertificateForSAML_CorrectFingerprintPin(t *testing.T) {
	now := time.Now()
	certPEM, cert := generateTestCert(t, now.Add(-1*time.Hour), now.Add(24*time.Hour))
	fp := CertFingerprint(cert)

	got, err := ValidateIDPCertificateForSAML(certPEM, fp)
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestValidateIDPCertificateForSAML_WrongFingerprintPin(t *testing.T) {
	now := time.Now()
	certPEM, _ := generateTestCert(t, now.Add(-1*time.Hour), now.Add(24*time.Hour))
	wrongPin := "0000000000000000000000000000000000000000000000000000000000000000"

	_, err := ValidateIDPCertificateForSAML(certPEM, wrongPin)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fingerprint mismatch")
}

func TestValidateIDPCertificateForSAML_EmptyFingerprintSkipsCheck(t *testing.T) {
	now := time.Now()
	certPEM, _ := generateTestCert(t, now.Add(-1*time.Hour), now.Add(24*time.Hour))

	// Empty pinnedFingerprint → no fingerprint check → must succeed.
	got, err := ValidateIDPCertificateForSAML(certPEM, "")
	require.NoError(t, err)
	require.NotNil(t, got)
}

// ── ParsePEMOrDERCertificate ──────────────────────────────────────────────────

func TestParsePEMOrDERCertificate_ValidPEM(t *testing.T) {
	now := time.Now()
	certPEM, _ := generateTestCert(t, now.Add(-1*time.Hour), now.Add(24*time.Hour))

	cert, err := ParsePEMOrDERCertificate(certPEM)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestParsePEMOrDERCertificate_ValidBase64DER(t *testing.T) {
	now := time.Now()
	certPEM, _ := generateTestCert(t, now.Add(-1*time.Hour), now.Add(24*time.Hour))

	// Extract the DER bytes from the PEM and base64-encode them.
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	b64DER := base64.StdEncoding.EncodeToString(block.Bytes)

	cert, err := ParsePEMOrDERCertificate(b64DER)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestParsePEMOrDERCertificate_EmptyInput(t *testing.T) {
	_, err := ParsePEMOrDERCertificate("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestParsePEMOrDERCertificate_WhitespaceOnlyInput(t *testing.T) {
	_, err := ParsePEMOrDERCertificate("   \n\t  ")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestParsePEMOrDERCertificate_InvalidPEM(t *testing.T) {
	// A string that looks like PEM headers but has garbage content.
	_, err := ParsePEMOrDERCertificate("-----BEGIN CERTIFICATE-----\nnotbase64!!!\n-----END CERTIFICATE-----")
	require.Error(t, err)
}

func TestParsePEMOrDERCertificate_InvalidBase64(t *testing.T) {
	// Not a PEM header, not valid base64 either.
	_, err := ParsePEMOrDERCertificate("this is not base64 @@@!!!")
	require.Error(t, err)
}

// ── CertFingerprint ────────────────────────────────────────────────────────────

func TestCertFingerprint_HexEncodedSHA256(t *testing.T) {
	now := time.Now()
	_, cert := generateTestCert(t, now.Add(-1*time.Hour), now.Add(24*time.Hour))

	fp := CertFingerprint(cert)

	// Must be a lower-case hex string of length 64 (32 bytes × 2 hex chars).
	assert.Len(t, fp, 64, "SHA-256 fingerprint must be 64 hex characters")
	_, err := hex.DecodeString(fp)
	assert.NoError(t, err, "fingerprint must be valid hex")

	// Cross-check against manual SHA-256.
	expected := sha256.Sum256(cert.Raw)
	assert.Equal(t, hex.EncodeToString(expected[:]), fp)
}

func TestCertFingerprint_Deterministic(t *testing.T) {
	now := time.Now()
	_, cert := generateTestCert(t, now.Add(-1*time.Hour), now.Add(24*time.Hour))

	fp1 := CertFingerprint(cert)
	fp2 := CertFingerprint(cert)
	assert.Equal(t, fp1, fp2, "fingerprint must be deterministic for the same certificate")
}

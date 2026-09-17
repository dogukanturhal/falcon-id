// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// generateTestCert builds a self-signed leaf cert with the supplied
// Subject DN for use in cert-verification tests. Returns the
// certificate + its PEM-encoded form (the same shape APISIX would
// forward in X-Forwarded-Client-Cert).
func generateTestCert(t *testing.T, subjectCN string, subjectO string) (*x509.Certificate, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   subjectCN,
			Organization: []string{subjectO},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return cert, string(pemBlock)
}

func TestParseClientCertFromHeader_BarePEM(t *testing.T) {
	_, pemStr := generateTestCert(t, "client-001", "Example Corp")
	cert, err := ParseClientCertFromHeader(pemStr)
	if err != nil {
		t.Fatalf("ParseClientCertFromHeader (bare PEM): %v", err)
	}
	if cert.Subject.CommonName != "client-001" {
		t.Errorf("CN = %q, want client-001", cert.Subject.CommonName)
	}
}

func TestParseClientCertFromHeader_URLEncoded(t *testing.T) {
	// APISIX URL-encodes the PEM block before placing it in the header
	// value — newlines become %0A. The parser must transparently
	// reverse this encoding.
	_, pemStr := generateTestCert(t, "apisix-client", "APISIX Org")
	encoded := url.QueryEscape(pemStr)
	cert, err := ParseClientCertFromHeader(encoded)
	if err != nil {
		t.Fatalf("ParseClientCertFromHeader (URL-encoded): %v", err)
	}
	if cert.Subject.CommonName != "apisix-client" {
		t.Errorf("CN = %q, want apisix-client", cert.Subject.CommonName)
	}
}

func TestParseClientCertFromHeader_EmptyReturnsMissingError(t *testing.T) {
	if _, err := ParseClientCertFromHeader(""); !errors.Is(err, ErrTLSCertHeaderMissing) {
		t.Errorf("empty header: got %v, want ErrTLSCertHeaderMissing", err)
	}
	if _, err := ParseClientCertFromHeader("   "); !errors.Is(err, ErrTLSCertHeaderMissing) {
		t.Errorf("whitespace header: got %v, want ErrTLSCertHeaderMissing", err)
	}
}

func TestParseClientCertFromHeader_MalformedReturnsParseError(t *testing.T) {
	if _, err := ParseClientCertFromHeader("not pem"); !errors.Is(err, ErrTLSCertParseFailed) {
		t.Errorf("non-PEM: got %v, want ErrTLSCertParseFailed", err)
	}
	// Wrong PEM block type
	wrongType := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})
	if _, err := ParseClientCertFromHeader(string(wrongType)); !errors.Is(err, ErrTLSCertParseFailed) {
		t.Errorf("wrong PEM type: got %v, want ErrTLSCertParseFailed", err)
	}
}

func TestVerifyTLSClientAuth_HappyPath(t *testing.T) {
	cert, _ := generateTestCert(t, "happy-client", "ACME")
	expectedDN := cert.Subject.String()
	client := &models.OAuthClient{
		TLSClientAuthSubjectDN: &expectedDN,
	}
	if err := VerifyTLSClientAuth(client, cert); err != nil {
		t.Errorf("VerifyTLSClientAuth: unexpected error %v", err)
	}
}

func TestVerifyTLSClientAuth_SubjectDNMismatch(t *testing.T) {
	cert, _ := generateTestCert(t, "real-client", "ACME")
	wrong := "CN=different-client,O=ACME"
	client := &models.OAuthClient{
		TLSClientAuthSubjectDN: &wrong,
	}
	err := VerifyTLSClientAuth(client, cert)
	if !errors.Is(err, ErrTLSCertSubjectDNMismatch) {
		t.Errorf("got %v, want ErrTLSCertSubjectDNMismatch", err)
	}
}

func TestVerifyTLSClientAuth_NotConfiguredWhenSubjectDNNil(t *testing.T) {
	cert, _ := generateTestCert(t, "any", "X")
	client := &models.OAuthClient{TLSClientAuthSubjectDN: nil}
	if err := VerifyTLSClientAuth(client, cert); !errors.Is(err, ErrTLSClientAuthNotConfigured) {
		t.Errorf("got %v, want ErrTLSClientAuthNotConfigured", err)
	}
	// Empty string treated the same as nil — empty DN is not a valid
	// authentication ground truth.
	empty := ""
	client2 := &models.OAuthClient{TLSClientAuthSubjectDN: &empty}
	if err := VerifyTLSClientAuth(client2, cert); !errors.Is(err, ErrTLSClientAuthNotConfigured) {
		t.Errorf("empty DN: got %v, want ErrTLSClientAuthNotConfigured", err)
	}
}

func TestVerifyTLSClientAuth_NilCertReturnsMissingError(t *testing.T) {
	dn := "CN=x"
	client := &models.OAuthClient{TLSClientAuthSubjectDN: &dn}
	if err := VerifyTLSClientAuth(client, nil); !errors.Is(err, ErrTLSCertHeaderMissing) {
		t.Errorf("nil cert: got %v, want ErrTLSCertHeaderMissing", err)
	}
}

func TestCertificateThumbprintS256(t *testing.T) {
	cert, _ := generateTestCert(t, "fp-client", "Org")
	tp := CertificateThumbprintS256(cert)
	// Base64url-no-padding of a SHA-256 digest is always 43 chars.
	if len(tp) != 43 {
		t.Errorf("thumbprint length = %d, want 43", len(tp))
	}
	// Re-deriving from the same cert is stable.
	if again := CertificateThumbprintS256(cert); again != tp {
		t.Errorf("thumbprint not deterministic: %q vs %q", tp, again)
	}
	// Different cert → different thumbprint.
	cert2, _ := generateTestCert(t, "other-client", "Org")
	if other := CertificateThumbprintS256(cert2); other == tp {
		t.Error("different certs produced same thumbprint")
	}
	// Nil cert → empty (defensive).
	if got := CertificateThumbprintS256(nil); got != "" {
		t.Errorf("nil cert thumbprint = %q, want empty", got)
	}
	// Confirm the output is base64url with no padding (RFC 4648 §5).
	if strings.ContainsAny(tp, "+/=") {
		t.Errorf("thumbprint %q contains non-base64url chars", tp)
	}
}

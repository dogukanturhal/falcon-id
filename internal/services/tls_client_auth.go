// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication.
//
// This file ships the verification primitives the OAuth token endpoint
// uses when a client opts into `tls_client_auth` (PKI-mode, RFC 8705 §2.1)
// for `token_endpoint_auth_method`. Clients indicate enrollment by
// populating `OAuthClient.TLSClientAuthSubjectDN` with the EXACT
// Distinguished Name they expect to present on their client certificate.
//
// Wiring contract:
//
//   - APISIX (or any TLS-terminating proxy in front of Falcon-ID) MUST
//     forward the client's verified leaf certificate via the
//     `X-Forwarded-Client-Cert` header (PEM block, URL-encoded). APISIX
//     ssl-client-cert plugin does this natively. The proxy MUST refuse
//     to forward unverified certs — Falcon-ID does not re-validate the
//     chain (the proxy is the PKI trust boundary).
//
//   - Falcon-ID parses the header into an *x509.Certificate, then
//     compares the certificate's RFC 4514 Subject DN against the
//     client's registered DN. Match → client authenticated as RFC 8705
//     `tls_client_auth`. Mismatch or missing cert → invalid_client.
//
// Scope of this initial drop:
//
//   - RFC 8705 §2.1 (`tls_client_auth`, PKI-mode by Subject DN). The
//     subjectAlternativeName variants (§2.1.2) and §2.2
//     `self_signed_tls_client_auth` are intentionally deferred; clients
//     that need those will opt in via a follow-up MR that broadens
//     `VerifyTLSClientAuth` without changing the surrounding wiring.
//
//   - The discovery document advertises `tls_client_auth` as supported.
//
// Out of scope (deferred to a follow-up):
//
//   - Certificate-bound access tokens (RFC 8705 §3 — `cnf.x5t#S256`
//     claim). Required for sender-constrained tokens in FAPI 2.0
//     deployments. The thumbprint helper below is shipped so the
//     follow-up can wire it in token minting without re-implementing.

// ErrTLSCertHeaderMissing is returned when a client claims
// tls_client_auth but the upstream proxy did not forward a
// `X-Forwarded-Client-Cert` header. Operationally indicates either a
// misconfigured proxy or a client connecting over plain HTTP.
var ErrTLSCertHeaderMissing = errors.New("tls_client_auth: X-Forwarded-Client-Cert header missing or empty")

// ErrTLSCertParseFailed wraps any PEM/x509 decode error encountered
// while parsing the proxy-forwarded certificate.
var ErrTLSCertParseFailed = errors.New("tls_client_auth: failed to parse client certificate from X-Forwarded-Client-Cert")

// ErrTLSCertSubjectDNMismatch is returned when the certificate's
// Subject DN does not exactly match the client's registered
// `TLSClientAuthSubjectDN`.  RFC 8705 §2.1 requires "exact match" —
// no normalization beyond the standard RFC 4514 string form is
// performed.
var ErrTLSCertSubjectDNMismatch = errors.New("tls_client_auth: certificate subject DN does not match registered value")

// ErrTLSClientAuthNotConfigured is returned when a client requests
// tls_client_auth but the OAuthClient row has no
// `TLSClientAuthSubjectDN` registered. This is a configuration error
// — the client should either be re-registered with a subject DN or
// use a different `token_endpoint_auth_method`.
var ErrTLSClientAuthNotConfigured = errors.New("tls_client_auth: client has no registered subject DN")

// ParseClientCertFromHeader extracts a leaf certificate from the
// proxy-forwarded `X-Forwarded-Client-Cert` header value. APISIX +
// most modern reverse proxies emit the PEM block URL-encoded so it
// survives header serialization without newline collisions. This
// helper accepts BOTH the URL-encoded form AND the bare PEM form
// (some proxies emit raw — same parser handles both).
//
// Returns ErrTLSCertHeaderMissing on empty input,
// ErrTLSCertParseFailed on malformed PEM, or any x509 decode error.
//
// The caller MUST trust the upstream proxy to have already validated
// the certificate chain against the configured CA pool — this
// function performs NO chain validation. That trust boundary lives
// in the proxy by design.
func ParseClientCertFromHeader(headerValue string) (*x509.Certificate, error) {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return nil, ErrTLSCertHeaderMissing
	}
	// APISIX URL-encodes the PEM block; tolerate the bare form too.
	// CRITICAL: only URL-unescape when the input actually looks
	// URL-encoded (contains `%`). Unconditional QueryUnescape would
	// silently corrupt bare-PEM by treating `+` characters (legal in
	// base64) as spaces. Detection by `%` is sufficient because base64
	// itself never produces `%` — any presence is from URL-encoding.
	if strings.ContainsRune(headerValue, '%') {
		if decoded, err := url.QueryUnescape(headerValue); err == nil {
			headerValue = decoded
		}
	}
	// Strip APISIX-style outer quoting (\"-----BEGIN-----...-----END-----\").
	headerValue = strings.Trim(headerValue, `"`)

	block, _ := pem.Decode([]byte(headerValue))
	if block == nil {
		return nil, fmt.Errorf("%w: PEM decode returned nil", ErrTLSCertParseFailed)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: unexpected PEM type %q", ErrTLSCertParseFailed, block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTLSCertParseFailed, err)
	}
	return cert, nil
}

// VerifyTLSClientAuth implements RFC 8705 §2.1 PKI-mode authentication:
// the certificate's Subject DN must exactly match the registered DN.
//
// "Exact match" is the literal byte-for-byte comparison of the RFC
// 4514 string form (per x509.Certificate.Subject.String()). This is
// the contract every major IdP (Auth0, Okta, Duende) implements —
// looser matching (case-insensitive attribute names, OID-order
// normalization) introduces ambiguity that adversaries can exploit.
//
// Returns nil on match; one of the typed errors above on any failure.
//
// Future: §2.1.2 SAN matching (dNSName / URI / iPAddress) can be
// added as additional discriminated branches without changing this
// function's signature. §2.2 self_signed_tls_client_auth (per-client
// JWKS-bound cert thumbprint) is a separate code path because the
// trust model is different (no CA chain at all).
func VerifyTLSClientAuth(client *models.OAuthClient, cert *x509.Certificate) error {
	if client == nil {
		return errors.New("VerifyTLSClientAuth: client is nil")
	}
	if cert == nil {
		return ErrTLSCertHeaderMissing
	}
	if client.TLSClientAuthSubjectDN == nil || *client.TLSClientAuthSubjectDN == "" {
		return ErrTLSClientAuthNotConfigured
	}
	certDN := cert.Subject.String()
	if certDN != *client.TLSClientAuthSubjectDN {
		return fmt.Errorf("%w: got %q, want %q", ErrTLSCertSubjectDNMismatch, certDN, *client.TLSClientAuthSubjectDN)
	}
	return nil
}

// CertificateThumbprintS256 computes the RFC 8705 §3.1 `x5t#S256`
// confirmation method value for a leaf certificate: base64url(NoPadding)
// of SHA-256(DER). Used as the `cnf.x5t#S256` claim on tokens minted
// via mTLS-authenticated client credentials, enabling sender-constrained
// tokens (FAPI 2.0).
//
// Shipped now (zero callers) so the upcoming cert-bound-token MR can
// wire the value into TokenGenerationOptions without re-implementing
// the digest. RFC 7638-style canonicalization is NOT needed — the
// digest is over the raw DER bytes of the certificate.
func CertificateThumbprintS256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	digest := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

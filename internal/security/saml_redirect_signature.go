// SPDX-License-Identifier: AGPL-3.0-or-later

package security

// saml_redirect_signature.go verifies HTTP-Redirect binding signatures.
//
// This binding does NOT use XML-DSig. Its signature covers a query-string octet
// string and lives in the SigAlg and Signature query parameters, so goxmldsig
// cannot verify it -- goxmldsig ships SigningContext.SignString for the signing
// direction only and exposes no verify counterpart. Hence hand-written crypto.
//
// SAML 2.0 Bindings section 3.4.4.1 fixes both the ORDER and the ENCODING of the
// signed string, and getting either wrong makes every legitimate request fail:
//
//	SAMLRequest=<v>&RelayState=<v>&SigAlg=<v>     (RelayState omitted if absent)
//
// The values must be the RAW percent-encoded octets exactly as the IdP sent
// them. They cannot be rebuilt from decoded values: percent-encoding is not
// canonical (%2F vs %2f, space as + vs %20), so re-encoding a decoded value
// yields different bytes and a valid signature fails. That is why this reads
// url.URL.RawQuery and never url.Values or gin's c.Query.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrRedirectSignatureInvalid wraps every Redirect-binding verification failure.
var ErrRedirectSignatureInvalid = errors.New("SAML HTTP-Redirect signature verification failed")

// redirectSigAlgs is the allow-list for the SigAlg parameter.
//
// Same reasoning as c-090 on the XML-DSig side: SHA-1 is widespread on this
// binding and nothing else here would reject it, so this list is the only
// control. RSA-SHA1 and DSA-SHA1 are deliberately absent.
var redirectSigAlgs = map[string]crypto.Hash{
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   crypto.SHA384,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   crypto.SHA512,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": crypto.SHA384,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": crypto.SHA512,
}

// rawQueryParam returns the RAW, still-percent-encoded value of the named
// parameter, preserving the sender's exact octets.
//
// It deliberately does NOT use url.ParseQuery: that decodes, and the decoded
// value cannot be re-encoded back to the original bytes. A parameter appearing
// more than once is rejected rather than resolved, because picking one of two
// values is how a signature gets verified over a string the rest of the code
// never sees.
func rawQueryParam(rawQuery, name string) (value string, present bool, err error) {
	prefix := name + "="
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		if !strings.HasPrefix(pair, prefix) {
			// A bare key with no '=' is not a value we can sign over.
			if pair == name {
				return "", false, fmt.Errorf("%w: parameter %s present with no value", ErrRedirectSignatureInvalid, name)
			}
			continue
		}
		if present {
			return "", false, fmt.Errorf("%w: parameter %s repeated; refusing to guess which was signed", ErrRedirectSignatureInvalid, name)
		}
		value = strings.TrimPrefix(pair, prefix)
		present = true
	}
	return value, present, nil
}

// RedirectSignedOctetString rebuilds the exact string the IdP signed.
//
// messageParam is "SAMLRequest" or "SAMLResponse". Order is fixed by the spec
// and is NOT the order the parameters happen to appear in the query.
func RedirectSignedOctetString(rawQuery, messageParam string) (string, error) {
	msg, ok, err := rawQueryParam(rawQuery, messageParam)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w: %s missing", ErrRedirectSignatureInvalid, messageParam)
	}
	sigAlg, ok, err := rawQueryParam(rawQuery, "SigAlg")
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w: SigAlg missing; the request is unsigned", ErrRedirectSignatureInvalid)
	}
	relayState, hasRelayState, err := rawQueryParam(rawQuery, "RelayState")
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(messageParam)
	b.WriteString("=")
	b.WriteString(msg)
	if hasRelayState {
		b.WriteString("&RelayState=")
		b.WriteString(relayState)
	}
	b.WriteString("&SigAlg=")
	b.WriteString(sigAlg)
	return b.String(), nil
}

// VerifyRedirectSignature verifies an HTTP-Redirect binding signature against
// the stored IdP certificate.
//
// Trust is anchored solely in idpCert. Callers must treat any error as "reject
// this request", never as "continue unsigned".
func VerifyRedirectSignature(rawQuery, messageParam string, idpCert *x509.Certificate) error {
	if idpCert == nil {
		return fmt.Errorf("%w: no IdP certificate is configured for this provider", ErrRedirectSignatureInvalid)
	}

	sigAlgRaw, ok, err := rawQueryParam(rawQuery, "SigAlg")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: SigAlg missing; the request is unsigned", ErrRedirectSignatureInvalid)
	}
	sigAlg, err := url.QueryUnescape(sigAlgRaw)
	if err != nil {
		return fmt.Errorf("%w: SigAlg is not valid percent-encoding: %v", ErrRedirectSignatureInvalid, err)
	}
	hashAlg, allowed := redirectSigAlgs[sigAlg]
	if !allowed {
		return fmt.Errorf("%w: rejected signature algorithm %q", ErrRedirectSignatureInvalid, sigAlg)
	}

	sigRaw, ok, err := rawQueryParam(rawQuery, "Signature")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: Signature missing; the request is unsigned", ErrRedirectSignatureInvalid)
	}
	sigEncoded, err := url.QueryUnescape(sigRaw)
	if err != nil {
		return fmt.Errorf("%w: Signature is not valid percent-encoding: %v", ErrRedirectSignatureInvalid, err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigEncoded)
	if err != nil {
		return fmt.Errorf("%w: Signature is not valid base64: %v", ErrRedirectSignatureInvalid, err)
	}

	signed, err := RedirectSignedOctetString(rawQuery, messageParam)
	if err != nil {
		return err
	}

	var digest []byte
	switch hashAlg {
	case crypto.SHA256:
		sum := sha256.Sum256([]byte(signed))
		digest = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384([]byte(signed))
		digest = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512([]byte(signed))
		digest = sum[:]
	default:
		return fmt.Errorf("%w: unsupported hash for %q", ErrRedirectSignatureInvalid, sigAlg)
	}

	switch pub := idpCert.PublicKey.(type) {
	case *rsa.PublicKey:
		if !strings.Contains(sigAlg, "rsa-") {
			return fmt.Errorf("%w: SigAlg %q does not match the RSA certificate", ErrRedirectSignatureInvalid, sigAlg)
		}
		if err := rsa.VerifyPKCS1v15(pub, hashAlg, digest, sig); err != nil {
			return fmt.Errorf("%w: %v", ErrRedirectSignatureInvalid, err)
		}
		return nil
	case *ecdsa.PublicKey:
		if !strings.Contains(sigAlg, "ecdsa-") {
			return fmt.Errorf("%w: SigAlg %q does not match the ECDSA certificate", ErrRedirectSignatureInvalid, sigAlg)
		}
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return fmt.Errorf("%w: ECDSA signature did not verify", ErrRedirectSignatureInvalid)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported IdP public key type %T", ErrRedirectSignatureInvalid, pub)
	}
}

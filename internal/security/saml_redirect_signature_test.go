// SPDX-License-Identifier: AGPL-3.0-or-later

package security

// saml_redirect_signature_test.go pins the attacks VerifyRedirectSignature must
// reject, and the encoding mistake that would break every legitimate request.
//
// CONTROL 7 is the one that justifies the whole design: it rebuilds the query
// with url.Values.Encode() -- the obvious thing to reach for -- and shows the
// signature no longer verifies. That is the failure mode the standing
// instruction warns about, where the pressure is to relax the check rather than
// fix the encoding.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"
)

const (
	algRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
)

// signRedirect builds a signed HTTP-Redirect query exactly as a conformant IdP
// would: octet string in spec order, values percent-encoded once.
func signRedirect(t *testing.T, key *rsa.PrivateKey, samlRequest, relayState, sigAlg string) string {
	t.Helper()
	msg := url.QueryEscape(samlRequest)
	alg := url.QueryEscape(sigAlg)

	signed := "SAMLRequest=" + msg
	if relayState != "" {
		signed += "&RelayState=" + url.QueryEscape(relayState)
	}
	signed += "&SigAlg=" + alg

	var digest []byte
	var h crypto.Hash
	switch sigAlg {
	case algRSASHA1:
		sum := sha1.Sum([]byte(signed))
		digest, h = sum[:], crypto.SHA1
	default:
		sum := sha256.Sum256([]byte(signed))
		digest, h = sum[:], crypto.SHA256
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, h, digest)
	if err != nil {
		t.Fatal(err)
	}
	return signed + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}

func TestVerifyRedirectSignature_AttackControls(t *testing.T) {
	key, cert := mkKeyCert(t, "idp.example.test")
	_, otherCert := mkKeyCert(t, "attacker.example.test")

	const req = "fZJNb9swDIb/iqF7YtnOh2vEBrIGwwJ0W9Bku+wyKDKdCLAlV6Sd9d9PSVqsl+5Ggg9fviS1"
	const relay = "https://sp.example.test/after-logout?x=1/2 3"

	// ---- POSITIVE CONTROL: a conformant signed request must VERIFY ----
	q := signRedirect(t, key, req, relay, algRSASHA256)
	if err := VerifyRedirectSignature(q, "SAMLRequest", cert); err != nil {
		t.Fatalf("POSITIVE CONTROL FAILED — a legitimately signed request was rejected: %v", err)
	}
	t.Log("PASS positive: conformant Redirect signature verified")

	// ---- CONTROL 1: tampered SAMLRequest ----
	tampered := signRedirect(t, key, req, relay, algRSASHA256)
	tampered = "SAMLRequest=" + url.QueryEscape("EVIL"+req) + tampered[len("SAMLRequest=")+len(url.QueryEscape(req)):]
	if err := VerifyRedirectSignature(tampered, "SAMLRequest", cert); err == nil {
		t.Fatal("CONTROL 1 FAILED — tampered SAMLRequest ACCEPTED")
	} else {
		t.Logf("PASS control 1 (tampered SAMLRequest) rejected: %v", err)
	}

	// ---- CONTROL 2: tampered RelayState ----
	// RelayState is inside the signed octet string, which is exactly why the
	// handler must not blank an oversized one before verification.
	q2 := signRedirect(t, key, req, relay, algRSASHA256)
	bad := replaceParam(q2, "RelayState", url.QueryEscape("https://evil.example/"))
	if err := VerifyRedirectSignature(bad, "SAMLRequest", cert); err == nil {
		t.Fatal("CONTROL 2 FAILED — tampered RelayState ACCEPTED")
	} else {
		t.Logf("PASS control 2 (tampered RelayState) rejected: %v", err)
	}

	// ---- CONTROL 3: SHA-1 SigAlg (the c-090 allow-list on this binding) ----
	sha1q := signRedirect(t, key, req, relay, algRSASHA1)
	if err := VerifyRedirectSignature(sha1q, "SAMLRequest", cert); err == nil {
		t.Fatal("CONTROL 3 FAILED — rsa-sha1 ACCEPTED on the Redirect binding")
	} else {
		t.Logf("PASS control 3 (rsa-sha1) rejected: %v", err)
	}

	// ---- CONTROL 4: wrong certificate ----
	if err := VerifyRedirectSignature(q, "SAMLRequest", otherCert); err == nil {
		t.Fatal("CONTROL 4 FAILED — accepted under a certificate that is not the stored one")
	} else {
		t.Logf("PASS control 4 (wrong certificate) rejected: %v", err)
	}

	// ---- CONTROL 5: unsigned request ----
	unsigned := "SAMLRequest=" + url.QueryEscape(req) + "&RelayState=" + url.QueryEscape(relay)
	if err := VerifyRedirectSignature(unsigned, "SAMLRequest", cert); err == nil {
		t.Fatal("CONTROL 5 FAILED — unsigned request ACCEPTED")
	} else {
		t.Logf("PASS control 5 (unsigned) rejected: %v", err)
	}

	// ---- CONTROL 6: duplicated parameter (signature over one value, use of another) ----
	dup := q + "&SAMLRequest=" + url.QueryEscape("EVIL")
	if err := VerifyRedirectSignature(dup, "SAMLRequest", cert); err == nil {
		t.Fatal("CONTROL 6 FAILED — duplicated SAMLRequest ACCEPTED")
	} else {
		t.Logf("PASS control 6 (duplicated parameter) rejected: %v", err)
	}

	// ---- CONTROL 7: the encoding trap, with a NON-Go encoding ----
	// Go's url.QueryEscape encodes a space as '+'. Java and .NET IdPs commonly
	// emit '%20'. Both decode to the same string, so a decode/re-encode round
	// trip silently rewrites the bytes the IdP actually signed.
	//
	// First: a request signed with %20 must VERIFY when read from the raw query.
	spaceRelay := "https://sp.example.test/after%20logout"
	signedRaw := "SAMLRequest=" + url.QueryEscape(req) +
		"&RelayState=" + spaceRelay +
		"&SigAlg=" + url.QueryEscape(algRSASHA256)
	sum := sha256.Sum256([]byte(signedRaw))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	q7 := signedRaw + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sigBytes))
	if err := VerifyRedirectSignature(q7, "SAMLRequest", cert); err != nil {
		t.Fatalf("CONTROL 7a FAILED — a request encoded the way a Java IdP encodes it was rejected: %v", err)
	}
	t.Log("PASS control 7a: non-Go percent-encoding (%20) verified from the raw query")

	// Second: the SAME parameters, decoded and re-encoded by url.Values, must
	// NOT verify -- %20 becomes '+' and the signed bytes change. This is the
	// failure a c.Query/url.Values implementation would hit on every legitimate
	// request from such an IdP, and the moment the standing instruction matters.
	parsed, err := url.ParseQuery(q7)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRedirectSignature(parsed.Encode(), "SAMLRequest", cert); err == nil {
		t.Fatal("CONTROL 7b FAILED — a re-encoded query verified; the octet string is not being taken from RawQuery")
	} else {
		t.Logf("PASS control 7b (decoded then re-encoded) rejected as expected: %v", err)
	}

	// ---- CONTROL 8: no certificate configured ----
	if err := VerifyRedirectSignature(q, "SAMLRequest", nil); err == nil {
		t.Fatal("CONTROL 8 FAILED — accepted with no trust anchor")
	} else {
		t.Logf("PASS control 8 (no certificate) rejected: %v", err)
	}
}

// replaceParam swaps one raw parameter value, leaving the rest byte-identical.
func replaceParam(rawQuery, name, newRawValue string) string {
	out := ""
	for _, pair := range splitAmp(rawQuery) {
		if len(pair) > len(name)+1 && pair[:len(name)+1] == name+"=" {
			pair = name + "=" + newRawValue
		}
		if out != "" {
			out += "&"
		}
		out += pair
	}
	return out
}

func splitAmp(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '&' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}

func TestRedirectSignedOctetString_SpecOrder(t *testing.T) {
	// Spec order is SAMLRequest, RelayState, SigAlg -- NOT the order the
	// parameters happen to appear in the query.
	raw := "SigAlg=" + url.QueryEscape(algRSASHA256) + "&RelayState=abc&SAMLRequest=xyz&Signature=ignored"
	got, err := RedirectSignedOctetString(raw, "SAMLRequest")
	if err != nil {
		t.Fatal(err)
	}
	want := "SAMLRequest=xyz&RelayState=abc&SigAlg=" + url.QueryEscape(algRSASHA256)
	if got != want {
		t.Fatalf("octet string not in spec order:\n got: %s\nwant: %s", got, want)
	}
	t.Log("PASS: octet string is reassembled in spec order regardless of query order")
}

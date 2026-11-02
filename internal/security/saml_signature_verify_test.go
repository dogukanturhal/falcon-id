// SPDX-License-Identifier: AGPL-3.0-or-later

package security

// saml_signature_verify_test.go pins the attacks VerifySAMLResponseSignature
// must reject. Each control corresponds to a way inbound SAML has been broken in
// the wild, and each would be silently reopened by a plausible refactor.
//
// CONTROL 3 is the reason this file exists. Once goxmldsig is in place,
// saml_signature.go looks redundant -- it no longer does reference matching or
// presence checking -- so deleting it reads as correct cleanup a reviewer would
// approve. Its algorithm allow-list is the ONLY thing rejecting rsa-sha1, since
// goxmldsig accepts SHA-1 and exposes no option to refuse it. Control 3 is what
// fails the build if that deletion happens.
//
// The two POSITIVE controls are not padding: a verifier that rejects everything
// passes all seven negatives identically to one that works.
//
// Keep this fast and fixture-free. Its value is that it is too cheap to skip.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

func mkKeyCert(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}


// assertionXML builds a minimal but realistic SAML Assertion.
func assertionXML(id, nameID string) string {
	now := time.Now().UTC().Format(time.RFC3339)
	later := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
	return fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" IssueInstant="%s" Version="2.0">`+
		`<saml:Issuer>https://idp.example.test</saml:Issuer>`+
		`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>`+
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`+
		`<saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="https://sp.example.test/acs" InResponseTo="_req1"/>`+
		`</saml:SubjectConfirmation></saml:Subject>`+
		`<saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction>`+
		`<saml:Audience>https://sp.example.test/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>`+
		`</saml:Assertion>`, id, now, nameID, later, now, later)
}

func responseWrap(inner string) string {
	return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_resp1" Version="2.0" Destination="https://sp.example.test/acs" InResponseTo="_req1">` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		inner + `</samlp:Response>`
}

func signElement(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, xmlStr string, sigAlg string) string {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlStr); err != nil {
		t.Fatal(err)
	}
	sctx, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	if sigAlg != "" {
		if err := sctx.SetSignatureMethod(sigAlg); err != nil {
			t.Fatal(err)
		}
	}
	signed, err := sctx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	s, err := out.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signAssertionInPlace builds a Response containing the assertion and signs the
// ASSERTION WHERE IT SITS, which is what real IdPs (Okta, Azure AD, ADFS) do.
// Signing it standalone and then pasting it into a Response is not realistic and
// produces a signature computed without the Response's namespaces in scope.
func signAssertionInPlace(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, assertion string, sigAlg string) string {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(responseWrap(assertion)); err != nil {
		t.Fatal(err)
	}
	el, err := etreeutils.NSFindOne(doc.Root(), samlAssertionNS, assertionTag)
	if err != nil || el == nil {
		t.Fatalf("locate assertion to sign: %v", err)
	}
	sctx, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	// EXCLUSIVE c14n: what SAML IdPs actually use, and why assertions are
	// relocatable at all. goxmldsig's signing default is inclusive c14n11, which
	// is not representative of SAML traffic.
	sctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if sigAlg != "" {
		if err := sctx.SetSignatureMethod(sigAlg); err != nil {
			t.Fatal(err)
		}
	}
	sig, err := sctx.ConstructSignature(el, true)
	if err != nil {
		t.Fatal(err)
	}
	el.AddChild(sig)
	out := etree.NewDocument()
	out.SetRoot(doc.Root().Copy())
	s, err := out.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifySAMLResponseSignature_AttackControls(t *testing.T) {
	key, cert := mkKeyCert(t, "idp.example.test")
	_, otherCert := mkKeyCert(t, "attacker.example.test")

	// ---- POSITIVE CONTROL A: assertion-level signature must VERIFY ----
	respAssertionSigned := signAssertionInPlace(t, key, cert, assertionXML("_a1", "alice@example.test"), "")

	va, err := VerifySAMLResponseSignature([]byte(respAssertionSigned), cert)
	if err != nil {
		t.Fatalf("POSITIVE CONTROL A FAILED — a legitimately signed assertion was rejected: %v", err)
	}
	if va.Placement != SignedAtAssertion {
		t.Fatalf("expected assertion placement, got %q", va.Placement)
	}
	if !strings.Contains(string(va.XML), "alice@example.test") {
		t.Fatal("verified assertion does not carry the expected NameID")
	}
	t.Logf("PASS positive A: assertion-level signature verified, placement=%s alg=%s", va.Placement, va.SignatureAlgorithm)

	// ---- POSITIVE CONTROL B: response-level signature must VERIFY ----
	respSigned := signElement(t, key, cert, responseWrap(assertionXML("_a2", "bob@example.test")), "")
	vb, err := VerifySAMLResponseSignature([]byte(respSigned), cert)
	if err != nil {
		t.Fatalf("POSITIVE CONTROL B FAILED — response-level signature rejected: %v", err)
	}
	if vb.Placement != SignedAtResponse {
		t.Fatalf("expected response placement, got %q", vb.Placement)
	}
	if !strings.Contains(string(vb.XML), "bob@example.test") {
		t.Fatal("verified assertion does not carry the expected NameID")
	}
	t.Logf("PASS positive B: response-level signature verified, placement=%s", vb.Placement)

	// ---- CONTROL 1: tampered assertion body ----
	tampered := strings.Replace(respAssertionSigned, "alice@example.test", "mallory@example.test", 1)
	if _, err := VerifySAMLResponseSignature([]byte(tampered), cert); err == nil {
		t.Fatal("CONTROL 1 FAILED — tampered assertion body ACCEPTED")
	} else {
		t.Logf("PASS control 1 (tampered body) rejected: %v", err)
	}

	// ---- CONTROL 2: XML Signature Wrapping — valid signature over a DIFFERENT element ----
	// Attacker keeps the genuinely-signed assertion and injects their own
	// unsigned one carrying a different identity.
	// Inject the evil assertion as a SIBLING, leaving the genuinely-signed
	// assertion byte-identical and in the same namespace context. Its signature
	// therefore still verifies -- which is the whole point: a naive
	// implementation verifies "a" signature, then reads "the" assertion and gets
	// mallory. Only consuming the element Validate returned defeats this.
	evil := assertionXML("_evil", "mallory@example.test")
	const statusEnd = "</samlp:Status>"
	idx := strings.Index(respAssertionSigned, statusEnd)
	if idx < 0 {
		t.Fatal("could not build wrapping case")
	}
	cut := idx + len(statusEnd)
	wrapped := respAssertionSigned[:cut] + evil + respAssertionSigned[cut:]
	vw, err := VerifySAMLResponseSignature([]byte(wrapped), cert)
	if err == nil {
		if strings.Contains(string(vw.XML), "mallory@example.test") {
			t.Fatal("CONTROL 2 CATASTROPHIC — wrapping accepted AND attacker identity returned")
		}
		t.Fatal("CONTROL 2 FAILED — wrapped response ACCEPTED")
	}
	t.Logf("PASS control 2 (signature wrapping) rejected: %v", err)

	// ---- CONTROL 2b: wrapped assertion hidden DEEP, inside Extensions ----
	// The original code counted Assertion elements as direct children of
	// Response via encoding/xml, which this placement evades. countAssertions
	// walks the whole tree in the SAME parse we verify, so it must still fire.
	deep := `<samlp:Extensions xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
		assertionXML("_deep", "mallory@example.test") + `</samlp:Extensions>`
	deepWrapped := respAssertionSigned[:cut] + deep + respAssertionSigned[cut:]
	vd, err := VerifySAMLResponseSignature([]byte(deepWrapped), cert)
	if err == nil {
		if strings.Contains(string(vd.XML), "mallory@example.test") {
			t.Fatal("CONTROL 2b CATASTROPHIC — deep-wrapped attacker identity returned")
		}
		t.Fatal("CONTROL 2b FAILED — deep-wrapped assertion ACCEPTED")
	}
	t.Logf("PASS control 2b (assertion hidden in Extensions) rejected: %v", err)

	// ---- CONTROL 3: rsa-sha1 signature (the c-090 pre-filter) ----
	sha1Resp := signAssertionInPlace(t, key, cert, assertionXML("_a3", "alice@example.test"), dsig.RSASHA1SignatureMethod)
	if _, err := VerifySAMLResponseSignature([]byte(sha1Resp), cert); err == nil {
		t.Fatal("CONTROL 3 FAILED — rsa-sha1 ACCEPTED; the allow-list pre-filter is not running")
	} else {
		t.Logf("PASS control 3 (rsa-sha1) rejected: %v", err)
	}

	// ---- CONTROL 4: unsigned assertion (SPWantSigned default is irrelevant now) ----
	if _, err := VerifySAMLResponseSignature([]byte(responseWrap(assertionXML("_a4", "alice@example.test"))), cert); err == nil {
		t.Fatal("CONTROL 4 FAILED — unsigned assertion ACCEPTED")
	} else {
		t.Logf("PASS control 4 (unsigned) rejected: %v", err)
	}

	// ---- CONTROL 5: signature valid, but not against the STORED certificate ----
	if _, err := VerifySAMLResponseSignature([]byte(respAssertionSigned), otherCert); err == nil {
		t.Fatal("CONTROL 5 FAILED — assertion accepted under a certificate that is not the stored one")
	} else {
		t.Logf("PASS control 5 (wrong certificate) rejected: %v", err)
	}

	// ---- CONTROL 6: no certificate configured ----
	if _, err := VerifySAMLResponseSignature([]byte(respAssertionSigned), nil); err == nil {
		t.Fatal("CONTROL 6 FAILED — accepted with no trust anchor")
	} else {
		t.Logf("PASS control 6 (no certificate) rejected: %v", err)
	}
}

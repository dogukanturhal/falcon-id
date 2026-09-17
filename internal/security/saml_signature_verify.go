// SPDX-License-Identifier: AGPL-3.0-or-later

package security

// saml_signature_verify.go performs REAL cryptographic verification of inbound
// SAML, as opposed to the structural pre-checks in saml_signature.go.
//
// The two files are not alternatives and the structural one is not obsolete.
// goxmldsig accepts rsa-sha1, ecdsa-sha1 and sha1 digests, and its
// ValidationContext exposes no way to restrict algorithms, so the allow-list in
// saml_signature.go remains the ONLY control rejecting SHA-1 and must keep
// running in front of this. Deleting it as "now redundant" is a silent downgrade.

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

const (
	samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	assertionTag    = "Assertion"
)

// ErrSAMLSignatureInvalid wraps every verification failure. Callers must treat
// it as "reject this login", never as "degrade and continue".
var ErrSAMLSignatureInvalid = errors.New("SAML signature verification failed")

// SignaturePlacement records which element actually carried the verified
// signature. It is reported for audit, never used to decide whether to trust.
type SignaturePlacement string

const (
	SignedAtAssertion SignaturePlacement = "assertion"
	SignedAtResponse  SignaturePlacement = "response"
)

// VerifiedAssertion is the ONLY safe carrier of a verified SAML identity.
//
// XML holds the serialized assertion reconstructed from the exact canonical
// bytes whose digest matched the signature: goxmldsig's validateSignature
// re-parses `referencedBytes` and returns that, so this is not a copy of
// attacker input that happened to sit near a valid signature -- it IS the
// verified byte sequence. Callers MUST parse this and nothing else. Parsing the
// original response document instead re-opens XML Signature Wrapping, because
// encoding/xml and etree can disagree about the same bytes.
type VerifiedAssertion struct {
	XML                []byte
	Placement          SignaturePlacement
	SignatureAlgorithm string
}

// VerifySAMLResponseSignature cryptographically verifies a SAML Response and
// returns the assertion that was actually signed.
//
// Trust is anchored solely in idpCert, the certificate stored against the
// provider. Nothing inside the document selects its own trust anchor: a
// KeyInfo/X509Certificate embedded in the response is ignored, because honouring
// it would let an attacker present a self-signed certificate alongside a
// self-signed assertion and verify perfectly.
func VerifySAMLResponseSignature(rawXML []byte, idpCert *x509.Certificate) (*VerifiedAssertion, error) {
	if idpCert == nil {
		return nil, fmt.Errorf("%w: no IdP certificate is configured for this provider", ErrSAMLSignatureInvalid)
	}

	// (1) Round-trip validation on the RAW bytes, before anything parses them.
	// Go's encoding/xml is not round-trip safe; this is the mitigation for the
	// CVE-2020-2951x parser-differential class and it has to run first.
	if err := xrv.Validate(bytes.NewReader(rawXML)); err != nil {
		return nil, fmt.Errorf("%w: XML round-trip validation rejected the document: %v", ErrSAMLSignatureInvalid, err)
	}

	// (2) Algorithm allow-list pre-filter. Load-bearing: goxmldsig would accept
	// SHA-1 here and offers no option to refuse it.
	structural, err := ValidateSAMLResponseSignatureStructure(rawXML)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSAMLSignatureInvalid, err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rawXML); err != nil {
		return nil, fmt.Errorf("%w: parse response: %v", ErrSAMLSignatureInvalid, err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("%w: response has no root element", ErrSAMLSignatureInvalid)
	}

	// (3) Reject multiple assertions, counted in the SAME tree we are about to
	// verify rather than in a separate encoding/xml parse. Stricter than the
	// spec, which permits several individually-signed assertions: we have no use
	// for more than one, and every extra assertion is somewhere to hide a
	// wrapped one.
	if n := countAssertions(root); n != 1 {
		return nil, fmt.Errorf("%w: expected exactly 1 Assertion, found %d", ErrSAMLSignatureInvalid, n)
	}

	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{idpCert},
	})
	ctx.IdAttribute = "ID"

	// (4) Assertion-level signature preferred: it is the tighter guarantee,
	// binding the identity itself rather than the envelope carrying it.
	if structural.AssertionSignaturePresent {
		// NSSelectOne finds the Assertion and detaches it WITH its in-scope
		// namespace declarations attached. Never use etree's raw selectors here:
		// lifting a subtree drops declarations inherited from the Response, and
		// canonicalization is namespace-sensitive, so the digest of a legitimate
		// assertion would fail.
		// Two extractions, because the correct one depends on the
		// CanonicalizationMethod the IdP chose, and we do not control that.
		//
		//  - EXCLUSIVE c14n (the SAML norm): the assertion must be DETACHED with
		//    its in-scope namespace declarations attached. TransformExcC14n then
		//    drops whichever are not visibly utilised, reproducing the signed form.
		//  - INCLUSIVE c14n11: goxmldsig canonicalizes by serializing the subtree
		//    as-is, without collecting ancestor declarations. Detaching would ADD
		//    declarations that were absent when the digest was computed and break a
		//    legitimate assertion, so the element must be passed in place.
		//
		// Trying both is not a relaxation: each attempt demands a cryptographically
		// valid signature over the stored certificate, and a forged assertion fails
		// both. Only the element Validate RETURNS is ever consumed.
		detached, err := etreeutils.NSSelectOne(root, samlAssertionNS, assertionTag)
		if err != nil {
			return nil, fmt.Errorf("%w: locate signed assertion: %v", ErrSAMLSignatureInvalid, err)
		}
		inPlace, err := etreeutils.NSFindOne(root, samlAssertionNS, assertionTag)
		if err != nil {
			return nil, fmt.Errorf("%w: locate signed assertion in place: %v", ErrSAMLSignatureInvalid, err)
		}
		if detached == nil && inPlace == nil {
			return nil, fmt.Errorf("%w: assertion reported signed but not found", ErrSAMLSignatureInvalid)
		}

		var verified *etree.Element
		var lastErr error
		for _, candidate := range []*etree.Element{detached, inPlace} {
			if candidate == nil {
				continue
			}
			v, vErr := ctx.Validate(candidate)
			if vErr == nil {
				verified = v
				break
			}
			lastErr = vErr
		}
		if verified == nil {
			return nil, fmt.Errorf("%w: assertion signature: %v", ErrSAMLSignatureInvalid, lastErr)
		}
		out, err := serializeElement(verified)
		if err != nil {
			return nil, err
		}
		return &VerifiedAssertion{
			XML:                out,
			Placement:          SignedAtAssertion,
			SignatureAlgorithm: structural.SignatureAlgorithm,
		}, nil
	}

	// (5) Response-level signature: verify the envelope, then take the assertion
	// out of the VERIFIED element. The assertion is covered by that signature
	// only because it is inside the bytes that were digested -- which is exactly
	// why it must be read out of the returned element and never out of `root`.
	if structural.ResponseSignaturePresent {
		verifiedResponse, err := ctx.Validate(root)
		if err != nil {
			return nil, fmt.Errorf("%w: response signature: %v", ErrSAMLSignatureInvalid, err)
		}
		assertionEl, err := etreeutils.NSSelectOne(verifiedResponse, samlAssertionNS, assertionTag)
		if err != nil {
			return nil, fmt.Errorf("%w: locate assertion inside verified response: %v", ErrSAMLSignatureInvalid, err)
		}
		if assertionEl == nil {
			return nil, fmt.Errorf("%w: verified response contains no assertion", ErrSAMLSignatureInvalid)
		}
		out, err := serializeElement(assertionEl)
		if err != nil {
			return nil, err
		}
		return &VerifiedAssertion{
			XML:                out,
			Placement:          SignedAtResponse,
			SignatureAlgorithm: structural.SignatureAlgorithm,
		}, nil
	}

	return nil, fmt.Errorf("%w: response carries no signature", ErrSAMLSignatureInvalid)
}

// countAssertions counts Assertion elements anywhere in the tree, not just as
// direct children of Response, because wrapping hides them deeper.
func countAssertions(root *etree.Element) int {
	n := 0
	var walk func(el *etree.Element)
	walk = func(el *etree.Element) {
		if el.Tag == assertionTag {
			n++
		}
		for _, child := range el.ChildElements() {
			walk(child)
		}
	}
	walk(root)
	return n
}

// serializeElement renders a verified element without reformatting it.
func serializeElement(el *etree.Element) ([]byte, error) {
	out := etree.NewDocument()
	out.SetRoot(el.Copy())
	b, err := out.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("%w: serialize verified element: %v", ErrSAMLSignatureInvalid, err)
	}
	return b, nil
}

// validateSignatureAlgorithmsInElement applies the c-090 allow-list to the
// enveloped Signature on el.
//
// ValidateSAMLResponseSignatureStructure only understands <Response>, so it
// cannot pre-filter a <LogoutRequest>. This is the same control expressed
// generically: goxmldsig accepts SHA-1 and offers no way to refuse it, so
// without this the LogoutRequest path would silently accept rsa-sha1.
func validateSignatureAlgorithmsInElement(el *etree.Element) error {
	sig := el.FindElement("./Signature")
	if sig == nil {
		for _, child := range el.ChildElements() {
			if child.Tag == "Signature" {
				sig = child
				break
			}
		}
	}
	if sig == nil {
		return fmt.Errorf("no enveloped Signature on <%s>", el.Tag)
	}
	signedInfo := findChildByTag(sig, "SignedInfo")
	if signedInfo == nil {
		return fmt.Errorf("Signature has no SignedInfo")
	}
	method := findChildByTag(signedInfo, "SignatureMethod")
	if method == nil {
		return fmt.Errorf("SignedInfo has no SignatureMethod")
	}
	alg := method.SelectAttrValue("Algorithm", "")
	if rejectedAlgorithms[alg] {
		return fmt.Errorf("rejected signature algorithm: %s", alg)
	}
	if !allowedSignatureAlgorithms[alg] {
		return fmt.Errorf("unsupported signature algorithm: %s", alg)
	}
	for _, ref := range signedInfo.ChildElements() {
		if ref.Tag != "Reference" {
			continue
		}
		dm := findChildByTag(ref, "DigestMethod")
		if dm == nil {
			return fmt.Errorf("Reference has no DigestMethod")
		}
		digestAlg := dm.SelectAttrValue("Algorithm", "")
		if rejectedAlgorithms[digestAlg] {
			return fmt.Errorf("rejected digest algorithm: %s", digestAlg)
		}
		if !allowedDigestAlgorithms[digestAlg] {
			return fmt.Errorf("unsupported digest algorithm: %s", digestAlg)
		}
	}
	return nil
}

func findChildByTag(el *etree.Element, tag string) *etree.Element {
	for _, child := range el.ChildElements() {
		if child.Tag == tag {
			return child
		}
	}
	return nil
}

// VerifySignedRootElement verifies an enveloped XML-DSig covering the ROOT
// element of rawXML and returns the verified element, serialized.
//
// Used for <LogoutRequest> over the HTTP-POST binding, where the signature
// covers the root rather than a nested assertion. Same guarantees as
// VerifySAMLResponseSignature: round-trip validation first, algorithm
// allow-list before goxmldsig, trust anchored only in idpCert, and the caller
// gets back ONLY what ctx.Validate returned.
func VerifySignedRootElement(rawXML []byte, idpCert *x509.Certificate, expectedTag string) ([]byte, error) {
	if idpCert == nil {
		return nil, fmt.Errorf("%w: no IdP certificate is configured for this provider", ErrSAMLSignatureInvalid)
	}
	if err := xrv.Validate(bytes.NewReader(rawXML)); err != nil {
		return nil, fmt.Errorf("%w: XML round-trip validation rejected the document: %v", ErrSAMLSignatureInvalid, err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rawXML); err != nil {
		return nil, fmt.Errorf("%w: parse document: %v", ErrSAMLSignatureInvalid, err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("%w: document has no root element", ErrSAMLSignatureInvalid)
	}
	if expectedTag != "" && root.Tag != expectedTag {
		return nil, fmt.Errorf("%w: expected <%s>, got <%s>", ErrSAMLSignatureInvalid, expectedTag, root.Tag)
	}
	if err := validateSignatureAlgorithmsInElement(root); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSAMLSignatureInvalid, err)
	}
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{idpCert},
	})
	ctx.IdAttribute = "ID"
	verified, err := ctx.Validate(root)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSAMLSignatureInvalid, err)
	}
	return serializeElement(verified)
}

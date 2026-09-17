// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeXMLInput_AcceptsValidSAMLResponse(t *testing.T) {
	input := []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_abc123"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>`)
	err := SanitizeXMLInput(input)
	assert.NoError(t, err)
}

func TestSanitizeXMLInput_RejectsEmptyInput(t *testing.T) {
	err := SanitizeXMLInput([]byte{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestSanitizeXMLInput_RejectsNilInput(t *testing.T) {
	err := SanitizeXMLInput(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestSanitizeXMLInput_RejectsOversizedPayload(t *testing.T) {
	// maxXMLSize is 1<<20 = 1 048 576 bytes.  Build a slice one byte larger.
	big := make([]byte, maxXMLSize+1)
	for i := range big {
		big[i] = 'a'
	}
	err := SanitizeXMLInput(big)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestSanitizeXMLInput_AcceptsExactlyMaxSize(t *testing.T) {
	// A payload of exactly maxXMLSize bytes must be accepted (not > maxXMLSize).
	exact := make([]byte, maxXMLSize)
	for i := range exact {
		exact[i] = 'a'
	}
	// Override first bytes with something that won't trigger any pattern check.
	// The content is not valid XML but the sanitizer does not parse XML; it only
	// checks size, null bytes, and dangerous patterns.
	err := SanitizeXMLInput(exact)
	assert.NoError(t, err)
}

func TestSanitizeXMLInput_RejectsDOCTYPE(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY>]><foo/>`)
	err := SanitizeXMLInput(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prohibited")
}

func TestSanitizeXMLInput_RejectsENTITY(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!ENTITY xxe "evil"><foo>&xxe;</foo>`)
	err := SanitizeXMLInput(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prohibited")
}

func TestSanitizeXMLInput_RejectsSYSTEMKeyword(t *testing.T) {
	input := []byte(`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`)
	err := SanitizeXMLInput(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prohibited")
}

func TestSanitizeXMLInput_RejectsPUBLICKeyword(t *testing.T) {
	input := []byte(`<!DOCTYPE foo PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">`)
	err := SanitizeXMLInput(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prohibited")
}

func TestSanitizeXMLInput_RejectsCaseInsensitiveDOCTYPE(t *testing.T) {
	variants := []string{
		`<!doctype foo>`,
		`<!DocType foo>`,
		`<!DOCTYPE foo>`,
		`<!DOCTYPE foo>`,
	}
	for _, v := range variants {
		v := v
		t.Run(v, func(t *testing.T) {
			err := SanitizeXMLInput([]byte(v))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "prohibited")
		})
	}
}

func TestSanitizeXMLInput_RejectsNullBytes(t *testing.T) {
	input := []byte("<foo>bar\x00baz</foo>")
	err := SanitizeXMLInput(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "null")
}

func TestSanitizeXMLInput_RejectsNullByteAtStart(t *testing.T) {
	input := []byte("\x00<foo/>")
	err := SanitizeXMLInput(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "null")
}

func TestSanitizeXMLInput_RejectsUTF16BOM_LE(t *testing.T) {
	// UTF-16 little-endian BOM: 0xFF 0xFE followed by non-null bytes.
	// The null-byte check runs first; using non-null bytes here exercises the
	// BOM check specifically.  Both checks ultimately produce an error.
	input := []byte{0xFF, 0xFE, 0x41, 0x42} // BOM + "AB" (no null bytes)
	err := SanitizeXMLInput(input)
	require.Error(t, err)
	// The implementation checks null bytes before BOM, so both orderings can
	// surface.  Accept any rejection error here.
	assert.NotEmpty(t, err.Error())
}

func TestSanitizeXMLInput_RejectsUTF16BOM_BE(t *testing.T) {
	// UTF-16 big-endian BOM: 0xFE 0xFF followed by non-null bytes.
	input := []byte{0xFE, 0xFF, 0x41, 0x42} // BOM + "AB" (no null bytes)
	err := SanitizeXMLInput(input)
	require.Error(t, err)
	assert.NotEmpty(t, err.Error())
}

func TestSanitizeXMLInput_RejectsUTF16BOM_LE_CheckMessage(t *testing.T) {
	// Use exactly two BOM bytes so null-byte check passes, proving the BOM
	// check fires and returns the UTF-16 message.
	input := []byte{0xFF, 0xFE}
	err := SanitizeXMLInput(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UTF-16")
}

func TestSanitizeXMLInput_RejectsUTF16BOM_BE_CheckMessage(t *testing.T) {
	input := []byte{0xFE, 0xFF}
	err := SanitizeXMLInput(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UTF-16")
}

func TestSanitizeXMLInput_RejectsNonUTF8EncodingDeclaration(t *testing.T) {
	cases := []string{
		`<?xml version="1.0" encoding="UTF-16"?>`,
		`<?xml version="1.0" encoding="ISO-8859-1"?>`,
		`<?xml version="1.0" encoding="Windows-1252"?>`,
		`<?xml version="1.0" encoding='Shift_JIS'?>`,
	}
	for _, c := range cases {
		c := c
		t.Run(c, func(t *testing.T) {
			err := SanitizeXMLInput([]byte(c))
			require.Error(t, err)
			assert.True(t,
				strings.Contains(err.Error(), "non-UTF-8") || strings.Contains(err.Error(), "UTF-8"),
				"expected encoding error, got: %v", err)
		})
	}
}

func TestSanitizeXMLInput_AcceptsUTF8EncodingDeclaration(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?><foo/>`)
	// UTF-8 is not listed in the rejected encoding pattern.
	err := SanitizeXMLInput(input)
	assert.NoError(t, err)
}

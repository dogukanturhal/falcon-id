// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"bytes"
	"fmt"
	"regexp"
)

// maxXMLSize is the maximum allowed size for any SAML XML document (1 MB).
const maxXMLSize = 1 << 20

// xmlDangerousPatterns detects DOCTYPE, ENTITY, and SYSTEM declarations that
// could indicate XXE payloads. Go's encoding/xml does not resolve external
// entities, but we reject these as defense-in-depth.
var xmlDangerousPatterns = regexp.MustCompile(
	`(?i)(<!DOCTYPE|<!ENTITY|SYSTEM\s+["']|PUBLIC\s+["'])`,
)

// xmlEncodingPattern detects XML declarations that specify a non-UTF-8 encoding.
// We only support UTF-8; documents declaring other encodings are rejected to
// prevent parser confusion and encoding-based attacks.
var xmlEncodingPattern = regexp.MustCompile(`(?i)<\?xml[^?]*encoding\s*=\s*["'](?i:(?:utf-16|utf-32|iso-|windows-|shift[_-]?jis|euc))`)

// SanitizeXMLInput validates raw XML bytes before they are parsed.
// It rejects documents that:
//   - exceed the maximum allowed size
//   - contain DOCTYPE/ENTITY/SYSTEM declarations (XXE defense-in-depth)
//   - contain null bytes
//   - are empty
//
// Returns nil if the input is safe, or an error describing the violation.
func SanitizeXMLInput(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty XML input")
	}
	if len(data) > maxXMLSize {
		return fmt.Errorf("XML input exceeds maximum allowed size (%d bytes)", maxXMLSize)
	}
	if bytes.ContainsRune(data, 0) {
		return fmt.Errorf("XML input contains null bytes")
	}
	// Reject UTF-16 BOM (we only support UTF-8).
	if len(data) >= 2 && ((data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF)) {
		return fmt.Errorf("XML input uses UTF-16 encoding; only UTF-8 is supported")
	}
	if xmlDangerousPatterns.Match(data) {
		return fmt.Errorf("XML input contains prohibited DTD/entity declarations")
	}
	if xmlEncodingPattern.Match(data) {
		return fmt.Errorf("XML input declares a non-UTF-8 encoding; only UTF-8 is supported")
	}
	return nil
}

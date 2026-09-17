// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseSPIFFETrustDomain extracts the trust domain from a SPIFFE ID.
//
// Input:  "spiffe://example.com/workload/api-server"
// Output: "example.com", nil
//
// The SPIFFE specification (https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)
// defines a SPIFFE ID as "spiffe://<trust-domain>/<workload-path>".  The trust
// domain is the authority component (host[:port]) of that URI.
func ParseSPIFFETrustDomain(spiffeID string) (string, error) {
	if err := ValidateSPIFFEID(spiffeID); err != nil {
		return "", err
	}
	u, err := url.Parse(spiffeID)
	if err != nil {
		return "", fmt.Errorf("spiffe: parse ID %q: %w", spiffeID, err)
	}
	return u.Host, nil
}

// ValidateSPIFFEID checks that a SPIFFE ID conforms to the SPIFFE specification.
//
// Requirements enforced:
//   - Scheme must be exactly "spiffe" (case-sensitive).
//   - Authority (trust domain) must be non-empty.
//   - Trust domain must not contain upper-case letters, slashes, or control
//     characters (SPIFFE spec §2).
//   - Path must be present and start with "/" followed by at least one character.
//   - The ID must not contain a query string or fragment.
func ValidateSPIFFEID(spiffeID string) error {
	if spiffeID == "" {
		return fmt.Errorf("spiffe: ID must not be empty")
	}

	u, err := url.Parse(spiffeID)
	if err != nil {
		return fmt.Errorf("spiffe: malformed ID %q: %w", spiffeID, err)
	}

	if u.Scheme != "spiffe" {
		return fmt.Errorf("spiffe: scheme must be \"spiffe\", got %q", u.Scheme)
	}

	if u.Host == "" {
		return fmt.Errorf("spiffe: trust domain (authority) must not be empty")
	}

	// Trust domain must be all lower-case and must not contain a path separator.
	// We check for upper-case letters as a proxy for the broader requirement.
	if u.Host != strings.ToLower(u.Host) {
		return fmt.Errorf("spiffe: trust domain %q must be lower-case", u.Host)
	}

	// A valid SPIFFE ID must have a non-trivial workload path ("/something").
	if u.Path == "" || u.Path == "/" {
		return fmt.Errorf("spiffe: ID %q must include a workload path after the trust domain", spiffeID)
	}

	if u.RawQuery != "" {
		return fmt.Errorf("spiffe: ID must not contain a query string")
	}

	if u.Fragment != "" {
		return fmt.Errorf("spiffe: ID must not contain a fragment")
	}

	return nil
}

// TrustDomainFromIssuer extracts a trust domain string from a provider's
// issuer URL.  For SPIFFE providers the issuer URL is typically the SPIRE
// server address, e.g. "https://spire.example.com".  This function strips the
// scheme and any trailing path so only the host[:port] authority remains.
//
// Input:  "https://spire.example.com"
// Output: "spire.example.com"
//
// If the input cannot be parsed as a URL the raw input is returned unchanged so
// callers always receive a usable (if possibly imprecise) value.
func TrustDomainFromIssuer(issuerURL string) string {
	if issuerURL == "" {
		return ""
	}
	u, err := url.Parse(issuerURL)
	if err != nil || u.Host == "" {
		// Fall back: strip a leading scheme manually.
		trimmed := strings.TrimPrefix(issuerURL, "https://")
		trimmed = strings.TrimPrefix(trimmed, "http://")
		// Drop any path component.
		if idx := strings.IndexByte(trimmed, '/'); idx != -1 {
			trimmed = trimmed[:idx]
		}
		return trimmed
	}
	return u.Host
}

// DefaultBundleEndpoint returns the conventional JWKS bundle endpoint URL for a
// SPIFFE trust domain.
//
// SPIRE exposes its JWT bundle at this well-known path by default:
//
//	https://<trust-domain>/.well-known/jwks.json
//
// This is used when the provider configuration does not supply an explicit
// jwks_endpoint override.
func DefaultBundleEndpoint(trustDomain string) string {
	return "https://" + trustDomain + "/.well-known/jwks.json"
}

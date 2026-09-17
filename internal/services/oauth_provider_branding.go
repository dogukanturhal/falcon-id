// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"errors"
	"fmt"
	"net/url"
)

// validateBrandingURIs checks that the registered RFC 7591 §2 branding
// URIs (logo_uri, client_uri, tos_uri, policy_uri) satisfy the
// platform's tier-1 contract:
//
//   - URL parses cleanly via net/url.
//   - Scheme is exactly "https" — the consent screen renders these as
//     <a> + <img> elements; allowing http would either trigger mixed-
//     content blocking when /oauth/consent is served over HTTPS (every
//     deploy) or open the door to a request-smuggling RP that hosts
//     branding over HTTP and can intercept end-user impressions.
//   - Has a host segment — guards against rare-but-legal forms like
//     "https:/" or "https:" that net/url accepts.
//   - Length ≤ brandingURIMaxLen (1024) — matches the column width in
//     migration 227 and Microsoft Entra's documented limit.
//
// Each pointer is independently optional; a nil value short-circuits to
// "no change requested" so callers can pass the request DTOs verbatim
// without pre-filtering. Empty-string pointers are also no-ops so a
// caller that explicitly clears a field gets validation skipped (the
// store-empty path is handled at the model level).
//
// Done as a free function (not a method on OAuthProviderService) so
// tests don't have to construct a full service to exercise validation.
func validateBrandingURIs(logoURL, clientURI, tosURL, policyURL *string) error {
	for _, e := range []struct {
		name  string
		value *string
	}{
		{"logo_url", logoURL},
		{"client_uri", clientURI},
		{"tos_url", tosURL},
		{"policy_url", policyURL},
	} {
		if err := validateBrandingURI(e.name, e.value); err != nil {
			return err
		}
	}
	return nil
}

// brandingURIMaxLen mirrors VARCHAR(1024) in migration 227 and the
// Microsoft Entra documented maximum for these fields.
const brandingURIMaxLen = 1024

func validateBrandingURI(name string, raw *string) error {
	if raw == nil || *raw == "" {
		return nil
	}
	value := *raw
	if len(value) > brandingURIMaxLen {
		return fmt.Errorf("%s exceeds %d characters", name, brandingURIMaxLen)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", name, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("%s must use the https scheme (RFC 7591 §2 + tier-1 mixed-content policy)", name)
	}
	if parsed.Host == "" {
		return errors.New(name + " must include a host")
	}
	return nil
}

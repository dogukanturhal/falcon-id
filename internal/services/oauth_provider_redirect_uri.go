// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// redirectURIMaxLen mirrors the TEXT column allowance and aligns with
// Microsoft Entra's documented per-URI cap of 1024 characters.
const redirectURIMaxLen = 1024

var privateUseSchemeRe = regexp.MustCompile(`^[a-z][a-z0-9.+-]*$`)

// validateRedirectURIs runs validateRedirectURI on every URI in the
// list and returns the first failure. An empty list is permitted —
// non-authorization-code grants register no redirect URIs (RFC 6749
// §3.1.2). The required-non-empty check for authorization_code lives
// in the request DTO Validate() method, not here.
//
// nativeApp tells the validator that the client being registered is
// a RFC 8252 §7.3 native application — i.e. PUBLIC (no client_secret)
// + PKCE-required + first-party. Native apps MAY register loopback
// redirect URIs (http://127.0.0.1/cb, http://localhost/cb, http://[::1]/cb)
// on production tenants — RFC 8252 §7.3 specifies loopback IP
// redirection as the RECOMMENDED redirect mechanism for native apps,
// and OAuth 2.1 §1.4.2 explicitly carves this out from the general
// "no http://" rule. Non-native clients (services, server-side web
// apps) continue to reject loopback on production tenants.
func validateRedirectURIs(tenantType models.TenantType, uris []string, nativeApp bool, schemeDomains []string) error {
	for _, uri := range uris {
		if err := validateRedirectURI(tenantType, uri, nativeApp, schemeDomains); err != nil {
			return err
		}
	}
	return nil
}

// validateRedirectURI enforces the tier-1 redirect-URI policy:
//
//   - URL parses cleanly via net/url.
//   - Length ≤ redirectURIMaxLen.
//   - Scheme is http or https (no custom / no urn: schemes today).
//   - No URL fragment — RFC 6749 §3.1.2 forbids fragments in
//     redirect_uri, since the authorization server appends its own
//     fragment-or-query response on the way back.
//   - No wildcard characters anywhere — OAuth 2.0 Security BCP §4.1.1
//     and OAuth 2.1 draft §1.4.2 mandate strict-string matching.
//   - Tenant-type-aware http/loopback rules:
//
// Customer-tier tenants (customer, internal, trial, partner) — i.e.
// every tenant that serves real production traffic — require
// https:// schemes and reject loopback hosts (localhost, 127.0.0.1,
// [::1], *.localhost). This is the same posture WorkOS Production
// Environments enforce and the OAuth 2.1 baseline.
//
// Sandbox-tier tenants (demo) permit http:// for the localhost /
// 127.0.0.1 / [::1] / *.localhost loopback hosts only — the
// developer-experience exception that Auth0 / WorkOS / Microsoft
// Entra all carve out for non-production environments. https:// is
// still accepted on any host inside a sandbox tenant so cloud-IDE
// callbacks (e.g. https://*.gitpod.io) work without further config.
//
// Empty / unparseable URIs always reject. Same set of checks
// regardless of create-vs-update so the invariant lives in one place.
//
// Free function (not a method) so tests can call it without standing
// up the surrounding OAuthProviderService.
//
// nativeApp toggles the RFC 8252 §7.3 native-app exception: when true,
// loopback hosts are permitted on production tenants AND http:// is
// permitted on loopback hosts (since loopback traffic never traverses
// the network). When false, the existing tier-1 production-vs-sandbox
// policy applies. Callers compute nativeApp from the client's
// registration metadata (IsPublic + RequirePKCE + IsFirstParty in the
// CreateClient path).
func validateRedirectURI(tenantType models.TenantType, raw string, nativeApp bool, schemeDomains []string) error {
	if raw == "" {
		return errors.New("redirect_uri must not be empty")
	}
	if len(raw) > redirectURIMaxLen {
		return fmt.Errorf("redirect_uri exceeds %d characters", redirectURIMaxLen)
	}
	if strings.ContainsRune(raw, '*') {
		return errors.New("redirect_uri must not contain wildcards (OAuth 2.0 Security BCP §4.1.1 / OAuth 2.1 §1.4.2 — strict string match)")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri is not a valid URL: %w", err)
	}
	if parsed.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("redirect_uri must not include a URL fragment (RFC 6749 §3.1.2)")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		// RFC 8252 §7.1 private-use scheme: native clients only, and only
		// when NATIVE_APP_SCHEME_DOMAINS enables the feature.
		if nativeApp && len(schemeDomains) > 0 {
			return validatePrivateUseScheme(raw, schemeDomains)
		}
		return fmt.Errorf("redirect_uri scheme %q is not permitted (http and https only)", parsed.Scheme)
	}
	if parsed.Host == "" {
		return errors.New("redirect_uri must include a host")
	}

	isLoopback := isLoopbackHost(parsed.Host)
	isSandbox := tenantType == models.TenantTypeDemo

	// RFC 8252 §7.3 native-app carve-out — loopback OK on prod tenants,
	// http:// OK on loopback hosts, regardless of tenant tier. The
	// carve-out is intentionally narrow: only public+first-party PKCE
	// clients qualify, gated at the caller (CreateClient/UpdateClient).
	if nativeApp && isLoopback {
		return nil
	}

	if scheme == "http" && !isSandbox {
		return errors.New("redirect_uri must use the https scheme on production-tier tenants")
	}
	if scheme == "http" && isSandbox && !isLoopback {
		return errors.New("redirect_uri with http scheme is only permitted for loopback hosts (localhost / 127.0.0.1 / [::1]) even on sandbox tenants")
	}
	if isLoopback && !isSandbox {
		return errors.New("redirect_uri may not use a loopback host on production-tier tenants — register the dev variant under the dev-sandbox tenant instead OR mark the client as a native app (is_public + require_pkce + is_first_party) per RFC 8252")
	}
	return nil
}

// matchRedirectURI reports whether the requested redirect_uri matches
// any of the URIs the client registered. Returns true on exact string
// match for all URIs. For LOOPBACK redirect URIs (127.0.0.1, ::1,
// localhost), the match is port-fuzzy per RFC 8252 §7.3:
//
//	"The authorization server MUST allow any port to be specified at
//	 the time of the request for loopback IP redirect URIs, to
//	 accommodate clients that obtain an available ephemeral port from
//	 the operating system at the time of the request."
//
// Concrete behaviour:
//   - Registered "http://127.0.0.1/oidc-callback" matches a request
//     "http://127.0.0.1:45829/oidc-callback".
//   - Registered "http://localhost/oidc-callback" matches a request
//     "http://localhost:31337/oidc-callback".
//   - Non-loopback URIs are exact-matched (scheme/host/port/path).
//   - Path comparison stays exact in both modes — only the port is fuzzed.
//
// Free function so the equivalent test_redirect_uri_match.go test
// can drive it directly.
func matchRedirectURI(registered []string, requested string) bool {
	for _, reg := range registered {
		if reg == requested {
			return true
		}
		if loopbackRedirectMatch(reg, requested) {
			return true
		}
	}
	return false
}

// stripBrackets removes the [...] wrapping that IPv6 hosts carry in
// URL.Host when no port is present (net.SplitHostPort only strips
// them when it successfully parses the port).
func stripBrackets(h string) string {
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		return h[1 : len(h)-1]
	}
	return h
}

func loopbackRedirectMatch(registered, requested string) bool {
	r, err1 := url.Parse(registered)
	q, err2 := url.Parse(requested)
	if err1 != nil || err2 != nil {
		return false
	}
	if !strings.EqualFold(r.Scheme, q.Scheme) {
		return false
	}
	rHost, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		rHost = stripBrackets(r.Host)
	}
	qHost, _, err := net.SplitHostPort(q.Host)
	if err != nil {
		qHost = stripBrackets(q.Host)
	}
	if !strings.EqualFold(rHost, qHost) {
		return false
	}
	if !isLoopbackHost(rHost) {
		return false
	}
	// Same scheme + same loopback host + arbitrary ports: match if
	// path + query + fragment are identical. (Fragments are rejected
	// at registration by validateRedirectURI; check anyway for safety.)
	if r.Path != q.Path {
		return false
	}
	if r.RawQuery != q.RawQuery {
		return false
	}
	if r.Fragment != q.Fragment {
		return false
	}
	return true
}

// isLoopbackHost reports whether host is a loopback hostname or
// loopback IP literal. host comes from url.URL.Host which already
// strips brackets from IPv6 literals via net.SplitHostPort, but Host
// can still be "[::1]" or "[::1]:3000" — handle both forms.
func isLoopbackHost(host string) bool {
	// Strip a trailing :port if present. net.SplitHostPort handles
	// IPv6-bracket forms correctly; on failure (no port), host is
	// already the bare host.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	host = strings.ToLower(host)

	switch host {
	case "localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1":
		return true
	}
	if strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// validatePrivateUseScheme checks an RFC 8252 §7.1 private-use URI scheme
// redirect (com.example.app:/oauth/callback). The scheme must be lowercase,
// contain a dot, and be the reversed form of a domain that equals or sits
// under an entry of schemeDomains. Both scheme:/path and scheme://host/path
// are accepted; userinfo, port, fragment and wildcards are not.
func validatePrivateUseScheme(raw string, schemeDomains []string) error {
	scheme, _, _ := strings.Cut(raw, ":")
	if !privateUseSchemeRe.MatchString(scheme) || !strings.Contains(scheme, ".") {
		return fmt.Errorf("redirect_uri scheme %q is not a valid private-use scheme (lowercase reverse-DNS, RFC 8252 §7.1)", scheme)
	}
	if strings.ContainsAny(raw, "*#") {
		return errors.New("redirect_uri must not contain wildcards or a fragment")
	}
	labels := strings.Split(scheme, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	domain := strings.Join(labels, ".")
	allowed := false
	for _, d := range schemeDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && (domain == d || strings.HasSuffix(domain, "."+d)) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("redirect_uri scheme %q is not under an allowed native app domain", scheme)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri is not a valid URL: %w", err)
	}
	if parsed.User != nil || parsed.Port() != "" || strings.Contains(parsed.Host, ":") {
		return errors.New("redirect_uri private-use scheme must not include userinfo or a port")
	}
	if !strings.HasPrefix(parsed.Path, "/") {
		return errors.New("redirect_uri private-use scheme must have a path starting with '/'")
	}
	return nil
}

// validatePostLogoutRedirectURIs applies validatePrivateUseScheme to every
// post-logout URI that is not http(s); http(s) entries are left to the
// existing handling.
func validatePostLogoutRedirectURIs(uris []string, nativeApp bool, schemeDomains []string) error {
	for _, uri := range uris {
		scheme, _, found := strings.Cut(uri, ":")
		if !found || strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https") {
			continue
		}
		if !nativeApp || len(schemeDomains) == 0 {
			return fmt.Errorf("post_logout_redirect_uri scheme %q is not permitted", scheme)
		}
		if err := validatePrivateUseScheme(uri, schemeDomains); err != nil {
			return fmt.Errorf("post_logout_redirect_uri: %w", err)
		}
	}
	return nil
}

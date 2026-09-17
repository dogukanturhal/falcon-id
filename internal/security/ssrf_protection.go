// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// blockedHosts is the list of well-known cloud-metadata and internal endpoints
// that must never be contacted regardless of how DNS resolves them.
var blockedHosts = []string{
	"169.254.169.254",
	"metadata.google.internal",
	"metadata.google.com",
	"100.100.100.200", // Alibaba Cloud
}

// ValidateMetadataURL checks that a metadata URL is safe to fetch:
//   - Must use HTTPS (or HTTP only when allowHTTP is true, e.g. in development)
//   - Must not target well-known cloud metadata endpoints (literal hostname check)
//
// DNS resolution is intentionally omitted here; it is performed at dial time by
// SafeTransport to close the TOCTOU window that arises when a pre-flight check
// and the HTTP client resolve the name independently.
func ValidateMetadataURL(rawURL string, allowHTTP bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if parsed.Scheme != "https" && (parsed.Scheme != "http" || !allowHTTP) {
		return fmt.Errorf("metadata URL must use HTTPS, got %q", parsed.Scheme)
	}

	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("metadata URL has no hostname")
	}

	// Block well-known cloud metadata endpoints by literal hostname.
	for _, blocked := range blockedHosts {
		if strings.EqualFold(host, blocked) {
			return fmt.Errorf("metadata URL targets a blocked host: %s", host)
		}
	}

	return nil
}

// validateSSRFHostname returns an error if host is in the blocked list.
func validateSSRFHostname(host string) error {
	hostLower := strings.ToLower(host)
	for _, blocked := range blockedHosts {
		if hostLower == blocked {
			return fmt.Errorf("SSRF: blocked host %q", host)
		}
	}
	return nil
}

// validateSSRFResolvedIP returns an error if ip represents a private,
// loopback, link-local, or unspecified address.
func validateSSRFResolvedIP(ipStr, host string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("SSRF: resolved to blocked IP %s for host %q", ipStr, host)
	}
	if ip.Equal(net.IPv4zero) || ip.IsUnspecified() {
		return fmt.Errorf("SSRF: resolved to unspecified IP for host %q", host)
	}
	return nil
}

// dialSSRFSafe resolves host, validates all returned IPs against SSRF rules,
// and dials using the first safe IP to avoid a second resolver call.
func dialSSRFSafe(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("SSRF: invalid address %q: %w", addr, err)
	}

	if err := validateSSRFHostname(host); err != nil {
		return nil, err
	}

	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("SSRF: DNS resolution failed for %q: %w", host, err)
	}

	for _, ipStr := range ips {
		if err := validateSSRFResolvedIP(ipStr, host); err != nil {
			return nil, err
		}
	}

	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
}

// SafeTransport returns an *http.Transport that validates resolved IPs at
// connect time to prevent SSRF via DNS rebinding. It blocks connections to
// private, loopback, link-local, and unspecified addresses, as well as any
// hostname in the blockedHosts list. Because the IP check happens inside the
// dialer — after the OS resolves the name for the actual connection — this
// eliminates the TOCTOU race that a pre-flight DNS check leaves open.
func SafeTransport(_ bool) *http.Transport {
	return &http.Transport{
		DialContext: dialSSRFSafe,
	}
}

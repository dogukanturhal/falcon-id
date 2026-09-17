// SPDX-License-Identifier: AGPL-3.0-or-later

// Package middleware exposes helpers for reading the originating client's
// public IP + ISO country code from inbound HTTP requests.
//
// TRUST MODEL (post-the GitOps repository!558, 2026-05-16):
//
//	Falcon-ID is reachable ONLY through APISIX (Linkerd network policy
//	denies all other paths into pod :8080). APISIX is reachable ONLY
//	through Cloudflare Tunnel + OPNsense IP-allowlist at the edge.
//	The path is:
//
//	    user → Cloudflare edge → CF Tunnel → OPNsense → APISIX → falcon-id
//
//	Cloudflare sets `CF-Connecting-IP` (real client public IP) and
//	`CF-IPCountry` (ISO 3166-1 alpha-2) AFTER terminating TLS. Both are
//	stripped + re-stamped at the edge — un-spoofable from outside the
//	cluster. Inside the cluster, mesh net-pol guarantees only APISIX can
//	deliver requests to this pod, so any header on an inbound request
//	necessarily transited Cloudflare's edge then APISIX's edge.
//
//	APISIX's `real-ip` global plugin (chart values key apisix.pluginAttrs)
//	is configured to source from `CF-Connecting-IP` and re-write the
//	upstream `X-Real-IP` header. `CF-IPCountry` is preserved unchanged.
//	So every inbound request reaching falcon-id has:
//
//	    X-Real-IP:    <real client public IP>   (set by APISIX from CF-Connecting-IP)
//	    CF-IPCountry: <ISO 3166-1 alpha-2 or XX> (preserved through APISIX)
//
//	Reading these headers — without a peer-trust gate — is now the
//	correct behavior. The peer gate was a defense against spoofing by
//	cluster-internal callers in the pre-MR!558 world where X-Real-IP
//	was not authoritatively-set; with APISIX now stamping X-Real-IP on
//	EVERY request, any cluster-internal caller would be overwritten by
//	APISIX's own value at the gateway before reaching us. There is no
//	in-cluster path to falcon-id that bypasses APISIX.
//
// CALLER GUIDANCE:
//
//	RemoteAddrIP(r)   — TCP peer (linkerd-proxy / APISIX pod IP).
//	                    Use for service-to-service identity checks where
//	                    the immediate caller's mesh identity matters.
//	                    DO NOT use for audit / session / login-history /
//	                    geo-block / rate-limit-by-client — those need
//	                    the real end-user IP.
//
//	ClientIP(r)       — Real client public IP from X-Real-IP. Falls
//	                    back to RemoteAddrIP on missing / invalid
//	                    header (defensive — happens in local dev and
//	                    unit tests where APISIX is not in the path).
//
//	ClientCountry(r)  — ISO 3166-1 alpha-2 country from CF-IPCountry.
//	                    "" when absent or invalid. "XX" / "T1" (CF's
//	                    Tor / unknown) are sanitized to "" because they
//	                    aren't useful audit values; any other 2-letter
//	                    A-Z value passes through unchanged.
package middleware

import (
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// cfConnectingIPHeader is the Cloudflare-edge-set authoritative real-
// client-IP header. Cloudflare strips any client-provided value at the
// edge and re-sets it itself, so it's the most trusted source of the
// originating client's public IP for any traffic that reaches us
// through Cloudflare (orange-cloud DNS or Tunnel). Preserved unchanged
// by every proxy in our chain (cloudflared → traefik → APISIX → BFF).
// Canonical MIME form per textproto.CanonicalMIMEHeaderKey.
const cfConnectingIPHeader = "Cf-Connecting-Ip"

// xRealIPHeader is the (legacy) APISIX-stamped upstream header carrying
// the real client public IP. Kept as fallback when CF-Connecting-IP is
// absent (e.g. internal traefik path with no Cloudflare hop, or a non-
// CF callsite that explicitly writes X-Real-Ip).
const xRealIPHeader = "X-Real-Ip"

// cfIPCountryHeader is the Cloudflare-set country header (ISO 3166-1
// alpha-2). APISIX preserves it unchanged. Canonical MIME form.
const cfIPCountryHeader = "Cf-Ipcountry"

// RemoteAddrIP extracts the client IP from the TCP-level RemoteAddr of the
// request, stripping the port component.
//
// SECURITY: this returns the immediate TCP peer (linkerd-proxy /
// APISIX pod IP), not the originating client. Use it for service-to-
// service identity checks where the immediate caller's mesh identity
// matters. For audit, session, login-history, geo-block, or
// rate-limit-by-client, use ClientIP(r) — which reads X-Real-IP
// authoritatively stamped by APISIX from CF-Connecting-IP.
//
// For IPv4 the address arrives as "1.2.3.4:port"; for IPv6 as "[::1]:port".
// net.SplitHostPort handles both forms correctly. If the address has no port
// component (unusual but possible in tests) the raw value is returned as-is.
func RemoteAddrIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// No port separator — return the raw value (e.g. a bare IP in tests).
		return r.RemoteAddr
	}
	return host
}

// ClientIP returns the originating client's real public IP, with a
// three-tier preference chain:
//
//  1. `CF-Connecting-IP` — Cloudflare-edge-set, authoritative, stripped+
//     re-set by CF on every inbound request that traverses Cloudflare
//     (orange-cloud or Tunnel). Preserved unchanged through cloudflared
//     → traefik → APISIX → BFF when each proxy trusts the chain (see
//     traefik-public-dmz.yaml `forwardedHeaders.trustedIPs` and the BFF
//     `falcon-id-client` server forwardHeaders allowlist). Single-value
//     header; never spoofable by external clients.
//
//  2. `X-Real-IP` — fallback for callsites that explicitly write the
//     header (some legacy APISIX routes, internal-traefik writes for
//     non-CF traffic, or test fixtures). Treated as authoritative when
//     present because the only path to this pod is through Linkerd-
//     enforced net-policy (no direct external reach).
//
//  3. `RemoteAddrIP(r)` — final fallback to the TCP peer. Matters for
//     local dev (no proxy chain at all) and for unit tests building
//     *http.Request directly.
//
// Returns the first valid (net.ParseIP-able) value. Non-IP garbage
// in either header falls through to the next tier rather than poisoning
// downstream storage.
//
// Output: a non-empty string. Caller-side empty handling is unnecessary
// — the RemoteAddrIP fall-back guarantees a value, even if it is the
// local loopback during testing.
func ClientIP(r *http.Request) string {
	if v := r.Header.Get(cfConnectingIPHeader); v != "" {
		v = strings.TrimSpace(v)
		if ip := net.ParseIP(v); ip != nil {
			return v
		}
		// CF-Connecting-IP present but malformed — fall through.
	}
	if v := r.Header.Get(xRealIPHeader); v != "" {
		// X-Real-IP is a single-value header (unlike X-Forwarded-For's
		// comma-separated chain). Trim whitespace defensively in case
		// upstream picks up a stray space.
		v = strings.TrimSpace(v)
		if ip := net.ParseIP(v); ip != nil {
			return v
		}
		// Header present but not a parsable IP — fall through to the
		// RemoteAddr fall-back rather than return garbage. In prod this
		// branch should be unreachable (APISIX writes a parsed IP); in
		// tests it lets us assert the defensive behavior explicitly.
	}
	return RemoteAddrIP(r)
}

// ClientCountry returns the 2-letter ISO 3166-1 alpha-2 country code that
// Cloudflare reported for the originating client via the `CF-IPCountry`
// request header. Returns "" when:
//
//   - header is absent (local dev / direct test);
//   - header is "XX" (Cloudflare's marker for unknown / non-geolocatable);
//   - header is "T1" (Cloudflare's marker for Tor exit);
//   - header is anything other than two A–Z letters (sanitization guard —
//     don't store garbage in a varchar(2) column).
//
// Cloudflare uses uppercase letters (per ISO 3166-1); we accept any-case
// input and uppercase it before returning so downstream storage is
// canonical. The output is either "" or a two-letter A–Z string.
//
// Trust model: CF-IPCountry, like CF-Connecting-IP, is stripped + re-
// stamped at Cloudflare's edge and passed through APISIX unchanged.
// See the file-level package comment for the full chain.
func ClientCountry(r *http.Request) string {
	cc := strings.TrimSpace(r.Header.Get(cfIPCountryHeader))
	if cc == "" {
		return ""
	}
	cc = strings.ToUpper(cc)
	if cc == "XX" || cc == "T1" {
		// CF's "unknown" + "Tor exit" markers — explicitly NOT a useful
		// audit value (don't pollute the country_code column with them).
		return ""
	}
	if len(cc) != 2 {
		return ""
	}
	for _, r := range cc {
		if r < 'A' || r > 'Z' {
			return ""
		}
	}
	return cc
}

// RealClientIP is the *gin.Context-flavored wrapper around ClientIP.
// Preserved for the existing handler callsites that pass `c` directly;
// new code should prefer ClientIP(r) on the underlying http.Request to
// keep the trust-model gate explicit.
func RealClientIP(c *gin.Context) string {
	return ClientIP(c.Request)
}

// ClientCountryGin is the *gin.Context-flavored wrapper around
// ClientCountry. Same delegation pattern as RealClientIP; preserved for
// the existing call site in auth_handler.go that fans the country into
// clientctx.WithCountry on the request context.
func ClientCountryGin(c *gin.Context) string {
	return ClientCountry(c.Request)
}

// IPGeo holds the per-request geo attribution stamped by the
// `id-hexxlock-geo-stamp` Cloudflare Worker (infrastructure-iac MR-114).
// All fields are best-effort — any single field is "" when Cloudflare's
// `request.cf` object did not have that property at the edge.
//
// Lifecycle: the Worker reads `request.cf.{asn,asOrganization,city,...}`
// at edge time and stamps it onto request headers (X-Geo-*). falcon-id
// reads those headers via ClientGeo() at the trust boundary in
// auth_handler.go::Login, stamps the result onto the request context via
// clientctx.WithGeo, and AuthService.createSession (auth_credentials_
// service.go) reads it back and persists the relevant fields on
// iam_sessions (asn / asn_org / city / region / is_vpn_hint).
//
// IsVPNHint is the only derived field. It is set to true when ASNOrg
// matches the curated regex of known VPN providers + hosting / cloud
// ASNs (see vpnHintRegexp). False positives are biased toward "looks
// like a VPN" rather than "looks like a real ISP" — the UI surfaces a
// neutral [VPN] badge, not a security verdict.
type IPGeo struct {
	ASN        string // numeric, "13335" — kept as string to round-trip CF's wire form unchanged
	ASNOrg     string // "Vodafone Mobile", "NordVPN", "DigitalOcean LLC", ...
	City       string // "Istanbul"
	Region     string // "Istanbul Province"
	RegionCode string // "34"
	Country    string // 2-letter ISO 3166-1 alpha-2; DUPLICATES CF-IPCountry but useful for sanity-check
	Continent  string // "AS"
	Timezone   string // "Europe/Istanbul"
	Latitude   string // CF emits decimal-string form (e.g. "41.0082")
	Longitude  string // CF emits decimal-string form
	Colo       string // CF datacenter IATA-ish 3-letter code, "IST", "FRA", ...
	IsVPNHint  bool   // derived: ASNOrg matches a known VPN/datacenter pattern
}

// Worker-stamped header names. Canonical MIME form per
// textproto.CanonicalMIMEHeaderKey — Go's net/http normalises arbitrary-
// case headers on read, but we use the canonical form for grep-ability
// and to keep test fixtures predictable.
const (
	xGeoASN        = "X-Geo-Asn"
	xGeoASNOrg     = "X-Geo-As-Org"
	xGeoCity       = "X-Geo-City"
	xGeoRegion     = "X-Geo-Region"
	xGeoRegionCode = "X-Geo-Region-Code"
	xGeoCountry    = "X-Geo-Country"
	xGeoContinent  = "X-Geo-Continent"
	xGeoTimezone   = "X-Geo-Timezone"
	xGeoLatitude   = "X-Geo-Latitude"
	xGeoLongitude  = "X-Geo-Longitude"
	xGeoColo       = "X-Geo-Colo"
)

// vpnHintRegexp matches AS organization names that are very likely to be
// VPN providers, datacenter hosts, or cloud platforms. Case-insensitive.
// Curated from:
//
//   - Known commercial VPNs (NordVPN, Mullvad, ProtonVPN, ExpressVPN,
//     Surfshark, CyberGhost, Private Internet Access, IPVanish, ...)
//   - Major cloud / hosting providers commonly used as VPN egress
//     (DigitalOcean, AWS / Amazon, GCP / Google Cloud, Azure /
//     Microsoft, OVH, Hetzner, Linode / Akamai, Vultr, Leaseweb, M247)
//   - Generic hosting markers ("hosting", "data center", "cloud",
//     "server", "vps")
//
// Intentionally NOT in the list:
//
//   - Residential ISPs (Vodafone, Turk Telekom, AT&T, Comcast, Deutsche
//     Telekom, ...) — these are the "looks like a real user" baseline.
//   - Mobile carriers (which often have "Mobile" in the AS org name;
//     the regex deliberately avoids that token).
//
// Tradeoff: cloud-deployed corporate / SSO-tunnel users (e.g., an
// employee browsing through a corp AWS PrivateLink) will be flagged
// as VPN. The badge is informational, not a block — the user-facing
// effect is just a label, never a rejection.
//
// Updates: this list is maintained in code (not config / external feed)
// so every change goes through MR review and ships unit-tested. For a
// full-fidelity VPN/Tor/proxy DB upgrade, the next step is MaxMind
// GeoIP2 Anonymous IP or IPinfo.io Privacy Detection — both are paid
// and would replace this regex with a DB lookup.
var vpnHintRegexp = regexp.MustCompile(`(?i)\b(` + strings.Join([]string{
	// Commercial VPN providers
	"nordvpn", "mullvad", "protonvpn", "expressvpn", "surfshark",
	"cyberghost", "private internet access", "ipvanish", "vyprvpn",
	"tunnelbear", "hidemyass", "purevpn", "windscribe", "torguard",
	"perfect privacy", "airvpn", "ovpn",
	// Generic VPN tokens
	"vpn",
	// Major clouds / hosting (high VPN-exit incidence)
	"digitalocean", "linode", "akamai", "vultr", "ovh", "hetzner",
	"leaseweb", "m247", "online s.a.s",
	"amazon", "aws", "ec2",
	"google cloud", "gcp",
	"azure", "microsoft corp",
	"oracle cloud",
	"contabo", "scaleway", "upcloud", "ionos",
	"choopa", "psychz",
	// Generic hosting markers
	"hosting", "data center", "datacenter", "cloud services", "server",
}, "|") + `)\b`)

// ClientGeo returns the geo attribution stamped onto the request by the
// `id-hexxlock-geo-stamp` Cloudflare Worker. Returns a zero-value IPGeo
// (all fields "") when no headers are present — e.g. when the Worker
// has not yet been deployed, when the route is not under the Worker's
// route pattern (id.hexxlock.com/api/v1/auth/* + id.hexxlock.com/oauth/*),
// or during local-dev / unit tests that build *http.Request directly
// without a proxy chain.
//
// IsVPNHint is computed locally from ASNOrg via vpnHintRegexp; the
// Worker stamps only raw fields so VPN classification is a Go-side
// concern and ships unit-tested.
//
// Trust model: see the file-level package doc. The cf object the Worker
// reads from is set by Cloudflare's edge on every request and is not
// spoofable by clients; the Worker additionally strips client-provided
// X-Geo-* headers before stamping. So the headers we read here can be
// trusted as edge-stamped — same chain as CF-Connecting-IP and
// CF-IPCountry.
func ClientGeo(r *http.Request) IPGeo {
	geo := IPGeo{
		ASN:        strings.TrimSpace(r.Header.Get(xGeoASN)),
		ASNOrg:     strings.TrimSpace(r.Header.Get(xGeoASNOrg)),
		City:       strings.TrimSpace(r.Header.Get(xGeoCity)),
		Region:     strings.TrimSpace(r.Header.Get(xGeoRegion)),
		RegionCode: strings.TrimSpace(r.Header.Get(xGeoRegionCode)),
		Country:    strings.ToUpper(strings.TrimSpace(r.Header.Get(xGeoCountry))),
		Continent:  strings.ToUpper(strings.TrimSpace(r.Header.Get(xGeoContinent))),
		Timezone:   strings.TrimSpace(r.Header.Get(xGeoTimezone)),
		Latitude:   strings.TrimSpace(r.Header.Get(xGeoLatitude)),
		Longitude:  strings.TrimSpace(r.Header.Get(xGeoLongitude)),
		Colo:       strings.ToUpper(strings.TrimSpace(r.Header.Get(xGeoColo))),
	}
	if geo.ASNOrg != "" {
		geo.IsVPNHint = vpnHintRegexp.MatchString(geo.ASNOrg)
	}
	return geo
}

// ClientGeoGin is the *gin.Context-flavored wrapper around ClientGeo.
// Mirrors RealClientIP / ClientCountryGin for the existing call-site
// shape in auth_handler.go.
func ClientGeoGin(c *gin.Context) IPGeo {
	return ClientGeo(c.Request)
}

// The context-propagation helpers (WithClientCountry / ClientCountryFromContext)
// live in pkg/clientctx so both middleware and services can import them
// without creating a cycle (middleware → services, services → clientctx
// — no edge back to middleware).

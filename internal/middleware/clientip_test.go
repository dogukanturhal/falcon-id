// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// Test that RemoteAddrIP strips the port and accepts both IPv4 / IPv6 / no-port forms.
func TestRemoteAddrIP_StripsPortAndHandlesShapes(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"ipv4 with port", "1.2.3.4:5678", "1.2.3.4"},
		{"ipv6 with port", "[::1]:5678", "::1"},
		{"no port (bare ipv4)", "1.2.3.4", "1.2.3.4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			got := RemoteAddrIP(r)
			if got != tc.want {
				t.Fatalf("RemoteAddrIP(%q) = %q, want %q", tc.remoteAddr, got, tc.want)
			}
		})
	}
}

// ClientIP_ReadsXRealIP — header present + valid → returned.
func TestClientIP_ReadsXRealIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.42.1.89:54321" // APISIX pod IP — should NOT be returned
	r.Header.Set("X-Real-IP", "203.0.113.5")
	if got := ClientIP(r); got != "203.0.113.5" {
		t.Fatalf("ClientIP() = %q, want %q (X-Real-IP value)", got, "203.0.113.5")
	}
}

// ClientIP_ReadsIPv6XRealIP — IPv6 also valid.
func TestClientIP_ReadsIPv6XRealIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.42.1.89:54321"
	r.Header.Set("X-Real-IP", "2001:db8::1")
	if got := ClientIP(r); got != "2001:db8::1" {
		t.Fatalf("ClientIP() = %q, want %q (IPv6 X-Real-IP)", got, "2001:db8::1")
	}
}

// ClientIP_FallsBackToRemoteAddr — header absent → RemoteAddr returned.
func TestClientIP_FallsBackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.42.1.89:54321"
	// No X-Real-IP header set.
	if got := ClientIP(r); got != "10.42.1.89" {
		t.Fatalf("ClientIP() = %q, want %q (RemoteAddr fall-back)", got, "10.42.1.89")
	}
}

// ClientIP_RejectsInvalidIP — header with non-IP garbage → falls back.
func TestClientIP_RejectsInvalidIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.42.1.89:54321"
	r.Header.Set("X-Real-IP", "not-an-ip-at-all")
	got := ClientIP(r)
	if got == "not-an-ip-at-all" {
		t.Fatalf("ClientIP() returned the unparseable header value %q — must fall back", got)
	}
	if got != "10.42.1.89" {
		t.Fatalf("ClientIP() = %q, want %q (RemoteAddr fall-back on invalid X-Real-IP)", got, "10.42.1.89")
	}
}

// ClientIP_TrimsWhitespaceInHeader — defensive trim in case upstream picks up a stray space.
func TestClientIP_TrimsWhitespaceInHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.42.1.89:54321"
	r.Header.Set("X-Real-IP", "  203.0.113.5  ")
	if got := ClientIP(r); got != "203.0.113.5" {
		t.Fatalf("ClientIP() = %q, want %q (trim should normalize whitespace)", got, "203.0.113.5")
	}
}

// ClientCountry_ReadsCFIPCountry — header present → returned.
func TestClientCountry_ReadsCFIPCountry(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("CF-IPCountry", "TR")
	if got := ClientCountry(r); got != "TR" {
		t.Fatalf("ClientCountry() = %q, want %q", got, "TR")
	}
}

// ClientCountry_UppercasesLowercaseInput — accept any-case input, store canonical uppercase.
func TestClientCountry_UppercasesLowercaseInput(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("CF-IPCountry", "us")
	if got := ClientCountry(r); got != "US" {
		t.Fatalf("ClientCountry() = %q, want %q (uppercase canonicalization)", got, "US")
	}
}

// ClientCountry_EmptyOnAbsent — header absent → "".
func TestClientCountry_EmptyOnAbsent(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := ClientCountry(r); got != "" {
		t.Fatalf("ClientCountry() = %q, want \"\" (absent header)", got)
	}
}

// ClientCountry_SanitizesUnexpected — bad values (not 2-letter A-Z) → "".
func TestClientCountry_SanitizesUnexpected(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"empty string", ""},
		{"XX unknown marker", "XX"},
		{"T1 tor marker", "T1"},
		{"single letter", "T"},
		{"three letters", "TUR"},
		{"digits", "12"},
		{"mixed alnum", "T2"},
		{"injection-style garbage", "TR'; DROP TABLE--"},
		{"whitespace only", "   "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("CF-IPCountry", tc.value)
			if got := ClientCountry(r); got != "" {
				t.Fatalf("ClientCountry(%q) = %q, want \"\"", tc.value, got)
			}
		})
	}
}

// ClientCountry_TrimsWhitespace — defensive trim before validation.
func TestClientCountry_TrimsWhitespace(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("CF-IPCountry", "  TR  ")
	if got := ClientCountry(r); got != "TR" {
		t.Fatalf("ClientCountry() = %q, want %q (trim should normalize)", got, "TR")
	}
}

// RealClientIP_DelegatesToClientIP — gin wrapper returns the same value.
func TestRealClientIP_DelegatesToClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.RemoteAddr = "10.42.1.89:54321"
	c.Request.Header.Set("X-Real-IP", "203.0.113.5")

	if got := RealClientIP(c); got != "203.0.113.5" {
		t.Fatalf("RealClientIP(c) = %q, want %q", got, "203.0.113.5")
	}
}

// ClientCountryGin_DelegatesToClientCountry — gin wrapper returns the same value.
func TestClientCountryGin_DelegatesToClientCountry(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("CF-IPCountry", "TR")

	if got := ClientCountryGin(c); got != "TR" {
		t.Fatalf("ClientCountryGin(c) = %q, want %q", got, "TR")
	}
}

// ClientIP_PrefersCFConnectingIPOverXRealIP — when both are present,
// CF-Connecting-IP wins (tier-1 trust order: Cloudflare-edge-stamped
// header is the most authoritative source).
func TestClientIP_PrefersCFConnectingIPOverXRealIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.42.1.89:54321"
	r.Header.Set("X-Real-IP", "203.0.113.5")          // would have won pre-MR
	r.Header.Set("CF-Connecting-IP", "198.51.100.42") // should win now
	if got := ClientIP(r); got != "198.51.100.42" {
		t.Fatalf("ClientIP() = %q, want %q (CF-Connecting-IP must beat X-Real-IP)", got, "198.51.100.42")
	}
}

// ClientIP_ReadsCFConnectingIPWhenOnlyHeader — typical accounts BFF path:
// CF-Connecting-IP forwarded from cloudflared, no X-Real-IP synthesized.
func TestClientIP_ReadsCFConnectingIPWhenOnlyHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.42.1.89:54321"
	r.Header.Set("CF-Connecting-IP", "198.51.100.42")
	if got := ClientIP(r); got != "198.51.100.42" {
		t.Fatalf("ClientIP() = %q, want %q", got, "198.51.100.42")
	}
}

// ClientIP_FallsThroughOnInvalidCFConnectingIP — malformed CF header
// falls through to X-Real-IP rather than poisoning audit rows.
func TestClientIP_FallsThroughOnInvalidCFConnectingIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.42.1.89:54321"
	r.Header.Set("CF-Connecting-IP", "junk-not-an-ip")
	r.Header.Set("X-Real-IP", "203.0.113.5")
	if got := ClientIP(r); got != "203.0.113.5" {
		t.Fatalf("ClientIP() = %q, want %q (malformed CF-Connecting-IP must fall through to X-Real-IP)", got, "203.0.113.5")
	}
}

// ----------------------------------------------------------------------------
// ClientGeo — Cloudflare Worker `id-hexxlock-geo-stamp` X-Geo-* headers
// ----------------------------------------------------------------------------

// ClientGeo_PopulatesFromHeaders — happy path: every X-Geo-* header set,
// every field populated, country/continent uppercased, IsVPNHint false
// for a residential ISP AS organization.
func TestClientGeo_PopulatesFromHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Geo-ASN", "28658")
	r.Header.Set("X-Geo-AS-Org", "Turk Telekom")
	r.Header.Set("X-Geo-City", "Istanbul")
	r.Header.Set("X-Geo-Region", "Istanbul Province")
	r.Header.Set("X-Geo-Region-Code", "34")
	r.Header.Set("X-Geo-Country", "tr") // lowercase on wire — middleware should uppercase
	r.Header.Set("X-Geo-Continent", "as")
	r.Header.Set("X-Geo-Timezone", "Europe/Istanbul")
	r.Header.Set("X-Geo-Latitude", "41.0082")
	r.Header.Set("X-Geo-Longitude", "28.9784")
	r.Header.Set("X-Geo-Colo", "ist")

	g := ClientGeo(r)
	if g.ASN != "28658" {
		t.Errorf("ASN = %q, want %q", g.ASN, "28658")
	}
	if g.ASNOrg != "Turk Telekom" {
		t.Errorf("ASNOrg = %q, want %q", g.ASNOrg, "Turk Telekom")
	}
	if g.City != "Istanbul" {
		t.Errorf("City = %q, want %q", g.City, "Istanbul")
	}
	if g.Region != "Istanbul Province" {
		t.Errorf("Region = %q, want %q", g.Region, "Istanbul Province")
	}
	if g.RegionCode != "34" {
		t.Errorf("RegionCode = %q, want %q", g.RegionCode, "34")
	}
	if g.Country != "TR" {
		t.Errorf("Country = %q, want %q (must uppercase)", g.Country, "TR")
	}
	if g.Continent != "AS" {
		t.Errorf("Continent = %q, want %q (must uppercase)", g.Continent, "AS")
	}
	if g.Timezone != "Europe/Istanbul" {
		t.Errorf("Timezone = %q, want %q", g.Timezone, "Europe/Istanbul")
	}
	if g.Latitude != "41.0082" {
		t.Errorf("Latitude = %q, want %q", g.Latitude, "41.0082")
	}
	if g.Longitude != "28.9784" {
		t.Errorf("Longitude = %q, want %q", g.Longitude, "28.9784")
	}
	if g.Colo != "IST" {
		t.Errorf("Colo = %q, want %q (must uppercase)", g.Colo, "IST")
	}
	if g.IsVPNHint {
		t.Errorf("IsVPNHint = true, want false for residential ISP %q", g.ASNOrg)
	}
}

// ClientGeo_ReturnsZeroWhenAbsent — pre-Worker / local-dev / unit-test
// path: no X-Geo-* headers set, every field "", IsVPNHint false (no org
// to classify against).
func TestClientGeo_ReturnsZeroWhenAbsent(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	g := ClientGeo(r)
	if g != (IPGeo{}) {
		t.Errorf("ClientGeo() = %+v, want zero IPGeo (no headers set)", g)
	}
}

// ClientGeo_TrimsWhitespace — header values arrive with whitespace
// (some proxies / Cloudflare middleware adds a leading space). Trim
// before stamping so downstream `if val != ""` checks behave.
func TestClientGeo_TrimsWhitespace(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Geo-City", "  Istanbul  ")
	r.Header.Set("X-Geo-AS-Org", "  Turk Telekom\t")
	g := ClientGeo(r)
	if g.City != "Istanbul" {
		t.Errorf("City = %q, want trimmed %q", g.City, "Istanbul")
	}
	if g.ASNOrg != "Turk Telekom" {
		t.Errorf("ASNOrg = %q, want trimmed %q", g.ASNOrg, "Turk Telekom")
	}
}

// ClientGeo_VPNHint_DetectsKnownProviders — the curated regex catches
// the obvious VPN providers + hosting / cloud ASNs that are commonly
// used as VPN egress. Residential ISPs and mobile carriers must NOT
// match (they're the baseline "real user" case).
func TestClientGeo_VPNHint_DetectsKnownProviders(t *testing.T) {
	cases := []struct {
		asnOrg     string
		wantIsVPN  bool
	}{
		// Commercial VPN providers
		{"NordVPN S.A.", true},
		{"Mullvad VPN AB", true},
		{"Proton AG", false}, // not "ProtonVPN" — generic Proton AG (mail) shouldn't fire
		{"ProtonVPN AG", true},
		{"Express VPN International Ltd", true}, // "VPN" token alone fires
		{"Surfshark Ltd", true},
		// Major clouds / hosting
		{"DigitalOcean LLC", true},
		{"Linode LLC", true},
		{"Vultr Holdings LLC", true},
		{"OVH SAS", true},
		{"Hetzner Online GmbH", true},
		{"Amazon.com Inc.", true},
		{"GOOGLE CLOUD", true},
		{"Microsoft Corp", true},
		{"M247 Ltd", true},
		// Generic hosting markers
		{"Some Random Hosting Provider", true},
		{"DataCenter Operations Ltd", true},
		// Residential / mobile — must NOT fire
		{"Vodafone Mobile", false},
		{"Turk Telekom", false},
		{"AT&T Services Inc.", false},
		{"Comcast Cable Communications", false},
		{"Deutsche Telekom AG", false},
		{"Iliad SA", false},
		// Empty / unknown
		{"", false},
		{"Some Boutique ISP", false},
	}
	for _, tc := range cases {
		t.Run(tc.asnOrg, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.asnOrg != "" {
				r.Header.Set("X-Geo-AS-Org", tc.asnOrg)
			}
			g := ClientGeo(r)
			if g.IsVPNHint != tc.wantIsVPN {
				t.Errorf("ClientGeo(%q).IsVPNHint = %v, want %v",
					tc.asnOrg, g.IsVPNHint, tc.wantIsVPN)
			}
		})
	}
}

// ClientGeo_VPNHint_OnlyWhenASNOrgPresent — IsVPNHint should be false
// when ASNOrg is empty (no org to classify against), even if other
// fields are populated. This prevents a stamped-false from looking
// like a confirmed "this user is not on VPN" — without the org name
// we genuinely don't know, and downstream persists NULL.
func TestClientGeo_VPNHint_OnlyWhenASNOrgPresent(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Geo-City", "Istanbul")
	r.Header.Set("X-Geo-Country", "TR")
	// No ASN org set.
	g := ClientGeo(r)
	if g.IsVPNHint {
		t.Errorf("IsVPNHint = true with no ASNOrg, want false")
	}
}

// ClientGeoGin — the *gin.Context wrapper just delegates. Smoke test
// so we get a regression bell if the wrapper accidentally diverges.
func TestClientGeoGin_DelegatesToClientGeo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("X-Geo-City", "Istanbul")
	c.Request.Header.Set("X-Geo-AS-Org", "NordVPN")
	g := ClientGeoGin(c)
	if g.City != "Istanbul" || !g.IsVPNHint {
		t.Errorf("ClientGeoGin() = %+v, want City=Istanbul + IsVPNHint=true", g)
	}
}

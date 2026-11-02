// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// These tests cover the OP-side HTML rendering of OIDC Front-Channel
// Logout 1.0 iframes. The end-to-end behaviour (DB → service → handler)
// is covered by service-level tests in
// internal/services/frontchannel_logout_service_test.go; here we
// exercise the HTML escaping and delay-budget computation that lives
// in the handler.

func TestRenderFCLIFrames_NoIFrames_ReturnsEmptyAndMinDelay(t *testing.T) {
	html, delay := renderFCLIFrames(nil)
	assert.Empty(t, html)
	assert.Equal(t, fclMinRedirectDelayMS, delay,
		"with no iframes only the cookie-clear race-protection window applies")
}

func TestRenderFCLIFrames_OneIFrame_RendersHiddenWithSecureAttrs(t *testing.T) {
	html, delay := renderFCLIFrames([]services.FrontchannelLogoutIFrame{
		{ClientID: "svc-talon", Src: "https://auth.internal.example.com/auth/frontchannel-logout?iss=https%3A%2F%2Fid.hexxlock.com&sid=abc"},
	})

	// HTML structure
	assert.Contains(t, html, `class="fcl"`, "iframe must use the .fcl class so display:none from the page CSS hides it")
	assert.Contains(t, html, `loading="eager"`, "FCL iframes must load eagerly — lazy-load defeats the cascade for hidden iframes")
	assert.Contains(t, html, `referrerpolicy="no-referrer"`, "MUST NOT leak the iframe URL via Referer")
	assert.Contains(t, html, `<!-- fcl: svc-talon -->`, "comment must identify the RP for log inspection")
	assert.Contains(t, html, `src="https://auth.internal.example.com/auth/frontchannel-logout?iss=https%3A%2F%2Fid.hexxlock.com&amp;sid=abc"`,
		"src must be HTML-escaped (& → &amp;)")

	// Delay budget
	assert.Equal(t, fclMinRedirectDelayMS+fclIFrameSettleMS, delay,
		"single iframe adds one settle window")
}

func TestRenderFCLIFrames_MultipleIFrames_ApplyDelayCap(t *testing.T) {
	frames := make([]services.FrontchannelLogoutIFrame, 0, 10)
	for i := 0; i < 10; i++ {
		frames = append(frames, services.FrontchannelLogoutIFrame{
			ClientID: "rp",
			Src:      "https://rp.example.com/fcl",
		})
	}
	html, delay := renderFCLIFrames(frames)
	assert.Equal(t, 10, strings.Count(html, "<iframe "), "one iframe per RP")
	assert.Equal(t, fclMaxRedirectDelayMS, delay,
		"delay must be capped at fclMaxRedirectDelayMS so a misbehaving RP can't stall logout")
}

func TestRenderFCLIFrames_HostileClientIDIsHTMLEscaped(t *testing.T) {
	// A hostile or buggy client_id stored in the DB MUST NOT escape the
	// HTML comment context — defense in depth even though the client_id
	// is admin-controlled at registration time.
	html, _ := renderFCLIFrames([]services.FrontchannelLogoutIFrame{
		{ClientID: `evil"--><script>alert(1)</script>`, Src: "https://example.com/fcl"},
	})
	assert.NotContains(t, html, "<script>alert(1)</script>",
		"raw <script> tag MUST NOT appear in the output")
	assert.Contains(t, html, "&lt;script&gt;",
		"angle brackets MUST be HTML-escaped")
}

func TestRenderFCLIFrames_HostileSrcIsHTMLEscaped(t *testing.T) {
	// FrontchannelLogoutService rebuilds the query and validates HTTPS,
	// but we still HTML-escape the Src here as defense in depth.
	html, _ := renderFCLIFrames([]services.FrontchannelLogoutIFrame{
		{ClientID: "x", Src: `https://a.example.com/fcl?iss=https://id&sid=abc"><script>alert(1)</script>`},
	})
	assert.NotContains(t, html, `"><script>`,
		"attribute-quote breakout MUST be neutralised")
	assert.Contains(t, html, "&#34;", "double quote MUST be escaped to &#34;")
}

func TestBuildLoggedOutPage_NoIFrames_RendersBaseCard(t *testing.T) {
	page := buildLoggedOutPage(nil)
	assert.Contains(t, page, "<title>Signed out — Hexxlock</title>")
	assert.Contains(t, page, "signed out", "signed-out confirmation copy")
	// The fallback card no longer dead-ends: it bounces to the centralized
	// login (/oauth/login) after the FCL settle window, with a <noscript>
	// meta-refresh + visible link fallback. Assert the onward navigation.
	assert.Contains(t, page, `window.location.replace("/oauth/login")`, "JS redirect to centralized login")
	assert.Contains(t, page, `content="0;url=/oauth/login"`, "noscript meta-refresh fallback")
	assert.NotContains(t, page, "<iframe ", "no iframe should be emitted when the slice is nil")
}

func TestBuildLoggedOutPage_WithIFrames_EmbedsHiddenIFrame(t *testing.T) {
	page := buildLoggedOutPage([]services.FrontchannelLogoutIFrame{
		{ClientID: "svc-talon", Src: "https://auth.internal.example.com/auth/frontchannel-logout?iss=x&sid=y"},
	})
	require.Contains(t, page, "<iframe ")
	assert.Contains(t, page, `class="fcl"`)
	// .fcl{display:none} must appear in the inline stylesheet so the
	// iframe is hidden but still triggers the network load.
	assert.Contains(t, page, `.fcl{display:none;}`)
}

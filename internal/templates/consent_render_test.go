// SPDX-License-Identifier: AGPL-3.0-or-later

package templates

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConsentTemplate_RendersBrandingFooter pins the RFC 7591 §2 branding
// behavior: when the client registered TosURL/PolicyURL/ContactEmail,
// the rendered HTML must carry visible <a href> links to each. Mirrors
// what an end-user sees on /oauth/consent for a third-party RP.
func TestConsentTemplate_RendersBrandingFooter(t *testing.T) {
	tmpl, err := template.ParseFS(FS, "consent.html")
	require.NoError(t, err)

	data := map[string]interface{}{
		"ClientID":            "test-client",
		"ClientName":          "Example Client",
		"ClientLogo":          "https://cdn.example.com/logo.png",
		"ClientURI":           "https://example.com",
		"TosURL":              "https://example.com/terms",
		"PolicyURL":           "https://example.com/privacy",
		"ContactEmail":        "support@example.com",
		"Scopes":              []map[string]string{{"Description": "Access your profile"}},
		"Scope":               "openid",
		"State":               "s",
		"Nonce":               "n",
		"RedirectURI":         "https://example.com/cb",
		"CodeChallenge":       "",
		"CodeChallengeMethod": "",
		"ResponseType":        "code",
		"CSRFToken":           "csrf",
	}

	var out bytes.Buffer
	require.NoError(t, tmpl.Execute(&out, data))
	html := out.String()

	assert.Contains(t, html, `href="https://example.com/terms"`,
		"ToS link must render in the footer")
	assert.Contains(t, html, `href="https://example.com/privacy"`,
		"Privacy link must render in the footer")
	assert.Contains(t, html, `href="mailto:support@example.com"`,
		"Contact email must render as mailto: link")
	assert.Contains(t, html, `href="https://example.com"`,
		"Client homepage URI must render under the client name")
	assert.Contains(t, html, `src="https://cdn.example.com/logo.png"`,
		"Logo must render in the app header")
	// External links MUST carry rel=noopener noreferrer per OWASP.
	assert.Contains(t, html, `rel="noopener noreferrer"`,
		"external <a> tags must carry rel=noopener noreferrer")
}

// TestConsentTemplate_OmitsBrandingFooterWhenAllNil pins the negative
// case: if no branding metadata is registered, the footer block does
// not render at all. Avoids an empty "·" separator dangling between
// unset fields.
func TestConsentTemplate_OmitsBrandingFooterWhenAllNil(t *testing.T) {
	tmpl, err := template.ParseFS(FS, "consent.html")
	require.NoError(t, err)

	data := map[string]interface{}{
		"ClientID":            "test-client",
		"ClientName":          "Bare Client",
		"ClientLogo":          "",
		"ClientURI":           "",
		"TosURL":              "",
		"PolicyURL":           "",
		"ContactEmail":        "",
		"Scopes":              []map[string]string{{"Description": "Access your profile"}},
		"Scope":               "openid",
		"State":               "s",
		"Nonce":               "n",
		"RedirectURI":         "https://example.com/cb",
		"CodeChallenge":       "",
		"CodeChallengeMethod": "",
		"ResponseType":        "code",
		"CSRFToken":           "csrf",
	}

	var out bytes.Buffer
	require.NoError(t, tmpl.Execute(&out, data))
	html := out.String()

	// `branding-footer` is also a CSS class name in the <style> block,
	// so look for the rendered footer text + link tags that only appear
	// when at least one of TosURL/PolicyURL/ContactEmail is non-empty.
	assert.NotContains(t, html, "Terms of Service",
		"footer copy must not appear when no fields are set")
	assert.NotContains(t, html, "Privacy Policy",
		"footer copy must not appear when no fields are set")
	assert.NotContains(t, html, "By continuing, you agree",
		"footer preamble must not appear when no fields are set")
}

// TestConsentTemplate_EscapesHTMLInClientName pins XSS hardening: the
// template uses {{.}} (not {{. | safehtml}} or template.HTML), so a
// malicious client_name is HTML-escaped — not rendered as live markup.
// Validates the html/template auto-escape contract is intact for
// the consent surface end-users see.
func TestConsentTemplate_EscapesHTMLInClientName(t *testing.T) {
	tmpl, err := template.ParseFS(FS, "consent.html")
	require.NoError(t, err)

	data := map[string]interface{}{
		"ClientID":            "x",
		"ClientName":          `<script>alert(1)</script>`,
		"ClientLogo":          "",
		"ClientURI":           "",
		"TosURL":              "",
		"PolicyURL":           "",
		"ContactEmail":        "",
		"Scopes":              []map[string]string{},
		"Scope":               "",
		"State":               "",
		"Nonce":               "",
		"RedirectURI":         "",
		"CodeChallenge":       "",
		"CodeChallengeMethod": "",
		"ResponseType":        "code",
		"CSRFToken":           "csrf",
	}

	var out bytes.Buffer
	require.NoError(t, tmpl.Execute(&out, data))
	html := out.String()

	assert.False(t, strings.Contains(html, "<script>alert(1)</script>"),
		"raw <script> must NOT appear — html/template auto-escape must rewrite it")
	assert.Contains(t, html, "&lt;script&gt;alert(1)&lt;/script&gt;",
		"escaped form MUST appear so the client_name is still readable")
}

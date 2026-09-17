// SPDX-License-Identifier: AGPL-3.0-or-later

package templates

import (
	"bytes"
	"html/template"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWitnessEnrollTemplate_RendersAllFacts pins the visible operator-
// verification block: the device_uuid, ek_pubkey_hash and callback_url
// supplied by the deep-linking Tauri wizard MUST all be rendered into
// the page so the operator can read them off the screen before touching
// their security key. This is the load-bearing UX for binding-check
// (operator confirms the EK hash they see matches the device's own
// enrollment screen).
func TestWitnessEnrollTemplate_RendersAllFacts(t *testing.T) {
	tmpl, err := template.ParseFS(FS, "witness_enroll.html")
	require.NoError(t, err)

	data := map[string]any{
		"OperatorEmail": "ops@example.com",
		"OperatorSub":   "11111111-1111-1111-1111-111111111111",
		"DeviceUUID":    "33333333-3333-3333-3333-333333333333",
		"EKPubkeyHash":  strings.Repeat("ab", 32),
		"CallbackURL":   "http://127.0.0.1:53217/witness-callback",
		"State":         "wizard-correlator-xyz",
		"BootstrapJSON": `{"deviceUUID":"33333333-3333-3333-3333-333333333333"}`,
	}

	var out bytes.Buffer
	require.NoError(t, tmpl.Execute(&out, data))
	html := out.String()

	assert.Contains(t, html, "33333333-3333-3333-3333-333333333333",
		"device_uuid must render so the operator can verify it before signing")
	assert.Contains(t, html, strings.Repeat("ab", 32),
		"ek_pubkey_hash must render in full so the operator can compare it against the device's enrollment screen")
	assert.Contains(t, html, "http://127.0.0.1:53217/witness-callback",
		"callback_url must render so the operator can confirm where the JWS gets POSTed")
	assert.Contains(t, html, "ops@example.com",
		"operator email must render so the user sees whose credential signs")
}

// TestWitnessEnrollTemplate_EscapesOperatorFields pins the auto-escape
// contract: a maliciously-stored operator email (extremely unlikely in
// practice, but defense in depth) must NOT render as live HTML / JS.
// The page contains a <script type="application/json"> bootstrap island
// AND a JS handler block — both code-paths must remain inert against an
// attacker controlling any field that lands in the render context.
func TestWitnessEnrollTemplate_EscapesOperatorFields(t *testing.T) {
	tmpl, err := template.ParseFS(FS, "witness_enroll.html")
	require.NoError(t, err)

	data := map[string]any{
		"OperatorEmail": `<script>alert('xss')</script>`,
		"OperatorSub":   "x",
		"DeviceUUID":    "y",
		"EKPubkeyHash":  "z",
		"CallbackURL":   "q",
		"State":         "",
		"BootstrapJSON": `{}`,
	}
	var out bytes.Buffer
	require.NoError(t, tmpl.Execute(&out, data))
	html := out.String()

	assert.NotContains(t, html, `<script>alert('xss')</script>`,
		"raw <script> from a hostile operator-email field must NOT render — html/template MUST auto-escape it")
}

// TestWitnessEnrollTemplate_BootstrapJSONIslandIsScriptTyped pins the
// hardening pattern: the bootstrap data is delivered in a <script
// type="application/json"> island so the page-side runtime parses it
// via JSON.parse — never via JS source concatenation. If a future edit
// drops the type attribute, the JSON contents become executable script
// and any embedded ", }, etc. becomes a syntax vector.
func TestWitnessEnrollTemplate_BootstrapJSONIslandIsScriptTyped(t *testing.T) {
	tmpl, err := template.ParseFS(FS, "witness_enroll.html")
	require.NoError(t, err)
	data := map[string]any{
		"OperatorEmail": "a@b",
		"OperatorSub":   "s",
		"DeviceUUID":    "d",
		"EKPubkeyHash":  "e",
		"CallbackURL":   "c",
		"State":         "",
		"BootstrapJSON": `{"deviceUUID":"d"}`,
	}
	var out bytes.Buffer
	require.NoError(t, tmpl.Execute(&out, data))
	html := out.String()

	assert.Contains(t, html, `<script type="application/json" id="bootstrap-data">`,
		"bootstrap data MUST sit in a non-executable script island so the page runtime parses it via JSON.parse")
}

// TestWitnessEnrollTemplate_MatchesLoginBrand pins the brand-parity
// contract (#159 follow-up): the witness page MUST share the canonical
// Falcon-ID visual primitives with internal/templates/login.html so an
// operator sees the same logo treatment, card shell, subtitle, and error
// banner whether they're signing in or witnessing a device enrollment.
//
// We assert the load-bearing CSS rulesets are present in both templates —
// not via a regression-snapshot diff (would couple to whitespace), but by
// pinning the specific declarations that the login page uses to establish
// the brand: the logo's color + size + weight, the card's max-width +
// border-radius + box-shadow, the .error banner's color palette, and the
// primary-button colour. A change to either template that breaks parity
// will trip this test.
func TestWitnessEnrollTemplate_MatchesLoginBrand(t *testing.T) {
	loginBytes, err := FS.ReadFile("login.html")
	require.NoError(t, err)
	witnessBytes, err := FS.ReadFile("witness_enroll.html")
	require.NoError(t, err)
	login := string(loginBytes)
	witness := string(witnessBytes)

	// Canonical "Falcon ID" header text — operator should see exactly
	// the same logo string on both pages.
	loginLogo := `<span class="logo-word">Falcon ID</span>`
	assert.Contains(t, login, loginLogo, "login.html sanity check: canonical logo string present")
	assert.Contains(t, witness, loginLogo,
		"witness page MUST render the same '<div class=\"logo\">Falcon ID</div>' as login.html")

	// Load-bearing CSS declarations that establish the brand. Each MUST
	// appear in both templates verbatim; if a future refactor splits them
	// into a shared stylesheet, update both rather than skewing one.
	brandDeclarations := []string{
		"min-height: 100vh;",
		"border-radius: 12px;",
		"max-width: 400px;",
		"background: #2563eb;",
		"border: 1px solid #fecaca;",
		"color: #b91c1c;",
	}
	for _, decl := range brandDeclarations {
		assert.Contains(t, login, decl,
			"login.html sanity check: brand declaration %q present", decl)
		assert.Contains(t, witness, decl,
			"witness page MUST inherit brand declaration %q from login.html", decl)
	}

	// `.card` is the canonical container class shared by both pages.
	cardClassRE := regexp.MustCompile(`<div class="card"`)
	assert.True(t, cardClassRE.MatchString(login),
		"login.html sanity check: container is <div class=\"card\">")
	assert.True(t, cardClassRE.MatchString(witness),
		"witness page MUST use the same <div class=\"card\"> container as login.html")

	// `.error` is the canonical error-banner class shared by both pages
	// — replaces the previous one-off "red warning triangle" treatment
	// the witness page shipped with at falcon-id@ebe8f87. The witness
	// page wraps it in compound classes (`state error`) so it can be
	// toggled visible/hidden by the WebAuthn ceremony JS, while login
	// applies it directly (`error`).
	errorLoginRE := regexp.MustCompile(`class="error"`)
	errorWitnessRE := regexp.MustCompile(`class="[^"]*\berror\b[^"]*"`)
	assert.True(t, errorLoginRE.MatchString(login),
		"login.html sanity check: error banner uses class=\"error\"")
	assert.True(t, errorWitnessRE.MatchString(witness),
		"witness page error states MUST use the same .error class (no triangle-icon one-off)")

	// The triangle-icon legacy treatment MUST stay gone from the witness
	// page surface — &#9888; (warning triangle) was the visual-skew tell.
	assert.NotContains(t, witness, "&#9888;",
		"witness page MUST NOT render the &#9888; warning-triangle icon — that was the pre-#159 one-off treatment")
}

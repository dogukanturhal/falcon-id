// SPDX-License-Identifier: AGPL-3.0-or-later

// Package templates provides HTML template rendering utilities.
package templates

import "embed"

// FS exposes the login/consent/etc. HTML templates baked into the
// binary at compile time via the //go:embed directive below. The
// OAuth provider handler reads this FS via template.ParseFS to render
// the /authorize login and consent pages.
//
// Without the //go:embed directive this variable is a zero-value
// embed.FS (empty), which causes template.ParseFS to return
// "template: pattern matches no files" at first OAuth request — a
// latent bug that manifests only when a user actually hits the
// authorization flow.
//
//go:embed *.html
var FS embed.FS

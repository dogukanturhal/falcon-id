// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"html/template"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/templates"
)

func hostedBrand(continuation string) string {
	u, err := url.Parse(continuation)
	if err == nil && u.Host == "" && u.Path == "/oauth/authorize" && u.Query().Get("client_id") == "acmeapp-bff" {
		return "AcmeApp"
	}
	return "Falcon ID"
}

func renderAcmeAppLogoutFallback(c *gin.Context, client *models.OAuthClient, target string) bool {
	if client == nil || client.ClientID != "acmeapp-bff" {
		return false
	}
	link := ""
	var logo bytes.Buffer
	if tmpl, err := template.ParseFS(templates.FS, "acmeapp-mark.html"); err == nil {
		_ = tmpl.ExecuteTemplate(&logo, "acmeapp-mark", nil)
	}
	for _, registered := range client.PostLogoutRedirectURIs {
		if registered == target {
			link = target
		}
	}
	body := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>Signed out — AcmeApp</title><style>
:root{color-scheme:light dark;--bg:#f8fafc;--card:#fff;--ink:#18181b;--muted:#64748b}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,system-ui,sans-serif;min-height:100vh;display:grid;place-items:center;padding:16px}.card{width:100%;max-width:400px;padding:32px;background:var(--card);border-radius:24px;border:1px solid #8884}h1{color:#594ce7}a{color:#594ce7}footer{margin-top:24px;color:var(--muted);font-size:12px}@media(prefers-color-scheme:dark){:root{--bg:#09090b;--card:#18181b;--ink:#fafafa;--muted:#a1a1aa}}</style></head><body><main class="card"><h1>AcmeApp</h1><p>You are signed out.</p>`
	body += logo.String()
	if link != "" {
		body += `<a href="` + template.HTMLEscapeString(link) + `">Sign in</a>`
	}
	body += `<footer>Secured by FALCON ID<br>© 2026 HexxLock</footer></main></body></html>`
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, contentTypeHTMLCharset, []byte(body))
	return true
}

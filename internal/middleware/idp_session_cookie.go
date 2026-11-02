// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

// IdpSessionCookieName is the browser SSO cookie carrying the IdP session id.
const IdpSessionCookieName = "falcon_idp_session"

// CookieDomain returns the Domain attribute for Set-Cookie responses:
// COOKIE_DOMAIN if set, else the request host (port stripped), with
// localhost/127.0.0.1 collapsed to "localhost" for cross-port dev sharing.
func CookieDomain(c *gin.Context) string {
	if v := os.Getenv("COOKIE_DOMAIN"); v != "" {
		return v
	}
	host := c.Request.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if host == "localhost" || strings.HasPrefix(host, "127.0.0.1") {
		return "localhost"
	}
	return host
}

// IsSecureEnvironment reports whether cookies must carry the Secure flag.
func IsSecureEnvironment() bool {
	env := os.Getenv("ENVIRONMENT")
	return env == "production" || env == "staging"
}

// SetIdpSessionCookie writes falcon_idp_session. It is the single place the
// cookie attributes are defined: HttpOnly, Secure in prod/staging, Path=/ and
// SameSite=Lax in every environment (the cookie must ride the top-level
// cross-site GET back into /oauth/authorize; Strict drops it, d-254).
func SetIdpSessionCookie(c *gin.Context, value string, maxAge time.Duration) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(IdpSessionCookieName, value, int(maxAge.Seconds()), "/", CookieDomain(c), IsSecureEnvironment(), true)
}

// PresentIdpSession stores the falcon_idp_session cookie UUID (if any) on the
// request context so login services can retire only this browser's old
// session instead of guessing by IP.
func PresentIdpSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		if v, err := c.Cookie(IdpSessionCookieName); err == nil && v != "" {
			if id, perr := uuid.Parse(v); perr == nil {
				c.Request = c.Request.WithContext(redispkg.WithPresentedIdpSession(c.Request.Context(), id))
			}
		}
		c.Next()
	}
}

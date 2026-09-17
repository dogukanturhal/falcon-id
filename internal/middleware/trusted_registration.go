// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import "github.com/gin-gonic/gin"

// CtxKeyTrustedRegistration is the gin.Context key set by
// TrustedRegistration() to signal that the inbound request reached
// the OAuth-client management handlers through a privileged platform-
// internal route (today: /api/v1/internal/oauth-clients/*).
//
// Handlers that mutate "trust" metadata on a client — most importantly
// is_first_party — MUST gate on this flag. The /api/v1/admin/oauth-
// clients/* surface is the browser admin path used by tenant admins
// to manage their own clients; allowing them to mark a client
// is_first_party=true would let a compromised tenant admin promote a
// third-party app past the consent screen, defeating the user-trust
// model OIDC consent is supposed to enforce.
//
// This mirrors the Okta TRUSTED-vs-REQUIRED split where consent_method
// can only be set to TRUSTED via the privileged /api/v1/apps endpoint
// (admin-managed) and Dynamic Client Registration via /api/v1/clients
// is forced to consent_method=REQUIRED.
const CtxKeyTrustedRegistration = "trusted_registration_allowed"

// TrustedRegistration marks the request as coming from a privileged
// platform-internal route. Mount this AFTER ServiceAuth +
// RequireScope("admin:oauth-clients") + BridgeServiceTenantToTenantID
// on the /api/v1/internal/oauth-clients/* group; do NOT mount it on
// any tenant-facing surface.
//
// The handler reads the flag via gin.Context.GetBool — see
// oauth_provider_handler.go CreateClient/UpdateClient for the gate.
func TrustedRegistration() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(CtxKeyTrustedRegistration, true)
		c.Next()
	}
}

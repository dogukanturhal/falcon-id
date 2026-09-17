// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"reflect"
	"sort"

	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// optionalHandlerFields is the set of *Handlers struct field names that are
// allowed to be nil at startup, together with the reason and — where a
// route registrar in cmd/routes.go already gates on the field — which
// routes are consequently absent.
//
// This is a deliberately hand-maintained allowlist: whether a nil handler
// is a startup misconfiguration or an intentionally feature-gated no-op is
// a judgement call only a human can make (see t-team-seats postmortem,
// 2026-09-10 — three routes silently 404'd because nobody could tell
// "wired but disabled" apart from "forgotten"). Every entry here was
// verified against cmd/handlers.go: the field is only ever left nil by an
// explicit `if <dependency> != nil { ... }` guard, never by omission.
//
// validateHandlerWiring (below) is the reflective sweep that keeps this
// list honest going forward: ANY *Handlers field that is nil and NOT
// listed here fails startup, so adding a new handler field without either
// wiring it unconditionally or adding it here (with a reason) is caught
// immediately instead of silently 404ing in production.
var optionalHandlerFields = map[string]string{
	// SSF and CAE are DECLARED on *Handlers but never assigned anywhere in
	// initHandlers — grep for "\.SSF =" / "\.CAE =" returns nothing. They are
	// therefore permanently nil, and every route registered against them has
	// always 404'd silently. That is exactly the defect this assertion exists
	// to surface, and it surfaced it on first deploy (2026-09-10): the canary
	// CrashLooped with missing_handlers ["CAE","SSF"].
	//
	// They are listed here rather than treated as required because failing the
	// whole service shut down authentication platform-wide over two endpoints
	// that have never worked. Startup now says so on every boot instead. The
	// real fix is to construct them (or delete the fields and their routes);
	// until then this is an honest, logged absence rather than a silent one.
	"SSF":              "handler never constructed in initHandlers — Shared Signals Framework stream endpoints unavailable (tracked: wire or remove)",
	"CAE":              "handler never constructed in initHandlers — Continuous Access Evaluation endpoints unavailable (tracked: wire or remove)",
	"Metrics":          "control-plane DB not configured (infra.ControlPlaneDB == nil) — GET /api/v1/platform/metrics/* unavailable",
	"Realm":             "control-plane DB absent, RealmEnabled=false, or realm service unwired — /api/v1/realms/* unavailable",
	"RealmMiddleware":   "same gate as Realm — realm-aware request routing middleware absent, falls back to default realm",
	"PushMFA":           "push MFA provider (FCM/APNs) not configured (services.PushMFA == nil) — push-MFA enroll/challenge routes unavailable",
	"Recovery":          "Redis unavailable (services.Recovery == nil) — /api/v1/users/me/recovery/* unavailable",
	"WebAuthn":          "WebAuthn service not wired (services.WebAuthn == nil) — /api/v1/auth/webauthn/* and passkey step-up routes unavailable",
	"RealmDB":           "realm DB provisioner or realm service not wired — realm-scoped DB admin routes unavailable",
	"ITDR":              "ITDR service not wired (services.ITDR == nil) — /platform/security/threats + /detection-rules unavailable",
	"SpiceDBDebug":      "SpiceDB client not configured (infra.SpiceDBClient == nil) — SpiceDB debug endpoints unavailable",
	"PermissionStream":  "Redis client not configured (infra.RedisClient == nil) — SSE permission-change stream unavailable",
	"InternalStorage":   "MinIO client init failed (best-effort, already logged above at Warn) — presigned-download endpoint returns 503",
	"AvatarUpload":      "MinIO client init failed (best-effort, already logged above at Warn) — avatar upload returns 503",
	"CSRFMiddleware":    "Redis unavailable (already logged above at Warn) — CSRF protection disabled",
}

// validateHandlerWiring reflects over every field of *Handlers and fails
// fast when a field is nil but not present in optionalHandlerFields.
//
// Rationale for reflection over a hand-maintained "required" list: the
// Handlers struct has ~150 fields and grows regularly. A hand-maintained
// required-list rots the same way the missing nil-guard it's meant to
// catch does — someone adds a field, forgets to add it to the list, and
// the check silently stops covering it. Reflection over ALL fields with a
// short, reasoned "optional" allowlist means a newly added field is
// covered by default (fails loud unless deliberately exempted), which is
// the safer failure mode.
//
// Call this immediately after initHandlers() and before registerRoutes()
// so a misconfigured handler is caught before any route referencing it
// (nil-pointer route handlers silently 404 in this codebase — see
// cmd/routes.go's `if handlers.X == nil { return }` registrar guards —
// rather than panicking, which is exactly what makes them silent).
func validateHandlerWiring(h *Handlers) {
	v := reflect.ValueOf(h).Elem()
	t := v.Type()

	var missing []string
	for i := 0; i < t.NumField(); i++ {
		field := v.Field(i)
		// Only pointer/interface fields can meaningfully be nil; skip
		// anything else (there are none today, but a value-typed field
		// added later shouldn't trip this).
		switch field.Kind() {
		case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		default:
			continue
		}
		if !field.IsNil() {
			continue
		}

		name := t.Field(i).Name
		if reason, ok := optionalHandlerFields[name]; ok {
			logger.Info("handler wiring: optional handler absent — feature disabled",
				zap.String("handler", name),
				zap.String("reason", reason),
			)
			continue
		}
		missing = append(missing, name)
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		logger.Fatal("handler wiring: required handler(s) are nil at startup — every route registered against "+
			"them would silently 404 or panic instead of erroring at boot. Either wire the handler unconditionally "+
			"in initHandlers(), or if it's genuinely feature-gated, add it to optionalHandlerFields in "+
			"cmd/handler_wiring.go with the condition and the routes it disables.",
			zap.Strings("missing_handlers", missing),
		)
	}
}

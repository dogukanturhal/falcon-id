// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clientctx propagates request-scoped client metadata
// (originating country code) from the HTTP handler boundary down to the
// services layer via context.Context.
//
// Why a leaf package: internal/middleware imports internal/services, so
// services can't depend on middleware. The context-stamping helpers
// need to be importable by both, so they live in pkg/clientctx — a
// dependency-free leaf both layers reach without creating a cycle.
package clientctx

import "context"

// countryKey is the unexported type-keyed context key used to propagate
// the originating client country code through the request pipeline.
// Type-keyed (not string-keyed) so collisions across packages are
// impossible.
type countryKey struct{}

// WithCountry stamps the country code onto ctx so downstream services
// (e.g. AuthService.buildRiskContext, AuthService.createSession) can
// read it without taking location as an explicit parameter on every
// signature in the auth flow.
//
// Empty cc is a no-op — the returned context is indistinguishable from
// one that was never stamped, so callers can pipe the result of
// middleware.ClientCountry / middleware.ClientCountryGin directly
// through without nil-guarding the happy path.
//
// Design choice: thread location through context rather than every
// signature in Login → assessLoginRisk → buildRiskContext → createSession
// (8+ call sites). Locations are a request-scoped concern, captured
// once at the trust boundary (handler reading CF-IPCountry from the
// proxy chain), then consumed wherever the same request lands. That's
// exactly what context.Context is for.
func WithCountry(ctx context.Context, cc string) context.Context {
	if cc == "" {
		return ctx
	}
	return context.WithValue(ctx, countryKey{}, cc)
}

// CountryFromContext reads the previously-stamped country code. Returns
// "" when not set (no Cloudflare header, untrusted peer, or service
// path that bypassed the handler). Callers should always check for ""
// before using the value as a non-NULL DB column.
func CountryFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(countryKey{}).(string); ok {
		return v
	}
	return ""
}

// Geo is the request-scoped geo snapshot stamped by the
// `geo-stamp` Cloudflare Worker (the edge infrastructure repository).
// Lives in this leaf package so the middleware (which reads it from
// request headers) and the services layer (which persists it on
// iam_sessions) can both reach it without an import cycle.
//
// This mirrors middleware.IPGeo field-for-field. The duplication is
// deliberate: keeping clientctx dependency-free means it can be
// imported anywhere. The boundary conversion lives in auth_handler.go
// next to ClientGeo() — one tiny copy, single source of geo truth.
type Geo struct {
	ASN        string
	ASNOrg     string
	City       string
	Region     string
	RegionCode string
	Country    string
	Continent  string
	Timezone   string
	Latitude   string
	Longitude  string
	Colo       string
	IsVPNHint  bool
}

type geoKey struct{}

// WithGeo stamps the geo snapshot onto ctx so downstream services
// (createSession, audit logging, future risk scoring) can read it
// without taking geo as an explicit parameter on every signature in
// the auth flow. Mirrors the WithCountry pattern.
//
// Zero-value Geo is a no-op (same idempotency as WithCountry's ""
// guard). Callers can pipe the middleware result through without
// nil-guarding the happy path. When the Worker has not yet been
// deployed (or this is the local-dev / unit-test path), ClientGeo
// returns the zero value and we leave ctx untouched.
func WithGeo(ctx context.Context, geo Geo) context.Context {
	if geo == (Geo{}) {
		return ctx
	}
	return context.WithValue(ctx, geoKey{}, geo)
}

// GeoFromContext reads the previously-stamped geo snapshot. Returns
// the zero value when not set (Worker not deployed, route outside the
// Worker's pattern, local-dev path). Callers must check each field
// individually before storing as a non-NULL DB column.
func GeoFromContext(ctx context.Context) Geo {
	if v, ok := ctx.Value(geoKey{}).(Geo); ok {
		return v
	}
	return Geo{}
}

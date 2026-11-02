// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// PlatformAPIAudienceURI is the canonical RFC 8707 / OIDC resource
// indicator for every HexxLock platform API surface served behind the
// `api.example.com` virtual host on APISIX. New services validate this
// as their `Jwt__Audience` (Auth0 / Microsoft Entra / Okta convention).
//
// Every OAuth access token minted by Falcon-ID carries this value as one
// of its `aud` entries so the platform can migrate receivers off the
// legacy single-string audience without lock-step deploys.
//
// Choice rationale (locked 2026-05-30 with user):
//   - Matches the gateway hostname documented in
//     `INTEGRATION_GUIDE.md` (Platform domain table) — explicit, easy
//     to map from incident-time logs to the audience claim.
//   - URI form (not bare slug) — required by RFC 8707 §2 validation
//     and by the audience-confusion defence comment in
//     `oauth_provider_service_tokens.go`.
//   - Single platform-wide identifier — not per-API. This matches the
//     existing "shared service-mesh audience" architecture (analogous
//     to the legacy `hexxlock-services` value). Per-API narrowing is
//     still available via RFC 8707 `resource` parameter — the default
//     just lands on the platform-wide URI.
//
// When the migration is complete (every `Jwt__Audience` deployment is
// updated and verified) we drop `LegacyServiceMeshAudience` from the
// emitted `aud` array. Until then it rides along so unmigrated
// receivers continue to pass token validation.
const PlatformAPIAudienceURI = "https://api.example.com"

// LegacyServiceMeshAudience is the historical hard-coded audience
// value that every .NET service in `example-business` /
// `example-platform` was deployed with (env var `Jwt__Audience:
// hexxlock-services`). It predates the RFC 8707 audience design.
//
// Kept here as a named constant for the duration of the multi-audience
// transition (see `PlatformAPIAudienceURI` doc for the migration plan).
// Every token mint path emits BOTH values; once every receiver
// validates `PlatformAPIAudienceURI` we delete this constant and remove
// it from the `aud` arrays.
const LegacyServiceMeshAudience = "hexxlock-services"

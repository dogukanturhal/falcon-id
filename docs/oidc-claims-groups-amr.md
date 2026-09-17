# Falcon-ID OIDC claims: `groups`, `roles`, `amr`

**Status:** implemented 2026-04-21 — migration 211 + service layer.
**Scope:** adds `groups`, `roles`, and `amr` claims to id_tokens (and the first
two to access tokens when scope-requested), plus `groups` / `roles` to
advertised scopes and all three to `claims_supported`.

## Motivation

`HANDOFF_TIER1_TIERING_PROMPT` Phase B (oauth2-proxy ForwardAuth) and Phase E
(Pomerium IAP) of the Internal/External Access Tiering program require:

- a `groups` claim for group-based authz (so every downstream admin tool —
  Grafana / Argo CD / Harbor / kubectl — can share one identity authz surface),
  and
- an `amr` claim so the identity-aware proxy can gate per-policy on MFA
  without a round-trip to a downstream tool.

Before this change, discovery advertised only
`sub, iss, aud, exp, iat, nonce, name, given_name, family_name, preferred_username, email, email_verified`
and the test tenant (admin@example.com, platform-admin) received id_tokens
with no way for a proxy to authorise on role or MFA.

## Claim shape

| Claim    | Type       | Emitted when                                                     | Source                                                               | Example                                 |
| -------- | ---------- | ---------------------------------------------------------------- | -------------------------------------------------------------------- | --------------------------------------- |
| `groups` | `[]string` | scope `groups` requested AND `"groups" ∈ client.Scopes`          | `GroupService.GetUserGroups(user.ID)` rendered as `/parent/child`    | `["/platform/admins","/ops"]`           |
| `roles`  | `[]string` | scope `roles` requested AND `"roles" ∈ client.Scopes`            | `GroupService.GetUserEffectiveRoles(user.ID)` → `role.Slug`, deduped | `["platform-admin","ops-viewer"]`       |
| `amr`    | `[]string` | always (user-subject tokens only); omitted when empty            | session → authorization_code → oauth_token chain                     | `["pwd"]`, `["pwd","otp"]`, `["ext"]`   |

### Format rationale

- **Groups use hierarchy paths `/parent/child`** — this is Keycloak's default
  (`Full group path = true`), is natively consumed by Argo CD, Grafana,
  oauth2-proxy, Pomerium PPL, and Kubernetes `--oidc-groups-claim`, and
  disambiguates same-named groups under different parents. Top-level groups
  render as `/groupname`.
- **Roles are flat slugs** from the effective-role set (direct + group-inherited
  roles, deduplicated). This matches the `EffectiveRoles` view already shown
  in the admin UI.
- **Claim names are NOT namespaced.** Auth0's `https://example.com/groups`
  convention is a SaaS-IdP-specific workaround for Auth0's reserved-claim-name
  policy; self-hosted IdPs (Keycloak, Okta tenants, Azure Entra, Google) emit
  bare `groups` / `roles` and downstream consumers default to those exact
  names.

### `amr` values (RFC 8176 §2)

| Authentication surface                      | `amr`                       |
| ------------------------------------------- | --------------------------- |
| Username + password                         | `["pwd"]`                   |
| Password + TOTP second factor               | `["pwd","otp"]`             |
| Password + email OTP second factor          | `["pwd","mfa"]`             |
| Social login (Google / LinkedIn)            | `["ext"]`                   |
| SAML / external IdP without MFA assertion   | `["ext"]`                   |
| SAML / external IdP with MFA AuthnContext   | `["ext","mfa"]`             |
| LDAP bind                                   | `["pwd"]`                   |

`acr` is NOT emitted at this stage — `amr` alone is sufficient for the current
Phase E Pomerium MFA-gating plan and `acr` semantics should not be invented
without a concrete downstream contract.

## Scope gating

Two new OIDC scopes are advertised:

- `groups` — grants the id_token and access_token a `groups` claim.
- `roles`  — grants the id_token and access_token a `roles` claim.

Both are **per-client gated**. A client requesting `groups` in its
`authorize` scope parameter only receives the claim when `"groups"` is in
`OAuthClient.Scopes`. This reuses the existing allowlist pattern
(`TestClientCredentialsGrant_AllowedScopesFiltered`).

`amr` is not scope-gated — it is authentication-context, not privacy-sensitive,
and OIDC Core §2 treats it as a standard top-level claim.

## Storage — snapshot-at-each-hop

Migration 211 adds `auth_methods_used TEXT[] NOT NULL DEFAULT '{}'` to three
tables:

```
iam_sessions                   — written at login / MFA completion
iam_oauth_authorization_codes  — copied from session at /authorize
iam_oauth_tokens               — copied from code (or prior refresh token)
                                 at /token → carried across refresh rotations
```

Refresh tokens rotate through this chain, so a long-lived session's id_tokens
preserve the `amr` from the original authentication event as RFC 8176
prescribes. This explicitly diverges from Auth0's default (drop `amr` on
refresh) — Auth0 users work around it with Refresh Token Metadata;
falcon-id builds it in by default.

## Backwards compatibility

- No existing claim removed, no lifetime changed, no JWK rotated.
- Clients that don't request `groups` / `roles` get today's exact id_token.
- Clients with `client.Scopes = []` (legacy edge case) keep today's behaviour.
- Pre-migration sessions get `auth_methods_used = '{}'` → id_tokens omit `amr`
  (spec-compliant; `amr` is OPTIONAL per OIDC Core §2).

## Code pointers

- `internal/services/oauth_provider_service_claims.go` — `buildSubjectClaims`
  helper, single source of truth for groups/roles/amr emission logic.
- `internal/services/oauth_provider_service_tokens.go` — `generateIDToken` and
  `generateTokens` delegate to the helper.
- `internal/services/oauth_provider_service_tokens.go :GetDiscoveryDocument` —
  `claims_supported` and `scopes_supported` advertise the new entries.
- `internal/handlers/auth_handler.go`, `auth_service.go`, MFA and social paths
  — populate `Session.AuthMethodsUsed`.
- `internal/services/oauth_provider_service.go :CreateAuthorizationCode` —
  snapshots session.AuthMethodsUsed onto the code record.
- `internal/services/oauth_provider_service.go :ExchangeAuthorizationCode`
  and `RefreshTokens` — thread `auth_methods_used` into `generateTokens`.

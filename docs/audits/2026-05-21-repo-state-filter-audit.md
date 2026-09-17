# Repo state-filter audit — `is_active` / `is_email_verified` / `is_locked`

Date: 2026-05-21
Trigger: MR `falcon-id!205` (`fix(discover): distinguish inactive user
from unknown email`). That fix moved `is_active` routing out of
`UserRepository.GetByEmailGlobal` and into `DiscoverService` so the
caller can distinguish "row doesn't exist" from "row exists but
inactive". This audit walks every other read path that filters on
`is_active` / `is_email_verified` / `is_locked` and classifies each
for the same semantic-collapse risk.

## Method

`python3 grep` against every `internal/repositories/*.go` raw-string
SQL, extracting WHERE-clauses that match `is_active = …` /
`is_email_verified = …` / `is_locked = …`. 74 methods matched across
23 repos. The full machine-generated list lives in the commit that
introduced this memo.

## Classification

### Tier A — READ + state-collapsing (must move policy to service)

These methods filter on `is_active=true` (or sibling) in a READ
context, and the caller cannot from the result alone distinguish
"row never existed" from "row exists but is inactive". These are the
direct semantic-collapse instances that MR !205 fixed for one
method; the same anti-pattern needs the same treatment for the rest.

The fix shape (per !205):

1. Repository read returns the row regardless of state — let the
   service layer branch on the column.
2. Service decides the user-visible behaviour (e.g.
   `contact_admin` vs `signup` vs `password`) from the state.
3. The repository's docstring is updated to call out that state
   semantics are NOT applied at the repo layer.

| Repo | Method | Filter | Caller-side impact |
|------|--------|--------|--------------------|
| `IdentityProviderRepository` | `GetByTenantAndType` | `is_active=true` | Tenant disables an IDP, caller sees "no such IDP for tenant" → either offers signup with a non-existent provider OR falls through to local-auth in a way the admin didn't intend. |
| `IDPRoutingRepository` | `FindByEmailDomain` | `is_active=true` | Domain claim disabled, caller routes the user as if the domain were unclaimed. Symmetric to the GetByEmailGlobal bug. |
| `OAuthClientRepository` | `Update` (`WHERE is_active=true`) — note this is a write-side check, but it silently no-ops on a soft-deleted client | `is_active=true` | Caller thinks the update landed (rows-affected=0 isn't checked downstream). Move to "return ErrNotFound for missing-or-inactive, callers branch". |
| `ServiceAccountRepository` | `GetByClientID` | `is_active=true` | Disabled service account looks like an unknown one — caller cannot tell the admin "this client was deactivated on date X" vs "this client never existed". |
| `WorkloadIdentityRepository` | `GetByIssuer` | `is_active=true` | Same pattern as `ServiceAccountRepository`. |
| `OAuthTrustedExternalIssuerRepository` | `GetByIssuer` | `is_active=true` | Same pattern. Caller (RFC 8693 token-exchange) can't surface "issuer was revoked yesterday" vs "issuer was never trusted". |
| `SCIMRepository` | `GetByTokenHash` | `is_active=true` | A revoked SCIM token looks like a never-issued one. Audit-trail "token X attempted use after revocation" is lost. |
| `APIKeyRepository` | `GetByPrefix` | `is_active=true` | Same as SCIMRepository — revoked vs nonexistent collapses. |

**Recommended next MR**: pick the two highest-impact (`IDPRoutingRepository.FindByEmailDomain`,
`OAuthTrustedExternalIssuerRepository.GetByIssuer`) and apply the !205
shape. The others can fold in as touched.

### Tier B — READ + intentionally state-filtered (correct as is)

These methods filter `is_active=true` BUT the contract is "give me
only the active set". No semantic-collapse because the caller is
asking for the active subset, not a uniqueness check.

- `ConsentRepository.GetConsentTypes`, `GetUserConsents`,
  `GetRequiredConsentTypes`, `GetPendingRequiredConsents` — listing
  active consent types; inactive types are deprecated and should not
  appear in the UI. Correct.
- `IdentityProviderRepository.GetEnabledLoginProviders`,
  `GetEnabledSocialProviders` — "what shows on the login page";
  inactive providers must not surface. Correct.
- `OAuthClientRepository.GetClientsWithFrontchannelLogout`,
  `GetClientsWithBackchannelLogout` — fan-out targets for OIDC
  back/front-channel logout; inactive clients legitimately excluded.
- `PolicyRepository.GetActive`, `CountActive` — explicit "active"
  in the name.
- `RateLimitRepository.GetActiveRules` — same.
- `IPRuleRepository.GetActiveRules` — same.
- `DatabaseHostRepository.ListActiveByRegion`, `ListActiveRegions` —
  same.
- `DynamicGroupRuleRepository.ListActiveByTenant` — same.
- `DefaultAccessPolicyRepository.ListByTenant` — listing-only;
  matches.
- `OrganizationRepository.GetChildren`, `GetRootOrganizations` —
  org tree should hide soft-deleted nodes. Correct.
- `WebhookRepository.List`, `GetActiveByEvent`, `GetPendingDeliveries`
  — webhook fan-out targets; inactive must not fire. Correct.
- `RiskRepository.GetPolicies` — risk policies UI; matches the
  "show me active" contract.
- `SAMLRepository.GetSPsForMetadataRefresh` — background metadata
  refresher only touches active SPs.
- `ADSyncRepository.GetGroupRoleMappings` — directory sync only
  applies live mappings.
- `SessionRepository.*` (15 methods) — every session-side filter
  is correctly bounded to active sessions (a revoked session is not
  a "missing" session from any caller's POV). Correct.

### Tier C — WRITE-side state checks (legitimate)

`Update` / `Revoke` / `Activate` / `Deactivate` / `LockUser` /
`UnlockUser` / `EndSession` / `RegenerateSession` etc. All check
`is_active`/`is_locked` to avoid no-op writes on soft-deleted rows.
These are correct as is — no semantic-collapse because the caller
is mutating, not querying for presence.

23 of the 74 matches are in this tier.

### Tier D — Cross-table joins that filter on a foreign `is_active`

- `OAuthClientRepository.GetClientsWithFrontchannelLogout`,
  `GetClientsWithBackchannelLogout` — already covered in Tier B
  (intentional fan-out filter).
- `IdentityProviderRepository.GetEnabledLoginProviders` —
  filter is on `iam_identity_providers.is_active`, not a joined
  table. Tier B.

No Tier D drift was found.

## `is_email_verified` / `is_locked`

Only one method touches `is_email_verified` in a filter context:
`UserRepository.Update` — which is a write-side state check (Tier C).
No read-time collapse.

Only `UserRepository.LockUser` / `UnlockUser` filter on `is_locked` —
both writes (Tier C).

The bigger concern for those columns is the SERVICE layer (and login
flow) trusting them — e.g. `AuthService.Login` correctly checks
`is_email_verified` after the password phase, and `AccountLockoutService`
checks `is_locked`. That logic is OUT of repository scope and OUT of
this audit's scope.

## Action items

1. **Next MR** — apply the !205 shape to
   `IDPRoutingRepository.FindByEmailDomain` and
   `OAuthTrustedExternalIssuerRepository.GetByEmailGlobal`. Pair them
   so the discover flow and the RFC 8693 trust-grant flow both stop
   collapsing "revoked" into "unknown".
2. **Audit-trail hygiene** — `SCIMRepository.GetByTokenHash` and
   `APIKeyRepository.GetByPrefix` should be modified to return a
   sentinel `ErrTokenRevoked` (distinct from `ErrNotFound`) so the
   audit pipeline can emit a `revoked_token_replay_attempt` event
   instead of the generic `bad_token` it emits today.
3. **Lint guard (future)** — add a `golangci-lint` custom linter
   that flags any new `WHERE … is_active = true` clause in a
   READ-named repository method (`Get*`, `Find*`, `Lookup*`) so
   this audit doesn't need to be re-run.

## Memory
- internal engineering notes —
  records this audit's verdict + the lint-guard recommendation.
- Related: internal engineering notes
  (similar semantic-distinction pattern, different layer).

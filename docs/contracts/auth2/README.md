# AcmeApp hosted authentication rollout

## Deploy in order

1. Add `https://example.com/login?signed_out=1` to the existing **acmeapp-bff**
   client's `post_logout_redirect_uris`, preserving every existing registered
   URI. Register the equivalent preview/dev origin URI separately when needed.
   Make this registration change in a **new additive versioned Keystone bundle**
   in the manifests repo; do not modify an already-applied bundle. No schema
   migration is needed in falcon-id itself.
2. Deploy falcon-id. A signed, correctly issued ID token hint (including an
   expired ID token) from acmeapp-bff ends the IdP session and sends an immediate
   302 to an exactly registered return URI. Other clients retain their existing
   front-channel logout implementation. AcmeApp relies on the RP's existing
   global `/api/v1/auth/logout` call for server-side revocation/back-channel
   notifications, rather than a visible front-channel iframe page.
3. Deploy frontend **apps/login** (the actual hosted UI is in frontend, not in
   a `falcon-id/packages/login-ui` directory) and acmeweb, with rebuilt shared
   `@hexxlock/login-ui` and `@hexxlock/falcon-id-client` packages.
4. Set `ACMEWEB_OIDC_POST_LOGOUT_REDIRECT_URI` to the registered sign-in URI if
   deployment currently overrides the default with `/`. Keep the issuer,
   client ID/secret and authorization callback registrations unchanged.

## Contract

- Hosted `POST /api/v1/auth/mfa/complete` uses `Prefer: return=minimal` (RFC 7240)
  and HttpOnly Set-Cookie for authentication. The body is
  `mfa-complete.success.json` (16 bytes on the wire), with no duplicated
  token, user, avatar, role or permission graph. apps/login forwards the cookies
  and resumes its already validated `/oauth/authorize` continuation.
  API/SDK callers without that preference retain compact token/expiry fields
  (`mfa-complete.api-success.json`); neither mode serializes the user graph.
- 401 `mfa_session_expired`: stop verification and offer **Start again**.
- 401 `mfa_code_invalid`: keep the live challenge and show `remaining_attempts`.
- 429 `mfa_rate_limited`: respect `Retry-After: 60`; switching methods does not
  reset the verification attempt budget or extend challenge expiry.
- Infrastructure failures are 503 `mfa_unavailable`, with a `traceId` matching
  the response request ID, never Redis/database/DI exception text.
- A successful challenge/code completion is cached for 60 seconds. An exact
  retry from the same browser and DPoP key reissues the same access-token result
  and resets cookies. IP is deliberately not bound, to survive network changes.
  A different code/browser/key fails closed. Accepted TOTP codes cannot be
  reused by a new challenge within the verifier's 90-second skew window.
  Replays revalidate token revocation and cannot resurrect a session after
  explicit IdP logout; newly authenticated sessions are not blocked.
- MFA login/switch responses additionally expose `masked_email`,
  `mfa_expires_in`, and `resend_after_seconds`; switches retain the original
  challenge ID and expiry. Authenticated `/mfa/send-code` exposes the delivery
  fields in `mfa-send-code.success.json`.
- Authenticated `/mfa/status` includes `masked_email`,
  `email_code_ttl_seconds`, and `passkey_available`. Step-up verification accepts
  an optional explicit `method`; legacy callers remain supported.
- Successful passkey/OTP step-up updates both DB freshness and the existing
  IdP SSO auth-time snapshot. Passkey step-up records the verification as well
  as AMR/freshness, so the next OAuth resume does not repeat MFA indefinitely.

## Ownership boundary

The separately labeled **team1** work package (membership backfill, global
verified-email uniqueness/dedupe, invitation registration/acceptance, seat math,
owner/admin MFA policy, service-principal cleanup, per-membership deactivate/
remove/reactivate, accounts portal and role search) must roll out separately.
This change neither migrates memberships nor changes prices, seats or offer
membership. Passkey selection in acmeweb's existing Team step-up dialog uses its
existing full-OIDC fallback; the hosted IdP provides the actual passkey ceremony.

Browser/Playwright specs are written but must not be executed under the current
operator memory policy. Targeted route/unit/typecheck/lint and Go boot gates
are the executable acceptance checks for this slot.

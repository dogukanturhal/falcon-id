# Login with Falcon-ID — Third-party RP integration guide

This guide is for application teams **outside** HexxLock who want to add
"Sign in with Falcon-ID" to their product. It covers OIDC discovery, the
recommended access-token lifetime, RFC 7662 token introspection, RFC 7009
token revocation, and when to opt into back-channel logout.

If you are integrating an internal HexxLock service that already lives in
the platform monorepo, prefer the `serviceauth.NewIAMHTTPClient` pattern
documented in `INTEGRATION_GUIDE.md` — it handles client-credentials
bootstrap and token refresh automatically.

---

## 1. Discovery URL

```
https://id.hexxlock.com/.well-known/openid-configuration
```

Bootstrap your RP SDK (panva/openid-client, oidc-client-ts, AppAuth, or
the Auth.js OIDC provider) by pointing it at this URL. The discovery
document advertises every endpoint, supported scope, supported response
type, supported PKCE method, and supported logout cascade — your SDK will
read it on startup and configure itself.

**Do not hardcode endpoint URLs into your client config.** Falcon-ID
endpoints can move; the discovery document is the single source of truth.

The conformance pack (2026-04-29) added the following fields to the
discovery document — every Auth0 / Okta / OpenID Foundation conformance
suite reads these on startup:

| Field                                          | Value                                            |
| ---------------------------------------------- | ------------------------------------------------ |
| `introspection_endpoint_auth_methods_supported`| `["client_secret_basic", "client_secret_post"]`  |
| `revocation_endpoint_auth_methods_supported`   | `["client_secret_basic", "client_secret_post"]`  |
| `claim_types_supported`                        | `["normal"]`                                     |
| `frontchannel_logout_supported`                | `true`                                           |
| `frontchannel_logout_session_supported`        | `true`                                           |
| `request_parameter_supported`                  | `false`                                          |
| `request_uri_parameter_supported`              | `false`                                          |
| `claims_parameter_supported`                   | `false`                                          |
| `tls_client_certificate_bound_access_tokens`   | `false`                                          |

---

## 2. Client registration

Register your client through the Falcon-ID admin UI or the
`POST /api/v1/oauth/clients` admin API. The minimum metadata you need:

- `redirect_uris` — exact-match HTTPS URLs your app will redirect to
- `grant_types` — `["authorization_code", "refresh_token"]` for browser
  apps; add `client_credentials` only for confidential server-to-server
  flows
- `scopes` — see §3 below
- `is_public` — `false` for confidential clients (server-side apps);
  `true` for browser-only public clients (PKCE-only)
- `token_endpoint_auth_method` — `client_secret_basic` for confidential,
  `none` for public

> **Public clients cannot introspect or revoke tokens.** Both
> `/oauth/introspect` and `/oauth/revoke` advertise only `client_secret_*`
> in their auth-methods-supported list. If you need introspection, you
> must register a confidential client and run the introspect call from
> your server, not the browser.

---

## 3. Scopes

Standard OIDC scopes (`openid`, `profile`, `email`, `offline_access`)
work as defined in OpenID Connect Core 1.0.

Falcon-ID-specific scopes that are sometimes useful:

- `groups` — emit a `groups` claim listing the user's group memberships
  (gated by client registration; the client must include `groups` in
  its registered `scopes`)
- `roles` — emit a `roles` claim listing assigned roles (same gating)
- `oidc:introspect` — **server-to-server only.** Lets a confidential
  client introspect tokens issued to *other* clients within the same
  tenant. Use this if you operate a resource server that accepts tokens
  from multiple front-end clients

By default `/oauth/introspect` only allows a client to introspect its
own tokens (introspection-as-discovery defense). Same-client tokens
work without any additional scope.

---

## 4. PKCE example (confidential client, authorization_code grant)

```
GET https://id.hexxlock.com/oauth/authorize
    ?response_type=code
    &client_id=YOUR_CLIENT_ID
    &redirect_uri=https%3A%2F%2Fyourapp.example.com%2Fcallback
    &scope=openid%20profile%20email%20offline_access
    &state=STATE_CSRF_NONCE
    &nonce=ID_TOKEN_REPLAY_NONCE
    &code_challenge=BASE64URL(SHA256(code_verifier))
    &code_challenge_method=S256
```

After consent, Falcon-ID redirects back with `code=…&state=…`. Exchange
the code at `/oauth/token`:

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic BASE64(client_id:client_secret)

grant_type=authorization_code
&code=CODE_FROM_REDIRECT
&redirect_uri=https%3A%2F%2Fyourapp.example.com%2Fcallback
&code_verifier=ORIGINAL_CODE_VERIFIER
```

Response:

```json
{
  "access_token": "eyJraWQiOi…",
  "id_token":     "eyJraWQiOi…",
  "refresh_token":"6cqcDlR…",
  "token_type":   "Bearer",
  "expires_in":   900,
  "scope":        "openid profile email offline_access"
}
```

---

## 5. Recommended access-token TTL

| Client type                     | Recommended `access_token_lifetime` |
| ------------------------------- | ----------------------------------- |
| First-party (HexxLock products) | 3600 (1 hour)                       |
| Confidential third-party        | 300–900 (5–15 minutes)              |
| Public third-party (browser)    | 300 (5 minutes)                     |

Third-party clients should **introspect on every refresh** (see §6) so
revocation propagates within the AT window. Long-lived access tokens
without introspection let revoked sessions stay alive until natural
expiry — that is the security gap this conformance pack closes for
third-party RPs that cannot host a back-channel logout listener.

---

## 6. Introspection (RFC 7662)

Use `/oauth/introspect` whenever you are about to trust a token (typical
points: every API request OR every refresh, depending on traffic
volume).

```
POST /oauth/introspect
Content-Type: application/x-www-form-urlencoded
Authorization: Basic BASE64(client_id:client_secret)

token=ACCESS_OR_REFRESH_TOKEN
&token_type_hint=access_token
```

Successful response (active token):

```json
{
  "active":     true,
  "scope":      "openid profile email",
  "client_id":  "your-client-id",
  "sub":        "user-uuid",
  "exp":        1714329600,
  "iat":        1714326000,
  "iss":        "https://id.hexxlock.com",
  "token_type": "Bearer"
}
```

Inactive token (revoked, expired, unknown, or owned by a different
client without the `oidc:introspect` scope):

```json
{ "active": false }
```

**The status code is always 200.** RFC 7662 §2.2 forbids leaking token
state via the HTTP status code; do not retry on 4xx — that means your
client credentials are wrong.

If `active` is `false`, treat the token as invalid regardless of any
local cache. Do not fall back to JWT-only validation; the conformance
pack added a revocation-store lookup so a revoked token never
introspects as active.

---

## 7. Revocation (RFC 7009)

Call `/oauth/revoke` on logout. Always revoke the **refresh token** —
revoking the refresh token also marks the row's access token revoked,
because Falcon-ID stores AT and RT in the same row and revocation is
keyed on either column.

```
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic BASE64(client_id:client_secret)

token=REFRESH_TOKEN
&token_type_hint=refresh_token
```

Response: HTTP 200, no body.

A 200 does **not** mean the token existed. RFC 7009 §2.2 — the response
is identical for known, unknown, already-revoked, and cross-client
tokens. This is intentional and prevents an RP from probing token state
through the revocation endpoint.

`token_type_hint` is optional. Falcon-ID searches both columns
regardless of the hint, so a wrong hint never causes a missed
revocation; the hint is an optimization only.

---

## 8. Logout cascade — when to opt into back-channel logout

OIDC supports three logout patterns. Pick based on what your RP can
host:

| RP capability                          | Use this                                |
| -------------------------------------- | --------------------------------------- |
| Server can host an HTTPS POST endpoint | Back-channel logout (preferred)         |
| Browser-only / cannot host endpoint    | Front-channel logout (iframe cascade)   |
| Neither (rare third-party RPs)         | Short AT TTL + introspect on every call |

To opt into back-channel logout, register a `backchannel_logout_uri` on
your client. Falcon-ID will POST a signed logout token there whenever
the user logs out at the IdP or any sibling RP. Verify the JWT
signature against the JWKS, look up the `sub` / `sid` claim, and
invalidate the local session.

To opt into front-channel logout, register a `frontchannel_logout_uri`.
Falcon-ID will render an iframe pointed at that URL during logout with
`iss` and `sid` query parameters; clear the local session in your iframe
handler.

**If you opt into neither**, you must rely on §6 introspection-on-every-call
to detect revoked sessions. Your effective propagation latency for
revoked sessions equals your access-token TTL — keep that short (5
minutes recommended).

---

## 9. Conformance test commands

Verify discovery (anonymous, no auth required):

```bash
curl -sS https://id.hexxlock.com/.well-known/openid-configuration | jq .
curl -sS https://id.hexxlock.com/.well-known/jwks.json | jq .
```

Verify introspection (replace `CLIENT_ID` / `CLIENT_SECRET` / `TOKEN`):

```bash
curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -X POST https://id.hexxlock.com/oauth/introspect \
  -d "token=${TOKEN}" -d 'token_type_hint=access_token' | jq .
```

Verify revocation:

```bash
curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -X POST -i https://id.hexxlock.com/oauth/revoke \
  -d "token=${TOKEN}" -d 'token_type_hint=refresh_token'
# Expect: HTTP/2 200, empty body
```

---

## 10. Reference specs

- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 7662 — OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 7009 — OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
- [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [OIDC Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
- [OpenID Continuous Access Evaluation Profile 1.0](https://openid.net/specs/openid-caep-1_0-final.html)
- [RFC 7636 — Proof Key for Code Exchange](https://datatracker.ietf.org/doc/html/rfc7636)

---

## Questions / problems

Open an issue on the falcon-id GitLab project (`hexxlock/falcon-id`) or
post in `#identity-platform` with a discovery dump, the redacted
introspection response, and the timestamp.

# OIDC Multi-Tenancy in Falcon-ID

## Overview

Falcon-ID is a **single-issuer multi-tenant** identity provider. The canonical OIDC
issuer for all platform and workforce SSO is:

```
https://auth.hexxlock.com
```

Customer-facing tenants receive their own subdomain
(`<slug>.auth.hexxlock.com`) and their own Realm record. Internal platform
tooling (Backstage, ArgoCD, Grafana, Atlantis, Harbor, SonarQube, …) uses
the bare `auth.hexxlock.com` domain via the **platform tenant**.

---

## OIDC Discovery

| Endpoint | URL | Public? |
|---|---|---|
| OpenID Configuration | `https://auth.hexxlock.com/.well-known/openid-configuration` | Yes (RFC 8414) |
| JWKS | `https://auth.hexxlock.com/.well-known/jwks.json` | Yes (RFC 8414) |
| Platform JWKS (unified) | `https://auth.hexxlock.com/.well-known/platform-jwks.json` | Yes |
| Authorization | `https://auth.hexxlock.com/oauth/authorize` | Platform tenant |
| Token | `https://auth.hexxlock.com/oauth/token` | Platform tenant |
| UserInfo | `https://auth.hexxlock.com/oauth/userinfo` | Authenticated |

Per **RFC 8414 §3** and **OpenID Connect Discovery 1.0 §4**, the `/.well-known/*`
paths are publicly accessible — no authentication, no `X-Tenant-ID` header, no
special configuration is required. Any OIDC client can discover the server
metadata without prior knowledge of tenant context.

---

## Platform Tenant (Internal Tooling SSO)

The **platform tenant** is a well-known sentinel with a fixed UUID:

```
WellKnownTenantPlatformID = 00000000-0000-0000-0000-000000000003
```

Defined in: `falcon-id/internal/models/well_known_ids.go`

### How it works

1. A request arrives at `auth.hexxlock.com`.
2. APISIX matches the `falcon-id-platform` route (priority 5, catch-all).
3. APISIX injects `X-Tenant-ID: 00000000-0000-0000-0000-000000000003` via the
   `proxy-rewrite` plugin before forwarding to falcon-id.
4. `ExtractTenant()` middleware in falcon-id reads the header and sets
   `tenant_id` in the Gin context.
5. Downstream handlers scope their DB queries to the platform tenant.

`/.well-known/*`, `/health/*`, and `/metrics` are matched by the
`falcon-id-discovery` route (priority 10) **before** the platform route and
pass through with **no header injection** — these paths are unconditionally
public.

---

## Registering an OIDC Client for Internal Tooling

All internal tools register under the **platform tenant**
(`00000000-0000-0000-0000-000000000003`). Use the Admin API:

```bash
# Obtain a platform-admin token first
TOKEN=$(curl -s -X POST https://auth.hexxlock.com/oauth/token \
  -H "X-Tenant-ID: 00000000-0000-0000-0000-000000000003" \
  -d "grant_type=client_credentials&client_id=<platform-admin-client>&client_secret=<secret>&scope=platform:admin" \
  | jq -r .access_token)

# Register the new OIDC client
curl -X POST https://auth.hexxlock.com/api/v1/oauth/clients \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: 00000000-0000-0000-0000-000000000003" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "backstage",
    "redirect_uris": ["https://backstage.hexxlock.com/api/auth/oidc/handler/frame"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "openid profile email groups"
  }'
```

Use the returned `client_id` and `client_secret` in the tool's OIDC
configuration. Set the issuer URL to `https://auth.hexxlock.com`.

### Example: Backstage `app-config.yaml`

```yaml
auth:
  environment: production
  providers:
    oidc:
      production:
        metadataUrl: https://auth.hexxlock.com/.well-known/openid-configuration
        clientId: ${BACKSTAGE_OIDC_CLIENT_ID}
        clientSecret: ${BACKSTAGE_OIDC_CLIENT_SECRET}
        scope: openid profile email groups
        signIn:
          resolvers:
            - resolver: emailMatchingUserEntityProfileEmail
```

### Example: ArgoCD `argocd-cm`

```yaml
oidc.config: |
  name: HexxLock SSO
  issuer: https://auth.hexxlock.com
  clientID: $oidc.clientId
  clientSecret: $oidc.clientSecret
  requestedScopes: ["openid", "profile", "email", "groups"]
  requestedIDTokenClaims: {"groups": {"essential": true}}
```

---

## Customer-Facing Tenants

Each enterprise or shared-tier customer is provisioned with:

1. A **Realm** record (`RealmType = enterprise` or `shared`) in the database.
2. A subdomain `<slug>.auth.hexxlock.com` pointing to APISIX.
3. An **ApisixRoute** in the customer's product namespace that injects
   `X-Tenant-ID: <customer-realm-uuid>`.

Customer tokens carry `tenant_id` as a JWT claim. The OIDC issuer for
customer tenants is `https://<slug>.auth.hexxlock.com` (separate realm,
separate discovery document at `<slug>.auth.hexxlock.com/.well-known/openid-configuration`).

---

## Architecture Diagram

```
Cloudflare → Traefik (TLS) → APISIX
                                │
              ┌─────────────────┼─────────────────────┐
              │                 │                      │
  auth.hexxlock.com     acme.auth.hexxlock.com  ...
  (platform tenant)    (enterprise tenant)
              │                 │
   ┌──────────┴────────┐  ┌─────┴──────────────┐
   │ falcon-id-discovery│  │ ApisixRoute         │
   │ (/.well-known/*)  │  │ X-Tenant-ID: <acme> │
   │ pass-through      │  └─────────────────────┘
   └──────────┬────────┘
              │
   ┌──────────┴────────────┐
   │ falcon-id-platform    │
   │ X-Tenant-ID: 000…0003 │
   └───────────────────────┘
              │
        falcon-id pod
```

---

## Middleware Behaviour

`ExtractTenant()` in `falcon-id/internal/middleware/tenant.go` enforces tenant
context on all requests in production/staging. Paths in `publicEndpoints` are
exempted unconditionally:

- `/.well-known/` (prefix match — all well-known metadata paths)
- `/health`, `/ready`, `/metrics`
- `/api/auth/login`, `/api/auth/refresh`, `/api/auth/logout`, etc.

The exemption is tested in `TestIsPublicEndpoint_WellKnownPaths` and
`TestExtractTenant_WellKnownPaths_NoTenantHeader_Production` in
`falcon-id/internal/middleware/tenant_test.go`.

---

## Rollback

If this change causes a regression:

1. Revert `falcon-id/internal/middleware/tenant.go` — remove `/.well-known/`
   from `publicEndpoints`. This re-gates discovery behind tenant context (broken
   state, but safe from a cross-tenant data leak perspective).
2. Revert `the GitOps repository/.../apisix-route-falcon-id.yaml` — collapse back
   to the single catch-all `falcon-id` route with no `proxy-rewrite` plugin.
3. ArgoCD will sync both changes within ~3 minutes (GitOps auto-sync interval).

Cross-tenant data leakage risk from Option A is **zero** — `/.well-known/*`
endpoints return only public metadata (issuer URL, algorithm list, JWKS public
keys). No per-tenant secrets are exposed.

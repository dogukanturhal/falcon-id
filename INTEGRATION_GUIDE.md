# Falcon-ID Integration Guide

> How to integrate Falcon-ID into other systems for **development** and **production** environments.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Development Setup](#development-setup)
4. [Production Deployment](#production-deployment)
5. [API Gateway Integration](#api-gateway-integration)
6. [Authentication Integration](#authentication-integration)
7. [Authorization Integration](#authorization-integration)
8. [Service-to-Service Communication](#service-to-service-communication)
9. [Multi-Tenant Integration](#multi-tenant-integration)
10. [Email / SMTP Configuration](#email--smtp-configuration)
11. [Frontend Integration](#frontend-integration)
12. [Federation & SSO](#federation--sso)
13. [SCIM Provisioning](#scim-provisioning)
14. [Webhook Integration](#webhook-integration)
15. [API Reference](#api-reference)
16. [Environment Variables](#environment-variables)
17. [Database Migrations](#database-migrations)
18. [Security Checklist](#security-checklist)
19. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

Falcon-ID is an enterprise IAM (Identity & Access Management) service built in Go with Gin. It provides:

- **Authentication**: JWT tokens, OAuth 2.0, SAML 2.0, OIDC, Magic Links, MFA (TOTP/Email)
- **Authorization**: RBAC + ABAC (OPA) + ReBAC (SpiceDB) with 3-layer caching
- **Multi-Tenancy**: Full tenant isolation with realm support
- **Federation**: Social login, LDAP/AD sync, SCIM 2.0 provisioning
- **Compliance**: GDPR consent management, audit logging with hash chain, data encryption

### Layered Subdomain Architecture

The platform uses a **layered subdomain model** — subdomains by audience, not by microservice. All business service APIs share a single gateway endpoint, differentiated by URL path.

```
DEVELOPMENT (localhost)
  localhost:9080/api/*         All services via path-based routing
  localhost:3000               Unified Dashboard (Next.js)
  localhost:3002               Platform Admin (Next.js)

PRODUCTION
  PLATFORM (hexxlock.com)
    api.hexxlock.com           APISIX  Platform management API (tenants, billing, licenses)
    admin.hexxlock.com         Platform Admin dashboard (Next.js)
    docs.hexxlock.com          Documentation
    status.hexxlock.com        Status page

  TENANT (hexxlock.io)
    api.hexxlock.io            APISIX  ALL business service APIs (path-based: /api/v1/crm/*, /api/v1/hr/*, etc.)
    {tenant}.hexxlock.io       Tenant-specific dashboard (realm extraction)
    ws.hexxlock.io             WebSocket/realtime connections
    oauth.hexxlock.io          OAuth/OIDC/SAML/SCIM endpoints
```

Both `api.hexxlock.com` and `api.hexxlock.io` run on the **same APISIX instance**. APISIX differentiates by `Host` header. One load balancer, one gateway, one security enforcement point.

### Cookie Isolation

```
Tenant cookies:   Domain=.hexxlock.io   SameSite=Lax     shared across api.hexxlock.io + {tenant}.hexxlock.io
Platform cookies: Domain=.hexxlock.com  SameSite=Strict   shared across api.hexxlock.com + admin.hexxlock.com
```

Cross-domain access between `.hexxlock.com` and `.hexxlock.io` is impossible — platform admin and tenant sessions are fully isolated.

### Internal Architecture

```
                        APISIX Gateway
                     (Host-based routing)
                            |
          +-----------------+-----------------+
          |                                   |
   api.hexxlock.com                    api.hexxlock.io
   (platform routes)                   (tenant routes)
          |                                   |
   +------+------+              +-------------+-------------+
   |             |              |      |      |      |      |
 Tenant    Subscription       CRM    HR    FiCo   SD    ...26 services
 Mgmt      Billing             |      |      |      |
   |             |              +------+------+------+
   |             |              All use forward-auth to Falcon-ID
   +------+------+              for JWT validation before routing
          |
   Falcon-ID (IAM)
   Port 8005
          |
   +------+------+------+
   |      |      |      |
  PgSQL  Redis  SpiceDB OPA
```

---

## Prerequisites

| Component    | Minimum Version | Purpose                        |
|-------------|----------------|--------------------------------|
| PostgreSQL  | 16+            | Primary data store             |
| Redis       | 7+             | Sessions, rate limiting, cache |
| Go          | 1.25+          | Build from source (optional)   |
| Docker      | 24+            | Container deployment           |

---

## Development Setup

### Routing in Development

In development, **all services are accessed via `localhost:9080`** with path-based routing through APISIX. There are no subdomains, no `hosts:` fields, and no domain separation.

```
Browser/Client
     |
     v
localhost:9080  (APISIX dev config)
     |
     +-- /api/auth/*           --> falcon-id:8005
     +-- /api/v1/users/*       --> falcon-id:8005
     +-- /api/v1/crm/*         --> crm-service:8080
     +-- /api/v1/hr/*          --> hr-service:8080
     +-- /api/v1/sd/*          --> sd-service:8110
     +-- /api/v1/pm/*          --> pm-service:8080
     +-- /api/v1/tenants*      --> tenant-management:8001
     +-- ...
```

The dev APISIX config (`config/apisix/apisix-dev.yaml`) uses `localhost` origins for CORS:
```
allow_origins: "http://localhost:3000,http://localhost:3002,http://localhost:3003"
```

### Option A: Docker Compose (Recommended)

```bash
cd falcon-id
docker compose up -d
```

This starts Falcon-ID with PostgreSQL and Redis. The service auto-migrates on startup.

**Default ports:**
- Falcon-ID API: `http://localhost:8010`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

### Option B: Local Development

1. **Start dependencies:**
```bash
# PostgreSQL
docker run -d --name falcon-pg \
  -e POSTGRES_USER=falcon \
  -e POSTGRES_PASSWORD=falcon_dev \
  -e POSTGRES_DB=falcon_id \
  -p 5432:5432 postgres:16-alpine

# Redis
docker run -d --name falcon-redis \
  -p 6379:6379 redis:7-alpine
```

2. **Create `.env` file:**
```bash
ENVIRONMENT=development
SERVICE_PORT=8010
DATABASE_URL=postgres://falcon:falcon_dev@localhost:5432/falcon_id?sslmode=disable
REDIS_URL=redis://localhost:6379/0
ALLOW_AUTO_JWT_SECRET=true
FRONTEND_URL=http://localhost:3000
INTERNAL_API_KEY=dev-internal-key-minimum-32-characters-long
```

3. **Run:**
```bash
go run ./cmd/
```

### Default Admin Credentials

After first migration, a default admin is seeded:
- **Username:** `admin`
- **Password:** `Admin@12345!`
- **Tenant:** `default`

> Change these immediately in non-dev environments.

---

## Production Deployment

### Subdomain Layout

Production uses the layered subdomain architecture described in [Architecture Overview](#layered-subdomain-architecture). APISIX routes requests based on the `Host` header.

| Host | Routes to | CORS allows |
|------|-----------|-------------|
| `api.hexxlock.io` | All tenant business service APIs | `https://*.hexxlock.io` |
| `api.hexxlock.com` | Platform management APIs (tenants, billing, licenses) | `https://admin.hexxlock.com, https://*.hexxlock.com` |
| Both | Auth endpoints (`/api/auth/*`, `/api/v1/auth/*`) | `https://*.hexxlock.io, https://*.hexxlock.com` |

### DNS Records

```dns
; hexxlock.com (platform)
A     api.hexxlock.com          --> Gateway LB IP
A     admin.hexxlock.com        --> Gateway LB IP
CNAME docs.hexxlock.com         --> docs provider
CNAME status.hexxlock.com       --> status provider

; hexxlock.io (tenant)
A     *.hexxlock.io             --> Gateway LB IP (catches all tenant subdomains)
A     api.hexxlock.io           --> Gateway LB IP
A     ws.hexxlock.io            --> Gateway LB IP
A     oauth.hexxlock.io         --> Gateway LB IP
```

### TLS Certificates

Two wildcard certificates:
- `*.hexxlock.com` — covers admin, api, docs, status
- `*.hexxlock.io` — covers all tenant subdomains, api, ws, oauth

### Required Environment Variables

```bash
# Core
ENVIRONMENT=production
SERVICE_PORT=8010

# Database (separate data and control plane DBs recommended)
DATABASE_URL=postgres://user:pass@db-host:5432/falcon_id?sslmode=require
CONTROL_PLANE_DATABASE_URL=postgres://user:pass@db-host:5432/falcon_id_control?sslmode=require

# Redis (with auth)
REDIS_URL=redis://:password@redis-host:6379/0

# Security (ALL REQUIRED IN PRODUCTION)
JWT_SECRET=<min-32-char-cryptographic-random>
ENCRYPTION_KEY=<exactly-32-bytes-for-aes-256>
TOKEN_HASH_SALT=<cryptographic-random-value>
EMAIL_HASH_KEY=<hmac-key-for-email-hashing>
INTERNAL_API_KEY=<min-32-char-service-to-service-key>

# Network Security
TRUSTED_PROXIES=10.0.0.1,10.0.0.2  # Your load balancer IPs

# Frontend
FRONTEND_URL=https://app.yourdomain.com
OAUTH_ISSUER=https://id.yourdomain.com
```

> **SMTP is no longer configured via environment variables.** See [Email / SMTP Configuration](#email--smtp-configuration) for the per-tenant database-driven approach.

### Docker Deployment

```dockerfile
# Pull the image or build from source
docker build -t falcon-id:latest .

docker run -d \
  --name falcon-id \
  --env-file .env.production \
  -p 8010:8005 \
  --restart unless-stopped \
  falcon-id:latest
```

### Health Check

```bash
curl http://localhost:8010/health
# Returns: {"status":"ok"}
```

### Kubernetes / Compose Healthcheck

```yaml
healthcheck:
  test: ["CMD", "wget", "-qO-", "http://localhost:8005/health"]
  interval: 30s
  timeout: 5s
  retries: 3
```

---

## API Gateway Integration

All services are routed through a single APISIX gateway. The gateway enforces authentication via Falcon-ID's `forward-auth` plugin before forwarding requests to upstream services.

### How Requests Flow

```
Client Request
     |
     v
  APISIX
     |
     +-- 1. Global rules: strip spoofable headers, extract realm from subdomain
     +-- 2. Route matching: URI path + Host header (production) or URI path only (dev)
     +-- 3. CORS enforcement
     +-- 4. forward-auth: POST to http://iam:8005/api/auth/validate
     |        - Sends: Authorization, X-Tenant-ID, X-Realm-ID headers
     |        - Receives: X-User-ID, X-Tenant-ID, X-User-Role headers
     +-- 5. Proxy to upstream service with validated headers
```

Your service receives these **trusted headers** (set by Falcon-ID, stripped from external requests by global rule):
- `X-User-ID` — Authenticated user UUID
- `X-Tenant-ID` — User's tenant UUID
- `X-User-Role` — User's role(s)
- `X-Realm-ID` — Realm UUID (if multi-realm enabled)
- `X-Realm-Slug` — Realm slug (if multi-realm enabled)

### Adding a New Service: Development Config

Edit `config/apisix/apisix-dev.yaml`. Dev routes use inline `upstream:` blocks and `localhost` CORS. No `hosts:` field needed.

```yaml
# Example: Adding a new "logistics" service
- uri: /api/v1/logistics/*
  name: logistics-route
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
  upstream:
    type: roundrobin
    nodes:
      "hexxlock-logistics-dev:8080": 1
  plugins:
    request-id:
      header_name: "X-Request-ID"
      include_in_response: true
    cors:
      allow_origins: "http://localhost:3000,http://localhost:3002,http://localhost:3003"
      allow_credential: true
      allow_methods: "GET,POST,PUT,DELETE,PATCH,OPTIONS"
      allow_headers: "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization"
    # forward-auth validates JWT via Falcon-ID
    forward-auth:
      uri: "http://hexxlock-iam-dev:8005/api/auth/validate"
      request_headers: ["Authorization", "X-Tenant-ID", "X-Realm-ID", "X-Realm-Slug", "X-Realm-Type"]
      upstream_headers: ["X-User-ID", "X-Tenant-ID", "X-User-Role", "X-Realm-ID", "X-Realm-Slug", "X-Realm-Type"]
    limit-req:
      rate: 1000
      burst: 500
      rejected_code: 429
      key_type: var
      key: remote_addr
```

Add the Docker service to `docker-compose.dev.yml`:
```yaml
hexxlock-logistics-dev:
  build: ./logistics-service
  ports:
    - "8085:8080"
  environment:
    - INTERNAL_API_KEY=${INTERNAL_API_KEY}
    - JWT_SECRET=${JWT_SECRET}
  networks:
    - hexxlock-network
```

### Adding a New Service: Production Config

Edit `api-gateway/apisix/apisix.yaml`. Production routes use shared `upstream_id` references, `hosts:` fields for subdomain routing, and tighter CORS.

**Step 1: Add an upstream** (at the bottom of the `upstreams:` section):

```yaml
- id: 27
  name: logistics-service
  type: roundrobin
  nodes:
    - host: logistics-service
      port: 8080
      weight: 1
  checks:
    active:
      type: http
      http_path: /health
      healthy:
        interval: 10
        successes: 2
      unhealthy:
        interval: 10
        http_failures: 3
```

**Step 2: Add routes** (in the `routes:` section). Choose the correct `hosts:` based on route type:

| Route type | `hosts:` value | CORS `allow_origins` |
|-----------|---------------|---------------------|
| Tenant business API | `["api.hexxlock.io"]` | `"https://*.hexxlock.io"` |
| Platform admin API | `["api.hexxlock.com"]` | `"https://admin.hexxlock.com,https://*.hexxlock.com"` |
| Auth (both domains) | `["api.hexxlock.io", "api.hexxlock.com"]` | `"https://*.hexxlock.io,https://*.hexxlock.com"` |

Most new business services are **tenant routes**:

```yaml
# Logistics Service
- id: 350
  uri: /api/v1/logistics/*
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
  hosts: ["api.hexxlock.io"]
  upstream_id: 27
  plugins:
    cors:
      allow_origins: "https://*.hexxlock.io"
      allow_methods: "GET,POST,PUT,DELETE,PATCH,OPTIONS"
      allow_headers: "Authorization,Content-Type,X-Tenant-ID,X-Realm-ID,X-Realm-Slug,X-Realm-Type"
      max_age: 3600
    forward-auth:
      uri: "http://iam:8005/api/auth/validate"
      request_headers: ["Authorization", "X-Tenant-ID", "X-Realm-ID", "X-Realm-Slug", "X-Realm-Type"]
      upstream_headers: ["X-User-ID", "X-Tenant-ID", "X-User-Role", "X-Realm-ID", "X-Realm-Slug", "X-Realm-Type"]
    limit-count:
      count: 500
      time_window: 60
      key_type: var
      key: remote_addr

# Logistics Health Check (no auth)
- id: 351
  uri: /api/logistics/health
  methods: ["GET"]
  hosts: ["api.hexxlock.io"]
  upstream_id: 27
  plugins:
    proxy-rewrite:
      uri: /health
```

**Step 3: If your service uses path rewriting** (e.g., `/api/v1/logistics/*` maps to `/api/v1/*` internally):

```yaml
plugins:
  proxy-rewrite:
    regex_uri: ["^/api/v1/logistics/(.*)", "/api/v1/$1"]
```

### Route ID Conventions

| Range | Purpose |
|-------|---------|
| 1 | Gateway health check |
| 10-34 | IAM/Auth public and protected routes |
| 40-46 | Platform management (tenant-mgmt, billing) |
| 50-59 | Email integration |
| 60-69 | CRM |
| 70-79 | Invoicing |
| 80-89 | Inventory |
| 90-99 | HR |
| 100-109 | Accounting |
| 110-119 | Finance |
| 120-129 | FiCo |
| 130-139 | SD (Sales & Distribution) |
| 140-149 | PP/SCM |
| 150-159 | Marketing |
| 200-209 | Workflow engine |
| 210-219 | Master data |
| 220-229 | Integration bus |
| 230-239 | Document numbering |
| 240-249 | Material management |
| 250-259 | Messaging integration |
| 260-269 | Marketing automation |
| 270-279 | Integration hub |
| 280-289 | Quota |
| 290-299 | Helpdesk |
| 300-309 | CMS |
| 310-315 | Subscription admin |
| 320-330 | Subscription tenant/public |
| 340-341 | Project management |

Pick the next available range for new services (e.g., 350+ for logistics).

### Realm Extraction

The APISIX global rule extracts realm slugs from subdomains (e.g., `acme.hexxlock.io` sets `X-Realm-Slug: acme`). The following subdomains are **skipped** (not treated as realm slugs):

`www`, `api`, `app`, `admin`, `portal`, `dashboard`, `platform`, `ws`, `oauth`

If you add a new infrastructure subdomain, add it to the `skip_subdomains` table in the global rule at the top of `api-gateway/apisix/apisix.yaml`.

---

## Authentication Integration

### Login Flow

```
Client                 Falcon-ID              Database
  |                       |                       |
  |  POST /api/v1/auth/login                      |
  |  {username, password} |                       |
  |---------------------->|                       |
  |                       |   Verify credentials  |
  |                       |---------------------->|
  |                       |                       |
  |  200 OK               |                       |
  |  {access_token,       |                       |
  |   refresh_token,      |                       |
  |   expires_in}         |                       |
  |<----------------------|                       |
```

**Login Request:**
```bash
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "user@example.com",
  "password": "SecureP@ss123",
  "device_id": "browser-uuid",           # optional, enables device trust
  "trust_device": true                     # optional, extends refresh token to 30 days
}
```

**Success Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...", <!-- gitleaks:allow — documentation example -->
  "refresh_token": "rt_abc123...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_expires_in": 604800,
  "user": {
    "id": "uuid",
    "username": "user@example.com",
    "roles": ["admin"],
    "permissions": ["core:users:read", "core:users:write"],
    "tenant_id": "uuid",
    "mfa_enabled": false
  }
}
```

**MFA Required Response (200):**
```json
{
  "mfa_required": true,
  "mfa_token": "mfa_temp_token...",
  "mfa_methods": ["totp", "email"]
}
```

### Token Refresh

```bash
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "rt_abc123..."
}
```

### Using Access Tokens

Include the access token in every API request:

```bash
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

Or as an HttpOnly cookie (automatically set during browser-based login):
```
Cookie: falcon_access_token=eyJhbGciOiJIUzI1NiIs... <!-- gitleaks:allow — documentation example -->
```

### JWT Claims Structure

```json
{
  "sub": "user-uuid",
  "tenant_id": "tenant-uuid",
  "username": "user@example.com",
  "roles": ["admin", "user"],
  "permissions": ["core:users:read", "core:roles:write"],
  "realm_id": "realm-uuid",
  "session_id": "session-uuid",
  "iss": "falcon-id",
  "exp": 1700000000,
  "iat": 1699999100
}
```

### Validating Tokens in Other Services

**Option 1: Verify JWT locally (recommended for performance)**

Use the same `JWT_SECRET` to verify tokens in your service:

```go
// Go example
import "github.com/golang-jwt/jwt/v5"

claims := &jwt.MapClaims{}
token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
    return []byte(os.Getenv("JWT_SECRET")), nil
})
if err != nil || !token.Valid {
    // Reject request
}

tenantID := (*claims)["tenant_id"].(string)
userID := (*claims)["sub"].(string)
permissions := (*claims)["permissions"].([]interface{})
```

```typescript
// TypeScript/Node.js example
import jwt from 'jsonwebtoken';

const claims = jwt.verify(token, process.env.JWT_SECRET!);
const { sub: userId, tenant_id, permissions } = claims;
```

**Option 2: Call Falcon-ID's authorization endpoint**

```bash
POST /api/v1/authorize/check
Authorization: Bearer <access_token>

{
  "permission": "crm:contacts:write",
  "resource_type": "contact",
  "resource_id": "uuid"
}
```

**Option 3: Use the context endpoint (gets full user context)**

```bash
GET /api/v1/auth/me
Authorization: Bearer <access_token>
```

---

## Authorization Integration

### Permission Format

Permissions follow the pattern: `module:resource:action`

Examples:
- `core:users:read` — Read user profiles
- `core:users:write` — Create/update users
- `core:roles:manage` — Full role management
- `crm:contacts:write` — Write CRM contacts
- `finance:invoices:approve` — Approve invoices

### Registering Module Permissions

When your service starts, register its permissions with Falcon-ID:

```bash
POST /api/v1/permissions/register
X-Internal-Key: <INTERNAL_API_KEY>
Content-Type: application/json

{
  "module": "crm",
  "permissions": [
    {
      "resource": "contacts",
      "action": "read",
      "name": "crm:contacts:read",
      "display_name": "View Contacts",
      "description": "View CRM contact records"
    },
    {
      "resource": "contacts",
      "action": "write",
      "name": "crm:contacts:write",
      "display_name": "Edit Contacts",
      "description": "Create and edit CRM contact records"
    }
  ]
}
```

### Checking Permissions in Your Service

**From JWT claims (local check):**
```go
func hasPermission(claims jwt.MapClaims, required string) bool {
    perms, ok := claims["permissions"].([]interface{})
    if !ok {
        return false
    }
    for _, p := range perms {
        if p.(string) == required {
            return true
        }
    }
    return false
}
```

**Via Falcon-ID API (for resource-level checks):**
```bash
POST /api/v1/authorize/check
Authorization: Bearer <access_token>

{
  "permission": "crm:contacts:write",
  "resource_type": "contact",
  "resource_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Batch check:**
```bash
POST /api/v1/authorize/batch
Authorization: Bearer <access_token>

{
  "checks": [
    {"permission": "crm:contacts:read"},
    {"permission": "crm:contacts:write"},
    {"permission": "crm:contacts:delete"}
  ]
}
```

---

## Service-to-Service Communication

For internal microservice communication, use the `X-Internal-Key` header:

```bash
GET /api/v1/users/<user-id>
X-Internal-Key: <INTERNAL_API_KEY>
X-Tenant-ID: <tenant-uuid>
```

The `INTERNAL_API_KEY` must be at least 32 characters and shared between services via secure configuration (e.g., Vault, K8s secrets).

### Shared Auth Library

For Go services in the monorepo, use the shared auth package:

```go
import "github.com/dogukanturhal/falcon-id/internal/shared/auth"

// Create a client
client := auth.NewClient(auth.ClientConfig{
    BaseURL:     "http://falcon-id:8010",
    InternalKey: os.Getenv("INTERNAL_API_KEY"),
})

// Validate a token
claims, err := client.ValidateToken(ctx, tokenString)

// Check permission
allowed, err := client.CheckPermission(ctx, userID, tenantID, "crm:contacts:write")
```

### Middleware for Other Go Services

```go
import sharedmw "github.com/dogukanturhal/falcon-id/internal/shared/middleware"

// JWT validation middleware
router.Use(sharedmw.JWTAuth(jwtSecret))

// Tenant extraction middleware
router.Use(sharedmw.ExtractTenant())

// Permission check middleware
router.Use(sharedmw.RequirePermission("crm:contacts:read"))
```

---

## Multi-Tenant Integration

### Tenant Identification

Every request must include tenant context. Falcon-ID supports multiple methods:

1. **JWT token** (preferred) — `tenant_id` is embedded in the token claims
2. **X-Tenant-ID header** — For service-to-service calls
3. **Realm subdomain** — `acme.hexxlock.io` (production only, extracted by APISIX global rule)
4. **Realm header** — `X-Realm-Slug: acme`

### Tenant Isolation

All database queries MUST filter by `tenant_id`:

```sql
-- CORRECT: Tenant-scoped query
SELECT * FROM crm_contacts WHERE tenant_id = $1 AND id = $2;

-- WRONG: No tenant filter -- data leak risk
SELECT * FROM crm_contacts WHERE id = $1;
```

### Creating a New Tenant

```bash
POST /api/v1/platform/tenants
X-Internal-Key: <INTERNAL_API_KEY>

{
  "name": "acme-corp",
  "display_name": "Acme Corporation",
  "domain": "acme.com",
  "plan": "professional",
  "admin_email": "admin@acme.com",
  "admin_username": "admin",
  "admin_password": "SecureP@ss123"
}
```

---

## Email / SMTP Configuration

SMTP configuration is **per-tenant and stored in the database**, not in environment variables. This allows each tenant to use their own SMTP server.

### How It Works

The `EmailService` resolves SMTP settings via the `ConfigProvider`, which uses a 3-layer cache:

```
1. Local LRU cache (30 seconds TTL)
2. Redis cache (5 minutes TTL)
3. Database (iam_tenant_configs table)
4. Static fallback (config.Config, typically empty)
```

Sensitive values like `smtp_password` are encrypted at rest in the database using AES-256-GCM (requires `ENCRYPTION_KEY`).

### Default SMTP Config

Migration `064` seeds default SMTP configuration for the `default` tenant:

| Key | Default Value |
|-----|--------------|
| `smtp_host` | `mail.hexxlock.com` |
| `smtp_port` | `587` |
| `smtp_from` | `noreply@falcon.hexxlock.com` |
| `smtp_username` | (empty) |
| `smtp_password` | (empty) |
| `smtp_use_tls` | `true` |

### Setting Per-Tenant SMTP via API

```bash
PUT /api/v1/admin/tenant-config
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "configs": {
    "smtp_host": "smtp.sendgrid.net",
    "smtp_port": 587,
    "smtp_from": "noreply@acme.com",
    "smtp_username": "apikey",
    "smtp_password": "SG.xxx",
    "smtp_use_tls": true
  }
}
```

### SMTP Config Keys

| Key | Type | Description |
|-----|------|-------------|
| `smtp_host` | string | SMTP server hostname |
| `smtp_port` | int | SMTP port (587 for STARTTLS, 465 for implicit TLS) |
| `smtp_from` | string | Sender email address |
| `smtp_username` | string | SMTP authentication username |
| `smtp_password` | string | SMTP authentication password (encrypted at rest) |
| `smtp_use_tls` | bool | Enable TLS (STARTTLS on port 587, implicit on port 465) |

### Migration from Environment Variables

If you previously configured SMTP via environment variables (`SMTP_HOST`, `SMTP_PORT`, etc.), those env vars are now **ignored** once `ConfigProvider` is wired. To migrate:

1. Set SMTP config via the API (see above) for each tenant
2. Remove `SMTP_*` variables from your `.env` / deployment config
3. The seed migration (`064`) ensures the `default` tenant always has working SMTP defaults

---

## Frontend Integration

### Development vs Production URLs

| Context | Development | Production (Tenant) | Production (Platform) |
|---------|------------|--------------------|-----------------------|
| API base | `http://localhost:9080` | `https://api.hexxlock.io` | `https://api.hexxlock.com` |
| Dashboard | `http://localhost:3000` | `https://{tenant}.hexxlock.io` | `https://admin.hexxlock.com` |
| Login | `/api/auth/login` | `/api/auth/login` | `/api/auth/login` |
| Cookie domain | `localhost` | `.hexxlock.io` | `.hexxlock.com` |

### Next.js / React Setup

**Login:**
```typescript
const login = async (username: string, password: string) => {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });

  if (!res.ok) throw new Error('Login failed');

  const data = await res.json();

  if (data.mfa_required) {
    // Redirect to MFA verification page
    return { mfaRequired: true, mfaToken: data.mfa_token };
  }

  // Store tokens (HttpOnly cookies recommended via BFF pattern)
  return data;
};
```

**Token Refresh (BFF route handler):**
```typescript
// app/api/auth/refresh/route.ts
export async function POST(request: Request) {
  const refreshToken = request.cookies.get('falcon_refresh_token')?.value;

  const res = await fetch(`${FALCON_ID_URL}/api/v1/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  const data = await res.json();

  // Set new tokens as HttpOnly cookies
  const response = NextResponse.json({ success: true });
  response.cookies.set('falcon_access_token', data.access_token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: data.expires_in,
  });

  return response;
}
```

**Authenticated API Calls:**
```typescript
// lib/api.ts
export const api = {
  fetch: async (url: string, options?: RequestInit) => {
    const res = await fetch(url, {
      ...options,
      credentials: 'include', // Include HttpOnly cookies
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    if (res.status === 401) {
      // Try refresh
      const refreshRes = await fetch('/api/auth/refresh', { method: 'POST' });
      if (refreshRes.ok) {
        return fetch(url, { ...options, credentials: 'include' });
      }
      // Redirect to login
      window.location.href = '/login';
    }

    return res;
  },
};
```

---

## Federation & SSO

### OAuth 2.0 Social Login

```bash
# Initiate social login
GET /api/auth/social/{provider}/authorize?redirect_uri=https://app.example.com/callback

# Supported providers: google, github, apple, microsoft
```

### SAML 2.0

**IdP Metadata:**
```bash
GET /saml/metadata
```

**Assertion Consumer Service:**
```bash
POST /saml/acs
```

**Configure SAML SP:**
```bash
POST /api/v1/admin/saml-sp
Authorization: Bearer <admin_token>

{
  "name": "Salesforce",
  "entity_id": "https://salesforce.com/sp",
  "acs_url": "https://salesforce.com/saml/acs",
  "metadata_url": "https://salesforce.com/saml/metadata"
}
```

### OIDC Discovery

```bash
GET /api/oauth/.well-known/openid-configuration
```

---

## SCIM Provisioning

Falcon-ID supports SCIM 2.0 for automated user provisioning from identity providers (Azure AD, Okta, etc.).

### SCIM Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/scim/v2/Users` | List users |
| GET | `/scim/v2/Users/:id` | Get user |
| POST | `/scim/v2/Users` | Create user |
| PUT | `/scim/v2/Users/:id` | Replace user |
| PATCH | `/scim/v2/Users/:id` | Update user |
| DELETE | `/scim/v2/Users/:id` | Delete user |
| GET | `/scim/v2/Groups` | List groups |
| POST | `/scim/v2/Groups` | Create group |
| GET | `/scim/v2/ServiceProviderConfig` | SCIM config |
| GET | `/scim/v2/Schemas` | SCIM schemas |
| GET | `/scim/v2/ResourceTypes` | Resource types |

**Authentication:** Bearer token (create via Admin UI or API):
```bash
POST /api/v1/admin/scim/tokens
Authorization: Bearer <admin_token>

{
  "name": "Azure AD Provisioning",
  "scopes": ["users:read", "users:write", "groups:read", "groups:write"]
}
```

---

## Webhook Integration

Register webhooks to receive real-time notifications:

```bash
POST /api/v1/admin/webhooks
Authorization: Bearer <admin_token>

{
  "url": "https://your-service.com/webhooks/falcon-id",
  "events": [
    "user.created",
    "user.updated",
    "user.deleted",
    "user.login",
    "user.logout",
    "role.assigned",
    "role.unassigned",
    "mfa.enabled",
    "mfa.disabled"
  ],
  "secret": "webhook-signing-secret"
}
```

**Webhook Payload:**
```json
{
  "event": "user.created",
  "timestamp": "2025-01-15T10:30:00Z",
  "tenant_id": "uuid",
  "data": {
    "user_id": "uuid",
    "username": "newuser@example.com",
    "roles": ["user"]
  },
  "signature": "sha256=..."
}
```

---

## API Reference

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/auth/login` | None | Login |
| POST | `/api/v1/auth/refresh` | None | Refresh token |
| POST | `/api/v1/auth/logout` | Bearer | Logout |
| POST | `/api/v1/auth/mfa/verify` | MFA Token | Verify MFA code |
| POST | `/api/v1/auth/password/reset` | None | Request password reset |
| POST | `/api/v1/auth/password/reset/confirm` | None | Confirm password reset |
| POST | `/api/v1/auth/magic-link` | None | Request magic link |
| GET | `/api/v1/auth/me` | Bearer | Get current user |
| PUT | `/api/v1/auth/profile` | Bearer | Update profile |
| POST | `/api/v1/auth/password/change` | Bearer | Change password |

### User Management

| Method | Path | Auth | Permission |
|--------|------|------|-----------|
| GET | `/api/v1/users` | Bearer | `core:users:read` |
| GET | `/api/v1/users/:id` | Bearer | `core:users:read` |
| POST | `/api/v1/users` | Bearer | `core:users:write` |
| PUT | `/api/v1/users/:id` | Bearer | `core:users:write` |
| DELETE | `/api/v1/users/:id` | Bearer | `core:users:delete` |
| POST | `/api/v1/users/:id/roles` | Bearer | `core:users:manage` |
| DELETE | `/api/v1/users/:id/roles/:roleId` | Bearer | `core:users:manage` |

### Role Management

| Method | Path | Auth | Permission |
|--------|------|------|-----------|
| GET | `/api/v1/roles` | Bearer | `core:roles:read` |
| POST | `/api/v1/roles` | Bearer | `core:roles:write` |
| PUT | `/api/v1/roles/:id` | Bearer | `core:roles:write` |
| DELETE | `/api/v1/roles/:id` | Bearer | `core:roles:delete` |
| POST | `/api/v1/roles/:id/permissions` | Bearer | `core:roles:manage` |

### Authorization

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/authorize/check` | Bearer | Check single permission |
| POST | `/api/v1/authorize/batch` | Bearer | Batch permission check |

### Admin Operations

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/admin/audit-logs` | Bearer + Admin | Query audit logs |
| GET | `/api/v1/admin/sessions` | Bearer + Admin | List active sessions |
| POST | `/api/v1/admin/settings` | Bearer + Admin | Update IAM settings |
| GET | `/api/v1/admin/identity-providers` | Bearer + Admin | List IdPs |
| PUT | `/api/v1/admin/tenant-config` | Bearer + Admin | Update tenant config (SMTP, etc.) |

### Platform Operations (Super Admin)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/platform/tenants` | Internal Key | List tenants |
| POST | `/api/v1/platform/tenants` | Internal Key | Create tenant |
| GET | `/api/v1/platform/metrics` | Internal Key | System metrics |

---

## Environment Variables

### Development Minimum

```bash
ENVIRONMENT=development
SERVICE_PORT=8010
DATABASE_URL=postgres://falcon:falcon_dev@localhost:5432/falcon_id?sslmode=disable
REDIS_URL=redis://localhost:6379/0
ALLOW_AUTO_JWT_SECRET=true
FRONTEND_URL=http://localhost:3000
INTERNAL_API_KEY=dev-internal-key-minimum-32-characters-long
```

### Production Required

| Variable | Description | Example |
|----------|-------------|---------|
| `JWT_SECRET` | Token signing key (min 32 chars) | Random 64-char hex |
| `ENCRYPTION_KEY` | AES-256 key (exactly 32 bytes) | `hexxlock_enc_key_prod_2024_32by` |
| `TOKEN_HASH_SALT` | Token hash salt | Random 32-char string |
| `EMAIL_HASH_KEY` | HMAC key for email hashing | Random 32-char string |
| `INTERNAL_API_KEY` | Service-to-service key (min 32 chars) | Random 64-char hex |
| `TRUSTED_PROXIES` | Load balancer IPs | `10.0.0.1,10.0.0.2` |
| `DATABASE_URL` | PostgreSQL connection string | `postgres://...?sslmode=require` |
| `CONTROL_PLANE_DATABASE_URL` | Control plane DB | `postgres://...?sslmode=require` |
| `REDIS_URL` | Redis connection string | `redis://:pass@host:6379/0` |
| `FRONTEND_URL` | Frontend base URL | `https://app.yourdomain.com` |

### Optional (Production)

| Variable | Default | Description |
|----------|---------|-------------|
| `ACCESS_TOKEN_EXPIRY` | `15m` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRY` | `7d` | Refresh token lifetime |
| `MAX_LOGIN_ATTEMPTS` | `5` | Before account lockout |
| `LOCKOUT_DURATION` | `30m` | Account lockout duration |
| `SPICEDB_ENABLED` | `false` | Enable SpiceDB authorization |
| `USE_ABAC` | `false` | Enable OPA/ABAC policies |
| `REALM_ENABLED` | `true` | Multi-realm support |
| `OTLP_ENDPOINT` | `` | OpenTelemetry tracing endpoint |
| `METRICS_ENABLED` | `true` | Prometheus metrics at `/metrics` |
| `SMTP_HOST` | `` | Legacy SMTP fallback (prefer database config) |
| `SMTP_PORT` | `0` | Legacy SMTP fallback |
| `SMTP_FROM` | `` | Legacy SMTP fallback |
| `SMTP_USERNAME` | `` | Legacy SMTP fallback |
| `SMTP_PASSWORD` | `` | Legacy SMTP fallback |
| `SMTP_USE_TLS` | `true` | Legacy SMTP fallback |

> SMTP is now configured per-tenant via the database. See [Email / SMTP Configuration](#email--smtp-configuration). Environment variables serve only as a last-resort static fallback when no database config exists.

---

## Database Migrations

Falcon-ID schema migrations have two delivery paths in 2026-05-02+:

### Path 1: Keystone MigrationBundle (production, recommended from v0.1.x onward)

In production clusters, Falcon-ID's databases are managed by the
Keystone operator (DatabaseProvider/LogicalDatabase/DatabaseSchema CRs
in `keystone-system` namespace). New migrations land via Keystone's
`MigrationBundle` CR — applied transactionally, recorded in
`public.keystone_schema_migrations`, and emitting a tamper-evident
`AuditEntry` per apply.

**Per-release workflow:**

1. Author your `migrations/<NNN>_*.up.sql` (and `.down.sql`) as usual.
2. Tag the falcon-id release: `git tag v1.2.3 && git push origin v1.2.3`.
3. Run the bundle generator against the new tag:
   ```
   ./hack/render-migration-bundle.sh \
       --tag v1.2.3 \
       --since <last-applied-migration-version> \
       --schema-ref falcon-id-public \
       --out /path/to/<gitops-repo>/keystone/resources/falcon-id/migration-bundles/falcon-id-v1.2.3.yaml
   ```
4. Commit + open MR in the GitOps repository. Argo syncs → Keystone applies.
5. `kubectl get migrationexecution -n keystone-system` to confirm
   Phase=Succeeded; `kubectl get auditentries.keystone.hexxlock.io`
   to see the chain entry.

`--since` is the highest migration NNN already in the live database —
check via `psql -c "SELECT MAX(version) FROM public.schema_migrations"`
on initial bootstrap, or `keystone_schema_migrations.version` after
the first Keystone-applied bundle. The script bundles only files
newer than `--since` to keep ConfigMap size tight.

**FF12 (deferred)**: a CI stage will eventually invoke this script
automatically on tag push, commit the YAML to the GitOps repository via
deploy key, and the operator never runs it manually.

### Path 2: Embedded golang-migrate (tenant-provisioning only)

The boot-time `runAutoMigration` path was removed in falcon-id MR !128
once Keystone took over public-schema lifecycle. The remaining users
of `migrations.FS` are the per-tenant provisioner paths:
`internal/services/realm_db_migrator.go`,
`internal/services/realm_db_provisioner.go`, and
`internal/services/provisioning_orchestrator.go` — they still apply
the embedded SQL when seeding a fresh tenant database. That coupling
will be cut in a follow-up MR that routes tenant provisioning through
Keystone too.

The two tracking tables coexist intentionally:
- `public.schema_migrations` — golang-migrate tracking, INTEGER PK,
  rows for files 001..NNN historically applied.
- `public.keystone_schema_migrations` — Keystone tracking, TEXT PK,
  rows for bundles applied via the operator from the Keystone-takeover
  point onward.

### Key migration milestones

- `001`: Core tables (users, roles, permissions, tenants, tokens)
- `024`: Email hashing for GDPR-compliant search
- `027`: Refresh token rotation
- `030-031`: Realm architecture
- `044`: Default admin user seed
- `053`: Tenant-level configuration (`iam_tenant_configs` table)
- `060-061`: Product & license management
- `062`: Security hardening (parameterized queries, enc:v1: prefix)
- `063`: Refresh token tenant binding (cross-tenant reuse prevention)
- `064`: SMTP system defaults (seeds default tenant SMTP config into `iam_tenant_configs`)
- `200-231`: Post-platform-split migrations (OAuth/PAR/JAR/JWKS,
  refresh-token rotation grace, SonarQube OIDC, audit partition
  security definer)

---

## Security Checklist

### Before Going to Production

- [ ] Set all required environment variables (see Production Required table)
- [ ] `ENVIRONMENT=production` (enables strict security headers, disables debug)
- [ ] `ALLOW_AUTO_JWT_SECRET=false` (forces explicit JWT secret)
- [ ] `TRUSTED_PROXIES` explicitly set (prevents IP spoofing)
- [ ] `DATABASE_URL` uses `sslmode=require` or `sslmode=verify-full`
- [ ] Default admin password changed
- [ ] `ENCRYPTION_KEY` set (enables PII encryption at rest + SMTP password encryption)
- [ ] `EMAIL_HASH_KEY` set (enables HMAC email hashing)
- [ ] SMTP configured per-tenant via `PUT /api/v1/admin/tenant-config`
- [ ] Rate limiting enabled (`REDIS_RATE_LIMIT_ENABLED=true`)
- [ ] Audit logging enabled and retention configured
- [ ] CORS origins match subdomain layer (`.hexxlock.io` for tenant, `.hexxlock.com` for platform)
- [ ] API Gateway (APISIX) configured with TLS termination
- [ ] Wildcard TLS certs deployed (`*.hexxlock.com` + `*.hexxlock.io`)
- [ ] DNS records configured for all subdomains
- [ ] Cookie domains set correctly (`.hexxlock.io` for tenant, `.hexxlock.com` for platform)
- [ ] Health check endpoint monitored (`/health`)
- [ ] Prometheus metrics endpoint secured (`/metrics`)

### Security Features Enabled by Default

- AES-256-GCM PII encryption with `enc:v1:` key versioning
- HMAC-SHA256 email hashing (rainbow-table resistant)
- Argon2id password hashing (`m=65536, t=3, p=4`)
- JWT session rotation on refresh (prevents fixation)
- Refresh token tenant binding (prevents cross-tenant reuse)
- Redis circuit breaker (fail-closed on Redis outage)
- Tiered rate limiting (per-IP, per-account, global)
- Audit log hash chain (tamper detection)
- CSRF protection (Redis-backed double-submit cookie)
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Cookie isolation between `.hexxlock.com` and `.hexxlock.io` domains
- SMTP passwords encrypted at rest in database (AES-256-GCM)
- Global APISIX rule strips spoofable internal headers from external requests

---

## Troubleshooting

### Common Issues

**"Authorization header required" (401)**
- Ensure `Authorization: Bearer <token>` header is set
- Check token expiration (`exp` claim)
- Try refreshing with the refresh token

**"Tenant ID not found in context" (400)**
- Include `X-Tenant-ID` header for service-to-service calls
- Ensure JWT token contains `tenant_id` claim

**"Service temporarily unavailable" (503)**
- Redis may be down — Falcon-ID uses fail-closed security
- Check Redis connectivity: `redis-cli -u $REDIS_URL ping`

**"LDAP password encryption is not configured" (503)**
- Set `ENCRYPTION_KEY` environment variable
- Required for storing LDAP bind passwords securely

**"user tenant mismatch" during token refresh**
- User was moved to a different tenant after the refresh token was issued
- User must re-authenticate (login again)

**Rate limited (429)**
- Authentication: 5 attempts per minute per IP
- General API: 100 requests per minute
- Wait for the rate limit window to expire

**Email not sending / SMTP errors**
- Verify SMTP config is set for the tenant: `GET /api/v1/admin/tenant-config?keys=smtp_host,smtp_port,smtp_from`
- Ensure `ENCRYPTION_KEY` is set (required to decrypt `smtp_password` from DB)
- Check that the SMTP host is reachable from the Falcon-ID container
- For the default tenant, migration `064` seeds defaults — verify it has run

**CORS errors in browser**
- Development: Ensure the dev APISIX config includes your `localhost` port in `allow_origins`
- Production: Tenant dashboards must be on `*.hexxlock.io`, platform admin on `*.hexxlock.com`
- Cross-domain requests between `.hexxlock.com` and `.hexxlock.io` are blocked by design

### Logs

Falcon-ID uses structured JSON logging (zap):

```bash
# View logs
docker logs falcon-id

# Filter errors
docker logs falcon-id 2>&1 | jq 'select(.level == "error")'
```

### Metrics

Prometheus metrics are available at `/metrics`:

```
# Key metrics
falcon_id_http_requests_total
falcon_id_http_request_duration_seconds
falcon_id_auth_login_attempts_total
falcon_id_auth_login_failures_total
falcon_id_token_validations_total
falcon_id_rate_limit_rejections_total
```

---

## Quick Start Checklist

For a new service integrating with Falcon-ID:

1. **Add APISIX routes** — Dev config (`config/apisix/apisix-dev.yaml`) + Production config (`api-gateway/apisix/apisix.yaml`). See [API Gateway Integration](#api-gateway-integration)
2. **Register permissions** — Call `/api/v1/permissions/register` with your module's permissions
3. **Validate JWT tokens** — Use shared JWT secret or call `/api/v1/auth/me`
4. **Read trusted headers** — `X-User-ID`, `X-Tenant-ID`, `X-User-Role` are set by the gateway after auth validation
5. **Check permissions** — From JWT claims or via `/api/v1/authorize/check`
6. **Include tenant context** — Always filter by `tenant_id` from JWT claims or `X-Tenant-ID` header
7. **Handle 401/403** — Redirect to login or show access denied
8. **Set up webhooks** — Subscribe to user lifecycle events if needed
9. **Add health checks** — Expose `/health` endpoint for APISIX upstream checks
10. **Configure SMTP** — If your service sends email, use Falcon-ID's `EmailService` or configure per-tenant SMTP via the admin API

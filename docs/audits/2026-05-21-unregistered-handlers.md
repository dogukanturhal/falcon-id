# Unregistered-handler audit — falcon-id

Date: 2026-05-21
Trigger: the same forgotten-one-liner pattern that bit the ITDR
handler (memory internal engineering notes)
and the `/login-methods` handler (live 404 in BFF logs, fixed in this
MR). Audit asks: how many other handler methods carry a Swagger
`@Router` annotation but are never wired to a gin route?

## Method

`python3` walk over `internal/handlers/*.go` extracting every
`@Router <path> [verb]` annotation paired with its `func (...)`
receiver. Cross-reference against `cmd/*.go` for any `.HandlerType.Method`
reference. Methods with annotation but no reference = "unregistered".

## Headline numbers

- 450 `@Router`-annotated methods total.
- 65 unregistered as of the master commit at the start of this MR.
- After the wiring in this MR: 50 remain unregistered.

The remaining 50 split into three buckets:

1. **Deliberately unwired** — 9 routes (ProductInstance, see below).
2. **Wired in this MR** — 15 routes (covered separately).
3. **Need new service+handler wiring before route registration** —
   the 41 routes listed below. Each requires NEW fields in the
   `Services` struct (`cmd/services.go`) and `Handlers` struct
   (`cmd/handlers.go`), plus the wiring in `initServices`/
   `initHandlers`. That's a non-trivial change per handler, NOT a
   one-line route addition, so each gets its own MR with its own
   security-envelope decision (auth middleware, rate-limit, step-up,
   tier classification).

This memo is the triage map for those follow-up MRs.

---

## Deliberately unwired (do NOT register)

### `ProductInstanceHandler` (9 routes)

```
POST   /api/v1/platform/products/{id}/instances                 → Provision
GET    /api/v1/platform/products/{id}/instances/{instance_id}   → Get
GET    /api/v1/platform/instances                               → ListByTenant
GET    /api/v1/platform/products/{id}/instances                 → ListByProduct
DELETE /api/v1/platform/products/{id}/instances/{instance_id}   → Deprovision
POST   /api/v1/platform/products/{id}/instances/{instance_id}/retry → Retry
GET    /internal/v1/tenant-databases/{tenant_id}/{database_name}    → LookupTenantDatabase
GET    /api/v1/platform/products/{id}/instances/{instance_id}/databases → ListInstanceDatabases
GET    /api/v1/platform/tenants/{tenant_id}/instances           → ListByTenantForPlatform
```

Per `cmd/routes_products.go:86-87`:

> // NOTE: Product Instances and Product Database Groups routes have been moved
> // to the db-provisioner service as part of Phase 1c decomposition.

The handler methods + their `@Router` annotations are vestigial
from before the Phase 1c split. They MUST NOT be re-registered —
re-registration would re-introduce the duplicated surface that the
Phase 1c decomposition was designed to remove. Action: delete the
unused handler methods + their annotations in a separate cleanup MR
to remove the false-positive from future audits.

---

## Needs new service + handler wiring (per-handler triage)

For each handler below, the work is:

1. Read the handler file to capture constructor signature + service
   interface.
2. Confirm the underlying `services/*.go` exists, OR build it.
3. Add the missing field to `Services` struct in `cmd/services.go`;
   wire the constructor with its repo deps.
4. Add the missing field to `Handlers` struct in `cmd/handlers.go`;
   wire the constructor.
5. Pick a register function in `cmd/routes*.go` matching the path
   prefix, OR create a new register function for the handler's
   surface. Wire each route with the correct middleware chain (auth
   middleware, role gate, step-up where appropriate, rate-limit
   where applicable).
6. Tests: a handler-level test and a route-registration smoke test.

### `AdminAuditHandler` (3 routes)

```
GET /api/admin/audit/admin-actions            → ListAdminAuditLogs
GET /api/admin/audit/admin-actions/{id}       → GetAdminAuditLog
GET /api/admin/audit/admin-actions/stats      → GetAdminAuditStats
```

- File: `internal/handlers/admin_audit_handler.go`.
- Service: `AdminAuditService` — confirm exists in `internal/services/`.
- Tier: admin (`registerAdminRoutes` in `cmd/routes_admin.go`).
- Middleware: `RequireAuth + RequireRole("admin", "platform_admin")`.
- Step-up: NOT required (read-only audit log).
- Note: distinct from the already-registered `AdminHandler.ListAuditLogs`
  (general audit) — this one is the dedicated admin-action audit log
  (who-did-what to admin surface mutations). Both must coexist.

### `AgentIdentityHandler` (9 routes)

```
POST /api/v1/platform/agents                            → Create
GET  /api/v1/platform/agents                            → List
GET  /api/v1/platform/agents/{id}                       → GetByID
PUT  /api/v1/platform/agents/{id}                       → Update
POST /api/v1/platform/agents/{id}/suspend               → Suspend
POST /api/v1/platform/agents/{id}/revoke                → Revoke
POST /api/v1/platform/agents/{id}/rotate-credentials    → RotateCredentials
GET  /api/v1/platform/agents/{id}/activity              → GetActivity
POST /api/v1/platform/agents/token                      → IssueToken
```

- File: `internal/handlers/agent_identity_handler.go`.
- Service: `AgentIdentityService`.
- Tier: platform admin (`registerPlatformAdminRoutes`).
- Middleware: `RequireAuth + RequireRole("platform_admin")`.
- Step-up: REQUIRED on Suspend / Revoke / RotateCredentials /
  IssueToken (token issuance is credential mint — equivalent in
  blast radius to OAuth-client mutations which are already step-up
  gated).
- Rate limit: IssueToken should sit behind a dedicated bucket
  (10 req/min/agent) similar to refresh-token issuance.
- Coordinate with `ServiceClientClaim` XRD (memory:
  internal engineering notes) — agents may
  be the next generation of that flow, or a parallel surface for
  human-attended automation. Verify the design intent before wiring.

### `AuditHandler` (5 routes)

```
GET  /api/v1/auth/audit/logs                                → GetAuditLogs
POST /api/v1/auth/audit/archive                             → ArchiveTenantLogs
GET  /api/v1/auth/audit/archives                            → GetArchiveMetadata
POST /api/v1/auth/audit/archives/{batch_id}/verify          → VerifyArchiveIntegrity
GET  /api/v1/auth/audit/export                              → ExportAuditReport
```

- File: `internal/handlers/audit_handler.go`.
- Service: needs `services.Audit` (exists) +
  `services.AuditArchiver` (NEW — verify exists in
  `internal/services/`; if not, the audit-archiver pattern lives
  in the integration-bus consumer per memory
  internal engineering notes).
- Tier: protected auth (`registerProtectedAuthRoutes`), but
  ArchiveTenantLogs + VerifyArchiveIntegrity gate on tenant-admin
  role at the handler level.
- Coordinate with WORM 7-year retention (project memory
  internal engineering notes) — `VerifyArchiveIntegrity`
  reaches into the audit-archive MinIO bucket; the verification
  endpoint MUST run with read-only S3 creds, not write.

### `ComplianceEvidenceHandler` (3 routes)

```
GET /api/v1/platform/compliance/soc2  → SOC2Report
GET /api/v1/platform/compliance/gdpr  → GDPRReport
GET /api/v1/platform/compliance/kvkk  → KVKKReport
```

- File: `internal/handlers/compliance_evidence_handler.go`.
- Service: `ComplianceLiveEvidenceService` — new build.
- Tier: platform admin (`registerComplianceReportRoutes` exists in
  `cmd/routes_admin.go:995` — add to that block).
- Middleware: platform_admin role; NO step-up (read-only reports).
- Note: distinct from `ComplianceReportHandler` which is already
  registered for the saved-report surface. This handler computes
  the live "snapshot of every compliance-relevant control" view.
  Likely fronted by Grafana/dashboards before the admin UI ships
  the read.

### `DeviceFingerprintHandler` (3 routes)

```
GET    /api/v1/auth/fingerprints           → ListDeviceFingerprints
POST   /api/v1/auth/fingerprints/{id}/trust → TrustDeviceFingerprint
DELETE /api/v1/auth/fingerprints/{id}      → RevokeDeviceFingerprint
```

- File: `internal/handlers/device_fingerprint_handler.go`.
- Service: `DeviceFingerprintService` (uses interface
  `deviceFingerprintServiceIface` in the handler).
- Tier: protected auth (user-scoped — fingerprints belong to the
  authenticated user).
- Middleware: `RequireAuth`. Trust + Revoke should gate on
  `freshAuth` (5min) — trusting a fingerprint creates a long-lived
  silent-MFA bypass, so a stolen cookie alone must not be enough.
- Coordinate with the existing `DeviceHandler` (registered) — the
  two handlers manage adjacent state (device record vs hardware
  fingerprint). Decide whether to MERGE them or keep separate.

### `FleetOperationsHandler` (4 routes)

```
POST /api/v1/platform/fleet/migrations    → RunMigrations
POST /api/v1/platform/fleet/sql           → RunSQL
POST /api/v1/platform/fleet/health-check  → RunHealthCheck
GET  /api/v1/platform/fleet/capacity      → GetCapacityReport
```

- File: `internal/handlers/fleet_operations_handler.go`.
- Service: abstract `fleetRunner` interface — needs concrete impl
  (probably backed by the keystone-sdk fleet runner OR moved into
  the fleet-operator k8s controller entirely).
- Tier: platform admin OR internal-s2s. `RunSQL` is a remote-code-
  execution surface; it MUST be gated by both platform_admin role
  AND step-up AND tenant-scoped audit. Probably better as internal
  S2S only (called by a CLI or controller, not the admin UI).
- **Action**: hold this one for explicit security review BEFORE
  registering ANY of the four. `RunSQL` registered carelessly is
  a sev-1 exposure.

### `GDPRHandler` (6 routes)

```
GET    /api/v1/users/{id}/export                       → ExportUserData
DELETE /api/v1/users/{id}/delete                       → RequestDeletion
GET    /api/v1/users/{id}/deletion-status              → GetDeletionRequest
POST   /api/v1/deletion-requests/{id}/cancel           → CancelDeletion
POST   /api/v1/deletion-requests/{id}/legal-hold       → SetLegalHold
DELETE /api/v1/deletion-requests/{id}/legal-hold       → RemoveLegalHold
```

- File: `internal/handlers/gdpr_handler.go`.
- Services: `DataExportService` + `DataDeletionService` + existing
  `services.User`.
- Tier: mixed — user-scoped (export, delete-self) + admin
  (legal-hold). Split across `registerProtectedAuthRoutes` (the
  user paths under `/users/me/*`) and `registerAdminRoutes` (the
  legal-hold paths).
- Middleware: step-up gate on RequestDeletion (matches the existing
  `/users/me/delete-account` pattern at `routes.go:636`); platform_admin
  + step-up on SetLegalHold + RemoveLegalHold (these override
  a user's deletion request — auditable + sensitive).
- **Compliance coupling**: KVKK / GDPR / SOC2 controls hinge on
  these endpoints being correctly wired with proof-of-access logs.
  The audit-archiver pattern (memory:
  internal engineering notes) must
  emit `gdpr_export_completed` / `legal_hold_placed` events.

### `ProvisioningPolicyHandler` (2 routes)

```
POST /api/v1/platform/policy/evaluate  → EvaluatePolicy
GET  /api/v1/platform/policy/rules     → ListRules
```

- File: `internal/handlers/provisioning_policy_handler.go`.
- Service: `provisioningPolicyEngine` interface.
- Tier: platform admin. `EvaluatePolicy` is read-only against the
  engine (no state change), `ListRules` is read-only.
- Middleware: `RequireAuth + RequireRole("platform_admin")`.
  No step-up.
- Coordinate with the existing OPA-backed `PolicyHandler` — these
  may be the same concern at different layers (policy decision vs.
  policy enforcement). Confirm the design before wiring two parallel
  policy surfaces.

### `SchemaVersionHandler` (3 routes)

```
GET /api/v1/platform/schema-versions                    → ListVersions
GET /api/v1/platform/schema-versions/drift              → GetDriftReport
GET /api/v1/platform/schema-versions/tenant/{tenant_id} → GetTenantVersions
```

- File: `internal/handlers/schema_version_handler.go`.
- Service: `schemaVersionService` interface.
- Tier: platform admin (read-only).
- Middleware: `RequireAuth + RequireRole("platform_admin")`. No
  step-up. No rate limit.
- Coordinate with the keystone-sdk SchemaDefinition controller —
  the drift report here may overlap with the controller's drift
  computation; confirm one canonical source.

### `TenantMeteringHandler` (3 routes)

```
GET /api/v1/platform/tenant-resources              → GetTenantResources
GET /api/v1/platform/metering/tenant/{tenant_id}   → GetTenantMetering
GET /api/v1/platform/metering/summary              → GetMeteringSummary
```

- File: `internal/handlers/tenant_metering_handler.go`.
- Service: `TenantResourceMonitor` — needs the pgxpool + the
  background-job scrape state.
- Tier: platform admin (read-only).
- Middleware: `RequireAuth + RequireRole("platform_admin")`.
- Coordinate with `services.UsageMetering` (`UsageHandler`) which IS
  registered — these are likely adjacent: UsageMetering = the
  per-tenant usage ledger, TenantResourceMonitor = the live
  resource snapshot. Confirm and keep both.

---

## Pre-existing duplicate surface (skip — no MR needed)

`RoleHandler.ListPermissions` (GET `/api/permissions`) and
`RoleHandler.ListPermissionsByModule` (GET `/api/permissions/by-module`)
are stale @Router annotations on what is functionally a duplicate of
`PermissionHandler.List` and `PermissionHandler.ListGroupedByModule`
(both registered in `registerPermissionRoutes`). The Permission
handler is canonical. Action: delete the Role-side method bodies +
annotations in the same cleanup MR that purges the ProductInstance
methods.

---

## Action items

1. Pick three MRs to land in priority order:
   1. **GDPR endpoints** (compliance gate — these MUST exist for
      KVKK/GDPR certification).
   2. **AdminAuditHandler** (security-audit surface; pairs with the
      admin-actions Argo CD dashboard).
   3. **AgentIdentityHandler** (unblocks the agent-driven automation
      track once the design intent is confirmed against
      `ServiceClientClaim`).
2. `FleetOperationsHandler.RunSQL` does NOT get wired until a
   formal threat-model review signs off. Default state: keep unwired.
3. After landing the next three handlers, add the lint guard
   (custom `golangci-lint` linter) that fails the build when an
   `@Router`-annotated handler method has no corresponding `.HandlerType.Method`
   reference anywhere in `cmd/*.go`. This stops the ITDR /
   `login-methods` /  current 41-handler-gap pattern from regrowing.
4. Delete dead handler methods (ProductInstance + Role aliases) in
   a cleanup MR so the audit number trends downward.

## Memory

- internal engineering notes —
  prior instance of this same forgotten-one-liner pattern.
- internal engineering notes — required
  context for `AgentIdentityHandler`.
- internal engineering notes — informs the WORM
  retention + step-up choices for the audit + GDPR endpoints.

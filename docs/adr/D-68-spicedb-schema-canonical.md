# D-68: Canonical SpiceDB schema — the Helm file is the single source of truth

- Status: Accepted
- Date: 2026-09-26
- Scope: falcon-id repository (this decision uses the `acmeapp-plan` D-NN
  decision numbering, not the repo-local `docs/adr/000N` series, because it
  is tracked as decision D-68 in `the product roadmap` R0 W8/W13 and
  `the product specification` §1.1a/§5.4/§12)
- Related: `the product roadmap` R0 W8 "Canonical SpiceDB schema" item and R0
  exit criteria; `23-authorization-rbac-abac-rebac.md` §1.1a (ground-truth
  audit of the 3-way divergence), §4.1 (what's already live-correct), §5.4
  (schema-drift CI gate); the 2026-04-28 internal-ops-IAP outage (missing
  `talon_route`); the t-582 schema audit (header comment of the canonical
  file, quoted below)

## Context

Before this change, falcon-id carried **three** divergent `.zed` files, plus
one dead reference, none of which pointed at each other:

1. **`deploy/helm/spicedb-schema/files/spicedb.zed`** (793 lines at HEAD) —
   the file the Helm chart's PreSync `schema-write-job` actually renders and
   writes to the live SpiceDB cluster (see
   `deploy/helm/spicedb-schema/templates/schema-write-job.yaml`,
   `schema-revision.yaml`). It carries its own header comment recording that
   it was authored against a **source-verified survey of business's real
   `ISpiceDbClient` writers and `[RequirePermission]`/`[RequireResourcePermission]`
   checks** (ticket t-582), and it is already covered by the `schema:spicedb`
   CI job (`.gitlab-ci.yml`), which compiles it against a real, throwaway
   SpiceDB `v1.35.1` container on every change and asserts every declared
   `definition` survives the write/read-back round trip. It includes
   `talon_route`, the internal ops IAP relation whose absence caused the
   2026-04-28 outage.
2. **`schema/spicedb.zed`** (492 lines) — the **default** `-schema-file`
   value baked into `schema/migrate.go`. Strictly a stale subset: every one
   of its 29 `definition`s already exists in the Helm file (verified by
   diffing `definition`/`caveat` names across all three files — see table
   below), and it is **missing `talon_route`**. Running `migrate.go` with
   its old default against a fresh environment would reproduce the exact
   2026-04-28 outage mechanism on a new cluster.
3. **`schema/example_complete.zed`** (1,448 lines, header "v1.0.0",
   2026-02-03) — an aspirational draft, **never wired into any deploy or CI
   path**. Its only reference anywhere in the Go codebase was an
   explanatory code comment in `internal/services/tenant_bootstrap.go:185`
   (now updated to point at the canonical file instead). It declares 72
   definitions, 16 of which already exist (redundantly) in the Helm file
   under the same or a differently-prefixed name, and 56 of which describe
   resources that are not live anywhere.
4. **`cmd/schema.go`** and **`cmd/migrate-spicedb/schema.go`** both hard-coded
   `schemaPath = "schemas/example.zed"` — a directory (`schemas/`, not
   `schema/`) that does not exist anywhere in the repo. `cmd/schema.go`'s
   `SchemaManager`/`RunMigration` are dead code in the main falcon-id server
   binary (nothing in `cmd/main.go` calls them — confirmed by grep, no
   `RunMigration(` or `SchemaManager` call site outside `cmd/schema.go`
   itself). `cmd/migrate-spicedb/schema.go` **is** live: `cmd/migrate-spicedb/main.go`'s
   `schema` subcommand (`migrate-spicedb schema --action=...`) calls
   `RunMigration`, so its broken default was a real footgun for whoever
   next runs that CLI tool without overriding the path.

**Decision**: `deploy/helm/spicedb-schema/files/spicedb.zed` is the single
source of truth. `schema/spicedb.zed` and `schema/example_complete.zed` are
deleted outright (see the per-definition table below for why nothing from
either needed to graduate first). `schema/migrate.go`, `cmd/schema.go`, and
`cmd/migrate-spicedb/schema.go` now default to the Helm file's path. A new
CI job, `schema:single-source` (`hack/check-canonical-spicedb-schema.sh`),
fails the build if any `*.zed` file other than the canonical one appears
anywhere in the repo again.

## Evidence method

For every `definition`/`caveat` name in `schema/spicedb.zed` and
`schema/example_complete.zed` that is **not already present** in the Helm
file, "graduate vs. retire" was decided by searching for a real writer or
checker of that exact SpiceDB object-type name:

- **Checker evidence** (business, read-only, `~/projects/_wt/R0-business`):
  `grep -rn 'RequireResourcePermission("<name>"' --include='*.cs'` — this
  attribute (`src/Shared/Hexxlock.Shared/ReBAC/Attributes/RequireResourcePermissionAttribute.cs`)
  is the only place a *specific SpiceDB object type* is checked by name
  (`[RequireResourcePermission("crm_contact", "edit", "contactId")]` checks
  permission `edit` on object type `crm_contact`). `[RequirePermission(module, resource, action)]`
  does **not** count as evidence for a `resource`-named definition — per
  spec §1.2, that attribute always checks the coarse `module` object
  (`view`/`edit`/`manage`/`delete`), not a dedicated SpiceDB type per
  resource; e.g. `[RequirePermission("inventory", "bom", "read")]` checks
  `module:inventory#view`-family permissions, it does not check an object of
  type `bom`. Treating every manifest `resource` string as schema evidence
  would be exactly the false-completeness `example_complete.zed` already
  represents.
- **Writer evidence** (falcon-id, this worktree):
  `grep -rn 'ObjectType:\s*"<name>"' --include='*.go'` across the whole
  repo — a real `WriteRelationships` call constructing that object type.

## Per-definition table

### `schema/spicedb.zed` (29 definitions) — retire the file, nothing to graduate

Every definition in this file already exists in the canonical Helm file.
Confirmed by diffing `grep -oE '^(definition|caveat)\S+ [A-Za-z_]+' ` output
across all three files:

`access_grant`, `api_key`, `application`, `crm_company`, `crm_contact`,
`crm_opportunity`, `document`, `ecommerce_category`, `ecommerce_customer`,
`ecommerce_order`, `ecommerce_product`, `employee`, `folder`, `group`,
`invoice`, `module`, `organization`, `payment`, `platform_product`,
`platform_product_instance`, `product`, `project`, `role`,
`service_principal`, `session`, `task`, `tenant`, `user`, `warehouse` — **all
29 already in the Helm file.** The file's only material difference from the
Helm file is the *absence* of `talon_route`, i.e. it is not a richer
alternative, it is a stale, dangerous subset. **Verdict: retire (delete)**,
no graduation needed.

### `schema/example_complete.zed` (72 definitions)

**Already redundant with the Helm file (16)** — retire the file's copies,
keep the Helm file's (in some cases differently-named/scoped) real version:
`access_grant`, `api_key`, `document`, `employee`, `folder`, `group`,
`invoice`, `module`, `organization`, `payment`, `product`, `project`,
`role`, `session`, `task`, `tenant`, `user`, `warehouse`, `budget`,
`delivery`, `production_scrap` — these overlap the Helm file either
byte-for-byte in name or are superseded by the Helm file's real,
production-prefixed equivalents (e.g. `company`/`contact` here vs. the
Helm file's real `crm_company`/`crm_contact`, which is what
`RequireResourcePermission("crm_company", ...)` / `("crm_contact", ...)`
actually check in CRM's controllers).

**No writer, no checker found anywhere — retire (55):** `abc_classification`,
`account`, `atp_check`, `audit_log`, `batch`, `batch_allocation`,
`batch_genealogy`, `bom`, `campaign`, `candidate`, `company`, `contact`,
`credit_note`, `custom_field`, `custom_object`, `cycle_count`, `dashboard`,
`deal`, `department`, `document_version`, `email_template`,
`engagement_survey`, `exchange_rate`, `goods_receipt`, `integration`,
`interview`, `inventory_valuation`, `job_posting`, `journal_entry`,
`kb_article`, `lead`, `leave_request`, `marketing_list`, `material_request`,
`offer`, `opportunity`, `pipeline`, `pipeline_stage`, `quote`, `report`,
`resource_allocation`, `resource_capacity`, `serial_number`, `skill`,
`stock_movement`, `succession_plan`, `ticket`, `timesheet`, `webhook`,
`work_center`, `workflow`, `workflow_instance`, `warehouse_selection`,
`realm`. For each of these, `grep -rn 'RequireResourcePermission("<name>"'`
over `~/projects/_wt/R0-business` and `grep -rn 'ObjectType:\s*"<name>"'`
over this repo returned nothing (a handful of literal-string matches on
e.g. `"company"`, `"quote"`, `"leave_request"` exist in business, but on
inspection they are unrelated `switch`/`case` branches on domain strings,
not SpiceDB object-type references). `realm` has one hit, but only inside
`cmd/schema.go`'s/`cmd/migrate-spicedb/schema.go`'s own hard-coded
"for now, using example data" placeholder backfill code (`tenant: "hexxlock"`,
`admin@example.com`) — an illustrative stub, not a production writer.
**Verdict: retire.**

**Checker exists, no writer — retire, precedent-matched (1):** `capacity_plan`.
`src/Modules/Hexxlock.Modules.PM/Controllers/CapacityPlanController.cs`
genuinely calls `[RequireResourcePermission("capacity_plan", "edit"/"delete"/"approve"/"archive", "id")]`
— a real, live checker. No writer exists anywhere (falcon-id has no
`ObjectType: "capacity_plan"` relationship write; business's PM module only
has a Postgres `capacity_plans` table, unrelated to SpiceDB). This is
exactly the same shape as the ~36 `cmms_*`/`plm_*`/`qms_*`/`allocation`/
`capacity`/`segment` resource types that the canonical Helm file's own t-582
audit **deliberately left undefined** (per `23-authorization-rbac-abac-rebac.md`
§1.1) precisely because a checker with no writer can never be satisfied —
every check against it returns `NOT_HAS_PERMISSION` (or, while undefined, a
schema-not-found API error) for every principal, forever, until a writer is
built. Defining `capacity_plan` today would not fix or change PM's current
behavior (those three endpoints already deny everyone, since the object
type is undefined in every schema PM has ever actually been enforced
against); it would just add a fourth never-populated definition. Consistent
with the existing audit's own precedent, this is tracked as a **known gap**
for whoever ships PM's own SpiceDB writer (out of this ADR's scope — D-68 is
about the schema *files*, not about building new writers) rather than
graduated speculatively. **Verdict: retire from `example_complete.zed`**; if
PM ships a real `capacity_plan` writer in a future module-S2 pass, add the
definition then, straight to the canonical Helm file, following the same
manifest-reconciliation discipline this ADR describes.

## What changed

1. `deploy/helm/spicedb-schema/files/spicedb.zed` — **unchanged**. It was
   already the correct, live, code-verified schema; nothing needed to
   graduate into it (see table above). Per the task's own constraint, no
   existing definition/relation/permission in this file was touched, added,
   removed, or renamed.
2. `schema/spicedb.zed`, `schema/example_complete.zed` — **deleted**.
3. `schema/migrate.go` — `-schema-file` default now
   `deploy/helm/spicedb-schema/files/spicedb.zed`.
4. `cmd/schema.go`, `cmd/migrate-spicedb/schema.go` — `schemaPath` constant
   now `deploy/helm/spicedb-schema/files/spicedb.zed` (previously the
   dead/nonexistent `schemas/example.zed`).
5. `internal/services/tenant_bootstrap.go:185` — comment updated to
   reference the canonical Helm file instead of the now-deleted
   `example_complete.zed`.
6. New CI job `schema:single-source` (`.gitlab-ci.yml`) running
   `hack/check-canonical-spicedb-schema.sh`, `allow_failure: false`,
   unconditional (no path filter, unlike `schema:spicedb`) — fails the
   build if any `*.zed` file other than the canonical one exists anywhere
   in the repo. This is a file-location/count gate; the existing
   `schema:spicedb` job remains the compile-correctness gate for the Helm
   file's contents.

## Non-goals (tracked elsewhere)

- Building the manifest→schema `.zed`-fragment exporter and the
  drift-detecting CI gate for *new* manifest permissions
  (`23-authorization-rbac-abac-rebac.md` §5.4) — that is the separate R0
  W13 "schema-drift CI gate" item, layered on top of this canonicalization,
  not part of it.
- Adding `capacity_plan` or any of the `cmms_*`/`plm_*`/`qms_*`/`allocation`/
  `capacity`/`segment` checker-only, no-writer resource types to the Helm
  file. Per the precedent above, these stay undefined until a real writer
  exists; adding them now would not change any observed behavior (those
  endpoints already deny everyone) and would reopen exactly the
  "define first, verify never" pattern this ADR is closing off.

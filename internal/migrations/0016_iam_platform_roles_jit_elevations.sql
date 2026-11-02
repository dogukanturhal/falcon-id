-- Migration 0016: Platform plane - iam_platform_roles, JIT elevation +
-- break-glass (iam_jit_elevations), append-only hash-chain transition log
-- (iam_jit_elevation_transitions).
--
-- Spec: the product roadmap §4.1 "Platform plane"; acmeapp-plan/specs/
-- 17-module-account.md §12 (ADR, §12.3 SpiceDB sketch, §12.4 state machine,
-- §6.5 exact column list) and §13.9 addendum (platform_role_not_standing_
-- assignable); 23-authorization-rbac-abac-rebac.md §4.2/§4.3 (hxl_platform
-- SpiceDB definition + active_elevation caveat - see the matching change
-- to deploy/helm/spicedb-schema/files/spicedb.zed in this same commit);
-- mockups account-admin/30-platform-jit-elevation.html (8h duration cap,
-- two-person/peer approval, break-glass card with retroactive-approver +
-- countdown) and account-admin/35-platform-roles-admin.html (rejection
-- copy for the standing-role guard rail).
--
-- Design:
--   iam_platform_roles(user_id, role_key, granted_at, granted_by) is the
--   MATERIALIZED platform-role-membership table (mirrors, but does not
--   replace, the SpiceDB hxl_platform relationship - see
--   platform_jit_service.go's write-DB-then-SpiceDB / delete-SpiceDB-then-DB
--   ordering notes). Only platform_viewer is a standing (permanent) row;
--   every other role_key may only exist while a confirmed, active
--   iam_jit_elevations row backs it - enforced by the trigger below, in
--   ADDITION to (not instead of) the handler-level 403
--   platform_role_not_standing_assignable check on the direct
--   POST /internal/v1/platform-roles admin endpoint (belt-and-suspenders:
--   the DB refuses the row even if a future code path forgets the check).
--
--   iam_jit_elevations is the JIT request/approval/activation/expiry
--   record. Two-person rule is a plain CHECK (approver_id <> requester_id,
--   retroactive_approver_id <> requester_id) - cheapest possible
--   enforcement, cannot be bypassed by an application bug. Duration cap
--   (8h standing JIT / 1h break-glass) is a CHECK. Break-glass requests
--   have no approver_id at creation time (self-granted immediately) but
--   MUST get retroactive_approver_id/retroactive_approved_at within 24h or
--   the auto-revoke sweep (platform_jit_service.go RunBreakGlassSLASweep)
--   flags break_glass_violation=true and revokes the grant.
--
--   iam_jit_elevation_transitions is an append-only hash chain (reuses
--   services.ComputeImmutableEntryHash - see immutable_audit_service.go -
--   rather than inventing a second hash function) satisfying the
--   "(hash-chain)" annotation on iam_jit_elevations in spec §6.5. Chosen
--   over the existing ImmutableAuditService because that service is wired
--   with a nil store (cmd/services.go:960) and is currently a
--   non-functional stub; this table is a real, queryable table from day
--   one. It is additional to, not a replacement for, the existing
--   AuditService.LogUserAction calls the service layer also makes on
--   every transition (the "full audit trail through the existing audit
--   log" requirement) - this table is specifically for chain-integrity
--   verification of the elevation lifecycle, the audit_events table is
--   for the general-purpose human-readable audit trail.
--
-- SpiceDB: elevations materialize as a time-bound hxl_platform relationship
-- (hxl_platform:hexxlock#<role>@user:<tenant_scoped_id>) written with an
-- active_elevation(now, expires_at) caveat - see pkg/spicedb/client.go
-- WritePlatformElevation/DeletePlatformElevation and the schema change in
-- this commit. Caveats are used (not deferred) because authzed-go v1.8.0
-- already supports ContextualizedCaveat/Context-on-Check; a caveat gives a
-- fail-closed instant cutoff at CHECK time without needing the sweep job to
-- have already run. The sweep job still deletes the relationship
-- afterwards (idempotent, DB-driven - see below) so stale relationships
-- don't accumulate.
--
-- Auto-revoke: DB-driven idempotent sweep, NOT an in-memory timer, so it
-- survives restarts/multiple replicas. The sweep's SELECT is
-- `WHERE status = 'active' AND expires_at < now()` (see
-- idx_iam_jit_elevations_sweep_active below) - re-running the sweep twice
-- on the same row is a no-op the second time because the first run already
-- flipped status to 'expired' (falls out of the WHERE clause).
--
-- RLS: per this repo's convention (see migration 0015's header), Row Level
-- Security is declared in the Keystone SchemaDefinition
-- (the GitOps repository), not in this migration. All three tables here are
-- platform-plane data (requester_id/user_id always belong to the
-- Platform-internal tenant), so their RLS policy is a fixed-tenant policy
-- rather than a `current_setting('app.current_tenant_id')` one - see the
-- schema-definition-main.yaml change in the the GitOps repository worktree.
--
-- Idempotency: CREATE TABLE/INDEX/TRIGGER IF NOT EXISTS,
-- CREATE OR REPLACE FUNCTION. Safe to re-run against a live DB.
--
-- Migration numbering: 0016 is next-free per sibling R1 worktrees
-- (0012 role-templates, 0013 invitations, 0014 entitlements, 0015 sod),
-- confirmed against the merged r1/falcon-schema integration branch.

SET LOCAL statement_timeout = '30s';

-- =====================================================================
-- iam_platform_roles - standing platform-role membership
-- =====================================================================

CREATE TABLE IF NOT EXISTS iam_platform_roles (
    user_id     uuid        NOT NULL REFERENCES iam_users(id) ON DELETE CASCADE,

    role_key    text        NOT NULL
                            CHECK (role_key IN (
                                'platform_admin',
                                'platform_support',
                                'platform_billing',
                                'platform_security',
                                'platform_viewer'
                            )),

    granted_at  timestamptz NOT NULL DEFAULT now(),
    granted_by  uuid        NULL REFERENCES iam_users(id),

    PRIMARY KEY (user_id, role_key)
);

CREATE INDEX IF NOT EXISTS idx_iam_platform_roles_role_key
    ON iam_platform_roles (role_key);

COMMENT ON TABLE iam_platform_roles IS
    'Standing Hexxlock platform-plane role membership. Only platform_viewer may exist as a standing row; any other role_key row must be backed by a currently-active iam_jit_elevations row (enforced by iam_platform_roles_enforce trigger) or a currently-active break-glass grant.';
COMMENT ON COLUMN iam_platform_roles.role_key IS
    'Mirrors the hxl_platform SpiceDB relation names 1:1 (platform_admin->admin, platform_support->support, platform_billing->billing, platform_security->security, platform_viewer->viewer).';

-- Cross-table membership + standing-role guard rail. A plain CHECK cannot
-- reference another table, so this is a trigger. Runs in ADDITION to the
-- handler-level 403 platform_role_not_standing_assignable check (defense
-- in depth - see migration header).
CREATE OR REPLACE FUNCTION iam_platform_roles_enforce() RETURNS trigger AS $$
DECLARE
    user_tenant_id uuid;
    has_active_elevation boolean;
BEGIN
    SELECT tenant_id INTO user_tenant_id FROM iam_users WHERE id = NEW.user_id;

    IF user_tenant_id IS NULL OR user_tenant_id::text <> '00000000-0000-0000-0000-000000000002' THEN
        RAISE EXCEPTION 'iam_platform_roles.user_id must belong to the Platform-internal tenant (00000000-0000-0000-0000-000000000002), got tenant %', user_tenant_id
            USING ERRCODE = '23514'; -- check_violation
    END IF;

    IF NEW.role_key <> 'platform_viewer' THEN
        SELECT EXISTS (
            SELECT 1 FROM iam_jit_elevations
            WHERE requester_id = NEW.user_id
              AND role_key = NEW.role_key
              AND status = 'active'
              AND expires_at > now()
        ) INTO has_active_elevation;

        IF NOT has_active_elevation THEN
            RAISE EXCEPTION 'role_key % is not standing-assignable; it requires a confirmed, active iam_jit_elevations row (platform_role_not_standing_assignable)', NEW.role_key
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_iam_platform_roles_enforce ON iam_platform_roles;
CREATE TRIGGER trg_iam_platform_roles_enforce
    BEFORE INSERT OR UPDATE ON iam_platform_roles
    FOR EACH ROW EXECUTE FUNCTION iam_platform_roles_enforce();

-- =====================================================================
-- iam_jit_elevations - JIT elevation request/approval/activation/expiry,
-- and break-glass self-grant + retroactive approval.
-- =====================================================================

CREATE TABLE IF NOT EXISTS iam_jit_elevations (
    id                          uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,

    requester_id                uuid        NOT NULL REFERENCES iam_users(id) ON DELETE CASCADE,

    role_key                    text        NOT NULL
                                            CHECK (role_key IN (
                                                'platform_admin',
                                                'platform_support',
                                                'platform_billing',
                                                'platform_security',
                                                'platform_viewer'
                                            )),

    -- NULL = platform-wide elevation. Non-NULL scopes the grant to a
    -- single customer tenant (e.g. platform_support diagnosing one
    -- tenant's data) - the SpiceDB relationship is written on that
    -- tenant's object rather than hxl_platform:hexxlock when set.
    tenant_scope                uuid        NULL REFERENCES iam_tenants(id) ON DELETE CASCADE,

    reason                      text        NOT NULL CHECK (length(btrim(reason)) > 0),

    status                      text        NOT NULL DEFAULT 'pending'
                                            CHECK (status IN (
                                                'pending', 'approved', 'active',
                                                'expired', 'revoked', 'denied'
                                            )),

    -- Two-person rule: the DB itself refuses a self-approval, independent
    -- of any application-layer bug.
    approver_id                 uuid        NULL REFERENCES iam_users(id),
    approved_at                 timestamptz NULL,

    -- Duration cap: 8h (28800s) standing JIT per mockup
    -- account-admin/30-platform-jit-elevation.html; break-glass is capped
    -- much shorter (1h) since it self-activates with no prior approval.
    requested_duration_seconds  integer     NOT NULL
                                            CHECK (requested_duration_seconds > 0
                                               AND requested_duration_seconds <= 28800),

    expires_at                  timestamptz NULL,

    is_break_glass               boolean     NOT NULL DEFAULT false,

    -- Break-glass 24h retroactive-approval SLA.
    retroactive_approver_id      uuid        NULL REFERENCES iam_users(id),
    retroactive_approved_at      timestamptz NULL,
    break_glass_violation        boolean     NOT NULL DEFAULT false,

    -- ZedToken from the SpiceDB WriteRelationships call that activated
    -- this grant, and from the DELETE that revoked it - lets an operator
    -- correlate this row with the exact SpiceDB write without a second
    -- round trip, and lets the revoke sweep detect "already deleted"
    -- idempotently even if the DELETE succeeded but the local commit
    -- crashed before marking the row expired.
    spicedb_activate_zed_token   text        NULL,
    spicedb_revoke_zed_token     text        NULL,

    created_at                   timestamptz NOT NULL DEFAULT now(),
    updated_at                   timestamptz NOT NULL DEFAULT now(),

    CHECK (approver_id IS NULL OR approver_id <> requester_id),
    CHECK (retroactive_approver_id IS NULL OR retroactive_approver_id <> requester_id),
    CHECK (NOT is_break_glass OR requested_duration_seconds <= 3600),
    -- Break-glass rows self-activate with no prior approver; only a
    -- non-break-glass row can carry an approver_id/approved_at before
    -- reaching 'active'.
    CHECK (NOT is_break_glass OR approver_id IS NULL)
);

-- Sweep hot-path: "every active grant whose window has closed" -
-- WHERE clause matches idx_iam_jit_elevations_sweep_active exactly so the
-- planner can use it; re-running the sweep is a no-op once status flips
-- (row falls out of this partial index).
CREATE INDEX IF NOT EXISTS idx_iam_jit_elevations_sweep_active
    ON iam_jit_elevations (expires_at)
    WHERE status = 'active';

-- Break-glass SLA sweep hot-path: "every break-glass grant still awaiting
-- retroactive approval and not yet flagged".
CREATE INDEX IF NOT EXISTS idx_iam_jit_elevations_break_glass_pending
    ON iam_jit_elevations (created_at)
    WHERE is_break_glass AND retroactive_approved_at IS NULL AND NOT break_glass_violation;

CREATE INDEX IF NOT EXISTS idx_iam_jit_elevations_requester
    ON iam_jit_elevations (requester_id);

CREATE INDEX IF NOT EXISTS idx_iam_jit_elevations_tenant_scope
    ON iam_jit_elevations (tenant_scope)
    WHERE tenant_scope IS NOT NULL;

-- At most one open request (pending/approved/active) per
-- (requester, role_key, scope) - prevents duplicate concurrent JIT
-- requests for the same elevation. Sentinel COALESCE for the NULL
-- (platform-wide) tenant_scope, same convention as migration 0015.
CREATE UNIQUE INDEX IF NOT EXISTS idx_iam_jit_elevations_one_open_per_subject
    ON iam_jit_elevations (
        requester_id,
        role_key,
        COALESCE(tenant_scope, '00000000-0000-0000-0000-000000000000'::uuid)
    )
    WHERE status IN ('pending', 'approved', 'active');

COMMENT ON TABLE iam_jit_elevations IS
    'JIT elevation request/approval/activation/expiry, and break-glass self-grant + 24h retroactive-approval tracking, for the Hexxlock platform plane. Two-person rule and duration caps are enforced by CHECK constraints.';
COMMENT ON COLUMN iam_jit_elevations.tenant_scope IS
    'NULL = platform-wide grant (hxl_platform:hexxlock relationship). Non-NULL = grant scoped to one customer tenant.';
COMMENT ON COLUMN iam_jit_elevations.break_glass_violation IS
    'Set true by the 24h SLA sweep when a break-glass grant did not receive retroactive_approved_at in time. A violation auto-revokes the grant (status set to revoked) in the same sweep pass.';

DROP TRIGGER IF EXISTS trg_iam_jit_elevations_updated_at ON iam_jit_elevations;
CREATE OR REPLACE FUNCTION iam_jit_elevations_set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_iam_jit_elevations_updated_at
    BEFORE UPDATE ON iam_jit_elevations
    FOR EACH ROW EXECUTE FUNCTION iam_jit_elevations_set_updated_at();

-- =====================================================================
-- iam_jit_elevation_transitions - append-only hash-chain audit log of
-- every status transition (per elevation, chained by prev_hash).
-- =====================================================================

CREATE TABLE IF NOT EXISTS iam_jit_elevation_transitions (
    id            uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    elevation_id  uuid        NOT NULL REFERENCES iam_jit_elevations(id) ON DELETE CASCADE,

    from_status   text        NULL,
    to_status     text        NOT NULL,

    actor_id      uuid        NULL REFERENCES iam_users(id),
    occurred_at   timestamptz NOT NULL DEFAULT now(),

    -- Hash chain (per elevation_id): prev_hash is the previous row's
    -- entry_hash for this elevation ('' for the first transition);
    -- entry_hash = ComputeImmutableEntryHash(prev_hash, occurred_at,
    -- actor, action, resource, resource_id, data) - reusing the existing
    -- helper in internal/services/immutable_audit_service.go.
    prev_hash     text        NOT NULL DEFAULT '',
    entry_hash    text        NOT NULL,

    details       jsonb       NULL
);

CREATE INDEX IF NOT EXISTS idx_iam_jit_elevation_transitions_elevation
    ON iam_jit_elevation_transitions (elevation_id, occurred_at);

COMMENT ON TABLE iam_jit_elevation_transitions IS
    'Append-only hash-chained record of every iam_jit_elevations status transition. Satisfies the "(hash-chain)" annotation in spec 17-module-account.md §6.5. INSERT-only by convention (see trg_iam_jit_elevation_transitions_immutable) - use RunAuditChainVerification to check integrity.';

-- True append-only: refuse any UPDATE/DELETE at the DB level, so a hash
-- chain break can never be caused by an application bug silently
-- rewriting history (only a superuser bypassing triggers could - same
-- guarantee level as the rest of this repo's audit tables).
CREATE OR REPLACE FUNCTION iam_jit_elevation_transitions_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'iam_jit_elevation_transitions is append-only; % is not permitted', TG_OP
        USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_iam_jit_elevation_transitions_immutable ON iam_jit_elevation_transitions;
CREATE TRIGGER trg_iam_jit_elevation_transitions_immutable
    BEFORE UPDATE OR DELETE ON iam_jit_elevation_transitions
    FOR EACH ROW EXECUTE FUNCTION iam_jit_elevation_transitions_immutable();

GRANT SELECT, INSERT, UPDATE, DELETE ON iam_platform_roles TO falcon_id_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON iam_jit_elevations TO falcon_id_app;
GRANT SELECT, INSERT ON iam_jit_elevation_transitions TO falcon_id_app;

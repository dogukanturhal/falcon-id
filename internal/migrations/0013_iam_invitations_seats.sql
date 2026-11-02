-- 0013_iam_invitations_seats.sql
--
-- Seat model for invitations/memberships (the product roadmap §4.1 "Invitations
-- and memberships", §2.1 commercial model, §4.9 R1 exit "Seat model live");
-- see also the product specification §13.2/§13.7/§13.17/§13.18
-- and specs/25-signup-onboarding-trials.md §4.5/§9.
--
-- WHAT THIS IS: falcon-id already ships a production invitation flow
-- (iam_team_invitations + TeamInvitationHandler, migrations 0002/0011) at
-- POST/GET /api/v1/invitations, .../accept, .../decline, DELETE /:id. That
-- flow has never enforced a seat quota — CreateInvitation persists an
-- invitation for any email with no seat check at all (the exact gap the
-- spec calls out: "notes-identity.md CreateInvitation gap", §13.2). Rather
-- than stand up a second, competing iam_invitations/invitations route
-- surface (which would collide with the live one at the same path and
-- violate the additive-only constraint), this migration extends the
-- existing table and adds the two new entities the spec calls for:
--   - iam_team_invitations gains seat_class (member/external/service,
--     matching §3.2's locked seat_class rule) and last_resent_at (resend
--     rate-limit bookkeeping, §13.17).
--   - iam_user_memberships: the tenant<->user membership/seat_class ledger
--     (spec §13.7), backfilled from every existing non-service iam_users
--     row so it becomes the seat-counting source of truth going forward.
--   - tenant_seat_counters: the race-free reservation row (spec §13.7/
--     §13.2's advisory-lock/atomic-UPDATE pattern). seat_limit is
--     nullable and defaults to NULL ("not yet configured"): the
--     included-seats-from-active-plans source (subscription-management /
--     falcon-id iam_tenant_module_entitlements) does not exist yet on this
--     branch (grepped: no included_seats/seat_limit column or resolver
--     anywhere in falcon-id today), so seat enforcement is OFF (fail-open,
--     not fail-closed) for any tenant whose seat_limit has never been set.
--     PUT /internal/v1/tenants/{id}/seat-limit (added alongside this
--     migration) is how an operator or a future subscription-management
--     sync sets it; once set, CreateInvitation enforces it atomically.
--     See docs/adr-follow-up note in the seat_counter_repository.go header
--     for the wiring-to-real-entitlements follow-up.
--
-- DESTRUCTIVE-DRIFT FREEZE: falcon-id has a pending destructive-drift
-- approval in Keystone, so this migration is purely additive — new tables,
-- ADD COLUMN IF NOT EXISTS with safe defaults, no DROP, no NOT NULL added
-- to an existing populated column, no type change. Idempotent: safe to
-- re-run against an already-migrated DB.
--
-- Canonical DDL source for the Keystone MigrationBundle:
-- falcon-id-v0.232.266 (the GitOps repository, see bundled.lock).

SET LOCAL statement_timeout = '30s';

-- -----------------------------------------------------------------------
-- 1. iam_team_invitations: seat_class + resend rate-limit bookkeeping
-- -----------------------------------------------------------------------

ALTER TABLE iam_team_invitations
    ADD COLUMN IF NOT EXISTS seat_class TEXT NOT NULL DEFAULT 'member'
        CHECK (seat_class IN ('member', 'external', 'service')),
    ADD COLUMN IF NOT EXISTS last_resent_at TIMESTAMPTZ NULL;

COMMENT ON COLUMN iam_team_invitations.seat_class IS
    'member consumes a seat; external (accountant/guest) and service never do, per the product roadmap §2.1/§3.2. Backfilled to member for every pre-existing row (the only kind this flow ever created before this column existed).';

COMMENT ON COLUMN iam_team_invitations.last_resent_at IS
    'Set by POST /api/v1/invitations/{id}/actions/resend. Resend is rejected with 429 when now() - last_resent_at < 5 minutes (§13.17).';

CREATE INDEX IF NOT EXISTS idx_iam_team_invitations_tenant_seat_class_status
    ON iam_team_invitations (tenant_id, seat_class, status);

-- -----------------------------------------------------------------------
-- 2. iam_user_memberships: tenant<->user membership + seat_class ledger
-- -----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS iam_user_memberships (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES iam_tenants(id),
    user_id         UUID NOT NULL REFERENCES iam_users(id),
    seat_class      TEXT NOT NULL DEFAULT 'member'
                        CHECK (seat_class IN ('member', 'external', 'service')),
    status          TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'deactivated')),
    invitation_id   UUID NULL REFERENCES iam_team_invitations(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deactivated_at  TIMESTAMPTZ NULL,

    CONSTRAINT iam_user_memberships_tenant_user_uq UNIQUE (tenant_id, user_id)
);

COMMENT ON TABLE iam_user_memberships IS
    'Tenant<->user membership + seat_class ledger (the product roadmap §4.1 "Invitations and memberships", the product specification §13.7). Backfilled from iam_users; going forward, AcceptInvitation upserts this row and it is the seat-counting source of truth (tenant_seat_counters.seats_used), not a live COUNT(*) over iam_users.';

CREATE INDEX IF NOT EXISTS idx_iam_user_memberships_seat_count
    ON iam_user_memberships (tenant_id)
    WHERE status = 'active' AND seat_class = 'member';

CREATE INDEX IF NOT EXISTS idx_iam_user_memberships_invitation
    ON iam_user_memberships (invitation_id)
    WHERE invitation_id IS NOT NULL;

ALTER TABLE iam_user_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam_user_memberships FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS iam_user_memberships_tenant_isolation ON iam_user_memberships;
CREATE POLICY iam_user_memberships_tenant_isolation ON iam_user_memberships
    USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- Backfill: one membership row per existing tenant user. svc-% rows are
-- excluded (mirrors SeatQuotaReconciler.countBillableSeatsByTenant's own
-- svc- exclusion — service identities are never a membership).
INSERT INTO iam_user_memberships (tenant_id, user_id, seat_class, status, created_at, deactivated_at)
SELECT
    u.tenant_id,
    u.id,
    'member',
    CASE WHEN u.is_active THEN 'active' ELSE 'deactivated' END,
    u.created_at,
    CASE WHEN NOT u.is_active THEN now() ELSE NULL END
FROM iam_users u
WHERE u.username NOT ILIKE 'svc-%'
  AND u.deletion_scheduled_at IS NULL
ON CONFLICT (tenant_id, user_id) DO NOTHING;

-- -----------------------------------------------------------------------
-- 3. tenant_seat_counters: race-free reservation row (spec §13.2/§13.7)
-- -----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tenant_seat_counters (
    tenant_id       UUID PRIMARY KEY REFERENCES iam_tenants(id),
    seats_used      INTEGER NOT NULL DEFAULT 0 CHECK (seats_used >= 0),
    seats_pending   INTEGER NOT NULL DEFAULT 0 CHECK (seats_pending >= 0),
    -- NULL = seat limit not yet configured for this tenant; enforcement is
    -- OFF (see header note). Set via PUT /internal/v1/tenants/{id}/seat-limit.
    seat_limit      INTEGER NULL CHECK (seat_limit IS NULL OR seat_limit >= 0),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE tenant_seat_counters IS
    'Single-row-per-tenant seat reservation counter. seats_used + seats_pending must never exceed seat_limit once seat_limit is set (the product roadmap §2.1/§4.9). Mutated exclusively via the atomic UPDATE ... WHERE seats_used + seats_pending < seat_limit RETURNING pattern in SeatCounterRepository — never read-then-write from application code.';

COMMENT ON COLUMN tenant_seat_counters.seat_limit IS
    'included_seats MAX(active module plans) + seat-pack quantities, per §2.1. NULL until subscription-management/entitlements data is wired (see 0013 migration header) or an operator sets it via PUT /internal/v1/tenants/{id}/seat-limit.';

ALTER TABLE tenant_seat_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_seat_counters FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_seat_counters_tenant_isolation ON tenant_seat_counters;
CREATE POLICY tenant_seat_counters_tenant_isolation ON tenant_seat_counters
    USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- Backfill: seed one counter row per tenant that has any membership or
-- pending invitation today, so the first invite after this migration reads
-- an accurate seats_used/seats_pending rather than starting from zero.
INSERT INTO tenant_seat_counters (tenant_id, seats_used, seats_pending, seat_limit, updated_at)
SELECT
    t.tenant_id,
    COALESCE(m.used_count, 0),
    COALESCE(p.pending_count, 0),
    NULL,
    now()
FROM (
    SELECT tenant_id FROM iam_user_memberships
    UNION
    SELECT tenant_id FROM iam_team_invitations WHERE status = 'pending'
) t
LEFT JOIN (
    SELECT tenant_id, COUNT(*) AS used_count
    FROM iam_user_memberships
    WHERE status = 'active' AND seat_class = 'member'
    GROUP BY tenant_id
) m ON m.tenant_id = t.tenant_id
LEFT JOIN (
    SELECT tenant_id, COUNT(*) AS pending_count
    FROM iam_team_invitations
    WHERE status = 'pending' AND seat_class = 'member'
    GROUP BY tenant_id
) p ON p.tenant_id = t.tenant_id
ON CONFLICT (tenant_id) DO NOTHING;

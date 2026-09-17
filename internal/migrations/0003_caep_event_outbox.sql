-- ZTNA Phase 6 — CAEP transactional outbox.
--
-- ADR cross-refs: Talon ADR 0040 (ZTNA Platform) Phase 6; Falcon-ID
-- ADR 0009 (CAEP Outbox, to be written alongside this migration's
-- bundle in the GitOps repository v0.232.256).
--
-- Why an outbox:
--   The Phase 1 CAEPEmitter (shipped 2026-06-06 wave 2 via MR 278+279)
--   delivers SETs via best-effort sync HTTP push. Any RP outage (5xx
--   / timeout / DNS hiccup) silently drops the SET — the only retry
--   is the next user action that triggers a re-emit. For tier-1 we
--   need at-least-once delivery so receivers like Talon don't miss
--   credential-change or session-revoked signals.
--
--   The pattern mirrors iam_oauth_logout_outbox (BCL drainer) exactly
--   — same column shape, same indexes, same status enum, same
--   advisory-lock + SKIP LOCKED single-flight discipline. The drainer
--   code (caep_outbox_drainer.go) is a near-1:1 fork of
--   backchannel_logout_drainer.go.
--
-- Idempotency: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.
-- Safe to apply against a live DB that already has the table (the
-- keystone bundle v0.232.256 records this migration as applied
-- without redundant DDL).
--
-- GRANTs: the matching keystone bundle issues GRANT SELECT, INSERT,
-- UPDATE, DELETE on this table to falcon_id_app (mirror of v0.232.234
-- pattern for iam_oauth_logout_outbox).
--
-- Privacy: subject_iss + subject_sub are pairwise identifiers per RFC
-- 9493; not directly PII but linkable. event_data is jsonb and CAN
-- contain credential_type names (e.g. 'password', 'fido2-platform') —
-- never the credential value itself. Retention pruner deletes
-- delivered_at < now() - 30d (configurable).

SET LOCAL statement_timeout = '30s';

CREATE TABLE IF NOT EXISTS iam_caep_event_outbox (
    id                uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,

    -- The SSF stream this event will be delivered to. FK to
    -- iam_ssf_streams.id. ON DELETE CASCADE because a stream removal
    -- means any pending events for it are no longer deliverable.
    stream_id         uuid        NOT NULL REFERENCES iam_ssf_streams(id) ON DELETE CASCADE,

    -- The CAEP / RISC event-type URN. Examples:
    --   https://schemas.openid.net/secevent/caep/event-type/session-revoked
    --   https://schemas.openid.net/secevent/caep/event-type/credential-change
    --   https://schemas.openid.net/secevent/risc/event-type/account-disabled
    event_type        text        NOT NULL,

    -- RFC 9493 subject identifier triple. format='iss_sub' for the
    -- CAEP transmitter's default; other formats supported (email,
    -- phone_number, opaque) as Phase 6.b expands.
    subject_format    text        NOT NULL DEFAULT 'iss_sub',
    subject_iss       text        NOT NULL,
    subject_sub       text        NOT NULL,

    -- Event payload (the data subobject keyed under event_type in the
    -- SET 'events' claim). Per CAEP 1.0 §3 this carries event-specific
    -- claims like reason_admin, credential_type, change_type,
    -- event_timestamp.
    event_data        jsonb       NOT NULL DEFAULT '{}'::jsonb,

    -- Lifecycle status. CHECK constraint mirrors iam_oauth_logout_outbox.
    status            text        NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending','sent','dead')),

    attempt_count     integer     NOT NULL DEFAULT 0,
    next_retry_at     timestamptz NOT NULL DEFAULT now(),
    last_error        text,

    -- The HTTP delivery target (resolved at enqueue-time from the
    -- iam_ssf_streams.delivery row). Frozen at enqueue to ride out
    -- mid-flight stream config changes.
    target_uri        text        NOT NULL,

    created_at        timestamptz NOT NULL DEFAULT now(),
    delivered_at      timestamptz
);

-- Drainer claim index: hot-path SELECT WHERE status='pending' AND
-- next_retry_at <= now() ORDER BY next_retry_at LIMIT N. Partial
-- index keeps it small even as sent/dead rows accumulate before the
-- retention pruner sweeps them.
CREATE INDEX IF NOT EXISTS idx_iam_caep_event_outbox_pending_retry
    ON iam_caep_event_outbox (next_retry_at)
    WHERE status = 'pending';

-- Operator queries: "all pending deliveries for stream X" or "events
-- of type Y for tenant Z's stream".
CREATE INDEX IF NOT EXISTS idx_iam_caep_event_outbox_stream_status
    ON iam_caep_event_outbox (stream_id, status);

CREATE INDEX IF NOT EXISTS idx_iam_caep_event_outbox_event_type
    ON iam_caep_event_outbox (event_type);

-- Retention-pruner index.
CREATE INDEX IF NOT EXISTS idx_iam_caep_event_outbox_created_at
    ON iam_caep_event_outbox (created_at);

COMMENT ON TABLE iam_caep_event_outbox IS
    'ZTNA Phase 6 transactional outbox for CAEP / RISC SETs. At-least-once delivery via caep_outbox_drainer.go (mirror of backchannel_logout_drainer.go).';

COMMENT ON COLUMN iam_caep_event_outbox.event_data IS
    'CAEP event-payload jsonb. Never contains credential VALUES — only claim metadata (credential_type, change_type, reason_admin, event_timestamp).';

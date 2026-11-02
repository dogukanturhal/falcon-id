SET LOCAL statement_timeout = '30s';

ALTER TABLE tenant_seat_counters
    ADD COLUMN IF NOT EXISTS seat_limit_version     BIGINT NULL,
    ADD COLUMN IF NOT EXISTS seat_limit_computed_at  TIMESTAMPTZ NULL;

COMMENT ON COLUMN tenant_seat_counters.seat_limit_version IS
    'Monotonic ordering key for seat_limit writes (subscription-management sends computed_at as Unix nanoseconds). NULL = never versioned (0013-era manual/operator PUT). SetSeatLimit applies a write only when the incoming version is NULL or strictly greater than this column -- an older, redelivered PUT (outbox retry) is rejected as a no-op rather than overwriting a newer value. See SetSeatLimit''s doc comment.';

COMMENT ON COLUMN tenant_seat_counters.seat_limit_computed_at IS
    'Wall-clock time subscription-management computed the seat_limit it PUT. Diagnostic only (mirrors tenant_subscriptions.plan_synced_at) -- seat_limit_version, not this column, is what the stale-write compare uses.';

-- 0005_user_recovery_methods.sql
-- Account-recovery methods (recovery email today; recovery phone reserved).
--
-- Kept in a dedicated table rather than as columns on iam_users so the
-- golden-locked core User model + its many scan sites stay untouched, and so a
-- user can hold more than one method type. Pending verification codes are NOT
-- stored here — they live in Redis as ephemeral, brute-force-limited OTPs — so
-- a row only ever holds the canonical value once it has been verified.
--
-- One row per (user, method_type): at most one recovery email and one recovery
-- phone per user. ON DELETE CASCADE ties lifecycle to the owning user (a
-- deleted account drops its recovery methods with it).

CREATE TABLE IF NOT EXISTS iam_user_recovery_methods (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES iam_users(id) ON DELETE CASCADE,
    tenant_id     UUID NOT NULL,
    method_type   TEXT NOT NULL CHECK (method_type IN ('email', 'phone')),
    value         TEXT NOT NULL,
    verified      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at   TIMESTAMPTZ,
    CONSTRAINT uq_recovery_user_method UNIQUE (user_id, method_type)
);

CREATE INDEX IF NOT EXISTS idx_recovery_methods_user_id
    ON iam_user_recovery_methods (user_id);

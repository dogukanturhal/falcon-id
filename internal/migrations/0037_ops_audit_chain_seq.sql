-- Migration 0037: operator audit chain position (chain_seq).
--
-- platform_admin_audit_log.chain_seq: strictly increasing position of a row in
-- the operator hash chain. The consumer assigns it (max + 1) while it holds the
-- chain advisory lock, so it follows commit order. The chain head used to be
-- picked by created_at (= transaction START time), which could fork the chain
-- when two writers overlapped. Rows written before this migration keep
-- chain_seq NULL and sort before sequenced rows in chain order (created_at, id).
--
-- Delivered to production by Keystone MigrationBundle falcon-id v0.232.292
-- (the GitOps repository); see bundled.lock.
--
-- Idempotent: IF NOT EXISTS.

SET LOCAL statement_timeout = '60s';
SET LOCAL lock_timeout = '5s';

ALTER TABLE platform_admin_audit_log ADD COLUMN IF NOT EXISTS chain_seq bigint NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_platform_admin_audit_log_chain_seq
    ON platform_admin_audit_log (chain_seq)
    WHERE chain_seq IS NOT NULL;

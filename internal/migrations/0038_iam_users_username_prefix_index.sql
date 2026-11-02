-- Migration 0038: global user search index.
--
-- idx_iam_users_username_lower_prefix: btree on lower(username)
-- text_pattern_ops, so the staff console's username prefix search
-- (lower(username) LIKE 'abc%') is an index range scan.
-- CREATE INDEX CONCURRENTLY cannot run inside Keystone's transactional
-- migration runner (see 0003_user_preferences.sql); iam_users is small, the
-- brief SHARE lock of a plain CREATE INDEX (writes wait, reads do not) is
-- accepted and lock_timeout bounds the wait.
--
-- Delivered to production by Keystone MigrationBundle falcon-id v0.232.293
-- (the GitOps repository); see bundled.lock.
--
-- Idempotent: IF NOT EXISTS.

SET LOCAL statement_timeout = '60s';
SET LOCAL lock_timeout = '5s';

CREATE INDEX IF NOT EXISTS idx_iam_users_username_lower_prefix
    ON iam_users (lower(username) text_pattern_ops);

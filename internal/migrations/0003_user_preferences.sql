-- Migration: per-user opaque preferences JSONB
--
-- Adds `preferences JSONB NOT NULL DEFAULT '{}'` to iam_users. Stores
-- user-scoped UI affordances that don't belong on workspace/tenant rows:
-- locale override, theme, dismissed banners, and (the proximate driver)
-- per-product onboarding state.
--
-- Why JSONB + namespacing under products.<slug> (Microsoft Graph schema-
-- extension convention, Atlassian Forge Storage SDK partition convention):
--
--   {
--     "schema_version": 1,
--     "global":   { "locale": "en-US", "theme": "dark" },
--     "products": {
--       "acmeweb":     { "schema_version": 1, "onboarding": { "tour_seen": true,  "dismissed_banners": ["welcome"] } },
--       "hexx_forge": { "schema_version": 1, "onboarding": { "tour_seen": false } }
--     }
--   }
--
-- Each product owns its own subtree and bumps its own schema_version
-- independently — no cross-product collisions, no flat key namespace
-- explosion at N products (avoids the `acmeweb_onboarding_*` anti-pattern
-- called out in the 2026-06-02 onboarding-architecture research,
-- transcript stored in repo /docs/decisions/).
--
-- We deliberately do NOT bake the JSON schema into a CHECK constraint:
-- every product schema bump would become a DDL migration with downtime
-- risk on iam_users (one of the hottest tables). Validation lives in
-- internal/services/user_preferences_service.go against a registry of
-- known product slugs — application-layer enforcement gives us the same
-- safety with zero migration coupling.
--
-- The only invariant baked into Postgres is "must be a JSON object" —
-- protects against accidental scalars or arrays at the top level.
--
-- GIN index uses jsonb_path_ops (smaller, faster for `@>` containment
-- queries) since the only foreseeable index access pattern is
-- "find users with preferences matching this filter" rather than
-- arbitrary JSON path projection.

SET LOCAL statement_timeout = '30s';

ALTER TABLE iam_users
    ADD COLUMN IF NOT EXISTS preferences JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE iam_users
    ADD CONSTRAINT iam_users_preferences_is_object
    CHECK (jsonb_typeof(preferences) = 'object')
    NOT VALID;

-- VALIDATE separately so the lock window is shorter (Postgres locks only
-- briefly to check existing rows once the column is in place, instead of
-- holding the ALTER TABLE lock for the full table scan).
ALTER TABLE iam_users VALIDATE CONSTRAINT iam_users_preferences_is_object;

-- jsonb_path_ops is the right operator class here — we'll query with @>
-- containment ("any user with products.acmeweb.onboarding.tour_seen=true"),
-- not arbitrary path projections. Smaller index, faster scans.
--
-- CONCURRENTLY would be ideal in prod but is rejected by Keystone's
-- transactional migration runner (CREATE INDEX CONCURRENTLY cannot run
-- inside a transaction). iam_users is small enough on the customer tier
-- (~10k rows) that the brief AccessShareLock during the regular CREATE
-- INDEX is acceptable for the v0.232.254 deploy window. If this ever
-- crosses 100k rows, split into a follow-up CONCURRENTLY migration run
-- outside Keystone (operational runbook, not a code change).
CREATE INDEX IF NOT EXISTS iam_users_preferences_gin
    ON iam_users USING GIN (preferences jsonb_path_ops);

COMMENT ON COLUMN iam_users.preferences IS
    'Per-user opaque JSONB. Namespaced under {global, products.<slug>}. '
    'Each product owns its subtree; schema_version is per-product. '
    'App-layer validation in user_preferences_service.go; no CHECK schema '
    'baked in to avoid coupling product roadmap to DDL migrations.';

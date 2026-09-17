#!/usr/bin/env bash
set -euo pipefail
name="falcon-team-postgres-$$"
port="55432"
docker run --rm -d --name "$name" -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test -p "$port:5432" postgres:16.4 >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
until docker exec "$name" pg_isready -U test -d test >/dev/null 2>&1; do sleep 1; done

docker exec -i "$name" psql -v ON_ERROR_STOP=1 -U test -d test <<'SQL'
CREATE SCHEMA team_migration;
SET search_path = team_migration;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE iam_tenants(id uuid PRIMARY KEY);
CREATE TABLE iam_users(id uuid PRIMARY KEY);
SQL
docker exec -e PGOPTIONS='-c search_path=team_migration' -i "$name" \
  psql -v ON_ERROR_STOP=1 -U test -d test < internal/migrations/0002_team_invitations_phase2.sql
docker exec -e PGOPTIONS='-c search_path=team_migration' -i "$name" \
  psql -v ON_ERROR_STOP=1 -U test -d test < internal/migrations/0011_team_invitation_pending_email_uniqueness.sql
docker exec -e PGOPTIONS='-c search_path=team_migration' -i "$name" \
  psql -v ON_ERROR_STOP=1 -U test -d test < internal/migrations/0011_team_invitation_pending_email_uniqueness.sql
docker exec -i "$name" psql -v ON_ERROR_STOP=1 -U test -d test <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_index i
    JOIN pg_class c ON c.oid = i.indexrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'team_migration'
      AND c.relname = 'idx_iam_team_invitations_pending_tenant_email_normalized_unique'
      AND i.indisunique
      AND pg_get_expr(i.indpred, i.indrelid) = '(status = ''pending''::text)'
  ) THEN
    RAISE EXCEPTION 'team invitation migration omitted the pending-email unique index';
  END IF;
END;
$$;
SQL
TEST_DATABASE_URL="postgres://test:test@127.0.0.1:${port}/test?sslmode=disable" go test ./internal/repositories -run 'Postgres' -count=1

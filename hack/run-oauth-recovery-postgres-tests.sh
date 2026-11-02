#!/usr/bin/env bash
# Runs the refresh-token lost-response recovery Postgres integration tests
# (internal/repositories/oauth_refresh_recovery_postgres_test.go) plus the
# released-schema gap test against a throwaway postgres:16.4 container.
# Mirrors hack/run-jit-postgres-tests.sh.
set -euo pipefail
name="falcon-oauth-recovery-postgres-$$"
port="${OAUTH_PG_PORT:-$((56000 + $$ % 3000))}"
docker run --rm -d --name "$name" -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test -p "$port:5432" postgres:16.4 >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
until docker exec "$name" pg_isready -h 127.0.0.1 -U test -d test >/dev/null 2>&1; do sleep 1; done

TEST_DATABASE_URL="postgres://test:test@127.0.0.1:${port}/test?sslmode=disable" \
  GOWORK=off go test -tags=integration ./internal/repositories/ -run 'RefreshRecoveryPostgres|TestReleasedSchemaGap' -v -count=1

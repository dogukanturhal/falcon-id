#!/usr/bin/env bash
# Runs the SoD continuous re-evaluation Postgres integration tests
# (internal/services/sod_reevaluator_postgres_integration_test.go) against a
# throwaway postgres:16.4 container. Same pattern as run-jit-postgres-tests.sh.
set -euo pipefail
name="falcon-sod-postgres-$$"
port="${SOD_PG_PORT:-$((56000 + $$ % 3000))}"
docker run --rm -d --name "$name" -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test -p "$port:5432" postgres:16.4 >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
until docker exec "$name" pg_isready -h 127.0.0.1 -U test -d test >/dev/null 2>&1; do sleep 1; done

TEST_DATABASE_URL="postgres://test:test@127.0.0.1:${port}/test?sslmode=disable" \
  GOWORK=off go test ./internal/services/ -run 'SoDReevaluatorPostgres' -v -count=1

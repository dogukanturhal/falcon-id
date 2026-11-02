#!/usr/bin/env bash
# Runs the R1 platform-plane JIT elevation + break-glass Postgres
# integration tests (internal/services/platform_jit_postgres_integration_test.go)
# against a throwaway postgres:16.4 container. Mirrors
# hack/run-team-postgres-tests.sh's pattern.
set -euo pipefail
name="falcon-platform-jit-postgres-$$"
port="${JIT_PG_PORT:-$((56000 + $$ % 3000))}"
docker run --rm -d --name "$name" -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test -p "$port:5432" postgres:16.4 >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
until docker exec "$name" pg_isready -h 127.0.0.1 -U test -d test >/dev/null 2>&1; do sleep 1; done

TEST_DATABASE_URL="postgres://test:test@127.0.0.1:${port}/test?sslmode=disable" \
  GOWORK=off go test -p 1 ./internal/services/... ./cmd/ -run 'Postgres|PlatformJITRouter' -v -count=1

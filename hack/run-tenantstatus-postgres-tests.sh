#!/usr/bin/env bash
# Runs internal/tenantstatus real-Postgres tests (idempotency, ordering,
# revocation on suspend, resume, protected tenant) against a throwaway
# postgres:16.4 container on an ephemeral port.
set -euo pipefail
name="falcon-tenantstatus-postgres-$$"
port="${TENANTSTATUS_PG_PORT:-$((56000 + $$ % 3000))}"
docker run --rm -d --name "$name" -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test -p "$port:5432" postgres:16.4 >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
until docker exec "$name" pg_isready -h 127.0.0.1 -U test -d test >/dev/null 2>&1; do sleep 1; done

TEST_DATABASE_URL="postgres://test:test@127.0.0.1:${port}/test?sslmode=disable" \
  GOWORK=off go test ./internal/tenantstatus/ -v -count=1

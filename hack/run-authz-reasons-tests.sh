#!/usr/bin/env bash
# Runs the authorize/batch reason + simulate integration tests against a
# throwaway postgres:16.4 AND a throwaway authzed/spicedb container (memory
# datastore, preshared key). Mirrors hack/run-sod-postgres-tests.sh.
set -euo pipefail
pg="falcon-authz-pg-$$"
sp="falcon-authz-spicedb-$$"
docker run --rm -d --name "$pg" -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test -p 127.0.0.1::5432 postgres:16.4 >/dev/null
docker run --rm -d --name "$sp" -p 127.0.0.1::50051 authzed/spicedb:v1.35.1 serve \
  --grpc-preshared-key testkey --datastore-engine memory >/dev/null
trap 'docker rm -f "$pg" "$sp" >/dev/null 2>&1 || true' EXIT
until docker exec "$pg" pg_isready -h 127.0.0.1 -U test -d test >/dev/null 2>&1; do sleep 1; done
pgport="$(docker port "$pg" 5432/tcp | head -1 | sed 's/.*://')"
spport="$(docker port "$sp" 50051/tcp | head -1 | sed 's/.*://')"
sleep 3

TEST_DATABASE_URL="postgres://test:test@127.0.0.1:${pgport}/test?sslmode=disable" \
TEST_SPICEDB_ENDPOINT="127.0.0.1:${spport}" TEST_SPICEDB_TOKEN=testkey \
  GOWORK=off go test -p 1 ./pkg/spicedb/ ./internal/services/ -run 'AuthzReasons' -v -count=1

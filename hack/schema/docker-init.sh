#!/bin/sh
# Runs once on first start of the compose Postgres (mounted into
# /docker-entrypoint-initdb.d). Loads the baseline into the main database
# ($POSTGRES_DB) and a second control-plane database.
set -eu

SCHEMA_DIR=/schema
CONTROL_DB="${POSTGRES_DB}_control"

psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f "$SCHEMA_DIR/001_main.sql"
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres -c "CREATE DATABASE \"$CONTROL_DB\""
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$CONTROL_DB" -f "$SCHEMA_DIR/002_control.sql"

if [ -f "$SCHEMA_DIR/010_dev_seed.sql" ]; then
    psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f "$SCHEMA_DIR/010_dev_seed.sql"
fi

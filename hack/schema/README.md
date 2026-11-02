# Schema baseline

Schema-only SQL for starting Falcon ID on an empty PostgreSQL, used by the
`docker compose` quickstart. It contains no data.

| File | Database | Contents |
| --- | --- | --- |
| `001_main.sql` | `falcon_id` | tables, indexes, constraints, functions, triggers, RLS policies |
| `002_control.sql` | `falcon_id_control` | `realms`, `realm_tenants` |
| `docker-init.sh` | | mounted into the Postgres container's `docker-entrypoint-initdb.d`; loads both files and creates the control database |

The server inserts its own bootstrap rows (platform and shared realms, the
internal tenant, the admin user) on first start, so no seed file is needed.

`001_main.sql` creates a `falcon_id_app` role (NOLOGIN) because some RLS
policies are attached to it. The compose database user is a superuser and
bypasses RLS; to exercise RLS, connect as a login role that is a member of
`falcon_id_app` and is not a superuser.

## Not for production

Production schema is managed by Keystone (a SchemaDefinition plus migration
bundles), not by these files. The baseline is a snapshot for local and
evaluation use and does not track individual migrations. It does not include
Keystone's bookkeeping tables.

## Regenerating

Take a schema-only dump of each database and pipe it through `regen.sh`
(needs `python3`):

```sh
PGDUMP="pg_dump --schema-only --no-owner --no-privileges --no-security-labels --no-tablespaces"

$PGDUMP -d "$MAIN_DB_URL"    | ./regen.sh main    > 001_main.sql
$PGDUMP -d "$CONTROL_DB_URL" | ./regen.sh control > 002_control.sql
```

`regen.sh` also accepts a dump file as its second argument. It:

- drops the pg_dump header settings, `COMMENT ON` statements, all `--` comments
  and psql meta-commands
- drops Keystone tables and sequences (`keystone_*`), the `user_search`
  function, extension comments, and any publication/subscription/ACL objects
- empties the default LDAP server and DN values in `iam_settings`
- renames an internal variable in two trigger functions
- adds the `falcon_id_app` role

Review the diff before committing, and grep the output for internal hostnames,
addresses and role names. `COPY` or `INSERT INTO` statements at top level mean
the dump was not schema-only.

## Remaining well-known IDs

The UUIDs `00000000-0000-0000-0000-000000000001` (shared realm and default
tenant) and `...0002` (internal platform tenant) appear in defaults, triggers
and RLS policies. The server code requires them (`internal/models/well_known_ids.go`).

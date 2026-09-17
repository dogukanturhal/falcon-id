# SpiceDB Data Backfill Service

Comprehensive data migration service for backfilling existing PostgreSQL data into SpiceDB relationships.

## Overview

This service migrates the following entities from PostgreSQL to SpiceDB:

1. **Tenants** → `tenant` type
2. **Users** → `user` type with tenant membership
3. **Roles** → `role` type with tenant relationship
4. **Permissions** → `permission` type (global)
5. **User-Role Assignments** → `role#member@user` relationships
6. **Role-Permission Assignments** → `role#permission@permission` relationships
7. **Groups** → `group` type with member relationships
8. **Group Members** → `group#member@user` relationships
9. **Group Roles** → `role#member@group` relationships
10. **Organizations** → `organization` type with hierarchy
11. **Organization Members** → `organization#{role}@user` relationships

## Features

### ✅ Idempotent Operations
- Uses `OPERATION_TOUCH` for all relationships
- Safe to run multiple times without duplicates
- Graceful handling of existing relationships

### ✅ Batch Processing
- Configurable batch size (default: 1000 relationships per batch)
- Memory-efficient streaming from PostgreSQL
- Automatic batching for optimal performance

### ✅ Progress Tracking
- Real-time statistics and logging
- Checkpoint system for resume capability
- Detailed progress reporting per entity type

### ✅ Error Handling
- Automatic retry with exponential backoff
- Graceful degradation on failures
- Comprehensive error reporting

### ✅ Verification
- Post-migration verification against PostgreSQL
- Sample permission checks for data integrity
- Detailed comparison reports

### ✅ Concurrency Control
- Parallel processing with configurable workers
- Rate limiting to prevent SpiceDB overload
- Safe concurrent batch writes

## Usage

### Quick Start

```bash
# Dry run to see what would be migrated
make backfill-spicedb-dry

# Full backfill with verification
make backfill-spicedb

# Backfill specific tenant
make backfill-tenant TENANT_ID=550e8400-e29b-41d4-a716-446655440000
```

### CLI Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--dry-run` | bool | false | Don't write to SpiceDB, just log what would be done |
| `--batch-size` | int | 1000 | Number of relationships per batch |
| `--verify` | bool | false | Verify relationships after migration |
| `--tenant-id` | string | "" | Migrate specific tenant only |
| `--resume` | bool | false | Resume from last checkpoint |
| `--concurrency` | int | 4 | Number of parallel workers |
| `--verbose` | bool | false | Enable verbose logging |
| `--database-url` | string | $DATABASE_URL | PostgreSQL connection string |
| `--spicedb-url` | string | $SPICEDB_ENDPOINT | SpiceDB gRPC endpoint |
| `--spicedb-token` | string | $SPICEDB_TOKEN | SpiceDB preshared token |
| `--insecure` | bool | false | Use insecure gRPC connection (dev only) |

### Environment Variables

```bash
export DATABASE_URL="postgresql://user:password@localhost:5432/hexxlock_master"
export SPICEDB_ENDPOINT="localhost:50051"
export SPICEDB_TOKEN="your-preshared-token"
```

## Examples

### 1. Dry Run Migration

Preview what would be migrated without making changes:

```bash
go run cmd/backfill-spicedb/main.go \
  --dry-run \
  --verbose \
  --database-url="postgresql://user:password@localhost:5432/hexxlock_master" \
  --spicedb-url="localhost:50051"
```

### 2. Full Migration with Verification

Migrate all data and verify:

```bash
go run cmd/backfill-spicedb/main.go \
  --verify \
  --batch-size=1000 \
  --concurrency=4
```

### 3. Tenant-Specific Migration

Migrate only a specific tenant:

```bash
go run cmd/backfill-spicedb/main.go \
  --tenant-id="550e8400-e29b-41d4-a716-446655440000" \
  --verify
```

### 4. Resume from Checkpoint

If migration was interrupted, resume from last checkpoint:

```bash
go run cmd/backfill-spicedb/main.go \
  --resume \
  --verify
```

### 5. High-Performance Migration

Optimize for speed with larger batches and more workers:

```bash
go run cmd/backfill-spicedb/main.go \
  --batch-size=5000 \
  --concurrency=8 \
  --verify
```

## Migration Stages

The backfill process follows these stages in order:

### Stage 1: Tenants
- Creates tenant objects in SpiceDB
- No relationships needed (root objects)

### Stage 2: Users
- Creates user objects
- Establishes `tenant#member@user` relationships

### Stage 3: Roles
- Creates role objects
- Establishes `tenant#role@role` relationships

### Stage 4: Permissions
- Processes permission definitions
- Permissions are global, no tenant relationship

### Stage 5: User-Role Assignments
- Creates `role#member@user` relationships
- Enables user permission inheritance

### Stage 6: Role-Permission Assignments
- Creates `role#permission@permission` relationships
- Defines what permissions each role grants

### Stage 7: Groups
- Creates group objects
- Establishes `tenant#group@group` relationships

### Stage 8: Group Members
- Creates `group#member@user` relationships
- Enables group-based access control

### Stage 9: Group Roles
- Creates `role#member@group#member` relationships
- Enables transitive permission inheritance

### Stage 10: Organizations
- Creates organization objects
- Establishes parent-child hierarchy
- Creates `tenant#organization@organization` relationships

### Stage 11: Organization Members
- Creates `organization#{role}@user` relationships
- Supports multiple roles: member, manager, lead, owner

## Checkpoint System

The backfill service automatically saves checkpoints to `.backfill-checkpoint.json`:

```json
{
  "entity_type": "users",
  "last_id": "550e8400-e29b-41d4-a716-446655440000",
  "processed_count": 5000,
  "total_count": 10000,
  "last_updated": "2025-01-30T12:34:56Z",
  "completed_stages": [
    "tenants",
    "users"
  ]
}
```

## Verification

After migration, run verification to ensure data integrity:

```bash
# Quick verification
go run cmd/verify-spicedb/main.go

# Detailed verification with sample permission checks
go run cmd/verify-spicedb/main.go --detailed --sample-size=20

# Verify specific tenant
go run cmd/verify-spicedb/main.go --tenant-id="uuid" --detailed
```

### Verification Checks

1. **Count Verification**: Compares entity counts between PostgreSQL and SpiceDB
2. **Relationship Verification**: Validates relationship counts match
3. **Sample Permission Checks**: Tests actual permission checks for random users
4. **Integrity Checks**: Ensures no orphaned relationships

## Performance Tuning

### Batch Size

- **Small (100-500)**: Better error isolation, slower overall
- **Medium (1000-2000)**: Balanced performance (recommended)
- **Large (5000+)**: Fastest, but larger rollback on errors

### Concurrency

- **Low (1-2)**: Sequential processing, safest
- **Medium (4-8)**: Good parallelism (recommended)
- **High (16+)**: Maximum throughput, ensure SpiceDB can handle load

### Example: Production Migration

```bash
# Production: Conservative settings
go run cmd/backfill-spicedb/main.go \
  --batch-size=1000 \
  --concurrency=4 \
  --verify \
  --verbose

# Production: High-performance
go run cmd/backfill-spicedb/main.go \
  --batch-size=5000 \
  --concurrency=16 \
  --verify
```

## Relationship Schema

### User → Tenant
```
tenant:550e8400-e29b-41d4-a716-446655440000#member@user:550e8400-e29b-41d4-a716-446655440000:user123
```

### User → Role
```
role:550e8400-e29b-41d4-a716-446655440000:role123#member@user:550e8400-e29b-41d4-a716-446655440000:user123
```

### Role → Permission
```
role:550e8400-e29b-41d4-a716-446655440000:role123#permission@permission:crm.companies.read
```

### Group → User
```
group:550e8400-e29b-41d4-a716-446655440000:group123#member@user:550e8400-e29b-41d4-a716-446655440000:user123
```

### Group → Role (Transitive)
```
role:550e8400-e29b-41d4-a716-446655440000:role123#member@group:550e8400-e29b-41d4-a716-446655440000:group123#member
```

### Organization Hierarchy
```
organization:550e8400-e29b-41d4-a716-446655440000:parent#child@organization:550e8400-e29b-41d4-a716-446655440000:child
```

### Organization Member
```
organization:550e8400-e29b-41d4-a716-446655440000:org123#manager@user:550e8400-e29b-41d4-a716-446655440000:user123
```

## Error Handling

### Automatic Retry

The service automatically retries failed batch writes with exponential backoff:

1. First retry: 1 second delay
2. Second retry: 2 seconds delay
3. Third retry: 3 seconds delay
4. After 3 failures: Error logged and migration continues

### Graceful Shutdown

Press `Ctrl+C` to gracefully shutdown:
- Current batch completes
- Checkpoint saved
- Statistics printed
- Can resume later with `--resume`

### Common Errors

#### Error: "Connection refused"
```bash
# Check SpiceDB is running
docker ps | grep spicedb

# Verify endpoint
echo $SPICEDB_ENDPOINT
```

#### Error: "Permission denied"
```bash
# Verify token
echo $SPICEDB_TOKEN

# Check SpiceDB authentication
grpcurl -plaintext -d '{}' localhost:50051 authzed.api.v1.SchemaService/ReadSchema
```

#### Error: "Duplicate relationship"
```bash
# Safe to ignore - OPERATION_TOUCH is idempotent
# Relationships are created if they don't exist, updated if they do
```

## Migration Statistics

After completion, you'll see statistics like:

```
Migration Statistics:
  Duration: 5m30s
  Total Relationships: 125,000
  Successful: 124,950
  Failed: 50

  Tenants Processed: 100
  Users Processed: 10,000
  Roles Processed: 500
  Permissions Processed: 1,000
  Groups Processed: 250
  Organizations Processed: 150

  Throughput: 378 relationships/second
```

## Best Practices

### 1. Always Dry Run First
```bash
make backfill-spicedb-dry
```

### 2. Verify After Migration
```bash
make verify-spicedb-detailed
```

### 3. Test with Single Tenant First
```bash
make backfill-tenant TENANT_ID=test-tenant-uuid
```

### 4. Monitor Progress
```bash
# Watch checkpoint file
watch -n 5 cat .backfill-checkpoint.json
```

### 5. Plan for Downtime
- Consider read-only mode during migration
- Or use dual-write mode (write to both PostgreSQL and SpiceDB)

## Rollback

To rollback the migration:

```bash
# Delete all relationships for a tenant
go run cmd/backfill-spicedb/main.go --tenant-id=uuid --delete

# Or use SpiceDB CLI
zed relationship delete \
  --endpoint=localhost:50051 \
  --token=your-token \
  'tenant:uuid#*'
```

## Troubleshooting

### Check Logs
```bash
# Verbose mode for detailed logs
go run cmd/backfill-spicedb/main.go --verbose --dry-run
```

### Validate Schema First
```bash
# Ensure SpiceDB schema is deployed
make schema-write
make schema-verify
```

### Test Connectivity
```bash
# PostgreSQL
psql $DATABASE_URL -c "SELECT COUNT(*) FROM users;"

# SpiceDB
grpcurl -plaintext localhost:50051 authzed.api.v1.SchemaService/ReadSchema
```

### Performance Issues

If migration is slow:

1. Increase batch size: `--batch-size=5000`
2. Increase concurrency: `--concurrency=8`
3. Check network latency between services
4. Monitor SpiceDB resource usage

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Backfill SpiceDB

on:
  workflow_dispatch:
    inputs:
      tenant_id:
        description: 'Tenant ID (optional)'
        required: false

jobs:
  backfill:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Run Backfill
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
          SPICEDB_ENDPOINT: ${{ secrets.SPICEDB_ENDPOINT }}
          SPICEDB_TOKEN: ${{ secrets.SPICEDB_TOKEN }}
        run: |
          cd platform-services/iam
          if [ -n "${{ github.event.inputs.tenant_id }}" ]; then
            make backfill-tenant TENANT_ID=${{ github.event.inputs.tenant_id }}
          else
            make backfill-spicedb
          fi

      - name: Verify Migration
        run: |
          cd platform-services/iam
          make verify-spicedb-detailed
```

## Support

For issues or questions:

1. Check logs with `--verbose` flag
2. Review checkpoint file: `.backfill-checkpoint.json`
3. Run verification: `make verify-spicedb-detailed`
4. Check SpiceDB documentation: https://docs.authzed.com

## License

Copyright © 2025 Hexxlock. All rights reserved.

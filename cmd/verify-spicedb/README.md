# SpiceDB Verification Tool

Verification tool that compares PostgreSQL and SpiceDB data to ensure migration accuracy.

## Overview

This tool performs comprehensive verification checks to ensure SpiceDB relationships match PostgreSQL data:

- **Entity Counts**: Compares counts between PostgreSQL and SpiceDB
- **Relationship Integrity**: Validates all relationships are correctly migrated
- **Sample Permission Checks**: Tests actual permission checks for random users
- **Discrepancy Detection**: Identifies and reports mismatches
- **Performance Metrics**: Measures verification time for each check

## Features

### ✅ Comprehensive Checks

1. Tenant counts
2. User counts
3. Role counts
4. User-Role assignment counts
5. Role-Permission assignment counts
6. Group counts
7. Group member counts
8. Group role counts
9. Organization counts
10. Organization member counts

### ✅ Sample Permission Checks

- Randomly samples users
- Performs actual permission checks in SpiceDB
- Validates tenant membership
- Reports pass/fail for each sample

### ✅ Detailed Reporting

- Tabular output with clear formatting
- Shows PostgreSQL vs SpiceDB counts
- Calculates discrepancy percentages
- Reports verification time per check
- Overall success rate

## Usage

### Quick Start

```bash
# Basic verification
make verify-spicedb

# Detailed verification with permission checks
make verify-spicedb-detailed

# Verify specific tenant
make verify-tenant TENANT_ID=550e8400-e29b-41d4-a716-446655440000
```

### CLI Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--database-url` | string | $DATABASE_URL | PostgreSQL connection string |
| `--spicedb-url` | string | $SPICEDB_ENDPOINT | SpiceDB gRPC endpoint |
| `--spicedb-token` | string | $SPICEDB_TOKEN | SpiceDB preshared token |
| `--insecure` | bool | false | Use insecure gRPC connection (dev only) |
| `--tenant-id` | string | "" | Verify specific tenant only |
| `--detailed` | bool | false | Show detailed comparison with sample checks |
| `--sample-size` | int | 10 | Number of samples for permission checks |

## Examples

### 1. Basic Verification

```bash
go run cmd/verify-spicedb/main.go
```

**Output:**
```
════════════════════════════════════════════════════════════════════════════════════════════════════════
SPICEDB VERIFICATION RESULTS
════════════════════════════════════════════════════════════════════════════════════════════════════════

Entity                      PostgreSQL   SpiceDB   Match   Discrepancy %   Time
------                      ----------   -------   -----   -------------   ----
Tenants                     100          100       ✓       -               0.15s
Users                       10000        10000     ✓       -               0.52s
Roles                       500          500       ✓       -               0.23s
User-Role Assignments       25000        25000     ✓       -               1.45s
Role-Permission Assignments 5000         5000      ✓       -               0.87s
Groups                      250          250       ✓       -               0.18s
Group Members               1500         1500      ✓       -               0.35s
Group Roles                 750          750       ✓       -               0.29s
Organizations               150          150       ✓       -               0.21s
Organization Members        2000         2000      ✓       -               0.48s

────────────────────────────────────────────────────────────────────────────────────────────────────────
Total Checks: 10 | Passed: 10 | Failed: 0 | Success Rate: 100.00%
────────────────────────────────────────────────────────────────────────────────────────────────────────

✓ ALL VERIFICATIONS PASSED
```

### 2. Detailed Verification with Sample Checks

```bash
go run cmd/verify-spicedb/main.go --detailed --sample-size=20
```

**Output includes sample permission checks:**
```
Sample Permission Checks    20 samples   20 passed   ✓   0 failed        2.15s
```

### 3. Verify Specific Tenant

```bash
go run cmd/verify-spicedb/main.go \
  --tenant-id="550e8400-e29b-41d4-a716-446655440000" \
  --detailed
```

### 4. Development Verification (Insecure)

```bash
go run cmd/verify-spicedb/main.go \
  --insecure \
  --spicedb-url="localhost:50051" \
  --detailed
```

## Verification Checks Explained

### 1. Tenant Counts

Compares the number of active tenants in PostgreSQL with tenant objects in SpiceDB.

**PostgreSQL Query:**
```sql
SELECT COUNT(*) FROM tenants WHERE status = 'active'
```

**SpiceDB Check:**
```
Count unique tenant IDs from all tenant relationships
```

### 2. User Counts

Compares active users with user-tenant membership relationships.

**PostgreSQL Query:**
```sql
SELECT COUNT(*) FROM users WHERE is_active = true
```

**SpiceDB Check:**
```
Count tenant#member@user relationships
```

### 3. Role Counts

Compares roles with role-tenant relationships.

**PostgreSQL Query:**
```sql
SELECT COUNT(*) FROM roles
```

**SpiceDB Check:**
```
Count tenant#role@role relationships
```

### 4. User-Role Assignment Counts

Compares user-role assignments with role membership relationships.

**PostgreSQL Query:**
```sql
SELECT COUNT(*)
FROM user_roles ur
JOIN users u ON u.id = ur.user_id
WHERE u.is_active = true
```

**SpiceDB Check:**
```
Count role#member@user relationships
```

### 5. Role-Permission Assignment Counts

Compares role-permission assignments with permission relationships.

**PostgreSQL Query:**
```sql
SELECT COUNT(*)
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id
```

**SpiceDB Check:**
```
Count role#permission@permission relationships
```

### 6. Group Counts

Compares groups with group-tenant relationships.

**PostgreSQL Query:**
```sql
SELECT COUNT(*) FROM groups
```

**SpiceDB Check:**
```
Count tenant#group@group relationships
```

### 7. Group Member Counts

Compares group memberships with group-user relationships.

**PostgreSQL Query:**
```sql
SELECT COUNT(*)
FROM group_members gm
JOIN groups g ON g.id = gm.group_id
JOIN users u ON u.id = gm.user_id
WHERE u.is_active = true
```

**SpiceDB Check:**
```
Count group#member@user relationships
```

### 8. Group Role Counts

Compares group role assignments with group-role relationships.

**PostgreSQL Query:**
```sql
SELECT COUNT(*)
FROM group_roles gr
JOIN groups g ON g.id = gr.group_id
```

**SpiceDB Check:**
```
Count role#member@group relationships
```

### 9. Organization Counts

Compares active organizations with organization-tenant relationships.

**PostgreSQL Query:**
```sql
SELECT COUNT(*) FROM organizations WHERE is_active = true
```

**SpiceDB Check:**
```
Count tenant#organization@organization relationships
```

### 10. Organization Member Counts

Compares organization memberships with org-user relationships.

**PostgreSQL Query:**
```sql
SELECT COUNT(*)
FROM org_members om
JOIN organizations o ON o.id = om.organization_id
JOIN users u ON u.id = om.user_id
WHERE o.is_active = true AND u.is_active = true
```

**SpiceDB Check:**
```
Count organization#{role}@user relationships (all roles)
```

### 11. Sample Permission Checks (--detailed only)

Randomly samples users and performs actual permission checks in SpiceDB.

**Process:**
1. Query random active users from PostgreSQL
2. For each user, check tenant membership in SpiceDB
3. Verify permission check returns PERMISSIONSHIP_HAS_PERMISSION
4. Report pass/fail for each sample

## Interpreting Results

### ✓ Match
- PostgreSQL count equals SpiceDB count
- No discrepancy
- Verification passed

### ✗ Mismatch
- PostgreSQL count differs from SpiceDB count
- Discrepancy percentage shown
- Requires investigation

### Discrepancy Percentage

Calculated as:
```
(SpiceDB Count - PostgreSQL Count) / PostgreSQL Count * 100
```

- **Positive**: SpiceDB has more relationships than expected
- **Negative**: SpiceDB has fewer relationships than expected

## Common Discrepancies

### PostgreSQL > SpiceDB (Negative Discrepancy)

**Possible Causes:**
1. Migration incomplete or interrupted
2. Filters applied during migration (e.g., `is_active = true`)
3. Data added to PostgreSQL after migration

**Resolution:**
```bash
# Re-run backfill
make backfill-spicedb

# Or resume from checkpoint
make backfill-resume
```

### SpiceDB > PostgreSQL (Positive Discrepancy)

**Possible Causes:**
1. Duplicate relationships (should not happen with OPERATION_TOUCH)
2. Test data in SpiceDB
3. Manual relationship creation

**Resolution:**
```bash
# Check for duplicates in SpiceDB
go run cmd/verify-spicedb/main.go --detailed

# Consider clearing and re-migrating
```

### Sample Permission Check Failures

**Possible Causes:**
1. User-tenant relationships missing
2. Role assignments incomplete
3. Permission definitions incorrect
4. SpiceDB schema mismatch

**Resolution:**
```bash
# Verify schema first
make schema-verify

# Re-run backfill
make backfill-spicedb

# Check individual user
go run cmd/verify-spicedb/main.go --detailed --sample-size=1
```

## Exit Codes

- **0**: All verifications passed
- **1**: One or more verifications failed

Use in CI/CD:
```bash
#!/bin/bash
if ! make verify-spicedb-detailed; then
  echo "Verification failed - aborting deployment"
  exit 1
fi
```

## Performance

### Verification Time

Typical verification times (10,000 users, 100 tenants):

- Tenants: ~0.2s
- Users: ~0.5s
- Roles: ~0.3s
- User-Role Assignments: ~1.5s
- Role-Permissions: ~1.0s
- Groups: ~0.2s
- Group Members: ~0.4s
- Group Roles: ~0.3s
- Organizations: ~0.2s
- Org Members: ~0.5s
- Sample Checks (10 users): ~2.0s

**Total: ~7.5s**

### Optimization

For faster verification:
```bash
# Skip detailed checks
go run cmd/verify-spicedb/main.go

# Reduce sample size
go run cmd/verify-spicedb/main.go --detailed --sample-size=5
```

## Automation

### Cron Job

Run verification daily:

```bash
# /etc/cron.d/spicedb-verify
0 2 * * * cd /app/platform-services/iam && make verify-spicedb-detailed | mail -s "SpiceDB Verification Report" admin@example.com
```

### Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: spicedb-verify
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: verify
            image: hexxlock/iam-service:latest
            command:
            - make
            - verify-spicedb-detailed
            env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: iam-secrets
                  key: database-url
            - name: SPICEDB_ENDPOINT
              value: "spicedb:50051"
            - name: SPICEDB_TOKEN
              valueFrom:
                secretKeyRef:
                  name: iam-secrets
                  key: spicedb-token
          restartPolicy: OnFailure
```

### Monitoring Integration

Send results to monitoring system:

```bash
#!/bin/bash
RESULT=$(make verify-spicedb-detailed 2>&1)
EXIT_CODE=$?

# Send to Prometheus Pushgateway
echo "spicedb_verification_success $EXIT_CODE" | curl --data-binary @- http://pushgateway:9091/metrics/job/spicedb_verify

# Send to Slack
if [ $EXIT_CODE -ne 0 ]; then
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"SpiceDB verification failed:\n\`\`\`$RESULT\`\`\`\"}" \
    $SLACK_WEBHOOK_URL
fi
```

## Troubleshooting

### Connection Issues

```bash
# Test PostgreSQL
psql $DATABASE_URL -c "SELECT 1;"

# Test SpiceDB
grpcurl -plaintext $SPICEDB_ENDPOINT authzed.api.v1.SchemaService/ReadSchema
```

### Timeout Issues

For large datasets, verification may timeout. Increase context timeout or verify specific tenants:

```bash
# Verify specific tenant (faster)
make verify-tenant TENANT_ID=uuid
```

### Memory Issues

If verification consumes too much memory:

1. Verify tenants one at a time
2. Use `--sample-size=5` for smaller sample checks
3. Increase container memory limits

## Best Practices

### 1. Verify After Every Migration
```bash
make backfill-spicedb && make verify-spicedb-detailed
```

### 2. Regular Verification Schedule
```bash
# Daily verification in production
0 2 * * * cd /app && make verify-spicedb-detailed
```

### 3. Pre-Deployment Verification
```bash
# CI/CD pipeline
- name: Verify SpiceDB
  run: make verify-spicedb-detailed
```

### 4. Monitor Verification Results
```bash
# Send to monitoring system
make verify-spicedb-detailed | tee verification.log
```

## Support

For issues or questions:

1. Check SpiceDB connectivity
2. Verify schema is deployed: `make schema-verify`
3. Review verification logs
4. Check PostgreSQL query performance

## License

Copyright © 2025 Hexxlock. All rights reserved.

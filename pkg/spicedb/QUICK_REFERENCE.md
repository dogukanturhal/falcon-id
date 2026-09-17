# SpiceDB Resource-Level Authorization - Quick Reference

## Quick Method Reference

### Write/Delete Operations

```go
// Single relationship
zedToken, err := client.WriteResourceRelationship(ctx, tenantID,
    resourceType, resourceID, relation, subjectType, subjectID)

err := client.DeleteResourceRelationship(ctx, tenantID,
    resourceType, resourceID, relation, subjectType, subjectID)

// Bulk relationships
updates := []spicedb.RelationshipUpdate{
    {ResourceType: "crm_contact", ResourceID: id1, Relation: "viewer",
     SubjectType: "user", SubjectID: userID, Operation: "touch"},
    {ResourceType: "crm_contact", ResourceID: id2, Relation: "owner",
     SubjectType: "user", SubjectID: userID, Operation: "delete"},
}
zedToken, err := client.BulkWriteRelationships(ctx, tenantID, updates)
```

### Permission Checks

```go
// Standard check (with caching)
allowed, err := client.CheckResourcePermission(ctx, tenantID,
    resourceType, resourceID, permission, userID)

// Consistency-aware check (uses ZedToken)
allowed, err := client.CheckResourcePermissionWithToken(ctx, tenantID,
    resourceType, resourceID, permission, userID, zedToken)
```

### Lookup Operations

```go
// Find who can access a resource
userIDs, err := client.LookupSubjects(ctx, tenantID,
    resourceType, resourceID, permission, "user")

// Find resources a user can access
resourceIDs, err := client.LookupResources(ctx, tenantID,
    resourceType, permission, userID, limit) // limit=0 for unlimited
```

## Common Patterns

### 1. Create Resource + Set Owner
```go
// After creating resource in DB
zedToken, err := client.WriteResourceRelationship(ctx, tenantID,
    "crm_contact", contactID.String(), "owner", "user", userID.String())
```

### 2. Share with Multiple Users
```go
updates := make([]spicedb.RelationshipUpdate, len(userIDs))
for i, uid := range userIDs {
    updates[i] = spicedb.RelationshipUpdate{
        ResourceType: "crm_contact",
        ResourceID:   contactID.String(),
        Relation:     "viewer",
        SubjectType:  "user",
        SubjectID:    uid.String(),
        Operation:    "touch",
    }
}
client.BulkWriteRelationships(ctx, tenantID, updates)
```

### 3. Check Before Action
```go
canEdit, err := client.CheckResourcePermission(ctx, tenantID,
    "crm_contact", contactID.String(), "edit", userID)
if err != nil || !canEdit {
    return ErrForbidden
}
// Proceed with edit
```

### 4. Read-After-Write Consistency
```go
// Write relationship and get ZedToken
zedToken, _ := client.WriteResourceRelationship(ctx, tenantID,
    "document", docID, "owner", "user", userID)

// Immediately check with consistency guarantee
canAccess, _ := client.CheckResourcePermissionWithToken(ctx, tenantID,
    "document", docID, "view", userID, zedToken)
```

### 5. Transfer Ownership
```go
updates := []spicedb.RelationshipUpdate{
    {ResourceType: "crm_contact", ResourceID: contactID,
     Relation: "owner", SubjectType: "user", SubjectID: oldOwner,
     Operation: "delete"},
    {ResourceType: "crm_contact", ResourceID: contactID,
     Relation: "owner", SubjectType: "user", SubjectID: newOwner,
     Operation: "touch"},
}
client.BulkWriteRelationships(ctx, tenantID, updates)
```

## Resource Types by Module

| Module | Resource Type | Example Relations |
|--------|--------------|-------------------|
| CRM | `crm_contact`, `crm_company`, `crm_deal` | owner, viewer, editor |
| PM | `pm_project`, `pm_task`, `pm_milestone` | owner, member, viewer |
| HR | `hr_employee`, `hr_document`, `hr_timeoff` | owner, manager, viewer |
| Accounting | `accounting_invoice`, `accounting_journal` | owner, approver, viewer |
| Invoicing | `invoicing_invoice`, `invoicing_quote` | owner, approver, viewer |
| Documents | `document`, `document_folder` | owner, editor, viewer |
| Helpdesk | `helpdesk_ticket` | owner, assignee, viewer |

## Standard Relations

| Relation | Typical Permissions |
|----------|---------------------|
| `owner` | view, edit, delete, share, transfer |
| `editor` | view, edit |
| `viewer` | view |
| `member` | view, edit (context-dependent) |
| `approver` | view, approve, reject |
| `assignee` | view, edit, complete |
| `manager` | view, edit, approve, assign |

## Performance Tips

1. **Use Bulk Operations**: Always prefer `BulkWriteRelationships` over multiple `WriteResourceRelationship` calls
2. **Set Limits**: Use the `limit` parameter in `LookupResources` to prevent large result sets
3. **Cache Awareness**: The client automatically caches checks; no manual cache management needed
4. **Rate Limiting**: Built-in semaphore limits concurrent checks (default: 100)

## Error Handling

```go
allowed, err := client.CheckResourcePermission(...)
if err != nil {
    if errors.Is(err, context.DeadlineExceeded) {
        // Timeout - fail closed
        return false, errors.New("permission check timeout")
    }
    // Other error - fail closed
    log.Error("permission check failed", "error", err)
    return false, err
}

if !allowed {
    return errors.New("access denied")
}
```

## Middleware Example

```go
func RequireResourcePermission(resourceType, permission string) gin.HandlerFunc {
    return func(c *gin.Context) {
        tenantID := getTenantID(c)
        userID := getUserID(c)
        resourceID := c.Param("id")

        allowed, err := spicedbClient.CheckResourcePermission(
            c.Request.Context(), tenantID,
            resourceType, resourceID, permission, userID,
        )

        if err != nil || !allowed {
            c.JSON(403, gin.H{"error": "forbidden"})
            c.Abort()
            return
        }

        c.Next()
    }
}

// Usage
router.PUT("/contacts/:id",
    RequireResourcePermission("crm_contact", "edit"),
    updateContact)
```

## Testing

```go
func TestContactPermissions(t *testing.T) {
    // Setup
    ctx := context.Background()
    tenantID, userID, contactID := uuid.New(), uuid.New(), uuid.New()

    // Test write
    zedToken, err := client.WriteResourceRelationship(ctx, tenantID,
        "crm_contact", contactID.String(), "owner", "user", userID.String())
    require.NoError(t, err)
    require.NotEmpty(t, zedToken)

    // Test check with token
    allowed, err := client.CheckResourcePermissionWithToken(ctx, tenantID,
        "crm_contact", contactID.String(), "edit", userID, zedToken)
    require.NoError(t, err)
    assert.True(t, allowed)

    // Test lookup
    subjects, err := client.LookupSubjects(ctx, tenantID,
        "crm_contact", contactID.String(), "view", "user")
    require.NoError(t, err)
    assert.Contains(t, subjects, userID.String())

    // Test delete
    err = client.DeleteResourceRelationship(ctx, tenantID,
        "crm_contact", contactID.String(), "owner", "user", userID.String())
    require.NoError(t, err)

    // Verify removed
    allowed, err = client.CheckResourcePermission(ctx, tenantID,
        "crm_contact", contactID.String(), "edit", userID)
    require.NoError(t, err)
    assert.False(t, allowed)
}
```

## Debugging

### Check Metrics
```go
metrics := client.Metrics()
log.Info("SpiceDB metrics",
    "checks", metrics.CheckCount,
    "cache_hits", metrics.CacheHits,
    "cache_misses", metrics.CacheMisses,
    "errors", metrics.ErrorCount)
```

### Log ZedTokens
- Always log ZedTokens from write operations
- Use them to trace consistency issues
- Compare tokens across different operations

### Cache Issues
- Cache is automatically invalidated on writes
- Cache key format: `spicedb:check:{tenant}:{user}:{type}:{id}:{perm}`
- TTL controlled by `SpiceDBCacheTTL` config

## Common Mistakes

❌ **Don't**: Use UUIDs directly without converting to string
```go
// WRONG
client.WriteResourceRelationship(ctx, tenantID,
    "crm_contact", contactID, "owner", "user", userID) // contactID is UUID
```

✅ **Do**: Convert UUIDs to strings
```go
// CORRECT
client.WriteResourceRelationship(ctx, tenantID,
    "crm_contact", contactID.String(), "owner", "user", userID.String())
```

❌ **Don't**: Ignore ZedTokens
```go
// WRONG
client.WriteResourceRelationship(ctx, tenantID, ...)
// Immediately check without ZedToken - may be inconsistent
client.CheckResourcePermission(ctx, tenantID, ...)
```

✅ **Do**: Use ZedTokens for read-after-write
```go
// CORRECT
zedToken, _ := client.WriteResourceRelationship(ctx, tenantID, ...)
client.CheckResourcePermissionWithToken(ctx, tenantID, ..., zedToken)
```

❌ **Don't**: Make multiple individual writes
```go
// WRONG - Multiple round trips
for _, userID := range users {
    client.WriteResourceRelationship(ctx, tenantID,
        "document", docID, "viewer", "user", userID)
}
```

✅ **Do**: Use bulk operations
```go
// CORRECT - Single round trip
updates := make([]spicedb.RelationshipUpdate, len(users))
for i, userID := range users {
    updates[i] = spicedb.RelationshipUpdate{
        ResourceType: "document", ResourceID: docID,
        Relation: "viewer", SubjectType: "user", SubjectID: userID,
        Operation: "touch",
    }
}
client.BulkWriteRelationships(ctx, tenantID, updates)
```

## When to Use Each Method

| Use Case | Method |
|----------|--------|
| Grant single access | `WriteResourceRelationship` |
| Share with team | `BulkWriteRelationships` |
| Revoke access | `DeleteResourceRelationship` |
| Check before action | `CheckResourcePermission` |
| Read-after-write | `CheckResourcePermissionWithToken` |
| Show "shared with" list | `LookupSubjects` |
| Filter user's resources | `LookupResources` |
| Transfer ownership | `BulkWriteRelationships` (delete + touch) |

## Integration Checklist

- [ ] Define resource types for your module
- [ ] Define standard relations (owner, viewer, editor)
- [ ] Add `WriteResourceRelationship` on entity creation
- [ ] Add `CheckResourcePermission` to API endpoints
- [ ] Add `LookupResources` to list endpoints
- [ ] Add bulk operations for sharing features
- [ ] Add `DeleteResourceRelationship` on entity deletion
- [ ] Add tests for all permission scenarios
- [ ] Add UI for permissions management
- [ ] Monitor metrics and cache hit rates

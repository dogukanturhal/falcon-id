# Resource-Level Authorization Examples

This document demonstrates how to use the resource-level authorization methods added to the SpiceDB client.

## Overview

The enhanced SpiceDB client now supports fine-grained, resource-level authorization with the following capabilities:

1. **WriteResourceRelationship** - Assign ownership/access to specific resources
2. **DeleteResourceRelationship** - Remove access to resources
3. **BulkWriteRelationships** - Batch relationship updates
4. **CheckResourcePermission** - Check user permissions on resources
5. **CheckResourcePermissionWithToken** - Consistency-aware permission checks
6. **LookupSubjects** - Find who has access to a resource
7. **LookupResources** - Find what resources a user can access

## Basic Examples

### 1. CRM Contact Ownership

When a CRM contact is created, assign the creator as the owner:

```go
import (
    "context"
    "github.com/google/uuid"
    "github.com/dogukanturhal/platform-services/iam/pkg/spicedb"
)

func CreateContact(ctx context.Context, spicedbClient *spicedb.Client, tenantID, userID, contactID uuid.UUID) error {
    // Create the contact in database...

    // Assign owner relationship in SpiceDB
    zedToken, err := spicedbClient.WriteResourceRelationship(
        ctx,
        tenantID,
        "crm_contact",           // resource type
        contactID.String(),      // resource ID
        "owner",                 // relation
        "user",                  // subject type
        userID.String(),         // subject ID
    )
    if err != nil {
        return fmt.Errorf("failed to set contact owner: %w", err)
    }

    log.Printf("Contact owner set with ZedToken: %s", zedToken)
    return nil
}
```

### 2. Check Edit Permission

Before allowing a user to edit a contact:

```go
func CanEditContact(ctx context.Context, spicedbClient *spicedb.Client, tenantID, userID, contactID uuid.UUID) (bool, error) {
    canEdit, err := spicedbClient.CheckResourcePermission(
        ctx,
        tenantID,
        "crm_contact",
        contactID.String(),
        "edit",
        userID,
    )
    if err != nil {
        return false, fmt.Errorf("permission check failed: %w", err)
    }

    return canEdit, nil
}
```

### 3. Share Contact with Team

Share a contact with multiple team members:

```go
func ShareContactWithTeam(ctx context.Context, spicedbClient *spicedb.Client, tenantID, contactID uuid.UUID, teamMemberIDs []uuid.UUID) error {
    updates := make([]spicedb.RelationshipUpdate, 0, len(teamMemberIDs))

    for _, memberID := range teamMemberIDs {
        updates = append(updates, spicedb.RelationshipUpdate{
            ResourceType: "crm_contact",
            ResourceID:   contactID.String(),
            Relation:     "viewer",
            SubjectType:  "user",
            SubjectID:    memberID.String(),
            Operation:    "touch",
        })
    }

    zedToken, err := spicedbClient.BulkWriteRelationships(ctx, tenantID, updates)
    if err != nil {
        return fmt.Errorf("failed to share contact: %w", err)
    }

    log.Printf("Contact shared with %d team members, ZedToken: %s", len(teamMemberIDs), zedToken)
    return nil
}
```

### 4. Find All Contact Viewers

Get a list of users who can view a contact:

```go
func GetContactViewers(ctx context.Context, spicedbClient *spicedb.Client, tenantID, contactID uuid.UUID) ([]string, error) {
    viewers, err := spicedbClient.LookupSubjects(
        ctx,
        tenantID,
        "crm_contact",
        contactID.String(),
        "view",
        "user",
    )
    if err != nil {
        return nil, fmt.Errorf("failed to lookup viewers: %w", err)
    }

    return viewers, nil
}
```

### 5. Find User's Accessible Contacts

Get all contacts a user has access to (e.g., for dashboard):

```go
func GetUserContacts(ctx context.Context, spicedbClient *spicedb.Client, tenantID, userID uuid.UUID, limit int) ([]string, error) {
    contactIDs, err := spicedbClient.LookupResources(
        ctx,
        tenantID,
        "crm_contact",
        "view",
        userID,
        limit, // 0 for unlimited
    )
    if err != nil {
        return nil, fmt.Errorf("failed to lookup contacts: %w", err)
    }

    return contactIDs, nil
}
```

## Advanced Examples

### 6. Consistency-Aware Permission Check

After creating a resource, check permissions with ZedToken to ensure consistency:

```go
func CreateAndVerifyAccess(ctx context.Context, spicedbClient *spicedb.Client, tenantID, userID, contactID uuid.UUID) error {
    // Create ownership relationship
    zedToken, err := spicedbClient.WriteResourceRelationship(
        ctx, tenantID,
        "crm_contact", contactID.String(),
        "owner", "user", userID.String(),
    )
    if err != nil {
        return err
    }

    // Verify permission with consistency guarantee
    canEdit, err := spicedbClient.CheckResourcePermissionWithToken(
        ctx, tenantID,
        "crm_contact", contactID.String(),
        "edit", userID,
        zedToken,
    )
    if err != nil {
        return err
    }

    if !canEdit {
        return fmt.Errorf("consistency check failed: owner should have edit permission")
    }

    return nil
}
```

### 7. Revoke Access

Remove a user's access to a resource:

```go
func RevokeContactAccess(ctx context.Context, spicedbClient *spicedb.Client, tenantID, userID, contactID uuid.UUID) error {
    err := spicedbClient.DeleteResourceRelationship(
        ctx,
        tenantID,
        "crm_contact",
        contactID.String(),
        "viewer",
        "user",
        userID.String(),
    )
    if err != nil {
        return fmt.Errorf("failed to revoke access: %w", err)
    }

    return nil
}
```

### 8. Transfer Ownership

Transfer ownership of a contact to another user:

```go
func TransferContactOwnership(ctx context.Context, spicedbClient *spicedb.Client, tenantID, contactID, oldOwnerID, newOwnerID uuid.UUID) error {
    updates := []spicedb.RelationshipUpdate{
        {
            ResourceType: "crm_contact",
            ResourceID:   contactID.String(),
            Relation:     "owner",
            SubjectType:  "user",
            SubjectID:    oldOwnerID.String(),
            Operation:    "delete",
        },
        {
            ResourceType: "crm_contact",
            ResourceID:   contactID.String(),
            Relation:     "owner",
            SubjectType:  "user",
            SubjectID:    newOwnerID.String(),
            Operation:    "touch",
        },
    }

    _, err := spicedbClient.BulkWriteRelationships(ctx, tenantID, updates)
    if err != nil {
        return fmt.Errorf("failed to transfer ownership: %w", err)
    }

    return nil
}
```

### 9. Multi-Module Resource Access

Grant access to resources across different modules:

```go
func GrantProjectAccess(ctx context.Context, spicedbClient *spicedb.Client, tenantID, userID uuid.UUID, projectID, invoiceID, documentID uuid.UUID) error {
    updates := []spicedb.RelationshipUpdate{
        {
            ResourceType: "pm_project",
            ResourceID:   projectID.String(),
            Relation:     "member",
            SubjectType:  "user",
            SubjectID:    userID.String(),
            Operation:    "touch",
        },
        {
            ResourceType: "invoicing_invoice",
            ResourceID:   invoiceID.String(),
            Relation:     "viewer",
            SubjectType:  "user",
            SubjectID:    userID.String(),
            Operation:    "touch",
        },
        {
            ResourceType: "document",
            ResourceID:   documentID.String(),
            Relation:     "viewer",
            SubjectType:  "user",
            SubjectID:    userID.String(),
            Operation:    "touch",
        },
    }

    zedToken, err := spicedbClient.BulkWriteRelationships(ctx, tenantID, updates)
    if err != nil {
        return fmt.Errorf("failed to grant project access: %w", err)
    }

    log.Printf("Project access granted with ZedToken: %s", zedToken)
    return nil
}
```

### 10. Group-Based Resource Access

Grant access to a resource for all members of a group:

```go
func ShareWithGroup(ctx context.Context, spicedbClient *spicedb.Client, tenantID uuid.UUID, resourceType, resourceID, groupID string) error {
    zedToken, err := spicedbClient.WriteResourceRelationship(
        ctx,
        tenantID,
        resourceType,
        resourceID,
        "viewer",
        "group",           // subject type is group
        groupID,           // group ID
    )
    if err != nil {
        return fmt.Errorf("failed to share with group: %w", err)
    }

    log.Printf("Resource shared with group, ZedToken: %s", zedToken)
    return nil
}
```

## Real-World Use Cases

### HR: Employee Document Access

```go
// Grant employee access to their own documents
func GrantEmployeeDocumentAccess(ctx context.Context, spicedbClient *spicedb.Client, tenantID, employeeID, documentID uuid.UUID) error {
    _, err := spicedbClient.WriteResourceRelationship(
        ctx, tenantID,
        "hr_document", documentID.String(),
        "owner", "user", employeeID.String(),
    )
    return err
}

// HR managers can view all employee documents
func CanHRManagerViewDocument(ctx context.Context, spicedbClient *spicedb.Client, tenantID, managerID, documentID uuid.UUID) (bool, error) {
    return spicedbClient.CheckResourcePermission(
        ctx, tenantID,
        "hr_document", documentID.String(),
        "view", managerID,
    )
}
```

### Accounting: Invoice Approval Workflow

```go
func SetupInvoiceApprovalChain(ctx context.Context, spicedbClient *spicedb.Client, tenantID, invoiceID uuid.UUID, approverIDs []uuid.UUID) error {
    updates := make([]spicedb.RelationshipUpdate, 0, len(approverIDs))

    for _, approverID := range approverIDs {
        updates = append(updates, spicedb.RelationshipUpdate{
            ResourceType: "accounting_invoice",
            ResourceID:   invoiceID.String(),
            Relation:     "approver",
            SubjectType:  "user",
            SubjectID:    approverID.String(),
            Operation:    "touch",
        })
    }

    _, err := spicedbClient.BulkWriteRelationships(ctx, tenantID, updates)
    return err
}
```

### Project Management: Task Assignment

```go
func AssignTaskToUser(ctx context.Context, spicedbClient *spicedb.Client, tenantID, taskID, userID uuid.UUID) error {
    _, err := spicedbClient.WriteResourceRelationship(
        ctx, tenantID,
        "pm_task", taskID.String(),
        "assignee", "user", userID.String(),
    )
    return err
}

func GetUserTasks(ctx context.Context, spicedbClient *spicedb.Client, tenantID, userID uuid.UUID) ([]string, error) {
    return spicedbClient.LookupResources(
        ctx, tenantID,
        "pm_task", "assignee",
        userID, 100, // limit to 100 tasks
    )
}
```

## Integration Patterns

### Middleware Integration

```go
func ResourceAuthorizationMiddleware(spicedbClient *spicedb.Client) gin.HandlerFunc {
    return func(c *gin.Context) {
        tenantID := c.GetString("tenant_id")
        userID := c.GetString("user_id")
        resourceType := c.Param("resourceType")
        resourceID := c.Param("resourceID")
        permission := c.GetString("required_permission")

        tenantUUID, _ := uuid.Parse(tenantID)
        userUUID, _ := uuid.Parse(userID)

        allowed, err := spicedbClient.CheckResourcePermission(
            c.Request.Context(),
            tenantUUID,
            resourceType,
            resourceID,
            permission,
            userUUID,
        )

        if err != nil || !allowed {
            c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
            c.Abort()
            return
        }

        c.Next()
    }
}
```

### Event-Driven Relationship Management

```go
// Listen for Kafka events and update SpiceDB relationships
func HandleResourceCreatedEvent(ctx context.Context, spicedbClient *spicedb.Client, event ResourceCreatedEvent) error {
    return spicedbClient.WriteResourceRelationship(
        ctx,
        event.TenantID,
        event.ResourceType,
        event.ResourceID.String(),
        "owner",
        "user",
        event.CreatorID.String(),
    )
}

func HandleResourceDeletedEvent(ctx context.Context, spicedbClient *spicedb.Client, event ResourceDeletedEvent) error {
    // Clean up all relationships for deleted resource
    subjects, err := spicedbClient.LookupSubjects(
        ctx,
        event.TenantID,
        event.ResourceType,
        event.ResourceID.String(),
        "view",
        "user",
    )
    if err != nil {
        return err
    }

    updates := make([]spicedb.RelationshipUpdate, 0, len(subjects))
    for _, subjectID := range subjects {
        updates = append(updates, spicedb.RelationshipUpdate{
            ResourceType: event.ResourceType,
            ResourceID:   event.ResourceID.String(),
            Relation:     "viewer",
            SubjectType:  "user",
            SubjectID:    subjectID,
            Operation:    "delete",
        })
    }

    _, err = spicedbClient.BulkWriteRelationships(ctx, event.TenantID, updates)
    return err
}
```

## Best Practices

1. **Use ZedTokens for Read-After-Write**
   - Always use `WriteResourceRelationship` to get a ZedToken
   - Use `CheckResourcePermissionWithToken` for immediate consistency

2. **Batch Operations**
   - Use `BulkWriteRelationships` for multiple updates
   - Reduces round-trips and improves performance

3. **Cache Invalidation**
   - The client automatically invalidates Redis cache on writes
   - No manual cache management needed

4. **Error Handling**
   - All methods return detailed errors
   - Log ZedTokens for debugging consistency issues

5. **Limit Results**
   - Use the `limit` parameter in `LookupResources` to prevent large result sets
   - Paginate if needed for UI display

6. **Resource Types**
   - Use module-prefixed resource types: `crm_contact`, `pm_project`, `hr_document`
   - Keeps namespaces clean and prevents collisions

## Performance Considerations

- **Rate Limiting**: Client has built-in rate limiting via semaphore
- **Caching**: Redis caching enabled by default with configurable TTL
- **Bulk Operations**: Preferred over individual writes when updating multiple relationships
- **Streaming**: `LookupSubjects` and `LookupResources` use streaming to handle large result sets

## Testing

Example test case:

```go
func TestResourcePermissions(t *testing.T) {
    ctx := context.Background()
    tenantID := uuid.New()
    userID := uuid.New()
    contactID := uuid.New()

    // Write relationship
    zedToken, err := spicedbClient.WriteResourceRelationship(
        ctx, tenantID,
        "crm_contact", contactID.String(),
        "owner", "user", userID.String(),
    )
    require.NoError(t, err)
    require.NotEmpty(t, zedToken)

    // Check permission with token
    canEdit, err := spicedbClient.CheckResourcePermissionWithToken(
        ctx, tenantID,
        "crm_contact", contactID.String(),
        "edit", userID, zedToken,
    )
    require.NoError(t, err)
    assert.True(t, canEdit)

    // Delete relationship
    err = spicedbClient.DeleteResourceRelationship(
        ctx, tenantID,
        "crm_contact", contactID.String(),
        "owner", "user", userID.String(),
    )
    require.NoError(t, err)

    // Verify removed
    canEdit, err = spicedbClient.CheckResourcePermission(
        ctx, tenantID,
        "crm_contact", contactID.String(),
        "edit", userID,
    )
    require.NoError(t, err)
    assert.False(t, canEdit)
}
```

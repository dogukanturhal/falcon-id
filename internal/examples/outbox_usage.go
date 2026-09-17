// SPDX-License-Identifier: AGPL-3.0-or-later

// Package examples demonstrates usage patterns.
package examples

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgExampleUsage                 = "ExampleUsage: %w"
	msgExampleDeletion              = "ExampleDeletion: %w"
	msgExampleMultipleRelationships = "ExampleMultipleRelationships: %w"
	eventRelationshipCreated        = "relationship.created"
)

// ExampleUsage demonstrates how to use the transactional outbox pattern
// in your application code to ensure atomic database writes and SpiceDB updates
func ExampleUsage(ctx context.Context, db *pgxpool.Pool, outboxService services.OutboxService) error {
	// Example: Creating a CRM contact with owner relationship

	// Start database transaction
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("ExampleUsage: Begin failed: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // Rollback if not committed

	// 1. Perform your business logic within the transaction
	// Example: Create a contact in the database
	contactID := uuid.New()
	userID := uuid.New()
	tenantID := uuid.New()

	_, err = tx.Exec(ctx, `
		INSERT INTO crm_contacts (id, tenant_id, name, email, created_by)
		VALUES ($1, $2, $3, $4, $5)
	`, contactID, tenantID, "John Doe", "john@example.com", userID)
	if err != nil {
		return fmt.Errorf(msgExampleUsage, err)
	}

	// 2. Add permission event to outbox (same transaction)
	// This ensures atomicity - if the contact creation fails, the outbox event won't be created
	err = outboxService.AddRelationshipEvent(ctx, tx, models.RelationshipEvent{
		TenantID:     tenantID,
		EventType:    eventRelationshipCreated,
		ResourceType: "crm_contact",
		ResourceID:   contactID.String(),
		Relation:     "owner",
		SubjectType:  "user",
		SubjectID:    userID.String(),
		Operation:    models.OutboxOperationTouch,
		Payload: map[string]interface{}{
			"contact_name":  "John Doe",
			"contact_email": "john@example.com",
		},
	})
	if err != nil {
		return fmt.Errorf(msgExampleUsage, err)
	}

	// 3. Commit the transaction
	// Both the contact and the outbox event are committed atomically
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(msgExampleUsage, err)
	}

	// The outbox worker will asynchronously process the event and write to SpiceDB
	// No manual SpiceDB calls needed!

	return nil
}

// ExampleDeletion demonstrates how to handle resource deletion
func ExampleDeletion(ctx context.Context, db *pgxpool.Pool, outboxService services.OutboxService) error {
	contactID := uuid.New()
	userID := uuid.New()
	tenantID := uuid.New()

	// Start transaction
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("ExampleDeletion: Begin failed: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// 1. Delete the contact from database
	_, err = tx.Exec(ctx, `
		DELETE FROM crm_contacts WHERE id = $1 AND tenant_id = $2
	`, contactID, tenantID)
	if err != nil {
		return fmt.Errorf(msgExampleDeletion, err)
	}

	// 2. Add delete event to outbox
	err = outboxService.AddRelationshipEvent(ctx, tx, models.RelationshipEvent{
		TenantID:     tenantID,
		EventType:    "relationship.deleted",
		ResourceType: "crm_contact",
		ResourceID:   contactID.String(),
		Relation:     "owner",
		SubjectType:  "user",
		SubjectID:    userID.String(),
		Operation:    models.OutboxOperationDelete, // Delete operation
	})
	if err != nil {
		return fmt.Errorf(msgExampleDeletion, err)
	}

	// 3. Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(msgExampleDeletion, err)
	}

	return nil
}

// ExampleMultipleRelationships demonstrates creating multiple relationships in one transaction
func ExampleMultipleRelationships(ctx context.Context, db *pgxpool.Pool, outboxService services.OutboxService) error {
	projectID := uuid.New()
	ownerID := uuid.New()
	viewerID := uuid.New()
	tenantID := uuid.New()

	// Start transaction
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("ExampleMultipleRelationships: Begin failed: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// 1. Create project in database
	_, err = tx.Exec(ctx, `
		INSERT INTO pm_projects (id, tenant_id, name, created_by)
		VALUES ($1, $2, $3, $4)
	`, projectID, tenantID, "Project Alpha", ownerID)
	if err != nil {
		return fmt.Errorf(msgExampleMultipleRelationships, err)
	}

	// 2. Add owner relationship to outbox
	err = outboxService.AddRelationshipEvent(ctx, tx, models.RelationshipEvent{
		TenantID:     tenantID,
		EventType:    eventRelationshipCreated,
		ResourceType: "pm_project",
		ResourceID:   projectID.String(),
		Relation:     "owner",
		SubjectType:  "user",
		SubjectID:    ownerID.String(),
		Operation:    models.OutboxOperationTouch,
	})
	if err != nil {
		return fmt.Errorf(msgExampleMultipleRelationships, err)
	}

	// 3. Add viewer relationship to outbox
	err = outboxService.AddRelationshipEvent(ctx, tx, models.RelationshipEvent{
		TenantID:     tenantID,
		EventType:    eventRelationshipCreated,
		ResourceType: "pm_project",
		ResourceID:   projectID.String(),
		Relation:     "viewer",
		SubjectType:  "user",
		SubjectID:    viewerID.String(),
		Operation:    models.OutboxOperationTouch,
	})
	if err != nil {
		return fmt.Errorf(msgExampleMultipleRelationships, err)
	}

	// 4. Commit transaction - all relationships created atomically
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(msgExampleMultipleRelationships, err)
	}

	return nil
}

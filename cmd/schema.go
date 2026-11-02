// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// D-68 (docs/adr/D-68-spicedb-schema-canonical.md): the previous
	// default, "schemas/example.zed", referenced a directory that never
	// existed in this repo — the Helm file is the single source of truth.
	schemaPath                = "deploy/helm/spicedb-schema/files/spicedb.zed"
	msgRunMigrationLoadSchema = "RunMigration: LoadSchema failed: %w"
	msgRunMigration           = "RunMigration: %w"
)

// SchemaManager handles SpiceDB schema operations
type SchemaManager struct {
	client *authzed.Client
}

// NewSchemaManager creates a new schema manager
func NewSchemaManager(endpoint, token string, useTLS bool) (*SchemaManager, error) {
	var opts []grpc.DialOption

	if useTLS {
		opts = append(opts, grpcutil.WithInsecureBearerToken(token))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if token != "" {
			opts = append(opts, grpcutil.WithInsecureBearerToken(token))
		}
	}

	client, err := authzed.NewClient(endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create SpiceDB client: %w", err)
	}

	return &SchemaManager{client: client}, nil
}

// LoadSchema loads the ExampleSuite schema from file
func (sm *SchemaManager) LoadSchema() (string, error) {
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		return "", fmt.Errorf("failed to read schema file: %w", err)
	}

	return string(schemaBytes), nil
}

// WriteSchema writes the schema to SpiceDB
func (sm *SchemaManager) WriteSchema(ctx context.Context, schema string) error {
	log.Println("Writing schema to SpiceDB...")

	resp, err := sm.client.WriteSchema(ctx, &v1.WriteSchemaRequest{
		Schema: schema,
	})
	if err != nil {
		return fmt.Errorf("failed to write schema: %w", err)
	}

	log.Printf("Schema written successfully at revision: %s", resp.WrittenAt.Token)
	return nil
}

// ReadSchema reads the current schema from SpiceDB
func (sm *SchemaManager) ReadSchema(ctx context.Context) (string, error) {
	log.Println("Reading current schema from SpiceDB...")

	resp, err := sm.client.ReadSchema(ctx, &v1.ReadSchemaRequest{})
	if err != nil {
		return "", fmt.Errorf("failed to read schema: %w", err)
	}

	log.Printf("Schema read successfully at revision: %s", resp.ReadAt.Token)
	return resp.SchemaText, nil
}

// ValidateSchema validates the schema syntax
func (sm *SchemaManager) ValidateSchema(ctx context.Context, schema string) error {
	log.Println("Validating schema...")

	// Attempt to write schema (validates syntax)
	_, err := sm.client.WriteSchema(ctx, &v1.WriteSchemaRequest{
		Schema: schema,
	})
	if err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}

	log.Println("Schema is valid")
	return nil
}

// CompareSchemas compares local schema with deployed schema
func (sm *SchemaManager) CompareSchemas(ctx context.Context) error {
	localSchema, err := sm.LoadSchema()
	if err != nil {
		return fmt.Errorf("CompareSchemas: LoadSchema failed: %w", err)
	}

	remoteSchema, err := sm.ReadSchema(ctx)
	if err != nil {
		return fmt.Errorf("CompareSchemas: ReadSchema failed: %w", err)
	}

	if localSchema == remoteSchema {
		log.Println("✅ Local schema matches deployed schema")
		return nil
	}

	log.Println("⚠️  Local schema differs from deployed schema")
	log.Println("\nTo update deployed schema, run:")
	log.Println("  go run cmd/migrate-spicedb/main.go --action write")

	return nil
}

// BackfillRelationships backfills relationships from PostgreSQL
func (sm *SchemaManager) BackfillRelationships(ctx context.Context) error {
	log.Println("Starting relationship backfill...")

	// This is a placeholder for the actual backfill logic
	// You would typically:
	// 1. Query PostgreSQL for existing authz data
	// 2. Transform to SpiceDB relationships
	// 3. Batch write relationships
	// 4. Verify critical paths

	// Example: Backfill tenant relationships
	if err := sm.backfillTenantRelationships(ctx); err != nil {
		return fmt.Errorf("failed to backfill tenant relationships: %w", err)
	}

	// Example: Backfill user relationships
	if err := sm.backfillUserRelationships(ctx); err != nil {
		return fmt.Errorf("failed to backfill user relationships: %w", err)
	}

	log.Println("Relationship backfill completed successfully")
	return nil
}

// backfillTenantRelationships backfills tenant-related relationships
func (sm *SchemaManager) backfillTenantRelationships(ctx context.Context) error {
	log.Println("Backfilling tenant relationships...")

	// For now, using example data
	tenants := []struct {
		ID      string
		OwnerID string
		RealmID string
	}{
		{ID: "hexxlock", OwnerID: "admin@example.com", RealmID: "master"},
	}

	updates := make([]*v1.RelationshipUpdate, 0)

	for _, tenant := range tenants {
		// Tenant owner relationship
		updates = append(updates, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "tenant",
					ObjectId:   tenant.ID,
				},
				Relation: "owner",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "user",
						ObjectId:   fmt.Sprintf("%s:%s", tenant.ID, tenant.OwnerID),
					},
				},
			},
		})

		// Tenant realm relationship
		updates = append(updates, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "tenant",
					ObjectId:   tenant.ID,
				},
				Relation: "realm",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "realm",
						ObjectId:   tenant.RealmID,
					},
				},
			},
		})
	}

	// Batch write relationships
	if len(updates) > 0 {
		if err := sm.batchWriteRelationships(ctx, updates); err != nil {
			return fmt.Errorf("backfillTenantRelationships: %w", err)
		}
	}

	log.Printf("Backfilled %d tenant relationships", len(updates))
	return nil
}

// backfillUserRelationships backfills user-related relationships
func (sm *SchemaManager) backfillUserRelationships(ctx context.Context) error {
	log.Println("Backfilling user relationships...")

	// For now, using example data
	users := []struct {
		ID       string
		TenantID string
		RealmID  string
		RoleIDs  []string
	}{
		{
			ID:       "admin@example.com",
			TenantID: "hexxlock",
			RealmID:  "master",
			RoleIDs:  []string{"admin"},
		},
	}

	updates := make([]*v1.RelationshipUpdate, 0)

	for _, user := range users {
		userID := fmt.Sprintf("%s:%s", user.TenantID, user.ID)

		// User tenant relationship
		updates = append(updates, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "user",
					ObjectId:   userID,
				},
				Relation: "tenant",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "tenant",
						ObjectId:   user.TenantID,
					},
				},
			},
		})

		// User realm relationship
		updates = append(updates, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "user",
					ObjectId:   userID,
				},
				Relation: "realm",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "realm",
						ObjectId:   user.RealmID,
					},
				},
			},
		})

		// Tenant member relationship
		updates = append(updates, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "tenant",
					ObjectId:   user.TenantID,
				},
				Relation: "member",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "user",
						ObjectId:   userID,
					},
				},
			},
		})

		// User role relationships
		for _, roleID := range user.RoleIDs {
			updates = append(updates, &v1.RelationshipUpdate{
				Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: "user",
						ObjectId:   userID,
					},
					Relation: "has_role",
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: "role",
							ObjectId:   fmt.Sprintf("%s:%s", user.TenantID, roleID),
						},
					},
				},
			})

			// Role member relationship
			updates = append(updates, &v1.RelationshipUpdate{
				Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: "role",
						ObjectId:   fmt.Sprintf("%s:%s", user.TenantID, roleID),
					},
					Relation: "member",
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: "user",
							ObjectId:   userID,
						},
					},
				},
			})
		}
	}

	// Batch write relationships
	if len(updates) > 0 {
		if err := sm.batchWriteRelationships(ctx, updates); err != nil {
			return fmt.Errorf("backfillUserRelationships: %w", err)
		}
	}

	log.Printf("Backfilled %d user relationships", len(updates))
	return nil
}

// batchWriteRelationships writes relationships in batches
func (sm *SchemaManager) batchWriteRelationships(ctx context.Context, updates []*v1.RelationshipUpdate) error {
	const batchSize = 1000

	for i := 0; i < len(updates); i += batchSize {
		end := i + batchSize
		if end > len(updates) {
			end = len(updates)
		}

		batch := updates[i:end]

		_, err := sm.client.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
			Updates: batch,
		})
		if err != nil {
			return fmt.Errorf("failed to write batch %d-%d: %w", i, end, err)
		}

		log.Printf("Wrote batch %d-%d (%d relationships)", i, end, len(batch))
	}

	return nil
}

// VerifyPermissions verifies critical permission paths
func (sm *SchemaManager) VerifyPermissions(ctx context.Context) error {
	log.Println("Verifying critical permission paths...")

	testCases := []struct {
		name       string
		subject    string
		permission string
		resource   string
		expected   bool
	}{
		{
			name:       "Tenant owner can manage tenant",
			subject:    "user:hexxlock:admin@example.com",
			permission: "manage",
			resource:   "tenant:hexxlock",
			expected:   true,
		},
		{
			name:       "Tenant member can access tenant",
			subject:    "user:hexxlock:user@example.com",
			permission: "access",
			resource:   "tenant:hexxlock",
			expected:   true,
		},
		// Add more test cases
	}

	failures := 0

	for _, tc := range testCases {
		resp, err := sm.client.CheckPermission(ctx, &v1.CheckPermissionRequest{
			Resource:   parseObjectReference(tc.resource),
			Permission: tc.permission,
			Subject:    parseSubjectReference(tc.subject),
		})
		if err != nil {
			log.Printf("❌ %s: ERROR - %v", tc.name, err)
			failures++
			continue
		}

		allowed := resp.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION
		if allowed != tc.expected {
			log.Printf("❌ %s: FAIL (expected %v, got %v)", tc.name, tc.expected, allowed)
			failures++
		} else {
			log.Printf("✅ %s: PASS", tc.name)
		}
	}

	if failures > 0 {
		return fmt.Errorf("%d verification test(s) failed", failures)
	}

	log.Println("All verification tests passed!")
	return nil
}

// parseObjectReference parses a string like "tenant:hexxlock" into ObjectReference
func parseObjectReference(ref string) *v1.ObjectReference {
	// Simple parsing - in production, use a more robust parser
	parts := splitN(ref, ":", 2)
	return &v1.ObjectReference{
		ObjectType: parts[0],
		ObjectId:   parts[1],
	}
}

// parseSubjectReference parses a string like "user:hexxlock:admin" into SubjectReference
func parseSubjectReference(ref string) *v1.SubjectReference {
	// Simple parsing - in production, use a more robust parser
	parts := splitN(ref, ":", 2)
	return &v1.SubjectReference{
		Object: &v1.ObjectReference{
			ObjectType: parts[0],
			ObjectId:   parts[1],
		},
	}
}

// splitN splits string by separator, handling edge cases
func splitN(s, sep string, n int) []string {
	parts := make([]string, 0, n)
	start := 0
	for i := 0; i < n-1; i++ {
		idx := findIndex(s[start:], sep)
		if idx == -1 {
			break
		}
		parts = append(parts, s[start:start+idx])
		start += idx + len(sep)
	}
	parts = append(parts, s[start:])
	return parts
}

// findIndex finds first occurrence of substring
func findIndex(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// RunMigration runs the complete migration process
func RunMigration(endpoint, token string, useTLS bool, action string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	sm, err := NewSchemaManager(endpoint, token, useTLS)
	if err != nil {
		return fmt.Errorf("RunMigration: r failed: %w", err)
	}

	return runMigrationAction(ctx, sm, action)
}

// runMigrationAction dispatches a migration action to the appropriate SchemaManager method.
func runMigrationAction(ctx context.Context, sm *SchemaManager, action string) error {
	switch action {
	case "validate":
		return runValidateAction(ctx, sm)
	case "write":
		return runWriteAction(ctx, sm)
	case "read":
		return runReadAction(ctx, sm)
	case "compare":
		return sm.CompareSchemas(ctx)
	case "backfill":
		return sm.BackfillRelationships(ctx)
	case "verify":
		return sm.VerifyPermissions(ctx)
	case "full":
		return runFullMigration(ctx, sm)
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
}

func runValidateAction(ctx context.Context, sm *SchemaManager) error {
	schema, err := sm.LoadSchema()
	if err != nil {
		return fmt.Errorf(msgRunMigrationLoadSchema, err)
	}
	return sm.ValidateSchema(ctx, schema)
}

func runWriteAction(ctx context.Context, sm *SchemaManager) error {
	schema, err := sm.LoadSchema()
	if err != nil {
		return fmt.Errorf(msgRunMigrationLoadSchema, err)
	}
	return sm.WriteSchema(ctx, schema)
}

func runReadAction(ctx context.Context, sm *SchemaManager) error {
	schema, err := sm.ReadSchema(ctx)
	if err != nil {
		return fmt.Errorf("RunMigration: ReadSchema failed: %w", err)
	}
	fmt.Println(schema)
	return nil
}

// runFullMigration executes all 5 migration steps in sequence.
func runFullMigration(ctx context.Context, sm *SchemaManager) error {
	log.Println("=== Starting Full Migration ===")

	log.Println("\n[1/5] Validating schema...")
	schema, err := sm.LoadSchema()
	if err != nil {
		return fmt.Errorf(msgRunMigrationLoadSchema, err)
	}
	if err := sm.ValidateSchema(ctx, schema); err != nil {
		return fmt.Errorf(msgRunMigration, err)
	}

	log.Println("\n[2/5] Writing schema...")
	if err := sm.WriteSchema(ctx, schema); err != nil {
		return fmt.Errorf(msgRunMigration, err)
	}

	log.Println("\n[3/5] Backfilling relationships...")
	if err := sm.BackfillRelationships(ctx); err != nil {
		return fmt.Errorf(msgRunMigration, err)
	}

	log.Println("\n[4/5] Verifying permissions...")
	if err := sm.VerifyPermissions(ctx); err != nil {
		return fmt.Errorf(msgRunMigration, err)
	}

	log.Println("\n[5/5] Comparing schemas...")
	if err := sm.CompareSchemas(ctx); err != nil {
		return fmt.Errorf(msgRunMigration, err)
	}

	log.Println("\n=== Migration Completed Successfully ===")
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main provides a CLI tool to migrate the SpiceDB schema and bootstrap relationships
// from the existing database.
//
// Usage:
//
//	go run schema/migrate.go -schema-only     # Write schema only
//	go run schema/migrate.go -bootstrap       # Bootstrap relationships from DB
//	go run schema/migrate.go -full            # Schema + bootstrap (default)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	spicedbEndpoint = flag.String("spicedb-endpoint", getEnv("SPICEDB_ENDPOINT", "localhost:50051"), "SpiceDB gRPC endpoint")
	spicedbToken    = flag.String("spicedb-token", getEnv("SPICEDB_TOKEN", ""), "SpiceDB preshared key")
	spicedbInsecure = flag.Bool("spicedb-insecure", getEnvBool("SPICEDB_INSECURE", true), "Use insecure connection")
	databaseURL     = flag.String("database-url", getEnv("DATABASE_URL", ""), "PostgreSQL connection string")
	schemaFile      = flag.String("schema-file", "schema/spicedb.zed", "Path to SpiceDB schema file")
	schemaOnly      = flag.Bool("schema-only", false, "Only write schema, skip bootstrap")
	bootstrapOnly   = flag.Bool("bootstrap-only", false, "Only bootstrap relationships, skip schema")
	dryRun          = flag.Bool("dry-run", false, "Print what would be done without executing")
)

func main() {
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Connect to SpiceDB
	log.Printf("Connecting to SpiceDB at %s...", *spicedbEndpoint)
	client, err := connectSpiceDB(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to SpiceDB: %v", err) //nolint:gocritic // exitAfterDefer: intentional in cmd
	}
	log.Println("Connected to SpiceDB")

	// Write schema
	if !*bootstrapOnly {
		if err := writeSchema(ctx, client); err != nil {
			log.Fatalf("Failed to write schema: %v", err)
		}
	}

	// Bootstrap relationships
	if !*schemaOnly {
		if *databaseURL == "" {
			log.Println("No database URL provided, skipping bootstrap")
			return
		}

		db, err := pgxpool.New(ctx, *databaseURL)
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		defer db.Close()

		if err := bootstrapRelationships(ctx, client, db); err != nil {
			log.Fatalf("Failed to bootstrap relationships: %v", err)
		}
	}

	log.Println("Migration completed successfully!")
}

func connectSpiceDB(_ context.Context) (*authzed.Client, error) {
	var opts []grpc.DialOption

	if *spicedbInsecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		opts = append(opts, grpcutil.WithInsecureBearerToken(*spicedbToken))
	} else {
		systemCertsOpt, err := grpcutil.WithSystemCerts(grpcutil.VerifyCA)
		if err != nil {
			return nil, fmt.Errorf("failed to load system certificates: %w", err)
		}
		opts = append(opts, systemCertsOpt)
		opts = append(opts, grpcutil.WithBearerToken(*spicedbToken))
	}

	return authzed.NewClient(*spicedbEndpoint, opts...)
}

func writeSchema(ctx context.Context, client *authzed.Client) error {
	log.Printf("Reading schema from %s...", *schemaFile)

	schemaContent, err := os.ReadFile(*schemaFile)
	if err != nil {
		return fmt.Errorf("failed to read schema file: %w", err)
	}

	log.Printf("Schema size: %d bytes", len(schemaContent))

	if *dryRun {
		log.Println("[DRY RUN] Would write schema to SpiceDB")
		return nil
	}

	log.Println("Writing schema to SpiceDB...")
	_, err = client.WriteSchema(ctx, &v1.WriteSchemaRequest{
		Schema: string(schemaContent),
	})
	if err != nil {
		return fmt.Errorf("failed to write schema: %w", err)
	}

	log.Println("Schema written successfully!")
	return nil
}

func bootstrapRelationships(ctx context.Context, client *authzed.Client, db *pgxpool.Pool) error {
	log.Println("Bootstrapping relationships from database...")

	// 1. Bootstrap tenant memberships
	if err := bootstrapTenants(ctx, client, db); err != nil {
		return fmt.Errorf("failed to bootstrap tenants: %w", err)
	}

	// 2. Bootstrap user-role relationships
	if err := bootstrapUserRoles(ctx, client, db); err != nil {
		return fmt.Errorf("failed to bootstrap user roles: %w", err)
	}

	// 3. Bootstrap role-permission relationships
	if err := bootstrapRolePermissions(ctx, client, db); err != nil {
		return fmt.Errorf("failed to bootstrap role permissions: %w", err)
	}

	// 4. Bootstrap group memberships
	if err := bootstrapGroups(ctx, client, db); err != nil {
		return fmt.Errorf("failed to bootstrap groups: %w", err)
	}

	log.Println("Bootstrap completed!")
	return nil
}

func bootstrapTenants(ctx context.Context, client *authzed.Client, db *pgxpool.Pool) error {
	log.Println("Bootstrapping tenant memberships...")

	// Get all users with their tenants
	rows, err := db.Query(ctx, `
		SELECT u.id, u.tenant_id,
		       CASE WHEN EXISTS (
		           SELECT 1 FROM iam_user_roles ur
		           JOIN iam_roles r ON ur.role_id = r.id
		           WHERE ur.user_id = u.id AND r.name IN ('admin', 'owner')
		       ) THEN 'admin' ELSE 'member' END as role_type
		FROM iam_users u
		WHERE u.is_active = true
	`)
	if err != nil {
		return fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var updates []*v1.RelationshipUpdate
	var count int

	for rows.Next() {
		var userID, tenantID, roleType string
		if err := rows.Scan(&userID, &tenantID, &roleType); err != nil {
			return fmt.Errorf("failed to scan user: %w", err)
		}

		updates = append(updates, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "tenant",
					ObjectId:   tenantID,
				},
				Relation: roleType, // "admin" or "member"
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "user",
						ObjectId:   tenantID + "_" + userID,
					},
				},
			},
		})
		count++

		// Batch write every 100 relationships
		if len(updates) >= 100 {
			if err := writeRelationships(ctx, client, updates); err != nil {
				return fmt.Errorf("bootstrapTenants: %w", err)
			}
			updates = updates[:0]
		}
	}

	// Write remaining
	if len(updates) > 0 {
		if err := writeRelationships(ctx, client, updates); err != nil {
			return fmt.Errorf("bootstrapTenants: %w", err)
		}
	}

	log.Printf("Bootstrapped %d tenant memberships", count)
	return nil
}

func bootstrapUserRoles(ctx context.Context, client *authzed.Client, db *pgxpool.Pool) error {
	log.Println("Bootstrapping user-role relationships...")

	rows, err := db.Query(ctx, `
		SELECT ur.user_id, ur.role_id, u.tenant_id
		FROM iam_user_roles ur
		JOIN iam_users u ON ur.user_id = u.id
		JOIN iam_roles r ON ur.role_id = r.id
		WHERE u.is_active = true
		  AND r.tenant_id = u.tenant_id
		  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
	`)
	if err != nil {
		return fmt.Errorf("failed to query user roles: %w", err)
	}
	defer rows.Close()

	var updates []*v1.RelationshipUpdate
	var count int

	for rows.Next() {
		var userID, roleID, tenantID string
		if err := rows.Scan(&userID, &roleID, &tenantID); err != nil {
			return fmt.Errorf("failed to scan user role: %w", err)
		}

		updates = append(updates, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "role",
					ObjectId:   tenantID + "_" + roleID,
				},
				Relation: "member",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "user",
						ObjectId:   tenantID + "_" + userID,
					},
				},
			},
		})
		count++

		if len(updates) >= 100 {
			if err := writeRelationships(ctx, client, updates); err != nil {
				return fmt.Errorf("bootstrapUserRoles: %w", err)
			}
			updates = updates[:0]
		}
	}

	if len(updates) > 0 {
		if err := writeRelationships(ctx, client, updates); err != nil {
			return fmt.Errorf("bootstrapUserRoles: %w", err)
		}
	}

	log.Printf("Bootstrapped %d user-role relationships", count)
	return nil
}

func bootstrapRolePermissions(ctx context.Context, client *authzed.Client, db *pgxpool.Pool) error {
	log.Println("Bootstrapping role-permission relationships...")

	rows, err := db.Query(ctx, `
		SELECT rp.role_id, p.name, r.tenant_id
		FROM iam_role_permissions rp
		JOIN iam_roles r ON rp.role_id = r.id
		JOIN iam_permissions p ON rp.permission_id = p.id
	`)
	if err != nil {
		return fmt.Errorf("failed to query role permissions: %w", err)
	}
	defer rows.Close()

	var updates []*v1.RelationshipUpdate
	var count int

	for rows.Next() {
		var roleID, permName, tenantID string
		if err := rows.Scan(&roleID, &permName, &tenantID); err != nil {
			return fmt.Errorf("failed to scan role permission: %w", err)
		}

		// Sanitize permission name (e.g., "crm:contacts:create" -> "crm/contacts/create")
		sanitizedPermName := sanitizeSpiceDBID(permName)

		updates = append(updates, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "access_grant",
					ObjectId:   tenantID + "_" + sanitizedPermName,
				},
				Relation: "granted_to_role",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "role",
						ObjectId:   tenantID + "_" + roleID,
					},
				},
			},
		})
		count++

		if len(updates) >= 100 {
			if err := writeRelationships(ctx, client, updates); err != nil {
				return fmt.Errorf("bootstrapRolePermissions: %w", err)
			}
			updates = updates[:0]
		}
	}

	if len(updates) > 0 {
		if err := writeRelationships(ctx, client, updates); err != nil {
			return fmt.Errorf("bootstrapRolePermissions: %w", err)
		}
	}

	log.Printf("Bootstrapped %d role-permission relationships", count)
	return nil
}

func bootstrapGroups(ctx context.Context, client *authzed.Client, db *pgxpool.Pool) error {
	log.Println("Bootstrapping group memberships...")

	rows, err := db.Query(ctx, `
		SELECT gm.group_id, gm.user_id, g.tenant_id
		FROM iam_group_members gm
		JOIN iam_groups g ON gm.group_id = g.id
		JOIN iam_users u ON gm.user_id = u.id
		WHERE u.is_active = true
	`)
	if err != nil {
		return fmt.Errorf("failed to query group members: %w", err)
	}
	defer rows.Close()

	var updates []*v1.RelationshipUpdate
	var count int

	for rows.Next() {
		var groupID, userID, tenantID string
		if err := rows.Scan(&groupID, &userID, &tenantID); err != nil {
			return fmt.Errorf("failed to scan group member: %w", err)
		}

		updates = append(updates, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "group",
					ObjectId:   tenantID + "_" + groupID,
				},
				Relation: "member",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "user",
						ObjectId:   tenantID + "_" + userID,
					},
				},
			},
		})
		count++

		if len(updates) >= 100 {
			if err := writeRelationships(ctx, client, updates); err != nil {
				return fmt.Errorf("bootstrapGroups: %w", err)
			}
			updates = updates[:0]
		}
	}

	if len(updates) > 0 {
		if err := writeRelationships(ctx, client, updates); err != nil {
			return fmt.Errorf("bootstrapGroups: %w", err)
		}
	}

	log.Printf("Bootstrapped %d group memberships", count)
	return nil
}

func writeRelationships(ctx context.Context, client *authzed.Client, updates []*v1.RelationshipUpdate) error {
	if *dryRun {
		log.Printf("[DRY RUN] Would write %d relationships", len(updates))
		return nil
	}

	_, err := client.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: updates,
	})
	return fmt.Errorf("writeRelationships: %w", err)
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return val == "true" || val == "1" || val == "yes"
}

// sanitizeSpiceDBID converts a string to a valid SpiceDB object ID.
// SpiceDB only allows: a-zA-Z0-9/_|-=+
// Permission names like "crm:contacts:create" become "crm/contacts/create"
// Wildcards "*" become "all"
func sanitizeSpiceDBID(id string) string {
	var result []byte
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch c {
		case ':':
			result = append(result, '/')
		case '.':
			result = append(result, '-')
		case '*':
			result = append(result, []byte("all")...)
		default:
			result = append(result, c)
		}
	}
	return string(result)
}

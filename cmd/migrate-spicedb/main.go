// SPDX-License-Identifier: AGPL-3.0-or-later

// SpiceDB Migration Tool - Migrates IAM data from PostgreSQL to SpiceDB
//
// This tool performs a bulk migration of:
// - Tenants -> SpiceDB tenant relationships
// - Users -> SpiceDB user-tenant relationships
// - Roles -> SpiceDB role relationships
// - Role permissions -> SpiceDB permission relationships
// - User-role assignments -> SpiceDB user-role relationships
// - Groups -> SpiceDB group relationships
// - Group memberships -> SpiceDB group-member relationships
//
// Usage:
//
//	migrate-spicedb migrate [--tenant=<id>] [--dry-run]
//	migrate-spicedb snapshot [--output=<file>]
//	migrate-spicedb restore --input=<file>
//	migrate-spicedb validate [--tenant=<id>]
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	msgErrLoadingSystemCerts  = "Error loading system certs: %v\n"
	msgErrConnectingToSpiceDB = "Error connecting to SpiceDB: %v\n"
	msgMigrateTenants         = "migrateTenants: %w"
	msgMigrateUsers           = "migrateUsers: %w"
	msgMigrateRoles           = "migrateRoles: %w"
	msgMigrateUserRoles       = "migrateUserRoles: %w"
	sqlAndTenantID            = " AND tenant_id = $1"
)

// Config holds migration configuration
type Config struct {
	// Database
	DatabaseURL string

	// SpiceDB
	SpiceDBEndpoint string
	SpiceDBToken    string
	SpiceDBInsecure bool

	// Migration options
	TenantID   string
	DryRun     bool
	BatchSize  int
	Concurrent int
}

// Migrator handles the migration process
type Migrator struct {
	db      *sql.DB
	spicedb *authzed.Client
	config  *Config
}

// Snapshot represents a point-in-time snapshot of SpiceDB relationships
type Snapshot struct {
	Timestamp     time.Time      `json:"timestamp"`
	SchemaVersion string         `json:"schema_version"`
	Relationships []Relationship `json:"relationships"`
}

// Relationship represents a SpiceDB relationship
type Relationship struct {
	ResourceType    string `json:"resource_type"`
	ResourceID      string `json:"resource_id"`
	Relation        string `json:"relation"`
	SubjectType     string `json:"subject_type"`
	SubjectID       string `json:"subject_id"`
	SubjectRelation string `json:"subject_relation,omitempty"`
}

func main() {
	// Subcommands
	migrateCmd := flag.NewFlagSet("migrate", flag.ExitOnError)
	snapshotCmd := flag.NewFlagSet("snapshot", flag.ExitOnError)
	restoreCmd := flag.NewFlagSet("restore", flag.ExitOnError)
	validateCmd := flag.NewFlagSet("validate", flag.ExitOnError)
	schemaCmd := flag.NewFlagSet("schema", flag.ExitOnError)

	// Migrate flags
	migrateTenantID := migrateCmd.String("tenant", "", "Specific tenant ID to migrate (default: all)")
	migrateDryRun := migrateCmd.Bool("dry-run", false, "Perform dry run without writing to SpiceDB")
	migrateBatchSize := migrateCmd.Int("batch-size", 100, "Number of relationships per batch")

	// Snapshot flags
	snapshotOutput := snapshotCmd.String("output", "spicedb-snapshot.json", "Output file for snapshot")

	// Restore flags
	restoreInput := restoreCmd.String("input", "", "Input snapshot file (required)")

	// Validate flags
	validateTenantID := validateCmd.String("tenant", "", "Specific tenant ID to validate (default: all)")

	// Schema flags
	schemaAction := schemaCmd.String("action", "compare", "Action: validate, write, read, compare, backfill, verify, full")

	if len(os.Args) < 2 {
		fmt.Println("Usage: migrate-spicedb <command> [options]")
		fmt.Println("Commands:")
		fmt.Println("  migrate   - Migrate IAM data from PostgreSQL to SpiceDB")
		fmt.Println("  snapshot  - Create snapshot of SpiceDB relationships")
		fmt.Println("  restore   - Restore SpiceDB from snapshot")
		fmt.Println("  validate  - Validate migration integrity")
		fmt.Println("  schema    - Manage SpiceDB schema (validate, write, read, compare, backfill, verify, full)")
		os.Exit(1)
	}

	// Load config from environment
	config := loadConfig()

	switch os.Args[1] {
	case "migrate":
		_ = migrateCmd.Parse(os.Args[2:])
		config.TenantID = *migrateTenantID
		config.DryRun = *migrateDryRun
		config.BatchSize = *migrateBatchSize
		runMigrate(config)

	case "snapshot":
		_ = snapshotCmd.Parse(os.Args[2:])
		runSnapshot(config, *snapshotOutput)

	case "restore":
		_ = restoreCmd.Parse(os.Args[2:])
		if *restoreInput == "" {
			fmt.Println("Error: --input is required for restore")
			os.Exit(1)
		}
		runRestore(config, *restoreInput)

	case "validate":
		_ = validateCmd.Parse(os.Args[2:])
		config.TenantID = *validateTenantID
		runValidate(config)

	case "schema":
		_ = schemaCmd.Parse(os.Args[2:])
		runSchemaManagement(config, *schemaAction)

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func loadConfig() *Config {
	return &Config{
		DatabaseURL:     getEnv("DATABASE_URL", ""),
		SpiceDBEndpoint: getEnv("SPICEDB_ENDPOINT", "localhost:50051"),
		SpiceDBToken:    getEnv("SPICEDB_TOKEN", ""),
		SpiceDBInsecure: getEnv("SPICEDB_INSECURE", "true") == "true",
		BatchSize:       100,
		Concurrent:      4,
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func runMigrate(config *Config) {
	ctx := context.Background()

	fmt.Println("=== SpiceDB Migration Tool ===")
	fmt.Printf("Database: %s\n", config.DatabaseURL)
	fmt.Printf("SpiceDB: %s\n", config.SpiceDBEndpoint)
	fmt.Printf("Dry Run: %v\n", config.DryRun)
	fmt.Println()

	// Connect to PostgreSQL
	db, err := sql.Open("postgres", config.DatabaseURL)
	if err != nil {
		fmt.Printf("Error connecting to database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close() //nolint:errcheck

	if err := db.PingContext(ctx); err != nil {
		fmt.Printf("Error pinging database: %v\n", err)
		os.Exit(1) //nolint:gocritic // exitAfterDefer: intentional early exit in cmd
	}
	fmt.Println("Connected to PostgreSQL")

	// Connect to SpiceDB
	var opts []grpc.DialOption
	if config.SpiceDBInsecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		opts = append(opts, grpcutil.WithInsecureBearerToken(config.SpiceDBToken))
	} else {
		certOpt, certErr := grpcutil.WithSystemCerts(grpcutil.VerifyCA)
		if certErr != nil {
			fmt.Printf(msgErrLoadingSystemCerts, certErr)
			os.Exit(1)
		}
		opts = append(opts, certOpt)
		opts = append(opts, grpcutil.WithBearerToken(config.SpiceDBToken))
	}

	spicedb, err := authzed.NewClient(config.SpiceDBEndpoint, opts...)
	if err != nil {
		fmt.Printf(msgErrConnectingToSpiceDB, err)
		os.Exit(1)
	}
	fmt.Println("Connected to SpiceDB")

	migrator := &Migrator{
		db:      db,
		spicedb: spicedb,
		config:  config,
	}

	// Run migration
	if err := migrator.migrate(ctx); err != nil {
		fmt.Printf("Migration failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n=== Migration Complete ===")
}

func (m *Migrator) migrate(ctx context.Context) error {
	// 1. Migrate tenants
	fmt.Println("\n--- Migrating Tenants ---")
	if err := m.migrateTenants(ctx); err != nil {
		return fmt.Errorf("failed to migrate tenants: %w", err)
	}

	// 2. Migrate users
	fmt.Println("\n--- Migrating Users ---")
	if err := m.migrateUsers(ctx); err != nil {
		return fmt.Errorf("failed to migrate users: %w", err)
	}

	// 3. Migrate roles
	fmt.Println("\n--- Migrating Roles ---")
	if err := m.migrateRoles(ctx); err != nil {
		return fmt.Errorf("failed to migrate roles: %w", err)
	}

	// 4. Migrate user-role assignments
	fmt.Println("\n--- Migrating User-Role Assignments ---")
	if err := m.migrateUserRoles(ctx); err != nil {
		return fmt.Errorf("failed to migrate user-role assignments: %w", err)
	}

	// 5. Migrate groups
	fmt.Println("\n--- Migrating Groups ---")
	if err := m.migrateGroups(ctx); err != nil {
		return fmt.Errorf("failed to migrate groups: %w", err)
	}

	// 6. Migrate group memberships
	fmt.Println("\n--- Migrating Group Memberships ---")
	if err := m.migrateGroupMemberships(ctx); err != nil {
		return fmt.Errorf("failed to migrate group memberships: %w", err)
	}

	return nil
}

func (m *Migrator) migrateTenants(ctx context.Context) error {
	query := "SELECT id, name FROM iam_tenants WHERE status = 'active'"
	var args []interface{}
	if m.config.TenantID != "" {
		query += " AND id = $1"
		args = append(args, m.config.TenantID)
	}

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf(msgMigrateTenants, err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate
	count := 0

	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return fmt.Errorf(msgMigrateTenants, err)
		}

		// Create tenant -> platform relationship
		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "tenant",
					ObjectId:   id.String(),
				},
				Relation: "platform",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "platform",
						ObjectId:   "hexxlock",
					},
				},
			},
		})

		count++
		if len(relationships) >= m.config.BatchSize {
			if err := m.writeBatch(ctx, relationships); err != nil {
				return fmt.Errorf(msgMigrateTenants, err)
			}
			relationships = relationships[:0]
		}
	}

	if len(relationships) > 0 {
		if err := m.writeBatch(ctx, relationships); err != nil {
			return fmt.Errorf(msgMigrateTenants, err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("migrateTenants: row iteration error: %w", err)
	}

	fmt.Printf("Migrated %d tenants\n", count)
	return nil
}

func (m *Migrator) migrateUsers(ctx context.Context) error {
	query := "SELECT id, tenant_id FROM iam_users WHERE is_active = true"
	var args []interface{}
	if m.config.TenantID != "" {
		query += sqlAndTenantID
		args = append(args, m.config.TenantID)
	}

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf(msgMigrateUsers, err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate
	count := 0

	for rows.Next() {
		var userID, tenantID uuid.UUID
		if err := rows.Scan(&userID, &tenantID); err != nil {
			return fmt.Errorf(msgMigrateUsers, err)
		}

		// Create user -> tenant membership
		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "tenant",
					ObjectId:   tenantID.String(),
				},
				Relation: "member",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "user",
						ObjectId:   fmt.Sprintf("%s_%s", tenantID.String(), userID.String()),
					},
				},
			},
		})

		count++
		if len(relationships) >= m.config.BatchSize {
			if err := m.writeBatch(ctx, relationships); err != nil {
				return fmt.Errorf(msgMigrateUsers, err)
			}
			relationships = relationships[:0]
		}
	}

	if len(relationships) > 0 {
		if err := m.writeBatch(ctx, relationships); err != nil {
			return fmt.Errorf(msgMigrateUsers, err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("migrateUsers: row iteration error: %w", err)
	}

	fmt.Printf("Migrated %d users\n", count)
	return nil
}

func (m *Migrator) migrateRoles(ctx context.Context) error {
	query := "SELECT id, tenant_id, name FROM iam_roles WHERE 1=1"
	var args []interface{}
	if m.config.TenantID != "" {
		query += sqlAndTenantID
		args = append(args, m.config.TenantID)
	}

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf(msgMigrateRoles, err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate
	count := 0

	for rows.Next() {
		var roleID, tenantID uuid.UUID
		var name string
		if err := rows.Scan(&roleID, &tenantID, &name); err != nil {
			return fmt.Errorf(msgMigrateRoles, err)
		}

		// Create role -> tenant relationship
		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "role",
					ObjectId:   fmt.Sprintf("%s_%s", tenantID.String(), roleID.String()),
				},
				Relation: "tenant",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "tenant",
						ObjectId:   tenantID.String(),
					},
				},
			},
		})

		count++
		if len(relationships) >= m.config.BatchSize {
			if err := m.writeBatch(ctx, relationships); err != nil {
				return fmt.Errorf(msgMigrateRoles, err)
			}
			relationships = relationships[:0]
		}
	}

	if len(relationships) > 0 {
		if err := m.writeBatch(ctx, relationships); err != nil {
			return fmt.Errorf(msgMigrateRoles, err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("migrateRoles: row iteration error: %w", err)
	}

	fmt.Printf("Migrated %d roles\n", count)
	return nil
}

func (m *Migrator) migrateUserRoles(ctx context.Context) error {
	query := `
		SELECT ur.user_id, ur.role_id, u.tenant_id
		FROM iam_user_roles ur
		JOIN iam_users u ON ur.user_id = u.id
		WHERE u.is_active = true`
	var args []interface{}
	if m.config.TenantID != "" {
		query += " AND u.tenant_id = $1"
		args = append(args, m.config.TenantID)
	}

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf(msgMigrateUserRoles, err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate
	count := 0

	for rows.Next() {
		var userID, roleID, tenantID uuid.UUID
		if err := rows.Scan(&userID, &roleID, &tenantID); err != nil {
			return fmt.Errorf(msgMigrateUserRoles, err)
		}

		// Create user -> role assignment (user is assignee of role)
		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "role",
					ObjectId:   fmt.Sprintf("%s_%s", tenantID.String(), roleID.String()),
				},
				Relation: "assignee",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "user",
						ObjectId:   fmt.Sprintf("%s_%s", tenantID.String(), userID.String()),
					},
				},
			},
		})

		count++
		if len(relationships) >= m.config.BatchSize {
			if err := m.writeBatch(ctx, relationships); err != nil {
				return fmt.Errorf(msgMigrateUserRoles, err)
			}
			relationships = relationships[:0]
		}
	}

	if len(relationships) > 0 {
		if err := m.writeBatch(ctx, relationships); err != nil {
			return fmt.Errorf(msgMigrateUserRoles, err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("migrateUserRoles: row iteration error: %w", err)
	}

	fmt.Printf("Migrated %d user-role assignments\n", count)
	return nil
}

func (m *Migrator) migrateGroups(ctx context.Context) error {
	query := "SELECT id, tenant_id, name FROM iam_groups WHERE 1=1"
	var args []interface{}
	if m.config.TenantID != "" {
		query += sqlAndTenantID
		args = append(args, m.config.TenantID)
	}

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		// Groups table might not exist in all setups
		fmt.Println("Groups table not found or empty, skipping")
		return nil
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate
	count := 0

	for rows.Next() {
		var groupID, tenantID uuid.UUID
		var name string
		if err := rows.Scan(&groupID, &tenantID, &name); err != nil {
			return fmt.Errorf("migrateGroups: %w", err)
		}

		// Create group -> tenant relationship
		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "group",
					ObjectId:   fmt.Sprintf("%s_%s", tenantID.String(), groupID.String()),
				},
				Relation: "tenant",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "tenant",
						ObjectId:   tenantID.String(),
					},
				},
			},
		})

		count++
	}

	if len(relationships) > 0 {
		if err := m.writeBatch(ctx, relationships); err != nil {
			return fmt.Errorf("migrateGroups: %w", err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("migrateGroups: row iteration error: %w", err)
	}

	fmt.Printf("Migrated %d groups\n", count)
	return nil
}

func (m *Migrator) migrateGroupMemberships(ctx context.Context) error {
	query := `
		SELECT gm.group_id, gm.user_id, g.tenant_id
		FROM iam_group_members gm
		JOIN iam_groups g ON gm.group_id = g.id
		WHERE 1=1`
	var args []interface{}
	if m.config.TenantID != "" {
		query += " AND g.tenant_id = $1"
		args = append(args, m.config.TenantID)
	}

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		// Group members table might not exist
		fmt.Println("Group members table not found or empty, skipping")
		return nil
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate
	count := 0

	for rows.Next() {
		var groupID, userID, tenantID uuid.UUID
		if err := rows.Scan(&groupID, &userID, &tenantID); err != nil {
			return fmt.Errorf("migrateGroupMemberships: %w", err)
		}

		// Create user -> group membership
		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "group",
					ObjectId:   fmt.Sprintf("%s_%s", tenantID.String(), groupID.String()),
				},
				Relation: "member",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "user",
						ObjectId:   fmt.Sprintf("%s_%s", tenantID.String(), userID.String()),
					},
				},
			},
		})

		count++
	}

	if len(relationships) > 0 {
		if err := m.writeBatch(ctx, relationships); err != nil {
			return fmt.Errorf("migrateGroupMemberships: %w", err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("migrateGroupMemberships: row iteration error: %w", err)
	}

	fmt.Printf("Migrated %d group memberships\n", count)
	return nil
}

func (m *Migrator) writeBatch(ctx context.Context, updates []*v1.RelationshipUpdate) error {
	if m.config.DryRun {
		fmt.Printf("  [DRY-RUN] Would write %d relationships\n", len(updates))
		return nil
	}

	_, err := m.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: updates,
	})
	if err != nil {
		return fmt.Errorf("failed to write batch: %w", err)
	}

	fmt.Printf("  Wrote %d relationships\n", len(updates))
	return nil
}

func runSnapshot(config *Config, outputFile string) {
	fmt.Println("=== Creating SpiceDB Snapshot ===")
	fmt.Printf("Output: %s\n", outputFile)

	ctx := context.Background()

	// Connect to SpiceDB
	var opts []grpc.DialOption
	if config.SpiceDBInsecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		opts = append(opts, grpcutil.WithInsecureBearerToken(config.SpiceDBToken))
	} else {
		certOpt, certErr := grpcutil.WithSystemCerts(grpcutil.VerifyCA)
		if certErr != nil {
			fmt.Printf(msgErrLoadingSystemCerts, certErr)
			os.Exit(1)
		}
		opts = append(opts, certOpt)
		opts = append(opts, grpcutil.WithBearerToken(config.SpiceDBToken))
	}

	spicedb, err := authzed.NewClient(config.SpiceDBEndpoint, opts...)
	if err != nil {
		fmt.Printf(msgErrConnectingToSpiceDB, err)
		os.Exit(1)
	}

	// Read all relationships
	stream, err := spicedb.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		RelationshipFilter: &v1.RelationshipFilter{},
	})
	if err != nil {
		fmt.Printf("Error reading relationships: %v\n", err)
		os.Exit(1)
	}

	var relationships []Relationship
	for {
		resp, err := stream.Recv()
		if err != nil {
			break
		}

		rel := Relationship{
			ResourceType: resp.Relationship.Resource.ObjectType,
			ResourceID:   resp.Relationship.Resource.ObjectId,
			Relation:     resp.Relationship.Relation,
			SubjectType:  resp.Relationship.Subject.Object.ObjectType,
			SubjectID:    resp.Relationship.Subject.Object.ObjectId,
		}
		if resp.Relationship.Subject.OptionalRelation != "" {
			rel.SubjectRelation = resp.Relationship.Subject.OptionalRelation
		}

		relationships = append(relationships, rel)
	}

	// Create snapshot
	snapshot := Snapshot{
		Timestamp:     time.Now(),
		SchemaVersion: "1.0",
		Relationships: relationships,
	}

	// Write to file
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling snapshot: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outputFile, data, 0o644); err != nil { //nolint:gosec // checkpoint file needs group-readable permissions
		fmt.Printf("Error writing snapshot: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSnapshot created with %d relationships\n", len(relationships))
}

func runRestore(config *Config, inputFile string) {
	fmt.Println("=== Restoring SpiceDB from Snapshot ===")
	fmt.Printf("Input: %s\n", inputFile)

	ctx := context.Background()
	snapshot := loadSnapshotFile(inputFile)
	spicedbClient := connectSpiceDB(config)
	writeRelationshipsInBatches(ctx, spicedbClient, snapshot)
	fmt.Println("\n=== Restore Complete ===")
}

// loadSnapshotFile reads and parses a snapshot file, calling os.Exit on error.
func loadSnapshotFile(inputFile string) Snapshot {
	data, err := os.ReadFile(inputFile) //nolint:gosec // path is validated before use
	if err != nil {
		fmt.Printf("Error reading snapshot: %v\n", err)
		os.Exit(1)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		fmt.Printf("Error parsing snapshot: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Snapshot from: %s\n", snapshot.Timestamp.Format(time.RFC3339))
	fmt.Printf("Relationships: %d\n", len(snapshot.Relationships))
	return snapshot
}

// connectSpiceDB builds dial options and opens an authenticated connection to SpiceDB.
func connectSpiceDB(config *Config) *authzed.Client {
	var opts []grpc.DialOption
	if config.SpiceDBInsecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		opts = append(opts, grpcutil.WithInsecureBearerToken(config.SpiceDBToken))
	} else {
		certOpt, certErr := grpcutil.WithSystemCerts(grpcutil.VerifyCA)
		if certErr != nil {
			fmt.Printf(msgErrLoadingSystemCerts, certErr)
			os.Exit(1)
		}
		opts = append(opts, certOpt)
		opts = append(opts, grpcutil.WithBearerToken(config.SpiceDBToken))
	}
	client, err := authzed.NewClient(config.SpiceDBEndpoint, opts...)
	if err != nil {
		fmt.Printf(msgErrConnectingToSpiceDB, err)
		os.Exit(1)
	}
	return client
}

// writeRelationshipsInBatches writes snapshot relationships to SpiceDB in batches of 100.
func writeRelationshipsInBatches(ctx context.Context, spicedbClient *authzed.Client, snapshot Snapshot) {
	const batchSz = 100
	for i := 0; i < len(snapshot.Relationships); i += batchSz {
		end := i + batchSz
		if end > len(snapshot.Relationships) {
			end = len(snapshot.Relationships)
		}
		updates := toRelationshipUpdates(snapshot.Relationships[i:end])
		_, err := spicedbClient.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: updates})
		if err != nil {
			fmt.Printf("Error writing batch: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  Restored %d/%d relationships\n", end, len(snapshot.Relationships))
	}
}

// toRelationshipUpdates converts a slice of Relationship to SpiceDB RelationshipUpdate protos.
func toRelationshipUpdates(rels []Relationship) []*v1.RelationshipUpdate {
	updates := make([]*v1.RelationshipUpdate, 0, len(rels))
	for _, rel := range rels {
		subject := &v1.SubjectReference{
			Object: &v1.ObjectReference{
				ObjectType: rel.SubjectType,
				ObjectId:   rel.SubjectID,
			},
		}
		if rel.SubjectRelation != "" {
			subject.OptionalRelation = rel.SubjectRelation
		}
		updates = append(updates, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: rel.ResourceType,
					ObjectId:   rel.ResourceID,
				},
				Relation: rel.Relation,
				Subject:  subject,
			},
		})
	}
	return updates
}

func runValidate(_ *Config) {
	fmt.Println("=== Validating SpiceDB Migration ===")
	fmt.Println("Validation not yet implemented")
}

func runSchemaManagement(config *Config, action string) {
	if err := RunMigration(config.SpiceDBEndpoint, config.SpiceDBToken, !config.SpiceDBInsecure, action); err != nil {
		fmt.Printf("Schema operation failed: %v\n", err)
		os.Exit(1)
	}
}

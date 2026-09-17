// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main provides the entry point.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// Entity types in order of migration
	EntityTypeTenant       = "tenant"
	EntityTypeUser         = "user"
	EntityTypeRole         = "role"
	EntityTypePermission   = "permission"
	EntityTypeGroup        = "group"
	EntityTypeOrganization = "organization"
)

// CLI flags
var (
	dryRun      = pflag.Bool("dry-run", false, "Don't write to SpiceDB, just log what would be done")
	batchSize   = pflag.Int("batch-size", 1000, "Number of relationships per batch")
	verify      = pflag.Bool("verify", false, "Verify relationships after migration")
	tenantID    = pflag.String("tenant-id", "", "Migrate specific tenant only")
	resume      = pflag.Bool("resume", false, "Resume from last checkpoint")
	concurrency = pflag.Int("concurrency", 4, "Number of parallel workers")
	verbose     = pflag.Bool("verbose", false, "Enable verbose logging")

	// Database connections
	databaseURL  = pflag.String("database-url", os.Getenv("DATABASE_URL"), "PostgreSQL connection string")
	spicedbURL   = pflag.String("spicedb-url", os.Getenv("SPICEDB_ENDPOINT"), "SpiceDB gRPC endpoint")
	spicedbToken = pflag.String("spicedb-token", os.Getenv("SPICEDB_TOKEN"), "SpiceDB preshared token")
	insecureConn = pflag.Bool("insecure", false, "Use insecure gRPC connection (dev only)")
)

// Checkpoint tracks migration progress
type Checkpoint struct {
	EntityType      string    `json:"entity_type"`
	LastID          uuid.UUID `json:"last_id"`
	ProcessedCount  int64     `json:"processed_count"`
	TotalCount      int64     `json:"total_count"`
	LastUpdated     time.Time `json:"last_updated"`
	CompletedStages []string  `json:"completed_stages"`
}

// MigrationStats tracks overall migration statistics
type MigrationStats struct {
	sync.Mutex
	TotalRelationships      int64
	SuccessfulRelationships int64
	FailedRelationships     int64
	TenantsProcessed        int64
	UsersProcessed          int64
	RolesProcessed          int64
	PermissionsProcessed    int64
	GroupsProcessed         int64
	OrganizationsProcessed  int64
	StartTime               time.Time
	EndTime                 time.Time
	Errors                  []string
}

// BackfillService manages the data migration
type BackfillService struct {
	logger       *zap.Logger
	db           *sql.DB
	spiceDB      *authzed.Client
	checkpoint   *Checkpoint
	stats        *MigrationStats
	dryRun       bool
	batchSize    int
	concurrency  int
	tenantFilter uuid.UUID
}

func main() {
	pflag.Parse()

	// Setup logger
	logger := setupLogger(*verbose)
	defer func() { _ = logger.Sync() }()

	logger.Info("Starting SpiceDB data backfill service",
		zap.Bool("dry_run", *dryRun),
		zap.Int("batch_size", *batchSize),
		zap.Bool("verify", *verify),
		zap.String("tenant_id", *tenantID),
		zap.Bool("resume", *resume),
		zap.Int("concurrency", *concurrency),
	)

	// Validate configuration
	if *databaseURL == "" {
		logger.Fatal("DATABASE_URL is required")
	}
	if *spicedbURL == "" {
		logger.Fatal("SPICEDB_ENDPOINT is required")
	}
	if !*dryRun && *spicedbToken == "" {
		logger.Fatal("SPICEDB_TOKEN is required for non-dry-run mode")
	}

	// Initialize service
	service, err := NewBackfillService(logger)
	if err != nil {
		logger.Fatal("Failed to initialize backfill service", zap.Error(err))
	}
	defer service.Close()

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal, saving checkpoint...")
		cancel()
	}()

	// Run migration
	if err := service.RunMigration(ctx); err != nil {
		logger.Fatal("Migration failed", zap.Error(err))
	}

	// Verify if requested
	if *verify && !*dryRun {
		logger.Info("Starting verification...")
		if err := service.VerifyMigration(ctx); err != nil {
			logger.Error("Verification failed", zap.Error(err))
			os.Exit(1) //nolint:gocritic // exitAfterDefer: intentional early exit in cmd
		}
	}

	// Print final statistics
	service.PrintStatistics()

	logger.Info("Migration completed successfully")
}

func NewBackfillService(logger *zap.Logger) (*BackfillService, error) {
	db, err := openPostgres()
	if err != nil {
		return nil, err
	}
	logger.Info("Connected to PostgreSQL")

	spiceDBClient, err := maybeConnectSpiceDB(logger)
	if err != nil {
		return nil, err
	}

	checkpoint := loadCheckpointOrFresh(logger)

	tenantFilter, err := parseTenantFilter()
	if err != nil {
		return nil, err
	}

	return &BackfillService{
		logger:       logger,
		db:           db,
		spiceDB:      spiceDBClient,
		checkpoint:   checkpoint,
		dryRun:       *dryRun,
		batchSize:    *batchSize,
		concurrency:  *concurrency,
		tenantFilter: tenantFilter,
		stats: &MigrationStats{
			StartTime: time.Now(),
			Errors:    []string{},
		},
	}, nil
}

// openPostgres connects to PostgreSQL using the databaseURL flag.
func openPostgres() (*sql.DB, error) {
	db, err := sql.Open("postgres", *databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}
	return db, nil
}

// maybeConnectSpiceDB connects to SpiceDB unless dry-run mode is active.
func maybeConnectSpiceDB(logger *zap.Logger) (*authzed.Client, error) {
	if *dryRun {
		return nil, nil
	}
	dialOpts, err := buildBackfillDialOpts()
	if err != nil {
		return nil, err
	}
	if *spicedbToken != "" {
		dialOpts = append(dialOpts, grpcutil.WithBearerToken(*spicedbToken))
	}
	client, err := authzed.NewClient(*spicedbURL, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SpiceDB: %w", err)
	}
	logger.Info("Connected to SpiceDB", zap.String("endpoint", *spicedbURL))
	return client, nil
}

// buildBackfillDialOpts builds the gRPC dial options for the backfill SpiceDB connection.
func buildBackfillDialOpts() ([]grpc.DialOption, error) {
	if *insecureConn {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}
	systemCerts, err := grpcutil.WithSystemCerts(grpcutil.VerifyCA)
	if err != nil {
		return nil, fmt.Errorf("failed to load system certificates: %w", err)
	}
	return []grpc.DialOption{systemCerts}, nil
}

// loadCheckpointOrFresh loads a checkpoint from disk when --resume is set, otherwise returns a fresh one.
func loadCheckpointOrFresh(logger *zap.Logger) *Checkpoint {
	if !*resume {
		return &Checkpoint{CompletedStages: []string{}}
	}
	checkpoint, err := loadCheckpoint()
	if err != nil {
		logger.Warn("Failed to load checkpoint, starting fresh", zap.Error(err))
		return &Checkpoint{CompletedStages: []string{}}
	}
	logger.Info("Resuming from checkpoint",
		zap.String("entity_type", checkpoint.EntityType),
		zap.Int64("processed_count", checkpoint.ProcessedCount),
	)
	return checkpoint
}

// parseTenantFilter parses the --tenant-id flag into a UUID, returning zero-UUID when not set.
func parseTenantFilter() (uuid.UUID, error) {
	if *tenantID == "" {
		return uuid.UUID{}, nil
	}
	parsed, err := uuid.Parse(*tenantID)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid tenant ID: %w", err)
	}
	return parsed, nil
}

func (s *BackfillService) Close() {
	if s.db != nil {
		_ = s.db.Close()
	}
}

func (s *BackfillService) RunMigration(ctx context.Context) error {
	s.logger.Info("Starting data migration")

	// Migration stages in order
	stages := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"tenants", s.migrateTenants},
		{"users", s.migrateUsers},
		{"roles", s.migrateRoles},
		{"permissions", s.migratePermissions},
		{"user_roles", s.migrateUserRoles},
		{"role_permissions", s.migrateRolePermissions},
		{"groups", s.migrateGroups},
		{"group_members", s.migrateGroupMembers},
		{"group_roles", s.migrateGroupRoles},
		{"organizations", s.migrateOrganizations},
		{"org_members", s.migrateOrgMembers},
	}

	for _, stage := range stages {
		// Skip if already completed
		if s.isStageCompleted(stage.name) {
			s.logger.Info("Stage already completed, skipping", zap.String("stage", stage.name))
			continue
		}

		s.logger.Info("Starting migration stage", zap.String("stage", stage.name))

		if err := stage.fn(ctx); err != nil {
			return fmt.Errorf("stage %s failed: %w", stage.name, err)
		}

		s.markStageCompleted(stage.name)
		_ = s.saveCheckpoint()

		s.logger.Info("Stage completed", zap.String("stage", stage.name))
	}

	s.stats.EndTime = time.Now()
	return nil
}

func (s *BackfillService) migrateTenants(ctx context.Context) error {
	var rows *sql.Rows
	var err error

	if s.tenantFilter != uuid.Nil {
		// SECURITY: Use parameterized query to prevent SQL injection
		query := `SELECT id, slug, name FROM tenants WHERE id = $1`
		rows, err = s.db.QueryContext(ctx, query, s.tenantFilter)
	} else {
		query := `SELECT id, slug, name FROM tenants WHERE status = 'active' ORDER BY id`
		rows, err = s.db.QueryContext(ctx, query)
	}
	if err != nil {
		return fmt.Errorf("failed to query tenants: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate
	count := 0

	for rows.Next() {
		var tenantID uuid.UUID
		var slug, name string

		if err := rows.Scan(&tenantID, &slug, &name); err != nil {
			return fmt.Errorf("failed to scan tenant: %w", err)
		}

		// Create tenant object (no relationships needed for tenant itself)
		// Tenants are root objects in SpiceDB
		s.logger.Debug("Processing tenant",
			zap.String("tenant_id", tenantID.String()),
			zap.String("slug", slug),
		)

		count++
		s.stats.Lock()
		s.stats.TenantsProcessed++
		s.stats.Unlock()
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating tenants: %w", err)
	}

	s.logger.Info("Tenants processed", zap.Int("count", count))
	return s.writeRelationships(ctx, relationships)
}

func (s *BackfillService) migrateUsers(ctx context.Context) error {
	var rows *sql.Rows
	var err error

	if s.tenantFilter != uuid.Nil {
		// SECURITY: Use parameterized query to prevent SQL injection
		query := `
			SELECT id, tenant_id, realm_id, username, email
			FROM users
			WHERE is_active = true AND tenant_id = $1
			ORDER BY id
		`
		rows, err = s.db.QueryContext(ctx, query, s.tenantFilter)
	} else {
		query := `
			SELECT id, tenant_id, realm_id, username, email
			FROM users
			WHERE is_active = true
			ORDER BY id
		`
		rows, err = s.db.QueryContext(ctx, query)
	}
	if err != nil {
		return fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate

	for rows.Next() {
		var userID, tenantID, realmID uuid.UUID
		var username, email string

		if err := rows.Scan(&userID, &tenantID, &realmID, &username, &email); err != nil {
			return fmt.Errorf("failed to scan user: %w", err)
		}

		// User belongs to tenant
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
						ObjectId:   fmt.Sprintf("%s:%s", tenantID, userID),
					},
				},
			},
		})

		s.stats.Lock()
		s.stats.UsersProcessed++
		s.stats.Unlock()

		// Batch write
		if len(relationships) >= s.batchSize {
			if err := s.writeRelationships(ctx, relationships); err != nil {
				return fmt.Errorf("migrateUsers: %w", err)
			}
			relationships = relationships[:0]
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating users: %w", err)
	}

	// Write remaining relationships
	return s.writeRelationships(ctx, relationships)
}

func (s *BackfillService) migrateRoles(ctx context.Context) error {
	var rows *sql.Rows
	var err error

	if s.tenantFilter != uuid.Nil {
		// SECURITY: Use parameterized query to prevent SQL injection
		query := `SELECT id, tenant_id, name, display_name FROM roles WHERE tenant_id = $1 ORDER BY id`
		rows, err = s.db.QueryContext(ctx, query, s.tenantFilter)
	} else {
		query := `SELECT id, tenant_id, name, display_name FROM roles ORDER BY id`
		rows, err = s.db.QueryContext(ctx, query)
	}
	if err != nil {
		return fmt.Errorf("failed to query roles: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate

	for rows.Next() {
		var roleID, tenantID uuid.UUID
		var name, displayName string

		if err := rows.Scan(&roleID, &tenantID, &name, &displayName); err != nil {
			return fmt.Errorf("failed to scan role: %w", err)
		}

		// Role belongs to tenant
		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "tenant",
					ObjectId:   tenantID.String(),
				},
				Relation: "role",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "role",
						ObjectId:   fmt.Sprintf("%s:%s", tenantID, roleID),
					},
				},
			},
		})

		s.stats.Lock()
		s.stats.RolesProcessed++
		s.stats.Unlock()

		if len(relationships) >= s.batchSize {
			if err := s.writeRelationships(ctx, relationships); err != nil {
				return fmt.Errorf("migrateRoles: %w", err)
			}
			relationships = relationships[:0]
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating roles: %w", err)
	}

	return s.writeRelationships(ctx, relationships)
}

func (s *BackfillService) migratePermissions(ctx context.Context) error {
	query := `SELECT id, module, resource, action, name FROM permissions ORDER BY id`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query permissions: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	count := 0
	for rows.Next() {
		var permID uuid.UUID
		var module, resource, action, name string

		if err := rows.Scan(&permID, &module, &resource, &action, &name); err != nil {
			return fmt.Errorf("failed to scan permission: %w", err)
		}

		s.stats.Lock()
		s.stats.PermissionsProcessed++
		s.stats.Unlock()

		count++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating permissions: %w", err)
	}

	s.logger.Info("Permissions processed", zap.Int("count", count))
	return nil
}

func (s *BackfillService) migrateUserRoles(ctx context.Context) error {
	var rows *sql.Rows
	var err error

	if s.tenantFilter != uuid.Nil {
		// SECURITY: Use parameterized query to prevent SQL injection
		query := `
			SELECT ur.user_id, ur.role_id, u.tenant_id
			FROM user_roles ur
			JOIN users u ON u.id = ur.user_id
			WHERE u.is_active = true AND u.tenant_id = $1
			ORDER BY ur.id
		`
		rows, err = s.db.QueryContext(ctx, query, s.tenantFilter)
	} else {
		query := `
			SELECT ur.user_id, ur.role_id, u.tenant_id
			FROM user_roles ur
			JOIN users u ON u.id = ur.user_id
			WHERE u.is_active = true
			ORDER BY ur.id
		`
		rows, err = s.db.QueryContext(ctx, query)
	}
	if err != nil {
		return fmt.Errorf("failed to query user roles: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate

	for rows.Next() {
		var userID, roleID, tenantID uuid.UUID

		if err := rows.Scan(&userID, &roleID, &tenantID); err != nil {
			return fmt.Errorf("failed to scan user role: %w", err)
		}

		// User is member of role
		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "role",
					ObjectId:   fmt.Sprintf("%s:%s", tenantID, roleID),
				},
				Relation: "member",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "user",
						ObjectId:   fmt.Sprintf("%s:%s", tenantID, userID),
					},
				},
			},
		})

		if len(relationships) >= s.batchSize {
			if err := s.writeRelationships(ctx, relationships); err != nil {
				return fmt.Errorf("migrateUserRoles: %w", err)
			}
			relationships = relationships[:0]
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating user roles: %w", err)
	}

	return s.writeRelationships(ctx, relationships)
}

func (s *BackfillService) migrateRolePermissions(ctx context.Context) error {
	var rows *sql.Rows
	var err error

	if s.tenantFilter != uuid.Nil {
		// SECURITY: Use parameterized query to prevent SQL injection
		query := `
			SELECT rp.role_id, rp.permission_id, r.tenant_id, p.module, p.resource, p.action
			FROM role_permissions rp
			JOIN roles r ON r.id = rp.role_id
			JOIN permissions p ON p.id = rp.permission_id
			WHERE r.tenant_id = $1
			ORDER BY rp.id
		`
		rows, err = s.db.QueryContext(ctx, query, s.tenantFilter)
	} else {
		query := `
			SELECT rp.role_id, rp.permission_id, r.tenant_id, p.module, p.resource, p.action
			FROM role_permissions rp
			JOIN roles r ON r.id = rp.role_id
			JOIN permissions p ON p.id = rp.permission_id
			ORDER BY rp.id
		`
		rows, err = s.db.QueryContext(ctx, query)
	}
	if err != nil {
		return fmt.Errorf("failed to query role permissions: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate

	for rows.Next() {
		var roleID, permissionID, tenantID uuid.UUID
		var module, resource, action string

		if err := rows.Scan(&roleID, &permissionID, &tenantID, &module, &resource, &action); err != nil {
			return fmt.Errorf("failed to scan role permission: %w", err)
		}

		// Role has permission
		permissionName := fmt.Sprintf("%s.%s.%s", module, resource, action)
		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "role",
					ObjectId:   fmt.Sprintf("%s:%s", tenantID, roleID),
				},
				Relation: "permission",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "permission",
						ObjectId:   permissionName,
					},
				},
			},
		})

		if len(relationships) >= s.batchSize {
			if err := s.writeRelationships(ctx, relationships); err != nil {
				return fmt.Errorf("migrateRolePermissions: %w", err)
			}
			relationships = relationships[:0]
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating role permissions: %w", err)
	}

	return s.writeRelationships(ctx, relationships)
}

func (s *BackfillService) migrateGroups(ctx context.Context) error {
	var rows *sql.Rows
	var err error

	if s.tenantFilter != uuid.Nil {
		// SECURITY: Use parameterized query to prevent SQL injection
		query := `SELECT id, tenant_id, name FROM groups WHERE tenant_id = $1 ORDER BY id`
		rows, err = s.db.QueryContext(ctx, query, s.tenantFilter)
	} else {
		query := `SELECT id, tenant_id, name FROM groups ORDER BY id`
		rows, err = s.db.QueryContext(ctx, query)
	}
	if err != nil {
		return fmt.Errorf("failed to query groups: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate

	for rows.Next() {
		var groupID, tenantID uuid.UUID
		var name string

		if err := rows.Scan(&groupID, &tenantID, &name); err != nil {
			return fmt.Errorf("failed to scan group: %w", err)
		}

		// Group belongs to tenant
		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "tenant",
					ObjectId:   tenantID.String(),
				},
				Relation: "group",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "group",
						ObjectId:   fmt.Sprintf("%s:%s", tenantID, groupID),
					},
				},
			},
		})

		s.stats.Lock()
		s.stats.GroupsProcessed++
		s.stats.Unlock()

		if len(relationships) >= s.batchSize {
			if err := s.writeRelationships(ctx, relationships); err != nil {
				return fmt.Errorf("migrateGroups: %w", err)
			}
			relationships = relationships[:0]
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating groups: %w", err)
	}

	return s.writeRelationships(ctx, relationships)
}

func (s *BackfillService) migrateGroupMembers(ctx context.Context) error {
	var rows *sql.Rows
	var err error

	if s.tenantFilter != uuid.Nil {
		// SECURITY: Use parameterized query to prevent SQL injection
		query := `
			SELECT gm.group_id, gm.user_id, g.tenant_id
			FROM group_members gm
			JOIN groups g ON g.id = gm.group_id
			JOIN users u ON u.id = gm.user_id
			WHERE u.is_active = true AND g.tenant_id = $1
			ORDER BY gm.id
		`
		rows, err = s.db.QueryContext(ctx, query, s.tenantFilter)
	} else {
		query := `
			SELECT gm.group_id, gm.user_id, g.tenant_id
			FROM group_members gm
			JOIN groups g ON g.id = gm.group_id
			JOIN users u ON u.id = gm.user_id
			WHERE u.is_active = true
			ORDER BY gm.id
		`
		rows, err = s.db.QueryContext(ctx, query)
	}
	if err != nil {
		return fmt.Errorf("failed to query group members: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate

	for rows.Next() {
		var groupID, userID, tenantID uuid.UUID

		if err := rows.Scan(&groupID, &userID, &tenantID); err != nil {
			return fmt.Errorf("failed to scan group member: %w", err)
		}

		// User is member of group
		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "group",
					ObjectId:   fmt.Sprintf("%s:%s", tenantID, groupID),
				},
				Relation: "member",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "user",
						ObjectId:   fmt.Sprintf("%s:%s", tenantID, userID),
					},
				},
			},
		})

		if len(relationships) >= s.batchSize {
			if err := s.writeRelationships(ctx, relationships); err != nil {
				return fmt.Errorf("migrateGroupMembers: %w", err)
			}
			relationships = relationships[:0]
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating group members: %w", err)
	}

	return s.writeRelationships(ctx, relationships)
}

func (s *BackfillService) migrateGroupRoles(ctx context.Context) error {
	var rows *sql.Rows
	var err error

	if s.tenantFilter != uuid.Nil {
		// SECURITY: Use parameterized query to prevent SQL injection
		query := `
			SELECT gr.group_id, gr.role_id, g.tenant_id
			FROM group_roles gr
			JOIN groups g ON g.id = gr.group_id
			WHERE g.tenant_id = $1
			ORDER BY gr.id
		`
		rows, err = s.db.QueryContext(ctx, query, s.tenantFilter)
	} else {
		query := `
			SELECT gr.group_id, gr.role_id, g.tenant_id
			FROM group_roles gr
			JOIN groups g ON g.id = gr.group_id
			ORDER BY gr.id
		`
		rows, err = s.db.QueryContext(ctx, query)
	}
	if err != nil {
		return fmt.Errorf("failed to query group roles: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate

	for rows.Next() {
		var groupID, roleID, tenantID uuid.UUID

		if err := rows.Scan(&groupID, &roleID, &tenantID); err != nil {
			return fmt.Errorf("failed to scan group role: %w", err)
		}

		// Group is member of role
		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "role",
					ObjectId:   fmt.Sprintf("%s:%s", tenantID, roleID),
				},
				Relation: "member",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "group",
						ObjectId:   fmt.Sprintf("%s:%s", tenantID, groupID),
					},
					OptionalRelation: "member",
				},
			},
		})

		if len(relationships) >= s.batchSize {
			if err := s.writeRelationships(ctx, relationships); err != nil {
				return fmt.Errorf("migrateGroupRoles: %w", err)
			}
			relationships = relationships[:0]
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating group roles: %w", err)
	}

	return s.writeRelationships(ctx, relationships)
}

func (s *BackfillService) migrateOrganizations(ctx context.Context) error {
	var rows *sql.Rows
	var err error

	if s.tenantFilter != uuid.Nil {
		// SECURITY: Use parameterized query to prevent SQL injection
		query := `SELECT id, tenant_id, parent_id, name, org_type FROM organizations WHERE tenant_id = $1 AND is_active = true ORDER BY level, id`
		rows, err = s.db.QueryContext(ctx, query, s.tenantFilter)
	} else {
		query := `SELECT id, tenant_id, parent_id, name, org_type FROM organizations WHERE is_active = true ORDER BY level, id`
		rows, err = s.db.QueryContext(ctx, query)
	}
	if err != nil {
		return fmt.Errorf("failed to query organizations: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate

	for rows.Next() {
		var orgID, tenantID uuid.UUID
		var parentID sql.NullString
		var name, orgType string

		if err := rows.Scan(&orgID, &tenantID, &parentID, &name, &orgType); err != nil {
			return fmt.Errorf("failed to scan organization: %w", err)
		}

		// Organization belongs to tenant
		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "tenant",
					ObjectId:   tenantID.String(),
				},
				Relation: "organization",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "organization",
						ObjectId:   fmt.Sprintf("%s:%s", tenantID, orgID),
					},
				},
			},
		})

		// Parent-child relationship
		if parentID.Valid {
			relationships = append(relationships, &v1.RelationshipUpdate{
				Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: "organization",
						ObjectId:   fmt.Sprintf("%s:%s", tenantID, parentID.String),
					},
					Relation: "child",
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: "organization",
							ObjectId:   fmt.Sprintf("%s:%s", tenantID, orgID),
						},
					},
				},
			})
		}

		s.stats.Lock()
		s.stats.OrganizationsProcessed++
		s.stats.Unlock()

		if len(relationships) >= s.batchSize {
			if err := s.writeRelationships(ctx, relationships); err != nil {
				return fmt.Errorf("migrateOrganizations: %w", err)
			}
			relationships = relationships[:0]
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating organizations: %w", err)
	}

	return s.writeRelationships(ctx, relationships)
}

func (s *BackfillService) migrateOrgMembers(ctx context.Context) error {
	var rows *sql.Rows
	var err error

	if s.tenantFilter != uuid.Nil {
		// SECURITY: Use parameterized query to prevent SQL injection
		query := `
			SELECT om.organization_id, om.user_id, om.role, o.tenant_id
			FROM org_members om
			JOIN organizations o ON o.id = om.organization_id
			JOIN users u ON u.id = om.user_id
			WHERE o.is_active = true AND u.is_active = true AND o.tenant_id = $1
			ORDER BY om.id
		`
		rows, err = s.db.QueryContext(ctx, query, s.tenantFilter)
	} else {
		query := `
			SELECT om.organization_id, om.user_id, om.role, o.tenant_id
			FROM org_members om
			JOIN organizations o ON o.id = om.organization_id
			JOIN users u ON u.id = om.user_id
			WHERE o.is_active = true AND u.is_active = true
			ORDER BY om.id
		`
		rows, err = s.db.QueryContext(ctx, query)
	}
	if err != nil {
		return fmt.Errorf("failed to query org members: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var relationships []*v1.RelationshipUpdate

	for rows.Next() {
		var orgID, userID, tenantID uuid.UUID
		var role string

		if err := rows.Scan(&orgID, &userID, &role, &tenantID); err != nil {
			return fmt.Errorf("failed to scan org member: %w", err)
		}

		// User is member of organization with specific role
		relationName := "member"
		if role == "manager" || role == "lead" || role == "owner" {
			relationName = role
		}

		relationships = append(relationships, &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "organization",
					ObjectId:   fmt.Sprintf("%s:%s", tenantID, orgID),
				},
				Relation: relationName,
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "user",
						ObjectId:   fmt.Sprintf("%s:%s", tenantID, userID),
					},
				},
			},
		})

		if len(relationships) >= s.batchSize {
			if err := s.writeRelationships(ctx, relationships); err != nil {
				return fmt.Errorf("migrateOrgMembers: %w", err)
			}
			relationships = relationships[:0]
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating org members: %w", err)
	}

	return s.writeRelationships(ctx, relationships)
}

func (s *BackfillService) writeRelationships(ctx context.Context, relationships []*v1.RelationshipUpdate) error {
	if len(relationships) == 0 {
		return nil
	}

	s.stats.Lock()
	s.stats.TotalRelationships += int64(len(relationships))
	s.stats.Unlock()

	if s.dryRun {
		s.logger.Info("DRY RUN: Would write relationships",
			zap.Int("count", len(relationships)),
		)
		return nil
	}

	// Retry logic
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		_, err := s.spiceDB.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
			Updates: relationships,
		})

		if err == nil {
			s.stats.Lock()
			s.stats.SuccessfulRelationships += int64(len(relationships))
			s.stats.Unlock()

			s.logger.Debug("Wrote relationships",
				zap.Int("count", len(relationships)),
			)
			return nil
		}

		if attempt < maxRetries {
			backoff := time.Duration(attempt) * time.Second
			s.logger.Warn("Failed to write relationships, retrying",
				zap.Error(err),
				zap.Int("attempt", attempt),
				zap.Duration("backoff", backoff),
			)
			time.Sleep(backoff)
		} else {
			s.stats.Lock()
			s.stats.FailedRelationships += int64(len(relationships))
			s.stats.Errors = append(s.stats.Errors, err.Error())
			s.stats.Unlock()

			return fmt.Errorf("failed to write relationships after %d attempts: %w", maxRetries, err)
		}
	}

	return nil
}

func (s *BackfillService) VerifyMigration(ctx context.Context) error {
	s.logger.Info("Starting verification")

	verifications := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"tenant_counts", s.verifyTenantCounts},
		{"user_counts", s.verifyUserCounts},
		{"role_assignments", s.verifyRoleAssignments},
		{"sample_permissions", s.verifySamplePermissions},
	}

	for _, v := range verifications {
		s.logger.Info("Running verification", zap.String("check", v.name))
		if err := v.fn(ctx); err != nil {
			return fmt.Errorf("verification %s failed: %w", v.name, err)
		}
	}

	s.logger.Info("All verifications passed")
	return nil
}

func (s *BackfillService) verifyTenantCounts(ctx context.Context) error {
	// Query PostgreSQL
	var pgCount int64
	query := `SELECT COUNT(*) FROM tenants WHERE status = 'active'`
	if err := s.db.QueryRowContext(ctx, query).Scan(&pgCount); err != nil {
		return fmt.Errorf("failed to count tenants in PostgreSQL: %w", err)
	}

	s.logger.Info("Tenant count verification",
		zap.Int64("postgresql", pgCount),
		zap.Int64("processed", s.stats.TenantsProcessed),
	)

	if pgCount != s.stats.TenantsProcessed {
		return fmt.Errorf("tenant count mismatch: PostgreSQL=%d, Processed=%d", pgCount, s.stats.TenantsProcessed)
	}

	return nil
}

func (s *BackfillService) verifyUserCounts(ctx context.Context) error {
	var pgCount int64
	var err error

	if s.tenantFilter != uuid.Nil {
		// SECURITY: Use parameterized query to prevent SQL injection
		query := `SELECT COUNT(*) FROM users WHERE is_active = true AND tenant_id = $1`
		err = s.db.QueryRowContext(ctx, query, s.tenantFilter).Scan(&pgCount)
	} else {
		query := `SELECT COUNT(*) FROM users WHERE is_active = true`
		err = s.db.QueryRowContext(ctx, query).Scan(&pgCount)
	}

	if err != nil {
		return fmt.Errorf("failed to count users in PostgreSQL: %w", err)
	}

	s.logger.Info("User count verification",
		zap.Int64("postgresql", pgCount),
		zap.Int64("processed", s.stats.UsersProcessed),
	)

	if pgCount != s.stats.UsersProcessed {
		return fmt.Errorf("user count mismatch: PostgreSQL=%d, Processed=%d", pgCount, s.stats.UsersProcessed)
	}

	return nil
}

func (s *BackfillService) verifyRoleAssignments(ctx context.Context) error {
	var pgCount int64
	var err error

	if s.tenantFilter != uuid.Nil {
		// SECURITY: Use parameterized query to prevent SQL injection
		query := `
			SELECT COUNT(*)
			FROM user_roles ur
			JOIN users u ON u.id = ur.user_id
			WHERE u.is_active = true AND u.tenant_id = $1
		`
		err = s.db.QueryRowContext(ctx, query, s.tenantFilter).Scan(&pgCount)
	} else {
		query := `
			SELECT COUNT(*)
			FROM user_roles ur
			JOIN users u ON u.id = ur.user_id
			WHERE u.is_active = true
		`
		err = s.db.QueryRowContext(ctx, query).Scan(&pgCount)
	}

	if err != nil {
		return fmt.Errorf("failed to count user roles in PostgreSQL: %w", err)
	}

	s.logger.Info("Role assignment verification",
		zap.Int64("postgresql_assignments", pgCount),
	)

	return nil
}

func (s *BackfillService) verifySamplePermissions(ctx context.Context) error {
	// Sample a few users and verify their permissions in SpiceDB
	var rows *sql.Rows
	var err error

	if s.tenantFilter != uuid.Nil {
		// SECURITY: Use parameterized query to prevent SQL injection
		query := `
			SELECT u.id, u.tenant_id, u.username
			FROM users u
			WHERE u.is_active = true AND u.tenant_id = $1
			LIMIT 5
		`
		rows, err = s.db.QueryContext(ctx, query, s.tenantFilter)
	} else {
		query := `
			SELECT u.id, u.tenant_id, u.username
			FROM users u
			WHERE u.is_active = true
			LIMIT 5
		`
		rows, err = s.db.QueryContext(ctx, query)
	}
	if err != nil {
		return fmt.Errorf("failed to query sample users: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var userID, tenantID uuid.UUID
		var username string

		if err := rows.Scan(&userID, &tenantID, &username); err != nil {
			return fmt.Errorf("failed to scan user: %w", err)
		}

		// Check if user is member of tenant in SpiceDB
		resp, err := s.spiceDB.CheckPermission(ctx, &v1.CheckPermissionRequest{
			Resource: &v1.ObjectReference{
				ObjectType: "tenant",
				ObjectId:   tenantID.String(),
			},
			Permission: "member",
			Subject: &v1.SubjectReference{
				Object: &v1.ObjectReference{
					ObjectType: "user",
					ObjectId:   fmt.Sprintf("%s:%s", tenantID, userID),
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to check permission for user %s: %w", username, err)
		}

		if resp.Permissionship != v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
			return fmt.Errorf("user %s should be member of tenant but is not", username)
		}

		s.logger.Debug("Sample permission check passed",
			zap.String("user", username),
			zap.String("tenant_id", tenantID.String()),
		)
	}

	return rows.Err()
}

func (s *BackfillService) PrintStatistics() {
	duration := s.stats.EndTime.Sub(s.stats.StartTime)

	s.logger.Info("Migration Statistics",
		zap.Duration("duration", duration),
		zap.Int64("total_relationships", s.stats.TotalRelationships),
		zap.Int64("successful_relationships", s.stats.SuccessfulRelationships),
		zap.Int64("failed_relationships", s.stats.FailedRelationships),
		zap.Int64("tenants_processed", s.stats.TenantsProcessed),
		zap.Int64("users_processed", s.stats.UsersProcessed),
		zap.Int64("roles_processed", s.stats.RolesProcessed),
		zap.Int64("permissions_processed", s.stats.PermissionsProcessed),
		zap.Int64("groups_processed", s.stats.GroupsProcessed),
		zap.Int64("organizations_processed", s.stats.OrganizationsProcessed),
	)

	if len(s.stats.Errors) > 0 {
		s.logger.Warn("Errors encountered during migration",
			zap.Int("error_count", len(s.stats.Errors)),
			zap.Strings("errors", s.stats.Errors[:min(10, len(s.stats.Errors))]),
		)
	}

	// Calculate throughput
	if duration > 0 {
		rps := float64(s.stats.SuccessfulRelationships) / duration.Seconds()
		s.logger.Info("Throughput",
			zap.Float64("relationships_per_second", rps),
		)
	}
}

func (s *BackfillService) isStageCompleted(stageName string) bool {
	for _, completed := range s.checkpoint.CompletedStages {
		if completed == stageName {
			return true
		}
	}
	return false
}

func (s *BackfillService) markStageCompleted(stageName string) {
	if !s.isStageCompleted(stageName) {
		s.checkpoint.CompletedStages = append(s.checkpoint.CompletedStages, stageName)
	}
}

func (s *BackfillService) saveCheckpoint() error {
	s.checkpoint.LastUpdated = time.Now()

	data, err := json.MarshalIndent(s.checkpoint, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}

	if err := os.WriteFile(".backfill-checkpoint.json", data, 0o644); err != nil { //nolint:gosec // checkpoint file needs group-readable permissions
		return fmt.Errorf("failed to write checkpoint: %w", err)
	}

	s.logger.Debug("Checkpoint saved")
	return nil
}

func loadCheckpoint() (*Checkpoint, error) {
	data, err := os.ReadFile(".backfill-checkpoint.json")
	if err != nil {
		return nil, fmt.Errorf("loadCheckpoint: ReadFile failed: %w", err)
	}

	var checkpoint Checkpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return nil, fmt.Errorf("loadCheckpoint: %w", err)
	}

	return &checkpoint, nil
}

func setupLogger(verbose bool) *zap.Logger {
	config := zap.NewProductionConfig()
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	if verbose {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	logger, _ := config.Build()
	return logger
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main provides the entry point.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	databaseURL  = pflag.String("database-url", os.Getenv("DATABASE_URL"), "PostgreSQL connection string")
	spicedbURL   = pflag.String("spicedb-url", os.Getenv("SPICEDB_ENDPOINT"), "SpiceDB gRPC endpoint")
	spicedbToken = pflag.String("spicedb-token", os.Getenv("SPICEDB_TOKEN"), "SpiceDB preshared token")
	insecureConn = pflag.Bool("insecure", false, "Use insecure gRPC connection (dev only)")
	tenantID     = pflag.String("tenant-id", "", "Verify specific tenant only")
	detailed     = pflag.Bool("detailed", false, "Show detailed comparison")
	sampleSize   = pflag.Int("sample-size", 10, "Number of samples to verify for permission checks")
)

type VerificationResult struct {
	Entity           string
	PostgreSQLCount  int64
	SpiceDBCount     int64
	Match            bool
	DiscrepancyPct   float64
	VerificationTime time.Duration
	SamplesChecked   int
	SamplesPassed    int
	SamplesFailed    int
	ErrorMessage     string
}

type VerificationService struct {
	logger       *zap.Logger
	db           *sql.DB
	spiceDB      *authzed.Client
	tenantFilter uuid.UUID
	results      []*VerificationResult
}

func main() {
	pflag.Parse()

	logger := setupLogger()
	defer func() { _ = logger.Sync() }()

	logger.Info("Starting SpiceDB verification tool")

	if *databaseURL == "" {
		logger.Fatal("DATABASE_URL is required")
	}
	if *spicedbURL == "" {
		logger.Fatal("SPICEDB_ENDPOINT is required")
	}

	service, err := NewVerificationService(logger)
	if err != nil {
		logger.Fatal("Failed to initialize verification service", zap.Error(err))
	}
	defer service.Close()

	ctx := context.Background()

	// Run all verifications
	service.verifyTenants(ctx)
	service.verifyUsers(ctx)
	service.verifyRoles(ctx)
	service.verifyUserRoles(ctx)
	service.verifyRolePermissions(ctx)
	service.verifyGroups(ctx)
	service.verifyGroupMembers(ctx)
	service.verifyGroupRoles(ctx)
	service.verifyOrganizations(ctx)
	service.verifyOrgMembers(ctx)

	// Sample permission checks
	if *detailed {
		service.verifySamplePermissions(ctx)
	}

	// Print results
	service.PrintResults()

	// Exit code
	if service.HasFailures() {
		os.Exit(1) //nolint:gocritic // exitAfterDefer: intentional early exit in cmd
	}
}

func NewVerificationService(logger *zap.Logger) (*VerificationService, error) {
	// Connect to PostgreSQL
	db, err := sql.Open("postgres", *databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	if err := db.PingContext(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	logger.Info("Connected to PostgreSQL")

	// Connect to SpiceDB
	var dialOpts []grpc.DialOption
	if *insecureConn {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		systemCerts, err := grpcutil.WithSystemCerts(grpcutil.VerifyCA)
		if err != nil {
			return nil, fmt.Errorf("failed to load system certificates: %w", err)
		}
		dialOpts = append(dialOpts, systemCerts)
	}

	if *spicedbToken != "" {
		dialOpts = append(dialOpts, grpcutil.WithBearerToken(*spicedbToken))
	}

	spiceDBClient, err := authzed.NewClient(*spicedbURL, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SpiceDB: %w", err)
	}

	logger.Info("Connected to SpiceDB", zap.String("endpoint", *spicedbURL))

	// Parse tenant filter
	var tenantFilter uuid.UUID
	if *tenantID != "" {
		tenantFilter, err = uuid.Parse(*tenantID)
		if err != nil {
			return nil, fmt.Errorf("invalid tenant ID: %w", err)
		}
	}

	return &VerificationService{
		logger:       logger,
		db:           db,
		spiceDB:      spiceDBClient,
		tenantFilter: tenantFilter,
		results:      []*VerificationResult{},
	}, nil
}

func (s *VerificationService) Close() {
	if s.db != nil {
		_ = s.db.Close()
	}
}

func (s *VerificationService) verifyTenants(ctx context.Context) {
	start := time.Now()
	result := &VerificationResult{
		Entity: "Tenants",
	}

	// Count in PostgreSQL using parameterized queries to prevent SQL injection
	var queryErr error
	if s.tenantFilter != uuid.Nil {
		queryErr = s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM tenants WHERE id = $1 AND status = 'active'`,
			s.tenantFilter,
		).Scan(&result.PostgreSQLCount)
	} else {
		queryErr = s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM tenants WHERE status = 'active'`,
		).Scan(&result.PostgreSQLCount)
	}

	if err := queryErr; err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	// Count tenant relationships in SpiceDB (this is approximate)
	// We count tenant objects by reading relationships
	filter := &v1.RelationshipFilter{
		ResourceType: "tenant",
	}

	if s.tenantFilter != uuid.Nil {
		filter.OptionalResourceId = s.tenantFilter.String()
	}

	readResp, err := s.spiceDB.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		RelationshipFilter: filter,
	})
	if err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	// Count unique tenant IDs
	tenantIDs := make(map[string]bool)
	for {
		rel, err := readResp.Recv()
		if err != nil {
			break
		}
		tenantIDs[rel.Relationship.Resource.ObjectId] = true
	}

	result.SpiceDBCount = int64(len(tenantIDs))
	result.Match = result.PostgreSQLCount == result.SpiceDBCount
	if result.PostgreSQLCount > 0 {
		result.DiscrepancyPct = float64(result.SpiceDBCount-result.PostgreSQLCount) / float64(result.PostgreSQLCount) * 100
	}
	result.VerificationTime = time.Since(start)

	s.results = append(s.results, result)
}

func (s *VerificationService) verifyUsers(ctx context.Context) {
	start := time.Now()
	result := &VerificationResult{
		Entity: "Users",
	}

	// Count in PostgreSQL
	query := `SELECT COUNT(*) FROM users WHERE is_active = true`
	var args []interface{}
	if s.tenantFilter != uuid.Nil {
		query += ` AND tenant_id = $1`
		args = append(args, s.tenantFilter)
	}

	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&result.PostgreSQLCount); err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	// Count user-tenant relationships in SpiceDB
	filter := &v1.RelationshipFilter{
		ResourceType:     "tenant",
		OptionalRelation: "member",
		OptionalSubjectFilter: &v1.SubjectFilter{
			SubjectType: "user",
		},
	}

	if s.tenantFilter != uuid.Nil {
		filter.OptionalResourceId = s.tenantFilter.String()
	}

	count, err := s.countRelationships(ctx, filter)
	if err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	result.SpiceDBCount = count
	result.Match = result.PostgreSQLCount == result.SpiceDBCount
	if result.PostgreSQLCount > 0 {
		result.DiscrepancyPct = float64(result.SpiceDBCount-result.PostgreSQLCount) / float64(result.PostgreSQLCount) * 100
	}
	result.VerificationTime = time.Since(start)

	s.results = append(s.results, result)
}

func (s *VerificationService) verifyRoles(ctx context.Context) {
	start := time.Now()
	result := &VerificationResult{
		Entity: "Roles",
	}

	query := `SELECT COUNT(*) FROM roles`
	var args []interface{}
	if s.tenantFilter != uuid.Nil {
		query += ` WHERE tenant_id = $1`
		args = append(args, s.tenantFilter)
	}

	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&result.PostgreSQLCount); err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	filter := &v1.RelationshipFilter{
		ResourceType:     "tenant",
		OptionalRelation: "role",
		OptionalSubjectFilter: &v1.SubjectFilter{
			SubjectType: "role",
		},
	}

	if s.tenantFilter != uuid.Nil {
		filter.OptionalResourceId = s.tenantFilter.String()
	}

	count, err := s.countRelationships(ctx, filter)
	if err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	result.SpiceDBCount = count
	result.Match = result.PostgreSQLCount == result.SpiceDBCount
	if result.PostgreSQLCount > 0 {
		result.DiscrepancyPct = float64(result.SpiceDBCount-result.PostgreSQLCount) / float64(result.PostgreSQLCount) * 100
	}
	result.VerificationTime = time.Since(start)

	s.results = append(s.results, result)
}

func (s *VerificationService) verifyUserRoles(ctx context.Context) {
	start := time.Now()
	result := &VerificationResult{
		Entity: "User-Role Assignments",
	}

	query := `
		SELECT COUNT(*)
		FROM user_roles ur
		JOIN users u ON u.id = ur.user_id
		WHERE u.is_active = true
	`
	var args []interface{}
	if s.tenantFilter != uuid.Nil {
		query += ` AND u.tenant_id = $1`
		args = append(args, s.tenantFilter)
	}

	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&result.PostgreSQLCount); err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	filter := &v1.RelationshipFilter{
		ResourceType:     "role",
		OptionalRelation: "member",
		OptionalSubjectFilter: &v1.SubjectFilter{
			SubjectType: "user",
		},
	}

	count, err := s.countRelationships(ctx, filter)
	if err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	result.SpiceDBCount = count
	result.Match = result.PostgreSQLCount == result.SpiceDBCount
	if result.PostgreSQLCount > 0 {
		result.DiscrepancyPct = float64(result.SpiceDBCount-result.PostgreSQLCount) / float64(result.PostgreSQLCount) * 100
	}
	result.VerificationTime = time.Since(start)

	s.results = append(s.results, result)
}

func (s *VerificationService) verifyRolePermissions(ctx context.Context) {
	start := time.Now()
	result := &VerificationResult{
		Entity: "Role-Permission Assignments",
	}

	query := `
		SELECT COUNT(*)
		FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id
	`
	var args []interface{}
	if s.tenantFilter != uuid.Nil {
		query += ` WHERE r.tenant_id = $1`
		args = append(args, s.tenantFilter)
	}

	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&result.PostgreSQLCount); err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	filter := &v1.RelationshipFilter{
		ResourceType:     "role",
		OptionalRelation: "permission",
		OptionalSubjectFilter: &v1.SubjectFilter{
			SubjectType: "permission",
		},
	}

	count, err := s.countRelationships(ctx, filter)
	if err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	result.SpiceDBCount = count
	result.Match = result.PostgreSQLCount == result.SpiceDBCount
	if result.PostgreSQLCount > 0 {
		result.DiscrepancyPct = float64(result.SpiceDBCount-result.PostgreSQLCount) / float64(result.PostgreSQLCount) * 100
	}
	result.VerificationTime = time.Since(start)

	s.results = append(s.results, result)
}

func (s *VerificationService) verifyGroups(ctx context.Context) {
	start := time.Now()
	result := &VerificationResult{
		Entity: "Groups",
	}

	query := `SELECT COUNT(*) FROM groups`
	var args []interface{}
	if s.tenantFilter != uuid.Nil {
		query += ` WHERE tenant_id = $1`
		args = append(args, s.tenantFilter)
	}

	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&result.PostgreSQLCount); err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	filter := &v1.RelationshipFilter{
		ResourceType:     "tenant",
		OptionalRelation: "group",
		OptionalSubjectFilter: &v1.SubjectFilter{
			SubjectType: "group",
		},
	}

	if s.tenantFilter != uuid.Nil {
		filter.OptionalResourceId = s.tenantFilter.String()
	}

	count, err := s.countRelationships(ctx, filter)
	if err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	result.SpiceDBCount = count
	result.Match = result.PostgreSQLCount == result.SpiceDBCount
	if result.PostgreSQLCount > 0 {
		result.DiscrepancyPct = float64(result.SpiceDBCount-result.PostgreSQLCount) / float64(result.PostgreSQLCount) * 100
	}
	result.VerificationTime = time.Since(start)

	s.results = append(s.results, result)
}

func (s *VerificationService) verifyGroupMembers(ctx context.Context) {
	start := time.Now()
	result := &VerificationResult{
		Entity: "Group Members",
	}

	query := `
		SELECT COUNT(*)
		FROM group_members gm
		JOIN groups g ON g.id = gm.group_id
		JOIN users u ON u.id = gm.user_id
		WHERE u.is_active = true
	`
	var args []interface{}
	if s.tenantFilter != uuid.Nil {
		query += ` AND g.tenant_id = $1`
		args = append(args, s.tenantFilter)
	}

	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&result.PostgreSQLCount); err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	filter := &v1.RelationshipFilter{
		ResourceType:     "group",
		OptionalRelation: "member",
		OptionalSubjectFilter: &v1.SubjectFilter{
			SubjectType: "user",
		},
	}

	count, err := s.countRelationships(ctx, filter)
	if err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	result.SpiceDBCount = count
	result.Match = result.PostgreSQLCount == result.SpiceDBCount
	if result.PostgreSQLCount > 0 {
		result.DiscrepancyPct = float64(result.SpiceDBCount-result.PostgreSQLCount) / float64(result.PostgreSQLCount) * 100
	}
	result.VerificationTime = time.Since(start)

	s.results = append(s.results, result)
}

func (s *VerificationService) verifyGroupRoles(ctx context.Context) {
	start := time.Now()
	result := &VerificationResult{
		Entity: "Group Roles",
	}

	query := `
		SELECT COUNT(*)
		FROM group_roles gr
		JOIN groups g ON g.id = gr.group_id
	`
	var args []interface{}
	if s.tenantFilter != uuid.Nil {
		query += ` WHERE g.tenant_id = $1`
		args = append(args, s.tenantFilter)
	}

	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&result.PostgreSQLCount); err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	filter := &v1.RelationshipFilter{
		ResourceType:     "role",
		OptionalRelation: "member",
		OptionalSubjectFilter: &v1.SubjectFilter{
			SubjectType: "group",
		},
	}

	count, err := s.countRelationships(ctx, filter)
	if err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	result.SpiceDBCount = count
	result.Match = result.PostgreSQLCount == result.SpiceDBCount
	if result.PostgreSQLCount > 0 {
		result.DiscrepancyPct = float64(result.SpiceDBCount-result.PostgreSQLCount) / float64(result.PostgreSQLCount) * 100
	}
	result.VerificationTime = time.Since(start)

	s.results = append(s.results, result)
}

func (s *VerificationService) verifyOrganizations(ctx context.Context) {
	start := time.Now()
	result := &VerificationResult{
		Entity: "Organizations",
	}

	query := `SELECT COUNT(*) FROM organizations WHERE is_active = true`
	var args []interface{}
	if s.tenantFilter != uuid.Nil {
		query += ` AND tenant_id = $1`
		args = append(args, s.tenantFilter)
	}

	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&result.PostgreSQLCount); err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	filter := &v1.RelationshipFilter{
		ResourceType:     "tenant",
		OptionalRelation: "organization",
		OptionalSubjectFilter: &v1.SubjectFilter{
			SubjectType: "organization",
		},
	}

	if s.tenantFilter != uuid.Nil {
		filter.OptionalResourceId = s.tenantFilter.String()
	}

	count, err := s.countRelationships(ctx, filter)
	if err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	result.SpiceDBCount = count
	result.Match = result.PostgreSQLCount == result.SpiceDBCount
	if result.PostgreSQLCount > 0 {
		result.DiscrepancyPct = float64(result.SpiceDBCount-result.PostgreSQLCount) / float64(result.PostgreSQLCount) * 100
	}
	result.VerificationTime = time.Since(start)

	s.results = append(s.results, result)
}

func (s *VerificationService) verifyOrgMembers(ctx context.Context) {
	start := time.Now()
	result := &VerificationResult{
		Entity: "Organization Members",
	}

	query := `
		SELECT COUNT(*)
		FROM org_members om
		JOIN organizations o ON o.id = om.organization_id
		JOIN users u ON u.id = om.user_id
		WHERE o.is_active = true AND u.is_active = true
	`
	var args []interface{}
	if s.tenantFilter != uuid.Nil {
		query += ` AND o.tenant_id = $1`
		args = append(args, s.tenantFilter)
	}

	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&result.PostgreSQLCount); err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}

	// Count all org member relationships (member, manager, lead, owner)
	var totalCount int64
	for _, relation := range []string{"member", "manager", "lead", "owner"} {
		filter := &v1.RelationshipFilter{
			ResourceType:     "organization",
			OptionalRelation: relation,
			OptionalSubjectFilter: &v1.SubjectFilter{
				SubjectType: "user",
			},
		}

		count, err := s.countRelationships(ctx, filter)
		if err != nil {
			result.ErrorMessage = err.Error()
			s.results = append(s.results, result)
			return
		}
		totalCount += count
	}

	result.SpiceDBCount = totalCount
	result.Match = result.PostgreSQLCount == result.SpiceDBCount
	if result.PostgreSQLCount > 0 {
		result.DiscrepancyPct = float64(result.SpiceDBCount-result.PostgreSQLCount) / float64(result.PostgreSQLCount) * 100
	}
	result.VerificationTime = time.Since(start)

	s.results = append(s.results, result)
}

func (s *VerificationService) verifySamplePermissions(ctx context.Context) {
	start := time.Now()
	result := &VerificationResult{
		Entity: "Sample Permission Checks",
	}

	query := `
		SELECT u.id, u.tenant_id, u.username
		FROM users u
		WHERE u.is_active = true
	`
	var args []interface{}
	paramIdx := 1
	if s.tenantFilter != uuid.Nil {
		query += fmt.Sprintf(` AND u.tenant_id = $%d`, paramIdx)
		args = append(args, s.tenantFilter)
		paramIdx++
	}
	query += fmt.Sprintf(` LIMIT $%d`, paramIdx) //nolint:gosec // SQL built with safe identifier components
	args = append(args, *sampleSize)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		result.ErrorMessage = err.Error()
		s.results = append(s.results, result)
		return
	}
	defer rows.Close() //nolint:errcheck

	samplesChecked := 0
	samplesPassed := 0
	samplesFailed := 0

	for rows.Next() {
		var userID, tenantID uuid.UUID
		var username string

		if err := rows.Scan(&userID, &tenantID, &username); err != nil {
			continue
		}

		samplesChecked++

		// Check tenant membership
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

		if err != nil || resp.Permissionship != v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
			samplesFailed++
			s.logger.Warn("Sample permission check failed",
				zap.String("user", username),
				zap.String("tenant_id", tenantID.String()),
			)
		} else {
			samplesPassed++
		}
	}

	if err := rows.Err(); err != nil {
		s.logger.Error("Row iteration error during permission sample check", zap.Error(err))
		result.Match = false
	}

	result.SamplesChecked = samplesChecked
	result.SamplesPassed = samplesPassed
	result.SamplesFailed = samplesFailed
	if result.Match {
		result.Match = samplesFailed == 0
	}
	result.VerificationTime = time.Since(start)

	s.results = append(s.results, result)
}

func (s *VerificationService) countRelationships(ctx context.Context, filter *v1.RelationshipFilter) (int64, error) {
	readResp, err := s.spiceDB.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		RelationshipFilter: filter,
	})
	if err != nil {
		return 0, fmt.Errorf("countRelationships: %w", err)
	}

	var count int64
	for {
		_, recvErr := readResp.Recv()
		if recvErr != nil {
			if !errors.Is(recvErr, io.EOF) {
				return count, fmt.Errorf("countRelationships: recv: %w", recvErr)
			}
			break
		}
		count++
	}

	return count, nil
}

func (s *VerificationService) PrintResults() {
	fmt.Println("\n" + strings.Repeat("═", 100))
	fmt.Println("SPICEDB VERIFICATION RESULTS")
	fmt.Println(strings.Repeat("═", 100) + "\n")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "Entity\tPostgreSQL\tSpiceDB\tMatch\tDiscrepancy %\tTime")
	_, _ = fmt.Fprintln(w, "------\t----------\t-------\t-----\t-------------\t----")

	totalMatches := 0
	totalChecks := len(s.results)

	for _, r := range s.results {
		matchStr := "✓"
		if !r.Match {
			matchStr = "✗"
		} else {
			totalMatches++
		}

		discrepancyStr := fmt.Sprintf("%.2f%%", r.DiscrepancyPct)
		if r.Match {
			discrepancyStr = "-"
		}

		timeStr := fmt.Sprintf("%.2fs", r.VerificationTime.Seconds())

		if r.SamplesChecked > 0 {
			_, _ = fmt.Fprintf(w, "%s\t%d samples\t%d passed\t%s\t%d failed\t%s\n",
				r.Entity, r.SamplesChecked, r.SamplesPassed, matchStr, r.SamplesFailed, timeStr)
		} else {
			_, _ = fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%s\t%s\n",
				r.Entity, r.PostgreSQLCount, r.SpiceDBCount, matchStr, discrepancyStr, timeStr)
		}

		if r.ErrorMessage != "" {
			_, _ = fmt.Fprintf(w, "\tError: %s\t\t\t\t\n", r.ErrorMessage)
		}
	}

	_ = w.Flush()

	fmt.Println("\n" + strings.Repeat("─", 100))
	fmt.Printf("Total Checks: %d | Passed: %d | Failed: %d | Success Rate: %.2f%%\n",
		totalChecks, totalMatches, totalChecks-totalMatches,
		float64(totalMatches)/float64(totalChecks)*100)
	fmt.Println(strings.Repeat("─", 100) + "\n")

	if totalMatches == totalChecks {
		fmt.Println("✓ ALL VERIFICATIONS PASSED")
	} else {
		fmt.Println("✗ SOME VERIFICATIONS FAILED - Please review discrepancies")
	}
}

func (s *VerificationService) HasFailures() bool {
	for _, r := range s.results {
		if !r.Match {
			return true
		}
	}
	return false
}

func setupLogger() *zap.Logger {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	logger, _ := config.Build()
	return logger
}

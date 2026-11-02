// SPDX-License-Identifier: AGPL-3.0-or-later

// Package spicedb provides a SpiceDB client wrapper for the IAM service.
// It integrates with the authorization package and provides IAM-specific
// functionality for managing user permissions and relationships.
package spicedb

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	resilient "github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	spicedbResultDenied     = "denied"
	spicedbObjectTypeUser   = "user"
	spicedbObjectTypeRole   = "role"
	spicedbObjectTypeTenant = "tenant"
	spicedbObjectDefault    = "default"
)

// Client wraps the SpiceDB client with IAM-specific functionality.
type Client struct {
	spicedb *authzed.Client
	redis   *redis.Client
	config  *config.Config

	// Rate limiting
	checkSem chan struct{}

	// DDIL P3.11 resilience: a SHARED circuit breaker + backoff + per-attempt
	// timeout around the SpiceDB read RPCs (permission checks). The breaker is
	// shared across all checks so shedding is coordinated, and when it opens the
	// check returns fast, letting the caller's governed offline-authz (P3.2)
	// serve a last-known-good decision instead of piling onto a failing PDP.
	// resilienceOn=false ⇒ direct passthrough (pre-DDIL behaviour).
	resilienceOn bool
	breaker      *resilient.Breaker
	readCfg      resilient.Config

	// Metrics
	mu          sync.RWMutex
	checkCount  int64
	cacheHits   int64
	cacheMisses int64
	errorCount  int64
}

// initResilience wires the shared read-path breaker/backoff from config. When
// SPICEDB_RESILIENCE_ENABLED is false, reads pass straight through.
func (c *Client) initResilience(cfg *config.Config) {
	if !cfg.SpiceDBResilienceEnabled {
		c.resilienceOn = false
		return
	}
	c.resilienceOn = true
	c.breaker = resilient.NewBreaker(resilient.BreakerConfig{
		FailureThreshold: cfg.SpiceDBBreakerFailureThreshold,
		OpenTimeout:      cfg.SpiceDBBreakerResetTimeout,
		OnStateChange: func(from, to resilient.State) {
			logger.Log.Warn("SpiceDB circuit breaker state change",
				zap.String("from", from.String()),
				zap.String("to", to.String()),
			)
			if to == resilient.StateOpen {
				RecordError("circuit_breaker", "open")
			}
		},
	})
	c.readCfg = resilient.Config{
		Timeout:     cfg.SpiceDBCallTimeout,
		MaxAttempts: cfg.SpiceDBMaxAttempts,
		Breaker:     c.breaker,
		Retryable:   spicedbRetryable,
	}
}

// runRead executes an idempotent SpiceDB read RPC under the resilience envelope
// (shared breaker + backoff-with-jitter + per-attempt timeout). Passthrough
// when resilience is disabled. Only read/check RPCs use this — writes are not
// wrapped because the breaker+retry envelope is intended for the idempotent
// read path that composes with offline authz.
func (c *Client) runRead(ctx context.Context, fn func(ctx context.Context) error) error {
	if !c.resilienceOn {
		return fn(ctx)
	}
	return resilient.Do(ctx, c.readCfg, fn)
}

// spicedbRetryable retries only transient gRPC conditions. Permanent errors
// (InvalidArgument, NotFound, PermissionDenied, Unauthenticated, …) are not
// retried — retrying them wastes the budget and cannot succeed. ErrBreakerOpen
// and context cancellation are handled by resilient.Do itself.
func spicedbRetryable(err error) bool {
	if err == nil {
		return false
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Aborted:
		return true
	default:
		return false
	}
}

// NewClient creates a new SpiceDB client for IAM.
func NewClient(ctx context.Context, cfg *config.Config, redisClient *redis.Client) (*Client, error) {
	if !cfg.SpiceDBEnabled {
		return nil, fmt.Errorf("SpiceDB is not enabled")
	}

	if cfg.SpiceDBEndpoint == "" {
		return nil, fmt.Errorf("SpiceDB endpoint is required")
	}

	if cfg.SpiceDBToken == "" {
		return nil, fmt.Errorf("SpiceDB token is required - cannot connect without authentication")
	}

	var opts []grpc.DialOption

	if cfg.SpiceDBInsecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		opts = append(opts, grpcutil.WithInsecureBearerToken(cfg.SpiceDBToken))
	} else {
		systemCertsOpt, err := grpcutil.WithSystemCerts(grpcutil.VerifyCA)
		if err != nil {
			return nil, fmt.Errorf("failed to load system certificates: %w", err)
		}
		opts = append(opts, systemCertsOpt)
		opts = append(opts, grpcutil.WithBearerToken(cfg.SpiceDBToken))
	}

	spicedb, err := authzed.NewClient(cfg.SpiceDBEndpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create SpiceDB client: %w", err)
	}

	maxChecks := cfg.SpiceDBMaxConcurrentChecks
	if maxChecks <= 0 {
		maxChecks = 100
	}

	client := &Client{
		spicedb:  spicedb,
		redis:    redisClient,
		config:   cfg,
		checkSem: make(chan struct{}, maxChecks),
	}
	client.initResilience(cfg)

	// Verify connection
	if err := client.HealthCheck(ctx); err != nil {
		return nil, fmt.Errorf("SpiceDB health check failed: %w", err)
	}

	logger.Info("SpiceDB client initialized",
		zap.String("endpoint", cfg.SpiceDBEndpoint),
		zap.Bool("insecure", cfg.SpiceDBInsecure),
		zap.Int("max_concurrent_checks", maxChecks),
	)

	return client, nil
}

// AuthzedClient returns the underlying authzed.Client for use by components
// that need direct access to the SpiceDB API (e.g. WatchService).
func (c *Client) AuthzedClient() *authzed.Client {
	return c.spicedb
}

// Close releases all resources.
func (c *Client) Close() error {
	// Note: authzed client doesn't have a Close method
	return nil
}

// HealthCheck verifies SpiceDB connectivity.
func (c *Client) HealthCheck(ctx context.Context) error {
	// Perform a simple schema read to verify connectivity
	_, err := c.spicedb.ReadSchema(ctx, &v1.ReadSchemaRequest{})
	if err != nil {
		// UNIMPLEMENTED is acceptable for health check (means server is up)
		if status.Code(err) == codes.Unimplemented {
			return nil
		}
		return fmt.Errorf("SpiceDB health check failed: %w", err)
	}
	return nil
}

// CheckPermission verifies if a user has a permission on a resource.
func (c *Client) CheckPermission(ctx context.Context, tenantID, userID uuid.UUID, objectType, objectID, permission string) (bool, error) {
	startTime := time.Now()

	// Rate limiting
	select {
	case c.checkSem <- struct{}{}:
		defer func() { <-c.checkSem }()
	case <-ctx.Done():
		return false, ctx.Err()
	}

	c.incrementCheckCount()

	// Check cache first
	cacheHit := false
	cacheKey := c.generateCacheKey(tenantID, userID, objectType, objectID, permission)
	if c.redis != nil {
		if cached, err := c.checkCache(ctx, cacheKey); err == nil {
			c.incrementCacheHits()
			cacheHit = true
			result := "allowed"
			if !cached {
				result = spicedbResultDenied
			}
			RecordPermissionCheck(tenantID, objectType, permission, result, time.Since(startTime), cacheHit)
			return cached, nil
		}
		c.incrementCacheMisses()
	}

	// Build SpiceDB request (check-time caveat context is attached by the helper)
	req := c.newCheckRequest(
		&v1.Consistency{Requirement: &v1.Consistency_MinimizeLatency{MinimizeLatency: true}},
		&v1.ObjectReference{ObjectType: objectType, ObjectId: c.tenantScopedID(tenantID, objectID)},
		&v1.ObjectReference{ObjectType: spicedbObjectTypeUser, ObjectId: c.tenantScopedID(tenantID, userID.String())},
		permission,
	)

	// Record consistency mode
	RecordConsistencyMode("minimize_latency")

	// Execute check under the DDIL resilience envelope (breaker + backoff +
	// per-attempt timeout). A shed (ErrBreakerOpen) or exhausted retries surface
	// as an error, driving the caller's fail-closed / offline-authz path.
	var resp *v1.CheckPermissionResponse
	err := c.runRead(ctx, func(ctx context.Context) error {
		var e error
		resp, e = c.spicedb.CheckPermission(ctx, req)
		return e
	})
	if err != nil {
		c.incrementErrorCount()
		RecordError("check_permission", "grpc_error")
		return false, fmt.Errorf("permission check failed: %w", err)
	}

	allowed := resp.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION

	// Cache result
	if c.redis != nil {
		_ = c.cacheResult(ctx, cacheKey, allowed)
	}

	result := "allowed"
	if !allowed {
		result = spicedbResultDenied
	}
	RecordPermissionCheck(tenantID, objectType, permission, result, time.Since(startTime), cacheHit)

	return allowed, nil
}

// CheckModulePermission checks if user has a permission on a module (e.g., crm.view).
func (c *Client) CheckModulePermission(ctx context.Context, tenantID, userID uuid.UUID, module, permission string) (bool, error) {
	objectType := fmt.Sprintf("%s_module", module)
	objectID := spicedbObjectDefault // Module-level permissions use default object
	return c.CheckPermission(ctx, tenantID, userID, objectType, objectID, permission)
}

// CheckRolePermission checks if user has a specific role-based permission.
func (c *Client) CheckRolePermission(ctx context.Context, tenantID, userID uuid.UUID, permission string) (bool, error) {
	// Role permissions are checked against the tenant object
	return c.CheckPermission(ctx, tenantID, userID, spicedbObjectTypeTenant, tenantID.String(), permission)
}

// CheckOutcome is the tri-state result of one SpiceDB check. Allowed is true
// only for PERMISSIONSHIP_HAS_PERMISSION. Conditional means a caveat could not
// be decided (required context was not supplied); MissingContext names the
// caveat parameters that were absent. Errored marks a per-item failure. Every
// non-Allowed outcome is a deny (fail closed); the extra fields only explain it.
type CheckOutcome struct {
	Allowed        bool
	Conditional    bool
	Errored        bool
	MissingContext []string
}

// outcomeFromPermissionship maps a SpiceDB permissionship (plus its optional
// partial-caveat info) to a CheckOutcome.
func outcomeFromPermissionship(p v1.CheckPermissionResponse_Permissionship, partial *v1.PartialCaveatInfo) CheckOutcome {
	switch p {
	case v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION:
		return CheckOutcome{Allowed: true}
	case v1.CheckPermissionResponse_PERMISSIONSHIP_CONDITIONAL_PERMISSION:
		return CheckOutcome{Conditional: true, MissingContext: partial.GetMissingRequiredContext()}
	default:
		return CheckOutcome{}
	}
}

// CheckBulkPermissions checks multiple objects of the same type in a single
// native SpiceDB CheckBulkPermissions gRPC call.
// Returns a map of objectID -> allowed.
func (c *Client) CheckBulkPermissions(
	ctx context.Context,
	tenantID, userID uuid.UUID,
	objectType string,
	objectIDs []string,
	permission string,
) (map[string]bool, error) {
	detailed, err := c.CheckBulkPermissionsDetailed(ctx, tenantID, userID, objectType, objectIDs, permission)
	if err != nil {
		return nil, err
	}
	results := make(map[string]bool, len(detailed))
	for id, o := range detailed {
		results[id] = o.Allowed
	}
	return results, nil
}

// CheckBulkPermissionsDetailed is CheckBulkPermissions that keeps the reason a
// check was not allowed (caveat undecided, per-item error) instead of
// collapsing it to false. Callers must still treat !Allowed as a deny.
func (c *Client) CheckBulkPermissionsDetailed(
	ctx context.Context,
	tenantID, userID uuid.UUID,
	objectType string,
	objectIDs []string,
	permission string,
) (map[string]CheckOutcome, error) {
	startTime := time.Now()

	if len(objectIDs) == 0 {
		return make(map[string]CheckOutcome), nil
	}

	// Build bulk request items
	items := make([]*v1.CheckBulkPermissionsRequestItem, len(objectIDs))
	for i, objID := range objectIDs {
		items[i] = c.newCheckBulkItem(
			&v1.ObjectReference{ObjectType: objectType, ObjectId: c.tenantScopedID(tenantID, objID)},
			&v1.ObjectReference{ObjectType: spicedbObjectTypeUser, ObjectId: c.tenantScopedID(tenantID, userID.String())},
			permission,
		)
	}

	var resp *v1.CheckBulkPermissionsResponse
	err := c.runRead(ctx, func(ctx context.Context) error {
		var e error
		resp, e = c.spicedb.CheckBulkPermissions(ctx, &v1.CheckBulkPermissionsRequest{
			Consistency: &v1.Consistency{
				Requirement: &v1.Consistency_MinimizeLatency{
					MinimizeLatency: true,
				},
			},
			Items: items,
		})
		return e
	})

	RecordBatchCheck(tenantID, len(objectIDs), time.Since(startTime))

	if err != nil {
		RecordError("check_bulk_permissions", "grpc_error")
		return nil, fmt.Errorf("CheckBulkPermissions: %w", err)
	}

	// Parse results — map objectID back to allowed/denied
	results := make(map[string]CheckOutcome, len(objectIDs))
	// Initialize all as denied (fail-closed default)
	for _, objID := range objectIDs {
		results[objID] = CheckOutcome{}
	}

	if resp != nil && resp.Pairs != nil {
		for i, pair := range resp.Pairs {
			if i >= len(objectIDs) {
				break
			}
			objID := objectIDs[i]

			switch r := pair.Response.(type) {
			case *v1.CheckBulkPermissionsPair_Item:
				results[objID] = outcomeFromPermissionship(r.Item.Permissionship, r.Item.PartialCaveatInfo)
			case *v1.CheckBulkPermissionsPair_Error:
				// Per-item error — fail-closed
				results[objID] = CheckOutcome{Errored: true}
				logger.Log.Warn("CheckBulkPermissions per-item error",
					zap.String("object_id", objID),
					zap.Int32("error_code", r.Error.GetCode()),
					zap.String("error_message", r.Error.GetMessage()),
				)
			}
		}
	}

	logger.Log.Debug("CheckBulkPermissions completed",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.Int("check_count", len(objectIDs)),
		zap.Duration("duration", time.Since(startTime)),
	)

	return results, nil
}

// PermissionCheck represents a single permission check request (legacy parallel API).
type PermissionCheck struct {
	TenantID   uuid.UUID
	UserID     uuid.UUID
	ObjectType string
	ObjectID   string
	Permission string
}

// WriteUserRole writes a standing (non-expiring) user-role relationship.
func (c *Client) WriteUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error) {
	return c.writeUserRole(ctx, tenantID, userID, roleID, nil)
}

// WriteUserRoleUntil writes a time-bound (JIT) user-role relationship carrying
// the active_elevation(now, expires_at) caveat, so the membership stops passing
// checks the instant expiresAt is reached, independent of the expiry sweeper.
func (c *Client) WriteUserRoleUntil(ctx context.Context, tenantID, userID, roleID uuid.UUID, expiresAt time.Time) (string, error) {
	return c.writeUserRole(ctx, tenantID, userID, roleID, &v1.ContextualizedCaveat{
		CaveatName: spicedbActiveElevationName,
		Context: &structpb.Struct{Fields: map[string]*structpb.Value{
			"expires_at": structpb.NewStringValue(expiresAt.UTC().Format(time.RFC3339)),
		}},
	})
}

func (c *Client) writeUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID, caveat *v1.ContextualizedCaveat) (string, error) {
	startTime := time.Now()

	resp, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{
			{
				Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: spicedbObjectTypeRole,
						ObjectId:   c.tenantScopedID(tenantID, roleID.String()),
					},
					Relation: "member",
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: spicedbObjectTypeUser,
							ObjectId:   c.tenantScopedID(tenantID, userID.String()),
						},
					},
					OptionalCaveat: caveat,
				},
			},
		},
	})
	if err != nil {
		RecordError("write_user_role", "grpc_error")
		return "", fmt.Errorf("failed to write user-role relationship: %w", err)
	}

	RecordRelationshipWrite(tenantID, "role", "member", "touch", time.Since(startTime))

	// Invalidate user's permission cache
	c.invalidateUserCache(ctx, tenantID, userID)

	token := ""
	if resp != nil && resp.WrittenAt != nil {
		token = resp.WrittenAt.Token
	}

	logger.Info("User role relationship written to SpiceDB",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.String("role_id", roleID.String()),
		zap.Bool("has_zed_token", token != ""),
	)

	return token, nil
}

// DeleteUserRole removes a user-role relationship.
func (c *Client) DeleteUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error) {
	startTime := time.Now()

	resp, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{
			{
				Operation: v1.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: spicedbObjectTypeRole,
						ObjectId:   c.tenantScopedID(tenantID, roleID.String()),
					},
					Relation: "member",
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: spicedbObjectTypeUser,
							ObjectId:   c.tenantScopedID(tenantID, userID.String()),
						},
					},
				},
			},
		},
	})
	if err != nil {
		RecordError("delete_user_role", "grpc_error")
		return "", fmt.Errorf("failed to delete user-role relationship: %w", err)
	}

	RecordRelationshipWrite(tenantID, "role", "member", "delete", time.Since(startTime))

	// Invalidate user's permission cache
	c.invalidateUserCache(ctx, tenantID, userID)

	token := ""
	if resp != nil && resp.WrittenAt != nil {
		token = resp.WrittenAt.Token
	}

	logger.Info("User role relationship deleted from SpiceDB",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.String("role_id", roleID.String()),
		zap.Bool("has_zed_token", token != ""),
	)

	return token, nil
}

// WriteRolePermission writes a role-permission relationship.
func (c *Client) WriteRolePermission(ctx context.Context, tenantID, roleID uuid.UUID, objectType, objectID, relation string) (string, error) {
	resp, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{
			{
				Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: objectType,
						ObjectId:   c.tenantScopedID(tenantID, objectID),
					},
					Relation: relation,
					Subject: &v1.SubjectReference{
						OptionalRelation: rolePermissionSubjectRelation(objectType, relation),
						Object: &v1.ObjectReference{
							ObjectType: spicedbObjectTypeRole,
							ObjectId:   c.tenantScopedID(tenantID, roleID.String()),
						},
					},
				},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to write role permission: %w", err)
	}

	// Invalidate role's permission cache
	c.invalidateRoleCache(ctx, tenantID, roleID)

	token := ""
	if resp != nil && resp.WrittenAt != nil {
		token = resp.WrittenAt.Token
	}
	return token, nil
}

// The narrow requester module relations take role#member, unlike access_grant's direct role subject.
func rolePermissionSubjectRelation(objectType, relation string) string {
	if objectType == "module" && (relation == "maintenance_request_creator" || relation == "maintenance_request_reader" || relation == "legal_entity_reader") {
		return "member"
	}
	return ""
}

// RolePermissionRelationship identifies one direct role grant in SpiceDB.
type RolePermissionRelationship struct {
	RoleID     uuid.UUID
	ObjectType string
	ObjectID   string
	Relation   string
}

// LookupTenantRolePermissions returns direct access-grant relationships for
// every role in a tenant, including roles since deleted from PostgreSQL.
func (c *Client) LookupTenantRolePermissions(ctx context.Context, tenantID uuid.UUID) ([]RolePermissionRelationship, error) {
	var relationships []RolePermissionRelationship
	for _, filter := range []struct{ objectType, relation string }{
		{"access_grant", "granted_to_role"},
		{"module", "maintenance_request_creator"},
		{"module", "maintenance_request_reader"},
		{"module", "legal_entity_reader"},
	} {
		stream, err := c.spicedb.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
			Consistency: &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
			RelationshipFilter: &v1.RelationshipFilter{
				ResourceType:             filter.objectType,
				OptionalResourceIdPrefix: tenantID.String() + "/",
				OptionalRelation:         filter.relation,
				OptionalSubjectFilter:    &v1.SubjectFilter{SubjectType: spicedbObjectTypeRole},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to read role permissions: %w", err)
		}

		for {
			resp, recvErr := stream.Recv()
			if recvErr == io.EOF {
				break
			}
			if recvErr != nil {
				return nil, fmt.Errorf("failed to receive role permissions: %w", recvErr)
			}
			roleID, parseErr := uuid.Parse(c.stripTenantPrefix(tenantID, resp.Relationship.Subject.Object.ObjectId))
			if parseErr != nil {
				return nil, fmt.Errorf("invalid tenant role subject %q: %w", resp.Relationship.Subject.Object.ObjectId, parseErr)
			}
			relationships = append(relationships, RolePermissionRelationship{
				RoleID:     roleID,
				ObjectType: resp.Relationship.Resource.ObjectType,
				ObjectID:   c.stripTenantPrefix(tenantID, resp.Relationship.Resource.ObjectId),
				Relation:   resp.Relationship.Relation,
			})
		}
	}
	return relationships, nil
}

// DeleteRolePermission removes one direct role grant from SpiceDB.
func (c *Client) DeleteRolePermission(ctx context.Context, tenantID, roleID uuid.UUID, objectType, objectID, relation string) (string, error) {
	resp, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{{
			Operation: v1.RelationshipUpdate_OPERATION_DELETE,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: objectType,
					ObjectId:   c.tenantScopedID(tenantID, objectID),
				},
				Relation: relation,
				Subject: &v1.SubjectReference{OptionalRelation: rolePermissionSubjectRelation(objectType, relation), Object: &v1.ObjectReference{
					ObjectType: spicedbObjectTypeRole,
					ObjectId:   c.tenantScopedID(tenantID, roleID.String()),
				}},
			},
		}},
	})
	if err != nil {
		return "", fmt.Errorf("failed to delete role permission: %w", err)
	}
	c.invalidateRoleCache(ctx, tenantID, roleID)
	token := ""
	if resp != nil && resp.WrittenAt != nil {
		token = resp.WrittenAt.Token
	}
	return token, nil
}

// WriteUserTenant establishes a user's membership in a tenant.
func (c *Client) WriteUserTenant(ctx context.Context, tenantID, userID uuid.UUID, relation string) (string, error) {
	if relation == "" {
		relation = "member"
	}

	resp, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{
			{
				Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: spicedbObjectTypeTenant,
						ObjectId:   tenantID.String(),
					},
					Relation: relation,
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: spicedbObjectTypeUser,
							ObjectId:   c.tenantScopedID(tenantID, userID.String()),
						},
					},
				},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to write user-tenant relationship: %w", err)
	}

	token := ""
	if resp != nil && resp.WrittenAt != nil {
		token = resp.WrittenAt.Token
	}
	return token, nil
}

// ReplaceUserTenant atomically removes obsolete direct tenant relations and,
// when relation is non-empty, touches the desired member or admin relation.
// LookupUserTenantRelation reports the tenant relation a user currently holds in
// SpiceDB — "admin", "member", or "" when the user holds neither.
//
// Exists so the reconciler can compare desired against actual BEFORE writing.
// ReplaceUserTenant below always issues TOUCH+DELETE unconditionally and returns
// only a zedToken, so it cannot report whether anything actually changed; without
// this read, a repair counter can only count users examined, not drift repaired.
//
// "admin" wins if both are somehow present. The two are mutually exclusive by
// construction (ReplaceUserTenant TOUCHes one and DELETEs the other), but if that
// invariant were ever broken, reporting the stronger relation stops the reconciler
// treating an over-privileged edge as already-correct and leaving it in place.
func (c *Client) LookupUserTenantRelation(ctx context.Context, tenantID, userID uuid.UUID) (string, error) {
	stream, err := c.spicedb.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		RelationshipFilter: &v1.RelationshipFilter{
			ResourceType:       spicedbObjectTypeTenant,
			OptionalResourceId: tenantID.String(),
			OptionalSubjectFilter: &v1.SubjectFilter{
				SubjectType:       spicedbObjectTypeUser,
				OptionalSubjectId: c.tenantScopedID(tenantID, userID.String()),
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to read user tenant membership: %w", err)
	}

	relation := ""
	for {
		resp, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			return "", fmt.Errorf("failed to receive user tenant membership: %w", recvErr)
		}
		switch resp.Relationship.Relation {
		case "admin":
			return "admin", nil
		case "member":
			relation = "member"
		}
	}
	return relation, nil
}

func (c *Client) ReplaceUserTenant(ctx context.Context, tenantID, userID uuid.UUID, relation string) (string, error) {
	updates := make([]*v1.RelationshipUpdate, 0, 2)
	for _, candidate := range []string{"member", "admin"} {
		operation := v1.RelationshipUpdate_OPERATION_DELETE
		if candidate == relation {
			operation = v1.RelationshipUpdate_OPERATION_TOUCH
		}
		updates = append(updates, &v1.RelationshipUpdate{
			Operation: operation,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{ObjectType: spicedbObjectTypeTenant, ObjectId: tenantID.String()},
				Relation: candidate,
				Subject: &v1.SubjectReference{Object: &v1.ObjectReference{
					ObjectType: spicedbObjectTypeUser,
					ObjectId:   c.tenantScopedID(tenantID, userID.String()),
				}},
			},
		})
	}
	resp, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: updates})
	if err != nil {
		return "", fmt.Errorf("failed to replace user-tenant relationship: %w", err)
	}
	c.invalidateUserCache(ctx, tenantID, userID)
	token := ""
	if resp != nil && resp.WrittenAt != nil {
		token = resp.WrittenAt.Token
	}
	return token, nil
}

// SetTenantGuest touches (present=true) or deletes (present=false) the
// tenant#guest relation of an external, seat-free member (an accountant
// invited from their own partner tenant). Deliberately separate from
// ReplaceUserTenant: guest is never folded into tenant view/manage, so it
// grants nothing on its own; access comes only from the member's read-only
// role grants.
func (c *Client) SetTenantGuest(ctx context.Context, tenantID, userID uuid.UUID, present bool) (string, error) {
	operation := v1.RelationshipUpdate_OPERATION_DELETE
	if present {
		operation = v1.RelationshipUpdate_OPERATION_TOUCH
	}
	resp, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: []*v1.RelationshipUpdate{{
		Operation: operation,
		Relationship: &v1.Relationship{
			Resource: &v1.ObjectReference{ObjectType: spicedbObjectTypeTenant, ObjectId: tenantID.String()},
			Relation: "guest",
			Subject: &v1.SubjectReference{Object: &v1.ObjectReference{
				ObjectType: spicedbObjectTypeUser,
				ObjectId:   c.tenantScopedID(tenantID, userID.String()),
			}},
		},
	}}})
	if err != nil {
		return "", fmt.Errorf("failed to write tenant guest relationship: %w", err)
	}
	c.invalidateUserCache(ctx, tenantID, userID)
	token := ""
	if resp != nil && resp.WrittenAt != nil {
		token = resp.WrittenAt.Token
	}
	return token, nil
}

// LookupUserRoles finds all roles assigned to a user.
func (c *Client) LookupUserRoles(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	stream, err := c.spicedb.LookupResources(ctx, c.newLookupResourcesRequest(
		&v1.Consistency{Requirement: &v1.Consistency_MinimizeLatency{MinimizeLatency: true}},
		spicedbObjectTypeRole,
		"member",
		&v1.ObjectReference{ObjectType: spicedbObjectTypeUser, ObjectId: c.tenantScopedID(tenantID, userID.String())},
	))
	if err != nil {
		return nil, fmt.Errorf("failed to lookup user roles: %w", err)
	}

	var roles []string
	for {
		resp, err := stream.Recv()
		if err != nil {
			// io.EOF means the stream ended normally - all results received
			if err.Error() == "EOF" || status.Code(err) == codes.OK {
				break
			}
			// Any other error means partial results - return error to caller
			c.incrementErrorCount()
			return nil, fmt.Errorf("error receiving user roles (got %d before failure): %w", len(roles), err)
		}
		// Strip tenant prefix
		roleID := c.stripTenantPrefix(tenantID, resp.ResourceObjectId)
		roles = append(roles, roleID)
	}

	return roles, nil
}

// GetUserPermissions returns all permissions a user has (for a specific object type).
func (c *Client) GetUserPermissions(ctx context.Context, tenantID, userID uuid.UUID, objectType, objectID string) ([]string, error) {
	// SpiceDB doesn't directly support "list all permissions"
	// We need to check each known permission individually
	// This is typically used for UI display, not authorization

	// Expanded permission list including common business permissions
	commonPermissions := []string{
		spicedbPermView, "edit", "delete", "create", "manage", "approve", "export",
		"submit", "archive", "transfer", "assign", "configure", "import", "publish",
	}
	var granted []string
	var checkErrors []error

	for _, perm := range commonPermissions {
		allowed, err := c.CheckPermission(ctx, tenantID, userID, objectType, objectID, perm)
		if err != nil {
			checkErrors = append(checkErrors, fmt.Errorf("permission %s: %w", perm, err))
			continue
		}
		if allowed {
			granted = append(granted, perm)
		}
	}

	// If all checks failed, return an error
	if len(checkErrors) == len(commonPermissions) {
		return granted, fmt.Errorf("all permission checks failed: first error: %w", checkErrors[0])
	}

	// If some checks failed but not all, log warning but return partial results
	if len(checkErrors) > 0 {
		logger.Warn("Some permission checks failed",
			zap.String("tenant_id", tenantID.String()),
			zap.String("user_id", userID.String()),
			zap.String("object_type", objectType),
			zap.String("object_id", objectID),
			zap.Int("failed_count", len(checkErrors)),
			zap.Int("total_count", len(commonPermissions)),
		)
	}

	return granted, nil
}

// Metrics returns client metrics.
func (c *Client) Metrics() ClientMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return ClientMetrics{
		CheckCount:  c.checkCount,
		CacheHits:   c.cacheHits,
		CacheMisses: c.cacheMisses,
		ErrorCount:  c.errorCount,
	}
}

// ClientMetrics contains SpiceDB client metrics.
type ClientMetrics struct {
	CheckCount  int64
	CacheHits   int64
	CacheMisses int64
	ErrorCount  int64
}

// Helper methods

func (c *Client) tenantScopedID(tenantID uuid.UUID, id string) string {
	return fmt.Sprintf("%s/%s", tenantID.String(), id)
}

func (c *Client) stripTenantPrefix(tenantID uuid.UUID, scopedID string) string {
	prefix := tenantID.String() + "/"
	if len(scopedID) > len(prefix) && scopedID[:len(prefix)] == prefix {
		return scopedID[len(prefix):]
	}
	return scopedID
}

func (c *Client) generateCacheKey(tenantID, userID uuid.UUID, objectType, objectID, permission string) string {
	return fmt.Sprintf("spicedb:check:%s:%s:%s:%s:%s", tenantID.String(), userID.String(), objectType, objectID, permission)
}

// generateRealmCacheKey returns a realm-scoped Redis cache key for a SpiceDB
// permission check result.  Adding the realm dimension prevents key collisions
// when identical (tenantID, userID, objectType, objectID, permission) tuples
// exist across multiple realms, and enables targeted per-realm cache
// invalidation without touching entries from other realms.
func (c *Client) generateRealmCacheKey(realmID, tenantID, userID uuid.UUID, objectType, objectID, permission string) string {
	return fmt.Sprintf("spicedb:realm:%s:check:%s:%s:%s:%s:%s",
		realmID.String(), tenantID.String(), userID.String(), objectType, objectID, permission)
}

func (c *Client) checkCache(ctx context.Context, key string) (bool, error) {
	val, err := c.redis.Get(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("checkCache: %w", err)
	}
	return val == "1", nil
}

func (c *Client) cacheResult(ctx context.Context, key string, allowed bool) error {
	val := "0"
	if allowed {
		val = "1"
	}
	return c.redis.Set(ctx, key, val, c.config.SpiceDBCacheTTL).Err()
}

func (c *Client) invalidateUserCache(ctx context.Context, tenantID, userID uuid.UUID) {
	if c.redis == nil {
		return
	}
	pattern := fmt.Sprintf("spicedb:check:%s:%s:*", tenantID.String(), userID.String())
	c.deleteByPattern(ctx, pattern)
}

// invalidateUserAllTenantsCache drops a user's cached checks in every tenant.
// Platform elevation (hxl_platform) is not tenant-scoped, so granting or
// revoking it can change the user's decision in any tenant.
func (c *Client) invalidateUserAllTenantsCache(ctx context.Context, userID uuid.UUID) {
	if c.redis == nil {
		return
	}
	c.deleteByPattern(ctx, fmt.Sprintf("spicedb:check:*:%s:*", userID.String()))
}

func (c *Client) invalidateRoleCache(ctx context.Context, tenantID, _ uuid.UUID) {
	if c.redis == nil {
		return
	}
	// Invalidate all permission checks for this tenant (role changes affect many users)
	pattern := fmt.Sprintf("spicedb:check:%s:*", tenantID.String())
	c.deleteByPattern(ctx, pattern)
}

func (c *Client) deleteByPattern(ctx context.Context, pattern string) {
	var keys []string
	iter := c.redis.Scan(ctx, 0, pattern, 100).Iterator()

	// Collect all keys first
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}

	// Check for scan errors
	if err := iter.Err(); err != nil {
		logger.Warn("Error during Redis SCAN operation",
			zap.Error(err),
			zap.String("pattern", pattern),
		)
		return
	}

	// Delete keys in batches using pipeline for better atomicity
	if len(keys) > 0 {
		pipe := c.redis.Pipeline()
		for _, key := range keys {
			pipe.Del(ctx, key)
		}

		if _, err := pipe.Exec(ctx); err != nil {
			logger.Warn("Error deleting keys by pattern",
				zap.Error(err),
				zap.String("pattern", pattern),
				zap.Int("key_count", len(keys)),
			)
		}
	}
}

func (c *Client) incrementCheckCount() {
	c.mu.Lock()
	c.checkCount++
	c.mu.Unlock()
}

func (c *Client) incrementCacheHits() {
	c.mu.Lock()
	c.cacheHits++
	c.mu.Unlock()
}

func (c *Client) incrementCacheMisses() {
	c.mu.Lock()
	c.cacheMisses++
	c.mu.Unlock()
}

func (c *Client) incrementErrorCount() {
	c.mu.Lock()
	c.errorCount++
	c.mu.Unlock()
}

// ConsistencyMode defines the consistency guarantee for a SpiceDB check.
type ConsistencyMode int

const (
	// ConsistencyMinimizeLatency uses SpiceDB's default minimize-latency mode.
	ConsistencyMinimizeLatency ConsistencyMode = iota
	// ConsistencyAtLeastAsFresh ensures the check is at least as fresh as the given ZedToken.
	ConsistencyAtLeastAsFresh
	// ConsistencyFullyConsistent forces a fully consistent check (linearizable).
	ConsistencyFullyConsistent
)

// LookupUserPermissions returns the list of permission names a user has across
// common resource types. This is a convenience wrapper that checks known permissions
// and returns those that are granted.
func (c *Client) LookupUserPermissions(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	// SpiceDB does not natively support "list all permissions for a user" in a single call.
	// We use GetUserPermissions with the tenant object as a reasonable default.
	return c.GetUserPermissions(ctx, tenantID, userID, spicedbObjectTypeTenant, tenantID.String())
}

// CheckPermissionWithConsistency checks a permission with a specific consistency guarantee.
func (c *Client) CheckPermissionWithConsistency(
	ctx context.Context,
	tenantID, userID uuid.UUID,
	resourceType, resourceID, permission string,
	mode ConsistencyMode,
	zedToken string,
) (bool, error) {
	// Rate limiting
	select {
	case c.checkSem <- struct{}{}:
		defer func() { <-c.checkSem }()
	case <-ctx.Done():
		return false, ctx.Err()
	}

	c.incrementCheckCount()

	// Build consistency requirement based on mode
	var consistency *v1.Consistency
	switch mode {
	case ConsistencyAtLeastAsFresh:
		if zedToken != "" {
			consistency = &v1.Consistency{
				Requirement: &v1.Consistency_AtLeastAsFresh{
					AtLeastAsFresh: &v1.ZedToken{Token: zedToken},
				},
			}
		} else {
			consistency = &v1.Consistency{
				Requirement: &v1.Consistency_MinimizeLatency{MinimizeLatency: true},
			}
		}
	case ConsistencyFullyConsistent:
		consistency = &v1.Consistency{
			Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true},
		}
	default:
		consistency = &v1.Consistency{
			Requirement: &v1.Consistency_MinimizeLatency{MinimizeLatency: true},
		}
	}

	req := c.newCheckRequest(
		consistency,
		&v1.ObjectReference{ObjectType: resourceType, ObjectId: c.tenantScopedID(tenantID, resourceID)},
		&v1.ObjectReference{ObjectType: spicedbObjectTypeUser, ObjectId: c.tenantScopedID(tenantID, userID.String())},
		permission,
	)

	var resp *v1.CheckPermissionResponse
	err := c.runRead(ctx, func(ctx context.Context) error {
		var e error
		resp, e = c.spicedb.CheckPermission(ctx, req)
		return e
	})
	if err != nil {
		c.incrementErrorCount()
		return false, fmt.Errorf("permission check failed: %w", err)
	}

	return resp.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}

// CheckPermissionConsistent checks a permission with AtLeastAsFresh consistency using a ZedToken.
// This solves the New Enemy Problem: pass the ZedToken from a recent write to guarantee
// the check sees that write. Implements SpiceDBChecker interface method.
func (c *Client) CheckPermissionConsistent(
	ctx context.Context,
	tenantID, userID uuid.UUID,
	objectType, objectID, permission, zedToken string,
) (bool, error) {
	return c.CheckPermissionWithConsistency(
		ctx, tenantID, userID,
		objectType, objectID, permission,
		ConsistencyAtLeastAsFresh, zedToken,
	)
}

// WriteResourceRelationship writes a generic resource relationship to SpiceDB.
// Returns the ZedToken from the write for consistency tracking.
func (c *Client) WriteResourceRelationship(
	ctx context.Context,
	tenantID uuid.UUID,
	resourceType, resourceID, relation, subjectType, subjectID string,
) (string, error) {
	resp, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{
			{
				Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: resourceType,
						ObjectId:   c.tenantScopedID(tenantID, resourceID),
					},
					Relation: relation,
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: subjectType,
							ObjectId:   c.tenantScopedID(tenantID, subjectID),
						},
					},
				},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to write resource relationship: %w", err)
	}

	// Resource relationships can grant or revoke access for any user in the tenant.
	c.invalidateRoleCache(ctx, tenantID, uuid.Nil)

	token := ""
	if resp != nil && resp.WrittenAt != nil {
		token = resp.WrittenAt.Token
	}
	return token, nil
}

// WriteRelationship writes a single SpiceDB relationship using pre-formatted,
// fully-qualified object and subject IDs. Unlike WriteResourceRelationship,
// no tenant-scoping is applied; callers are responsible for embedding tenant
// context in the IDs themselves (e.g. via denyGrantObjectID).
//
// This method satisfies the DenyGrantWriter interface.
func (c *Client) WriteRelationship(
	ctx context.Context,
	objectType, objectID, relation, subjectType, subjectID string,
) (string, error) {
	resp, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{
			{
				Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: objectType,
						ObjectId:   objectID,
					},
					Relation: relation,
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: subjectType,
							ObjectId:   subjectID,
						},
					},
				},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to write relationship: %w", err)
	}

	token := ""
	if resp != nil && resp.WrittenAt != nil {
		token = resp.WrittenAt.Token
	}
	return token, nil
}

// DeleteRelationship deletes a single SpiceDB relationship using pre-formatted,
// fully-qualified object and subject IDs. No tenant-scoping is applied.
//
// This method satisfies the DenyGrantWriter interface.
func (c *Client) DeleteRelationship(
	ctx context.Context,
	objectType, objectID, relation, subjectType, subjectID string,
) error {
	_, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{
			{
				Operation: v1.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: objectType,
						ObjectId:   objectID,
					},
					Relation: relation,
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: subjectType,
							ObjectId:   subjectID,
						},
					},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete relationship: %w", err)
	}
	return nil
}

// DeleteResourceRelationship deletes a generic resource relationship from SpiceDB.
func (c *Client) DeleteResourceRelationship(
	ctx context.Context,
	tenantID uuid.UUID,
	resourceType, resourceID, relation, subjectType, subjectID string,
) error {
	_, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{
			{
				Operation: v1.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: resourceType,
						ObjectId:   c.tenantScopedID(tenantID, resourceID),
					},
					Relation: relation,
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: subjectType,
							ObjectId:   c.tenantScopedID(tenantID, subjectID),
						},
					},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete resource relationship: %w", err)
	}
	c.invalidateRoleCache(ctx, tenantID, uuid.Nil)
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/authorization"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

// tenantPerReconcileTimeout caps the time spent reconciling a single tenant.
// A stalled SpiceDB write should not block the entire scheduler goroutine.
const tenantPerReconcileTimeout = 30 * time.Second

// reconcilerStartupDelay matches the pattern in ADSyncService: wait 60 s after
// startup before the first run so that all dependent services are fully ready.
const reconcilerStartupDelay = 60 * time.Second

// ReconcileStats holds aggregate metrics for a single reconciliation pass.
type ReconcileStats struct {
	TenantsProcessed      int
	UserTenantRepairs     int
	UserRoleRepairs       int
	RolePermissionRepairs int
	Errors                int
	StartedAt             time.Time
	CompletedAt           time.Time
}

// SpiceDBReconciler periodically compares PostgreSQL IAM state with the
// relationships stored in SpiceDB and writes any missing entries using
// idempotent TOUCH operations.
//
// Design invariants:
//   - All SpiceDB writes are TOUCH (idempotent): re-writing an existing
//     relationship is a safe no-op.
//   - One tenant failure never aborts the whole pass: errors are counted and
//     logged, then the loop continues.
//   - Per-tenant work is bounded by tenantPerReconcileTimeout.
type SpiceDBReconciler struct {
	client *spicedb.Client
	db     *pgxpool.Pool
	config *config.Config

	stopChan chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	cancel   context.CancelFunc

	// lastRun* fields are protected by mu and expose metrics via Stats().
	mu              sync.RWMutex
	lastRunTime     time.Time
	lastRunDuration time.Duration
	lastRunStats    ReconcileStats
}

// NewSpiceDBReconciler constructs a SpiceDBReconciler.
// The caller is responsible for calling StartScheduler when the service is
// ready to begin work, and StopScheduler during graceful shutdown.
func NewSpiceDBReconciler(
	client *spicedb.Client,
	db *pgxpool.Pool,
	cfg *config.Config,
) *SpiceDBReconciler {
	return &SpiceDBReconciler{
		client:   client,
		db:       db,
		config:   cfg,
		stopChan: make(chan struct{}),
	}
}

// StartScheduler launches the background reconciliation loop.  It returns
// immediately; all work is done in a managed goroutine.
//
// The scheduler respects cfg.SpiceDBReconcilerEnabled: if the feature flag is
// off it logs and returns without starting anything.
func (r *SpiceDBReconciler) StartScheduler(ctx context.Context) {
	if !r.config.SpiceDBReconcilerEnabled {
		logger.Info("SpiceDB reconciler scheduler disabled by configuration")
		return
	}

	interval := r.config.SpiceDBReconcilerInterval
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	logger.Info("Starting SpiceDB reconciler scheduler",
		zap.Duration("interval", interval),
		zap.Duration("startup_delay", reconcilerStartupDelay),
	)
	schedulerCtx, cancel := context.WithCancel(ctx)
	r.mu.Lock()
	r.cancel = cancel
	r.mu.Unlock()

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		// Honour startup delay so downstream services have time to initialise.
		select {
		case <-time.After(reconcilerStartupDelay):
			r.runReconcile(schedulerCtx)
		case <-r.stopChan:
			return
		case <-schedulerCtx.Done():
			return
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				r.runReconcile(schedulerCtx)
			case <-r.stopChan:
				logger.Info("SpiceDB reconciler scheduler stopped")
				return
			case <-schedulerCtx.Done():
				logger.Info("SpiceDB reconciler scheduler context cancelled")
				return
			}
		}
	}()
}

// StopScheduler signals the background goroutine to stop and waits for it to
// exit.  Safe to call multiple times.
func (r *SpiceDBReconciler) StopScheduler() {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		if r.cancel != nil {
			r.cancel()
		}
		r.mu.Unlock()
		close(r.stopChan)
	})
	r.wg.Wait()
	logger.Info("SpiceDB reconciler scheduler shutdown complete")
}

// Stats returns a snapshot of the most recent reconciliation pass.  The
// returned struct is a value copy so it is safe for the caller to read without
// additional synchronisation.
func (r *SpiceDBReconciler) Stats() ReconcileStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastRunStats
}

// runReconcile is the internal wrapper invoked by the scheduler goroutine.  It
// records timing metadata and delegates to Reconcile.
func (r *SpiceDBReconciler) runReconcile(ctx context.Context) {
	logger.Info("Running SpiceDB reconciliation pass")

	stats, err := r.Reconcile(ctx)
	if err != nil {
		logger.Warn("SpiceDB reconciliation pass returned an error",
			zap.Error(err),
		)
	}

	if stats != nil {
		r.mu.Lock()
		r.lastRunTime = stats.CompletedAt
		r.lastRunDuration = stats.CompletedAt.Sub(stats.StartedAt)
		r.lastRunStats = *stats
		r.mu.Unlock()

		logger.Info("SpiceDB reconciliation pass completed",
			zap.Int("tenants_processed", stats.TenantsProcessed),
			zap.Int("user_tenant_repairs", stats.UserTenantRepairs),
			zap.Int("user_role_repairs", stats.UserRoleRepairs),
			zap.Int("role_permission_repairs", stats.RolePermissionRepairs),
			zap.Int("errors", stats.Errors),
			zap.Duration("duration", r.lastRunDuration),
		)
	}
}

// Reconcile performs a full reconciliation pass: it iterates over every active
// tenant and calls the three sub-reconcilers in sequence.
//
// The method is exported so that operators can trigger an ad-hoc pass via an
// admin endpoint without waiting for the scheduler.
func (r *SpiceDBReconciler) Reconcile(ctx context.Context) (*ReconcileStats, error) {
	if r.db == nil {
		return nil, fmt.Errorf("reconcile: database pool not initialized")
	}

	stats := &ReconcileStats{
		StartedAt: time.Now(),
	}

	tenants, err := r.queryActiveTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("reconcile: list active tenants: %w", err)
	}

	for _, tenantID := range tenants {
		tenantCtx, cancel := context.WithTimeout(ctx, tenantPerReconcileTimeout)

		err := r.reconcileTenant(tenantCtx, tenantID, stats)
		cancel()

		if err != nil {
			// One tenant failure must not abort the rest of the pass.
			logger.Warn("SpiceDB reconciliation failed for tenant",
				zap.String("tenant_id", tenantID.String()),
				zap.Error(err),
			)
			stats.Errors++
			continue
		}

		stats.TenantsProcessed++
	}

	stats.CompletedAt = time.Now()
	return stats, nil
}

// reconcileTenant runs all three relationship types for a single tenant.
// Partial failures in one sub-reconciler are propagated so the caller can
// count them; the tenant still counts as "processed with errors".
func (r *SpiceDBReconciler) reconcileTenant(ctx context.Context, tenantID uuid.UUID, stats *ReconcileStats) error {
	logger.Debug("Reconciling tenant",
		zap.String("tenant_id", tenantID.String()),
	)

	var firstErr error

	if err := r.reconcileUserTenantMemberships(ctx, tenantID, stats); err != nil {
		logger.Warn("reconcileUserTenantMemberships failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		stats.Errors++
		firstErr = err
	}

	if err := r.reconcileUserRoles(ctx, tenantID, stats); err != nil {
		logger.Warn("reconcileUserRoles failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		stats.Errors++
		if firstErr == nil {
			firstErr = err
		}
	}

	if err := r.reconcileRolePermissions(ctx, tenantID, stats); err != nil {
		logger.Warn("reconcileRolePermissions failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		stats.Errors++
		if firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// ----------------------------------------------------------------------------
// Database helpers
// ----------------------------------------------------------------------------

// queryActiveTenants returns the IDs of all non-deleted tenants.
func (r *SpiceDBReconciler) queryActiveTenants(ctx context.Context) ([]uuid.UUID, error) {
	const q = `
		SELECT id
		FROM iam_tenants
		WHERE status != 'deleted'
		ORDER BY id`

	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("queryActiveTenants: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("queryActiveTenants scan: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("queryActiveTenants rows: %w", err)
	}
	return ids, nil
}

// ----------------------------------------------------------------------------
// Sub-reconcilers
// ----------------------------------------------------------------------------

// reconcileUserTenantMemberships makes each known user's direct tenant
// relation match PostgreSQL. Inactive users lose both member and admin edges.
func (r *SpiceDBReconciler) reconcileUserTenantMemberships(
	ctx context.Context,
	tenantID uuid.UUID,
	stats *ReconcileStats,
) error {
	const q = `
		SELECT u.id, u.is_active,
		       EXISTS (
			           SELECT 1 FROM iam_user_roles ur
			           JOIN iam_roles r ON r.id = ur.role_id
			            AND r.tenant_id = u.tenant_id
			           WHERE ur.user_id = u.id
			             AND lower(r.name) = ANY($2::text[])
			             AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
		       ) AS is_admin
		FROM iam_users u
		WHERE u.tenant_id = $1`

	rows, err := r.db.Query(ctx, q, tenantID, authorization.TenantAdministratorRoleNames())
	if err != nil {
		return fmt.Errorf("reconcileUserTenantMemberships query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			userID  uuid.UUID
			active  bool
			isAdmin bool
		)
		if err := rows.Scan(&userID, &active, &isAdmin); err != nil {
			return fmt.Errorf("reconcileUserTenantMemberships scan: %w", err)
		}

		relation := ""
		if active {
			relation = "member"
			if isAdmin {
				relation = roleNameAdmin
			}
		}
		// Compare against SpiceDB before writing, so UserTenantRepairs counts
		// DRIFT REPAIRED rather than users examined. ReplaceUserTenant always
		// issues TOUCH+DELETE and returns only a zedToken, so an unconditional
		// write-and-increment made this counter a constant equal to the tenant's
		// user count -- it could never signal drift, and every pass looked like
		// it had found problems. Matches reconcileUserRoles and
		// reconcileRolePermissions below, which already diff before writing.
		//
		// A failed lookup is NOT treated as "no relation": that would turn a
		// transient read error into a spurious repair. Fall back to writing
		// unconditionally (the previous behaviour) and count it, because the
		// desired state still needs asserting -- we simply cannot prove whether
		// it was drift.
		current, lookupErr := r.client.LookupUserTenantRelation(ctx, tenantID, userID)
		if lookupErr == nil && current == relation {
			logger.Debug("User-tenant membership already correct in SpiceDB",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", userID.String()),
				zap.String("relation", relation),
			)
			continue
		}
		if lookupErr != nil {
			logger.Warn("Failed to read user-tenant membership before repair; writing unconditionally",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", userID.String()),
				zap.Error(lookupErr),
			)
		}

		if _, err := r.client.ReplaceUserTenant(ctx, tenantID, userID, relation); err != nil {
			logger.Warn("Failed to reconcile user-tenant membership in SpiceDB",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", userID.String()),
				zap.Bool("active", active),
				zap.Error(err),
			)
			stats.Errors++
			continue
		}
		logger.Debug("Reconciled user-tenant membership in SpiceDB",
			zap.String("tenant_id", tenantID.String()),
			zap.String("user_id", userID.String()),
			zap.String("from_relation", current),
			zap.String("relation", relation),
		)
		stats.UserTenantRepairs++
	}

	return rows.Err()
}

// reconcileUserRoles makes every known user's SpiceDB role set match active
// PostgreSQL assignments exactly, including stale-edge removal and inactive
// users with no desired grants.
func (r *SpiceDBReconciler) reconcileUserRoles(
	ctx context.Context,
	tenantID uuid.UUID,
	stats *ReconcileStats,
) error {
	const q = `
		SELECT u.id, u.is_active, role.id
		FROM iam_users u
		LEFT JOIN iam_user_roles ur
		  ON ur.user_id = u.id
		 AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
		LEFT JOIN iam_roles role
		  ON role.id = ur.role_id
		 AND role.tenant_id = $1
		WHERE u.tenant_id = $1
		ORDER BY u.id, role.id`

	rows, err := r.db.Query(ctx, q, tenantID)
	if err != nil {
		return fmt.Errorf("reconcileUserRoles query: %w", err)
	}
	defer rows.Close()

	type userRoleState struct {
		active  bool
		desired map[uuid.UUID]struct{}
	}
	states := make(map[uuid.UUID]*userRoleState)
	for rows.Next() {
		var (
			userID uuid.UUID
			active bool
			roleID *uuid.UUID
		)
		if err := rows.Scan(&userID, &active, &roleID); err != nil {
			return fmt.Errorf("reconcileUserRoles scan: %w", err)
		}
		state := states[userID]
		if state == nil {
			state = &userRoleState{active: active, desired: make(map[uuid.UUID]struct{})}
			states[userID] = state
		}
		if active && roleID != nil {
			state.desired[*roleID] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	for userID, state := range states {
		actual, err := r.client.LookupUserRoles(ctx, tenantID, userID)
		if err != nil {
			logger.Warn("Failed to lookup user roles in SpiceDB",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
			stats.Errors++
			continue
		}
		actualSet := make(map[uuid.UUID]struct{}, len(actual))
		for _, rawRoleID := range actual {
			roleID, parseErr := uuid.Parse(rawRoleID)
			if parseErr != nil {
				logger.Warn("Ignoring malformed SpiceDB role id", zap.String("role_id", rawRoleID), zap.Error(parseErr))
				stats.Errors++
				continue
			}
			actualSet[roleID] = struct{}{}
			if _, keep := state.desired[roleID]; keep {
				continue
			}
			if _, err := r.client.DeleteUserRole(ctx, tenantID, userID, roleID); err != nil {
				logger.Warn("Failed to remove stale user-role assignment from SpiceDB", zap.Error(err))
				stats.Errors++
				continue
			}
			stats.UserRoleRepairs++
		}
		for roleID := range state.desired {
			if _, exists := actualSet[roleID]; exists {
				continue
			}
			if _, err := r.client.WriteUserRole(ctx, tenantID, userID, roleID); err != nil {
				logger.Warn("Failed to repair user-role assignment in SpiceDB", zap.Error(err))
				stats.Errors++
				continue
			}
			stats.UserRoleRepairs++
		}
	}
	return nil
}

// reconcileRolePermissions makes each tenant role's direct access grants match
// PostgreSQL exactly, including removal of permissions that were revoked.
func (r *SpiceDBReconciler) reconcileRolePermissions(
	ctx context.Context,
	tenantID uuid.UUID,
	stats *ReconcileStats,
) error {
	const q = `
		SELECT r.id, p.name
		FROM iam_roles r
		LEFT JOIN iam_role_permissions rp ON rp.role_id = r.id
		LEFT JOIN iam_permissions p ON p.id = rp.permission_id
		WHERE r.tenant_id = $1
		ORDER BY r.id, p.name`

	rows, err := r.db.Query(ctx, q, tenantID)
	if err != nil {
		return fmt.Errorf("reconcileRolePermissions query: %w", err)
	}
	defer rows.Close()

	type permissionEdge struct {
		objectType string
		objectID   string
		relation   string
	}
	desiredByRole := make(map[uuid.UUID]map[permissionEdge]struct{})
	for rows.Next() {
		var (
			roleID         uuid.UUID
			permissionName *string
		)
		if err := rows.Scan(&roleID, &permissionName); err != nil {
			return fmt.Errorf("reconcileRolePermissions scan: %w", err)
		}
		desired := desiredByRole[roleID]
		if desired == nil {
			desired = make(map[permissionEdge]struct{})
			desiredByRole[roleID] = desired
		}
		if permissionName == nil {
			continue
		}

		// Expand wildcard permissions (e.g. "core:users:*") into concrete
		// permission names from the iam_permissions table.
		permNames, expandErr := r.expandPermission(ctx, *permissionName)
		if expandErr != nil {
			return fmt.Errorf("expand permission %q for role %s: %w", *permissionName, roleID, expandErr)
		}

		for _, pName := range permNames {
			objectType, objectID, relation, err := parsePermissionName(pName, roleID)
			if err != nil {
				logger.Warn("Cannot derive SpiceDB relationship from permission name",
					zap.String("tenant_id", tenantID.String()),
					zap.String("role_id", roleID.String()),
					zap.String("permission_name", pName),
					zap.Error(err),
				)
				stats.Errors++
				continue
			}

			desired[permissionEdge{objectType: objectType, objectID: objectID, relation: relation}] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	actual, err := r.client.LookupTenantRolePermissions(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("read tenant role-permission relationships: %w", err)
	}
	actualByRole := make(map[uuid.UUID]map[permissionEdge]struct{})
	for _, relationship := range actual {
		actualSet := actualByRole[relationship.RoleID]
		if actualSet == nil {
			actualSet = make(map[permissionEdge]struct{})
			actualByRole[relationship.RoleID] = actualSet
		}
		edge := permissionEdge{objectType: relationship.ObjectType, objectID: relationship.ObjectID, relation: relationship.Relation}
		actualSet[edge] = struct{}{}
		if _, keep := desiredByRole[relationship.RoleID][edge]; keep {
			continue
		}
		if _, err := r.client.DeleteRolePermission(ctx, tenantID, relationship.RoleID, edge.objectType, edge.objectID, edge.relation); err != nil {
			logger.Warn("Failed to remove stale role-permission relationship from SpiceDB",
				zap.String("tenant_id", tenantID.String()), zap.String("role_id", relationship.RoleID.String()), zap.Error(err))
			stats.Errors++
			continue
		}
		stats.RolePermissionRepairs++
	}
	for roleID, desired := range desiredByRole {
		actualSet := actualByRole[roleID]
		for edge := range desired {
			if _, exists := actualSet[edge]; exists {
				continue
			}
			if _, err := r.client.WriteRolePermission(ctx, tenantID, roleID, edge.objectType, edge.objectID, edge.relation); err != nil {
				logger.Warn("Failed to write role-permission relationship to SpiceDB",
					zap.String("tenant_id", tenantID.String()), zap.String("role_id", roleID.String()), zap.Error(err))
				stats.Errors++
				continue
			}
			stats.RolePermissionRepairs++
		}
	}
	return nil
}

// expandPermission returns the concrete permission names for a given permission.
// Non-wildcard permissions are returned as-is in a single-element slice.
// Wildcard permissions (e.g. "core:users:*") are expanded by querying
// iam_permissions for all entries that match the module:resource prefix.
func (r *SpiceDBReconciler) expandPermission(ctx context.Context, name string) ([]string, error) {
	if !strings.Contains(name, ":*") && !strings.HasSuffix(name, "*") {
		return []string{name}, nil
	}

	// "core:users:*" → prefix "core:users:"
	prefix := strings.TrimSuffix(name, "*")
	if prefix == "" {
		return nil, fmt.Errorf("cannot expand bare wildcard %q", name)
	}

	const q = `SELECT name FROM iam_permissions WHERE name LIKE $1 AND name NOT LIKE '%%:*'`
	rows, err := r.db.Query(ctx, q, prefix+"%")
	if err != nil {
		return nil, fmt.Errorf("expandPermission query: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("expandPermission scan: %w", err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("expandPermission rows: %w", err)
	}

	if len(names) == 0 {
		logger.Warn("Wildcard permission expanded to zero concrete permissions",
			zap.String("wildcard", name),
			zap.String("prefix", prefix),
		)
	} else {
		logger.Info("Expanded wildcard permission",
			zap.String("wildcard", name),
			zap.Int("expanded_count", len(names)),
		)
	}

	return names, nil
}

// ----------------------------------------------------------------------------
// Permission name parsing
// ----------------------------------------------------------------------------

// parsePermissionName converts an IAM permission name into the SpiceDB triple
// (objectType, objectID, relation) required by WriteRolePermission.
//
// All permission formats are mapped to the access_grant pattern, which matches
// the authorization engine's CheckPermission logic:
//
//	objectType = "access_grant"
//	objectID   = PermissionToSpiceDBID(name)   // colons → double underscores
//	relation   = "granted_to_role"
//
// This ensures the reconciler writes relationships that the authorization engine
// can find when checking permissions.
//
// Examples:
//
//	"crm:contacts:read"  → ("access_grant", "crm__contacts__read", "granted_to_role")
//	"invoice.view"       → ("access_grant", "invoice.view",        "granted_to_role")
//	"billing"            → ("access_grant", "billing",             "granted_to_role")
func parsePermissionName(name string, _ uuid.UUID) (objectType, objectID, relation string, err error) {
	if name == "" {
		return "", "", "", fmt.Errorf("empty permission name")
	}

	// Wildcard permissions (e.g. "platform:tenants:*") cannot be represented
	// as SpiceDB ObjectIds — the regex only allows standalone "*", not embedded.
	// Skip them; the authorization engine checks specific actions, not wildcards.
	if strings.Contains(name, ":*") || strings.HasSuffix(name, "*") {
		return "", "", "", fmt.Errorf("wildcard permission %q cannot be synced to SpiceDB", name)
	}

	objectType = "access_grant"
	objectID = spicedb.PermissionToSpiceDBID(name)
	relation = "granted_to_role"
	return objectType, objectID, relation, nil
}

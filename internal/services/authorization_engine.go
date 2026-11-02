// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/metrics"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

const reasonGrantedViaSpiceDB = "granted via SpiceDB"

// SunsetChecker looks up a single permission by its canonical name so the
// authorization engine can enforce sunset dates before querying SpiceDB.
//
// If the permission is not found in the database (nil, nil response) the engine
// skips the sunset guard and proceeds normally — a DB miss must never become an
// accidental deny.  If the lookup itself returns an error the engine also
// proceeds (fail-open for the sunset guard, because the fail-closed guarantee
// lives in SpiceDB).
type SunsetChecker interface {
	// GetPermissionByName looks up a permission by its canonical name
	// (e.g. "crm:contacts:read").  Returns (nil, nil) when not found.
	GetPermissionByName(ctx context.Context, name string) (*models.Permission, error)
}

// SpiceDBChecker defines the SpiceDB permission check interface used by the engine.
// This enables testing with mocks and decouples the engine from the concrete SpiceDB client.
type SpiceDBChecker interface {
	// CheckPermission uses MinimizeLatency consistency (eventual consistency).
	CheckPermission(ctx context.Context, tenantID, userID uuid.UUID, objectType, objectID, permission string) (bool, error)

	// CheckPermissionConsistent uses AtLeastAsFresh consistency with a ZedToken.
	// This solves the New Enemy Problem: after a relationship write, pass the
	// returned ZedToken to guarantee the check sees the write.
	CheckPermissionConsistent(ctx context.Context, tenantID, userID uuid.UUID, objectType, objectID, permission, zedToken string) (bool, error)

	// CheckBulkPermissions checks multiple objects of the same type in a single gRPC call.
	// Returns a map of objectID -> allowed. Uses native SpiceDB CheckBulkPermissions API.
	CheckBulkPermissions(ctx context.Context, tenantID, userID uuid.UUID, objectType string, objectIDs []string, permission string) (map[string]bool, error)
}

// PermissionRepositoryInterface defines the methods used by AuthorizationEngine.
// Only used for OPA context (providing role/permission data to OPA policies).
// Both methods require tenantID to enforce cross-tenant isolation at the DB layer.
type PermissionRepositoryInterface interface {
	GetUserPermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]models.Permission, error)
	GetUserRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error)
}

// OPAServiceInterface defines the methods used by AuthorizationEngine
type OPAServiceInterface interface {
	IsEnabled() bool
	EvaluatePermission(ctx context.Context, userID, tenantID uuid.UUID, username, email string, roles, permissions, groups []string, permission, resourceType, resourceID, ownerID string, resourceAttrs map[string]interface{}, ipAddress, userAgent, requestPath string) (*AuthzResult, error)
}

// AuditServiceInterface defines the methods used by AuthorizationEngine
type AuditServiceInterface interface {
	// Add methods as needed when audit service integration is implemented
}

// AuthorizationEngine provides a unified interface for all authorization decisions.
// SpiceDB is the sole authorization authority. OPA provides contextual policy evaluation.
type AuthorizationEngine interface {
	// CheckPermission - module-level permission (SpiceDB access_grant check)
	// Example: "crm:contacts:read"
	CheckPermission(ctx context.Context, req PermissionRequest) (*PermissionResult, error)

	// CheckResourcePermission - object-level permission (SpiceDB resource check)
	// Example: "Can user edit invoice #123?"
	CheckResourcePermission(ctx context.Context, req ResourcePermissionRequest) (*PermissionResult, error)

	// CheckContextualPermission - policy-based (OPA, with SpiceDB fallback when OPA disabled)
	// Example: "Can user approve PO over $5000?"
	CheckContextualPermission(ctx context.Context, req ContextualPermissionRequest) (*PermissionResult, error)

	// BatchCheckPermissions - for UI rendering (returns map of permission -> allowed)
	BatchCheckPermissions(ctx context.Context, userID, tenantID uuid.UUID, permissions []string) (map[string]bool, error)

	// CheckProductAccess - verifies a user can access a specific product instance
	// Checks platform_product_instance#use permission in SpiceDB
	CheckProductAccess(ctx context.Context, req ProductAccessRequest) (*PermissionResult, error)
}

// PermissionRequest represents a module-level permission check
type PermissionRequest struct {
	UserID     uuid.UUID
	TenantID   uuid.UUID
	Permission string // e.g., "crm:contacts:read"
	ZedToken   string // Optional: when set, uses AtLeastAsFresh consistency (New Enemy Problem)
}

// ResourcePermissionRequest represents an object-level permission check
type ResourcePermissionRequest struct {
	UserID       uuid.UUID
	TenantID     uuid.UUID
	ResourceType string // e.g., "invoice", "document", "contact"
	ResourceID   string
	Action       string // e.g., "view", "edit", "delete", "share"
	ZedToken     string // Optional: when set, uses AtLeastAsFresh consistency
}

// ProductAccessRequest represents a product instance access check.
// Verifies that the user's tenant is subscribed to the product and the instance is accessible.
type ProductAccessRequest struct {
	UserID     uuid.UUID
	TenantID   uuid.UUID
	InstanceID string // product instance UUID
	Action     string // "use", "admin", or "view" (defaults to "use")
}

// ContextualPermissionRequest represents a policy-based permission check
type ContextualPermissionRequest struct {
	UserID       uuid.UUID
	TenantID     uuid.UUID
	Action       string
	ResourceType string
	ResourceID   string
	Attributes   map[string]interface{} // e.g., {"amount": 5000}
	IPAddress    string
	UserAgent    string
	RequestPath  string
}

// PermissionResult represents the result of an authorization check
type PermissionResult struct {
	Allowed  bool
	Reason   string // reasonGrantedViaSpiceDB, "denied: not owner", etc.
	Source   string // "spicedb", "opa"
	CacheHit bool
}

// ModuleEntitlementChecker verifies whether a tenant's subscription includes
// a specific module. Used as a pre-check before SpiceDB authorization to
// enforce subscription-tier boundaries on module access.
//
// IsTenantEntitled must be safe for concurrent use. Errors are treated as
// fail-open (the engine proceeds to SpiceDB) — entitlement is an optimization,
// not the security boundary.
type ModuleEntitlementChecker interface {
	IsTenantEntitled(ctx context.Context, tenantID uuid.UUID, module string) (bool, error)
}

// UniversalModules are always included regardless of tenant subscription.
// Every tenant has access to core platform and IAM permissions.
var UniversalModules = []string{"core", "iam"}

// isUniversalModule reports whether module is exempt from module-entitlement
// checks (see UniversalModules). RoleService.getEntitledModules and
// PermissionService's equivalent module listing already special-case these
// two modules; the per-request entitlement guard in CheckPermission (and,
// via checkEntitlementDenial, BatchCheckPermissions) must agree with that
// same exemption or every "core:*"/"iam:*" permission gets silently denied
// for any tenant whose sole active product instance is a paid module (e.g.
// "acmeweb") that does not itself declare core/iam in its manifest.
func isUniversalModule(module string) bool {
	for _, m := range UniversalModules {
		if m == module {
			return true
		}
	}
	return false
}

// authorizationEngine is the concrete implementation of AuthorizationEngine.
// SpiceDB is the sole authorization authority — no RBAC/PostgreSQL fallback.
type authorizationEngine struct {
	permissionRepo     PermissionRepositoryInterface // only for OPA context input
	opaService         OPAServiceInterface
	auditService       AuditServiceInterface
	sessionCache       *redis.SessionCache
	spicedbClient      SpiceDBChecker
	sunsetChecker      SunsetChecker            // optional; nil means no sunset enforcement
	entitlementChecker ModuleEntitlementChecker // optional; nil means no entitlement check
	logger             *zap.Logger
	config             *config.Config

	// offline is the DDIL governed offline-authorization layer (P3.2). nil (or
	// a nil-valued *offlineAuthz) means strictly fail-closed on SpiceDB error —
	// the pre-DDIL behaviour. All its methods are nil-safe.
	offline *offlineAuthz

	// Metrics counters
	spicedbChecks int64
	opaChecks     int64
}

// SetModuleEntitlementChecker wires an optional module entitlement checker.
// When set, CheckPermission verifies the tenant's subscription includes the
// module before querying SpiceDB. Errors from the checker are fail-open.
func (e *authorizationEngine) SetModuleEntitlementChecker(checker ModuleEntitlementChecker) {
	e.entitlementChecker = checker
}

// SetEngineModuleEntitlementChecker wires a ModuleEntitlementChecker on an
// AuthorizationEngine. This is a package-level helper because the concrete
// type is unexported. No-op if the engine is not the concrete implementation.
func SetEngineModuleEntitlementChecker(engine AuthorizationEngine, checker ModuleEntitlementChecker) {
	if ae, ok := engine.(*authorizationEngine); ok {
		ae.SetModuleEntitlementChecker(checker)
	}
}

// EnableEngineOfflineAuthz wires DDIL governed offline authorization (P3.2)
// into the engine. When enabled in config, a successful module-level check is
// recorded as a signed, time-boxed decision, and a subsequent SpiceDB outage
// serves the last-known-good decision within budget before failing closed.
//
// roleVer supplies the per-tenant revocation epoch (pass the redis
// PermissionCache); nil is permitted but then offline revocation relies solely
// on the staleness budget. Returns an error only if the issuer keypair cannot
// be generated — the caller MUST then leave offline authz unwired (strict
// fail-closed) rather than proceed. No-op if engine is not the concrete type.
func EnableEngineOfflineAuthz(engine AuthorizationEngine, cfg *config.Config, roleVer RoleVersionProvider, logger *zap.Logger) error {
	ae, ok := engine.(*authorizationEngine)
	if !ok {
		return nil
	}
	o, err := newOfflineAuthz(cfg, roleVer, logger)
	if err != nil {
		return err
	}
	ae.offline = o
	return nil
}

// RevokeTenantOffline advances the tenant's known revocation epoch in the
// offline-authz layer, immediately voiding that tenant's cached decisions
// carrying an older epoch — even while SpiceDB is unreachable. Call it from the
// online role/permission invalidation path (the same place the per-tenant
// role-version counter is bumped). No-op when offline authz is disabled.
func (e *authorizationEngine) RevokeTenantOffline(tenantID uuid.UUID, version uint64) {
	e.offline.revokeTenant(tenantID, version)
}

// RevokeEngineTenantOffline is a package-level helper to reach
// RevokeTenantOffline on an AuthorizationEngine (concrete type is unexported).
func RevokeEngineTenantOffline(engine AuthorizationEngine, tenantID uuid.UUID, version uint64) {
	if ae, ok := engine.(*authorizationEngine); ok {
		ae.RevokeTenantOffline(tenantID, version)
	}
}

// NewAuthorizationEngine creates a new unified authorization engine.
// SpiceDB is the sole authorization authority.
//
// To enable sunset-permission enforcement, use NewAuthorizationEngineWithSunset.
func NewAuthorizationEngine(
	permissionRepo PermissionRepositoryInterface,
	opaService OPAServiceInterface,
	auditService AuditServiceInterface,
	sessionCache *redis.SessionCache,
	spicedbClient SpiceDBChecker,
	cfg *config.Config,
) AuthorizationEngine {
	return NewAuthorizationEngineWithSunset(permissionRepo, opaService, auditService, sessionCache, spicedbClient, cfg, nil)
}

// NewAuthorizationEngineWithSunset creates a new unified authorization engine
// and wires a SunsetChecker that is consulted before every module-level
// permission check.  Pass nil for sunsetChecker to disable sunset enforcement
// (equivalent to calling NewAuthorizationEngine).
func NewAuthorizationEngineWithSunset(
	permissionRepo PermissionRepositoryInterface,
	opaService OPAServiceInterface,
	auditService AuditServiceInterface,
	sessionCache *redis.SessionCache,
	spicedbClient SpiceDBChecker,
	cfg *config.Config,
	sunsetChecker SunsetChecker,
) AuthorizationEngine {
	log := logger.Log
	if log == nil {
		log = zap.NewNop()
	}

	return &authorizationEngine{
		permissionRepo: permissionRepo,
		opaService:     opaService,
		auditService:   auditService,
		sessionCache:   sessionCache,
		spicedbClient:  spicedbClient,
		sunsetChecker:  sunsetChecker,
		logger:         log,
		config:         cfg,
	}
}

// preSpiceDBDenial evaluates the sunset and module-entitlement guards that
// must deny a permission BEFORE SpiceDB is ever consulted. It is shared by
// CheckPermission (used by RequirePermission middleware) and
// BatchCheckPermissions (used by POST /authorize/batch) so the two
// authorities can never disagree about a permission's sunset/entitlement
// status the way they used to: CheckPermission applied these guards and
// BatchCheckPermissions skipped them entirely, so authorize/batch reported
// "allowed" for module:resource:action permissions RequirePermission denied
// outright — most visibly "iam:*"/"core:*" permissions, which are declared
// universal (UniversalModules) but were never exempted here, so ANY tenant
// whose only active product instance doesn't itself declare "core"/"iam" in
// its manifest (e.g. a AcmeWeb-only tenant) had every core/iam permission
// denied by CheckPermission while authorize/batch kept saying "true".
//
// Returns (denied, metricReason, message). The two guards below have
// deliberately different error-handling policies — see spec 23 §1.4:
//   - Sunset lookup errors are fail-OPEN (proceeds to SpiceDB): this guard is
//     a low-risk metadata optimization, not a security decision, so a DB miss
//     must never become an accidental deny.
//   - Module entitlement check errors are fail-CLOSED (denies): this guard is
//     security-relevant (it is the only thing standing between an
//     unentitled tenant and a SpiceDB relationship graph that may still say
//     "allowed"), so an entitlement-repo outage must not silently widen
//     access to every module.
func (e *authorizationEngine) preSpiceDBDenial(ctx context.Context, tenantID uuid.UUID, permission string) (bool, string, string) {
	// Sunset guard — permission has passed its sunset date (GAP 8).
	// A DB miss or lookup error must never become an accidental deny.
	// Kept intentionally fail-open per spec 23 §1.4 (deliberate, narrow,
	// low-risk: metadata lookup only, never the actual authz decision).
	if e.sunsetChecker != nil {
		perm, lookupErr := e.sunsetChecker.GetPermissionByName(ctx, permission)
		if lookupErr != nil {
			e.logger.Warn("sunset lookup failed, proceeding to SpiceDB",
				zap.Error(lookupErr),
				zap.String("permission", permission),
			)
		} else if perm != nil && perm.IsSunset() {
			e.logger.Info("permission is sunset, denying immediately",
				zap.String("permission", permission),
				zap.Timep("sunset_at", perm.SunsetAt),
			)
			return true, "permission_sunset", fmt.Sprintf("permission %q is sunset and no longer honoured", permission)
		}
	}

	// Module entitlement guard — tenant's subscription must include the
	// module associated with this permission (e.g. "crm" from
	// "crm:contacts:read"). Only applies to module:resource:action format
	// permissions, and never to UniversalModules (core, iam): every tenant
	// has those regardless of which paid product instances are active.
	//
	// Errors are fail-CLOSED (spec 23 §1.4): unlike the sunset lookup above,
	// this guard is a security-relevant gate, not a metadata optimization —
	// an entitlement-repo outage must never let SpiceDB decide alone,
	// because SpiceDB's relationship graph can still say "allowed" for a
	// tenant that was never entitled to the module in the first place.
	if e.entitlementChecker != nil {
		parts := strings.SplitN(permission, ":", 3)
		if len(parts) == 3 && !isUniversalModule(parts[0]) {
			module := parts[0]
			entitled, entErr := e.entitlementChecker.IsTenantEntitled(ctx, tenantID, module)
			if entErr != nil {
				e.logger.Warn("module entitlement check failed, denying access (fail-closed)",
					zap.Error(entErr),
					zap.String("tenant_id", tenantID.String()),
					zap.String("module", module),
					zap.String("permission", permission),
				)
				return true, "entitlement_check_unavailable", fmt.Sprintf("module entitlement check unavailable: %s", module)
			} else if !entitled {
				e.logger.Info("module not entitled, denying immediately",
					zap.String("module", module),
					zap.String("permission", permission),
					zap.String("tenant_id", tenantID.String()),
				)
				return true, "module_not_entitled", fmt.Sprintf("module not entitled: %s", module)
			}
		}
	}

	return false, "", ""
}

// CheckPermission checks module-level permissions via SpiceDB.
// Uses access_grant object type with the permission string as object ID.
func (e *authorizationEngine) CheckPermission(ctx context.Context, req PermissionRequest) (*PermissionResult, error) {
	startTime := time.Now()
	defer func() {
		metrics.AuthzCheckDuration.WithLabelValues("spicedb").Observe(time.Since(startTime).Seconds())
	}()

	atomic.AddInt64(&e.spicedbChecks, 1)

	if req.UserID == uuid.Nil {
		metrics.RecordAuthzCheck("spicedb", "denied", "module", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "user ID is required",
			Source:  "spicedb",
		}, nil
	}

	if req.Permission == "" {
		metrics.RecordAuthzCheck("spicedb", "denied", "module", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "permission is required",
			Source:  "spicedb",
		}, nil
	}

	// SpiceDB is required — fail-closed if unavailable
	if e.spicedbClient == nil {
		e.logger.Error("SpiceDB client is nil — denying access (fail-closed)")
		metrics.RecordAuthzCheck("spicedb", "error", "module", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "authorization denied: SpiceDB unavailable (fail-closed)",
			Source:  "spicedb",
		}, nil
	}

	// Sunset + module-entitlement guards — deny immediately, without
	// consulting SpiceDB, when either applies. See preSpiceDBDenial: this is
	// the SAME check BatchCheckPermissions runs per-permission, so the two
	// authorities agree on every permission that goes through either path.
	if denied, metricReason, message := e.preSpiceDBDenial(ctx, req.TenantID, req.Permission); denied {
		metrics.RecordAuthzCheck("spicedb", "denied", "module", time.Since(startTime).Seconds())
		metrics.RecordAuthzDenial(req.Permission, metricReason)
		return &PermissionResult{
			Allowed: false,
			Reason:  message,
			Source:  "spicedb",
		}, nil
	}

	// Check permission via SpiceDB
	// access_grant object type with permission name as ID, "check" as the permission
	// Translate colon-separated permission names to SpiceDB-safe format
	// When ZedToken is provided, use AtLeastAsFresh consistency (New Enemy Problem prevention)
	spicedbPermID := spicedb.PermissionToSpiceDBID(req.Permission)
	var allowed bool
	var err error
	if req.ZedToken != "" {
		allowed, err = e.spicedbClient.CheckPermissionConsistent(
			ctx, req.TenantID, req.UserID,
			"access_grant", spicedbPermID, "check", req.ZedToken,
		)
	} else {
		allowed, err = e.spicedbClient.CheckPermission(
			ctx, req.TenantID, req.UserID,
			"access_grant", spicedbPermID, "check",
		)
	}
	if err != nil {
		// SECURITY: Fail-closed on SpiceDB error — never fall back to RBAC/PostgreSQL.
		e.logger.Warn("SpiceDB permission check failed, denying access (fail-closed)",
			zap.Error(err),
			zap.String("permission", req.Permission),
			zap.String("user_id", req.UserID.String()),
			zap.Bool("has_zed_token", req.ZedToken != ""),
		)

		// DDIL P3.2: SpiceDB unreachable — before failing closed, attempt a
		// governed offline decision (signed, time-boxed last-known-good within
		// budget, revocation-epoch honoured). serve returns served=false unless
		// a still-valid cached decision exists, so this NEVER fails open.
		if offlineAllowed, served := e.offline.serve(ctx, req.TenantID, req.UserID, req.Permission); served {
			resultStr := "denied"
			if offlineAllowed {
				resultStr = "allowed"
			}
			e.logger.Warn("DDIL offline authz: served last-known-good decision (SpiceDB unreachable)",
				zap.String("permission", req.Permission),
				zap.String("user_id", req.UserID.String()),
				zap.Bool("allowed", offlineAllowed),
			)
			metrics.RecordAuthzCheck("spicedb-offline", resultStr, "module", time.Since(startTime).Seconds())
			return &PermissionResult{
				Allowed:  offlineAllowed,
				Reason:   "DDIL governed offline decision (last-known-good within budget; SpiceDB unreachable)",
				Source:   "spicedb-offline",
				CacheHit: true,
			}, nil
		}

		metrics.RecordAuthzCheck("spicedb", "error", "module", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "authorization denied: SpiceDB error (fail-closed)",
			Source:  "spicedb",
		}, nil
	}

	// DDIL P3.2: cache this fresh, signed decision (stamped with the tenant's
	// current revocation epoch) so it can be served within budget if SpiceDB
	// later becomes unreachable. No-op when offline authz is disabled.
	e.offline.record(ctx, req.TenantID, req.UserID, req.Permission, allowed)

	result := &PermissionResult{
		Allowed: allowed,
		Source:  "spicedb",
	}

	if allowed {
		result.Reason = reasonGrantedViaSpiceDB
		metrics.RecordAuthzCheck("spicedb", "allowed", "module", time.Since(startTime).Seconds())
		metrics.RecordSpiceDBCheck("allowed", time.Since(startTime).Seconds())
	} else {
		result.Reason = "permission denied by SpiceDB"
		metrics.RecordAuthzCheck("spicedb", "denied", "module", time.Since(startTime).Seconds())
		metrics.RecordAuthzDenial(req.Permission, "spicedb_denied")
		metrics.RecordSpiceDBCheck("denied", time.Since(startTime).Seconds())
	}

	e.logger.Debug("Permission check",
		zap.String("user_id", req.UserID.String()),
		zap.String("permission", req.Permission),
		zap.Bool("allowed", allowed),
		zap.String("source", "spicedb"),
	)

	return result, nil
}

// CheckResourcePermission checks object-level permissions via SpiceDB.
// SECURITY: Fail-closed on any error — RBAC cannot make resource-level decisions.
func (e *authorizationEngine) CheckResourcePermission(ctx context.Context, req ResourcePermissionRequest) (*PermissionResult, error) {
	startTime := time.Now()
	defer func() {
		metrics.AuthzCheckDuration.WithLabelValues("spicedb").Observe(time.Since(startTime).Seconds())
	}()

	atomic.AddInt64(&e.spicedbChecks, 1)

	if req.UserID == uuid.Nil {
		metrics.RecordAuthzCheck("spicedb", "denied", "resource", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "user ID is required",
			Source:  "spicedb",
		}, nil
	}

	if req.ResourceType == "" || req.ResourceID == "" || req.Action == "" {
		metrics.RecordAuthzCheck("spicedb", "denied", "resource", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "resource type, ID, and action are required",
			Source:  "spicedb",
		}, nil
	}

	// SpiceDB is required — fail-closed if unavailable
	if e.spicedbClient == nil {
		e.logger.Error("SpiceDB client is nil — denying resource access (fail-closed)")
		metrics.RecordAuthzCheck("spicedb", "error", "resource", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "authorization denied: SpiceDB unavailable for resource check (fail-closed)",
			Source:  "spicedb",
		}, nil
	}

	// SpiceDB resource-level check
	// When ZedToken is provided, use AtLeastAsFresh consistency (New Enemy Problem prevention)
	var allowed bool
	var err error
	if req.ZedToken != "" {
		allowed, err = e.spicedbClient.CheckPermissionConsistent(
			ctx, req.TenantID, req.UserID,
			req.ResourceType, req.ResourceID, req.Action, req.ZedToken,
		)
	} else {
		allowed, err = e.spicedbClient.CheckPermission(
			ctx, req.TenantID, req.UserID,
			req.ResourceType, req.ResourceID, req.Action,
		)
	}
	if err != nil {
		// SECURITY: Fail-closed for resource-level checks.
		// SpiceDB is the only authority that can evaluate resource ownership.
		e.logger.Warn("SpiceDB resource check failed, denying access (fail-closed)",
			zap.Error(err),
			zap.String("resource_type", req.ResourceType),
			zap.String("resource_id", req.ResourceID),
			zap.String("action", req.Action),
			zap.String("user_id", req.UserID.String()),
			zap.Bool("has_zed_token", req.ZedToken != ""),
		)
		metrics.RecordAuthzCheck("spicedb", "error", "resource", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "authorization denied: SpiceDB error for resource check (fail-closed)",
			Source:  "spicedb",
		}, nil
	}

	result := &PermissionResult{
		Allowed: allowed,
		Source:  "spicedb",
	}

	if allowed {
		result.Reason = reasonGrantedViaSpiceDB
		metrics.RecordAuthzCheck("spicedb", "allowed", "resource", time.Since(startTime).Seconds())
		metrics.RecordSpiceDBCheck("allowed", time.Since(startTime).Seconds())
	} else {
		result.Reason = "access denied: insufficient resource permissions"
		metrics.RecordAuthzCheck("spicedb", "denied", "resource", time.Since(startTime).Seconds())
		metrics.RecordAuthzDenial(req.ResourceType+":"+req.Action, "spicedb_denied")
		metrics.RecordSpiceDBCheck("denied", time.Since(startTime).Seconds())
	}

	e.logger.Debug("Resource permission check",
		zap.String("user_id", req.UserID.String()),
		zap.String("resource_type", req.ResourceType),
		zap.String("resource_id", req.ResourceID),
		zap.String("action", req.Action),
		zap.Bool("allowed", allowed),
		zap.String("source", "spicedb"),
	)

	return result, nil
}

// CheckContextualPermission checks policy-based permissions using OPA.
// When OPA is unavailable, falls back to SpiceDB module-level permission check.
func (e *authorizationEngine) CheckContextualPermission(ctx context.Context, req ContextualPermissionRequest) (*PermissionResult, error) {
	startTime := time.Now()
	defer func() {
		metrics.AuthzCheckDuration.WithLabelValues("opa").Observe(time.Since(startTime).Seconds())
	}()

	atomic.AddInt64(&e.opaChecks, 1)

	if req.UserID == uuid.Nil {
		metrics.RecordAuthzCheck("opa", "denied", "contextual", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "user ID is required",
			Source:  "opa",
		}, nil
	}

	// If OPA is not available or disabled, fall back to SpiceDB module-level check
	if e.opaService == nil || !e.opaService.IsEnabled() {
		return e.checkContextualFallbackSpiceDB(ctx, req, startTime)
	}

	// Get user's roles and permissions for OPA evaluation context.
	// tenantID is passed to enforce row-level isolation at the DB layer.
	roles, err := e.permissionRepo.GetUserRoles(ctx, req.UserID, req.TenantID)
	if err != nil {
		metrics.RecordAuthzCheck("opa", "error", "contextual", time.Since(startTime).Seconds())
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	perms, err := e.permissionRepo.GetUserPermissions(ctx, req.UserID, req.TenantID)
	if err != nil {
		metrics.RecordAuthzCheck("opa", "error", "contextual", time.Since(startTime).Seconds())
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	permNames := make([]string, len(perms))
	for i, p := range perms {
		permNames[i] = p.Name
	}

	// Evaluate with OPA
	opaStartTime := time.Now()
	result, err := e.opaService.EvaluatePermission(
		ctx,
		req.UserID,
		req.TenantID,
		"", "", // username, email - would need to fetch from user repo
		roles,
		permNames,
		nil, // groups
		req.Action,
		req.ResourceType,
		req.ResourceID,
		"", // ownerID
		req.Attributes,
		req.IPAddress,
		req.UserAgent,
		req.RequestPath,
	)

	opaDuration := time.Since(opaStartTime).Seconds()

	if err != nil {
		metrics.RecordOPAEvaluation("error", opaDuration)
		metrics.RecordAuthzCheck("opa", "error", "contextual", time.Since(startTime).Seconds())
		return nil, fmt.Errorf("OPA evaluation failed: %w", err)
	}

	// OPA is deny-only: it can withhold access but never grants it. An OPA
	// "allow" (no deny fired) still needs the ReBAC (SpiceDB) grant.
	if result.Allowed {
		rebac, rerr := e.checkContextualFallbackSpiceDB(ctx, req, startTime)
		if rerr != nil || rebac == nil || !rebac.Allowed {
			metrics.RecordOPAEvaluation("allowed", opaDuration)
			if rerr != nil {
				return nil, rerr
			}
			return rebac, nil
		}
	}

	permResult := &PermissionResult{
		Allowed: result.Allowed,
		Source:  "opa",
	}

	if result.Allowed {
		permResult.Reason = "granted via SpiceDB; no OPA deny"
		if len(result.Reasons) > 0 {
			permResult.Reason = fmt.Sprintf("granted via SpiceDB; OPA: %s", strings.Join(result.Reasons, "; "))
		}
		metrics.RecordOPAEvaluation("allowed", opaDuration)
		metrics.RecordAuthzCheck("opa", "allowed", "contextual", time.Since(startTime).Seconds())
	} else {
		permResult.Reason = "denied by OPA policy"
		if len(result.Reasons) > 0 {
			permResult.Reason = fmt.Sprintf("denied by OPA: %s", strings.Join(result.Reasons, "; "))
		}
		metrics.RecordOPAEvaluation("denied", opaDuration)
		metrics.RecordAuthzCheck("opa", "denied", "contextual", time.Since(startTime).Seconds())
		metrics.RecordAuthzDenial(req.Action, "opa_policy_denied")
	}

	e.logger.Debug("Contextual permission check",
		zap.String("user_id", req.UserID.String()),
		zap.String("action", req.Action),
		zap.String("resource_type", req.ResourceType),
		zap.Bool("allowed", result.Allowed),
		zap.String("source", "opa"),
		zap.Duration("duration", time.Since(startTime)),
	)

	return permResult, nil
}

// checkContextualFallbackSpiceDB handles the OPA-disabled case by falling back to SpiceDB.
func (e *authorizationEngine) checkContextualFallbackSpiceDB(ctx context.Context, req ContextualPermissionRequest, startTime time.Time) (*PermissionResult, error) { //nolint:unparam // error return is kept for interface consistency
	modulePermission := e.resourceToModulePermission(req.ResourceType, req.Action)

	if e.spicedbClient == nil {
		metrics.RecordAuthzCheck("spicedb", "error", "contextual", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "authorization denied: both OPA and SpiceDB unavailable (fail-closed)",
			Source:  "spicedb",
		}, nil
	}

	spicedbPermID := spicedb.PermissionToSpiceDBID(modulePermission)
	allowed, err := e.spicedbClient.CheckPermission(
		ctx, req.TenantID, req.UserID,
		"access_grant", spicedbPermID, "check",
	)
	if err != nil {
		e.logger.Warn("SpiceDB fallback check failed, denying access (fail-closed)",
			zap.Error(err),
			zap.String("permission", modulePermission),
			zap.String("user_id", req.UserID.String()),
		)
		metrics.RecordAuthzCheck("spicedb", "error", "contextual", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "authorization denied: SpiceDB fallback error (fail-closed)",
			Source:  "spicedb",
		}, nil
	}

	result := &PermissionResult{
		Allowed: allowed,
		Source:  "spicedb",
	}
	if allowed {
		result.Reason = "granted via SpiceDB (OPA unavailable)"
		metrics.RecordAuthzCheck("spicedb", "allowed", "contextual", time.Since(startTime).Seconds())
	} else {
		result.Reason = "denied by SpiceDB (OPA unavailable)"
		metrics.RecordAuthzCheck("spicedb", "denied", "contextual", time.Since(startTime).Seconds())
	}
	return result, nil
}

// BatchCheckPermissions checks multiple module-level permissions via SpiceDB
// using the native CheckBulkPermissions API (single gRPC call). It is the
// bool projection of BatchCheckDecisions.
func (e *authorizationEngine) BatchCheckPermissions(ctx context.Context, userID, tenantID uuid.UUID, permissions []string) (map[string]bool, error) {
	decisions, err := e.BatchCheckDecisions(ctx, userID, tenantID, permissions)
	if err != nil {
		return nil, err
	}
	results := make(map[string]bool, len(decisions))
	for perm, d := range decisions {
		results[perm] = d.Allowed
	}
	return results, nil
}

// detailedBulkChecker is the optional SpiceDBChecker extension that keeps why a
// bulk check was not allowed (undecided caveat, per-item error). *spicedb.Client
// implements it; test doubles that do not fall back to the bool API and every
// deny is then classified permission_denied.
type detailedBulkChecker interface {
	CheckBulkPermissionsDetailed(ctx context.Context, tenantID, userID uuid.UUID, objectType string, objectIDs []string, permission string) (map[string]spicedb.CheckOutcome, error)
}

// preDenialReason maps preSpiceDBDenial's metric reason to the API reason.
func preDenialReason(metricReason string) models.DecisionReason {
	switch metricReason {
	case "module_not_entitled":
		return models.DecisionReasonEntitlementMissing
	case "permission_sunset":
		return models.DecisionReasonPermissionSunset
	case "entitlement_check_unavailable":
		return models.DecisionReasonUnavailable
	default:
		return models.DecisionReasonUnknown
	}
}

// BatchCheckDecisions is BatchCheckPermissions with the reason for every deny
// (spec 23 §7 authorize/batch). The verdicts are identical to
// BatchCheckPermissions; only the explanation is added. Fail-closed throughout:
// a dependency failure denies with DecisionReasonUnavailable.
func (e *authorizationEngine) BatchCheckDecisions(ctx context.Context, userID, tenantID uuid.UUID, permissions []string) (map[string]models.PermissionDecision, error) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime).Seconds()
		metrics.AuthzCheckDuration.WithLabelValues("batch").Observe(duration)
		metrics.RecordAuthzBatchCheck("spicedb", len(permissions))
	}()

	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}

	if len(permissions) == 0 {
		return make(map[string]models.PermissionDecision), nil
	}

	results := make(map[string]models.PermissionDecision, len(permissions))
	denyAll := func(perms []string, reason models.DecisionReason) {
		for _, perm := range perms {
			results[perm] = models.PermissionDecision{Reason: reason}
		}
	}

	// Apply the SAME sunset + module-entitlement guards CheckPermission
	// applies, permission by permission, BEFORE consulting SpiceDB. Without
	// this, authorize/batch reported a permission as allowed whenever
	// SpiceDB held the access_grant relationship, even when RequirePermission
	// (via CheckPermission) would deny it as sunset or not-entitled — the
	// divergence that broke Settings -> Team for tenants entitled only to a
	// non-core/iam product. Permissions denied here never reach SpiceDB;
	// everything else still goes through the bulk call below unchanged.
	spicedbPermissions := make([]string, 0, len(permissions))
	for _, perm := range permissions {
		if denied, metricReason, _ := e.preSpiceDBDenial(ctx, tenantID, perm); denied {
			d := models.PermissionDecision{Reason: preDenialReason(metricReason)}
			if d.Reason == models.DecisionReasonEntitlementMissing {
				d.Module = strings.SplitN(perm, ":", 2)[0]
			}
			results[perm] = d
			continue
		}
		spicedbPermissions = append(spicedbPermissions, perm)
	}

	if len(spicedbPermissions) == 0 {
		return results, nil
	}

	// SpiceDB is required — if nil, deny all remaining (fail-closed)
	if e.spicedbClient == nil {
		e.logger.Error("SpiceDB client is nil — denying all batch permissions (fail-closed)")
		denyAll(spicedbPermissions, models.DecisionReasonUnavailable)
		return results, nil
	}

	// Translate permission names to SpiceDB-safe IDs for the bulk check
	spicedbIDs := make([]string, len(spicedbPermissions))
	spicedbToOriginal := make(map[string]string, len(spicedbPermissions))
	for i, perm := range spicedbPermissions {
		sid := spicedb.PermissionToSpiceDBID(perm)
		spicedbIDs[i] = sid
		spicedbToOriginal[sid] = perm
	}

	// Native CheckBulkPermissions — single gRPC call for all remaining permissions
	var outcomes map[string]spicedb.CheckOutcome
	var err error
	if dc, ok := e.spicedbClient.(detailedBulkChecker); ok {
		outcomes, err = dc.CheckBulkPermissionsDetailed(ctx, tenantID, userID, "access_grant", spicedbIDs, "check")
	} else {
		var plain map[string]bool
		plain, err = e.spicedbClient.CheckBulkPermissions(ctx, tenantID, userID, "access_grant", spicedbIDs, "check")
		outcomes = make(map[string]spicedb.CheckOutcome, len(plain))
		for id, allowed := range plain {
			outcomes[id] = spicedb.CheckOutcome{Allowed: allowed}
		}
	}
	if err != nil {
		// Fail-closed: bulk error → deny all remaining
		e.logger.Error("SpiceDB CheckBulkPermissions failed — denying all (fail-closed)",
			zap.Error(err),
			zap.String("user_id", userID.String()),
			zap.Int("permission_count", len(spicedbPermissions)),
		)
		denyAll(spicedbPermissions, models.DecisionReasonUnavailable)
		return results, nil
	}

	grantedCount := 0
	for _, sid := range spicedbIDs {
		originalPerm := spicedbToOriginal[sid]
		o := outcomes[sid]
		results[originalPerm] = decisionFromOutcome(o)
		if o.Allowed {
			grantedCount++
		}
	}

	metrics.RecordAuthzCheck("batch", "success", "module", time.Since(startTime).Seconds())

	e.logger.Debug("Batch permission check (native bulk API)",
		zap.String("user_id", userID.String()),
		zap.Int("permission_count", len(permissions)),
		zap.Int("granted_count", grantedCount),
		zap.Duration("duration", time.Since(startTime)),
	)

	return results, nil
}

// decisionFromOutcome classifies one SpiceDB outcome. Only HAS_PERMISSION
// allows; everything else is a deny with the most specific reason known.
func decisionFromOutcome(o spicedb.CheckOutcome) models.PermissionDecision {
	switch {
	case o.Allowed:
		return models.PermissionDecision{Allowed: true}
	case o.Conditional:
		return models.PermissionDecision{Reason: models.DecisionReasonCaveatFailed, MissingContext: o.MissingContext}
	case o.Errored:
		return models.PermissionDecision{Reason: models.DecisionReasonUnavailable}
	default:
		return models.PermissionDecision{Reason: models.DecisionReasonPermissionDenied}
	}
}

// CheckProductAccess verifies that a user can access a product instance via SpiceDB.
// Checks platform_product_instance#{action} (default: "use") permission.
func (e *authorizationEngine) CheckProductAccess(ctx context.Context, req ProductAccessRequest) (*PermissionResult, error) {
	startTime := time.Now()
	defer func() {
		metrics.AuthzCheckDuration.WithLabelValues("spicedb").Observe(time.Since(startTime).Seconds())
	}()

	atomic.AddInt64(&e.spicedbChecks, 1)

	if req.UserID == uuid.Nil {
		metrics.RecordAuthzCheck("spicedb", "denied", "product_access", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "user ID is required",
			Source:  "spicedb",
		}, nil
	}

	if req.InstanceID == "" {
		metrics.RecordAuthzCheck("spicedb", "denied", "product_access", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "instance ID is required",
			Source:  "spicedb",
		}, nil
	}

	action := req.Action
	if action == "" {
		action = "use"
	}

	if e.spicedbClient == nil {
		e.logger.Error("SpiceDB client is nil — denying product access (fail-closed)")
		metrics.RecordAuthzCheck("spicedb", "error", "product_access", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "authorization denied: SpiceDB unavailable (fail-closed)",
			Source:  "spicedb",
		}, nil
	}

	allowed, err := e.spicedbClient.CheckPermission(
		ctx, req.TenantID, req.UserID,
		"platform_product_instance", req.InstanceID, action,
	)
	if err != nil {
		e.logger.Warn("SpiceDB product access check failed, denying (fail-closed)",
			zap.Error(err),
			zap.String("instance_id", req.InstanceID),
			zap.String("action", action),
			zap.String("user_id", req.UserID.String()),
		)
		metrics.RecordAuthzCheck("spicedb", "error", "product_access", time.Since(startTime).Seconds())
		return &PermissionResult{
			Allowed: false,
			Reason:  "authorization denied: SpiceDB error (fail-closed)",
			Source:  "spicedb",
		}, nil
	}

	result := &PermissionResult{
		Allowed: allowed,
		Source:  "spicedb",
	}

	if allowed {
		result.Reason = "product access granted via SpiceDB"
		metrics.RecordAuthzCheck("spicedb", "allowed", "product_access", time.Since(startTime).Seconds())
	} else {
		result.Reason = "product access denied: tenant not subscribed or insufficient permissions"
		metrics.RecordAuthzCheck("spicedb", "denied", "product_access", time.Since(startTime).Seconds())
		metrics.RecordAuthzDenial("product_instance:"+action, "spicedb_denied")
	}

	e.logger.Debug("Product access check",
		zap.String("user_id", req.UserID.String()),
		zap.String("instance_id", req.InstanceID),
		zap.String("action", action),
		zap.Bool("allowed", allowed),
	)

	return result, nil
}

// resourceToModulePermission converts a resource-level permission to a module permission.
// Example: "invoice" + "edit" -> "invoicing:invoices:edit"
func (e *authorizationEngine) resourceToModulePermission(resourceType, action string) string {
	moduleMap := map[string]string{
		"invoice":     "invoicing",
		"contact":     "crm",
		"company":     "crm",
		"lead":        "crm",
		"opportunity": "crm",
		"account":     "accounting",
		"document":    "documents",
		"project":     "projects",
		"task":        "projects",
	}

	module, ok := moduleMap[resourceType]
	if !ok {
		module = resourceType
	}

	pluralResourceType := resourceType
	if !strings.HasSuffix(resourceType, "s") {
		pluralResourceType = resourceType + "s"
	}

	return fmt.Sprintf("%s:%s:%s", module, pluralResourceType, action)
}

// GetMetrics returns current metrics for the authorization engine.
func (e *authorizationEngine) GetMetrics() map[string]int64 {
	return map[string]int64{
		"spicedb_checks": atomic.LoadInt64(&e.spicedbChecks),
		"opa_checks":     atomic.LoadInt64(&e.opaChecks),
	}
}

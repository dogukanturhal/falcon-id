// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

// AuthorizationService handles authorization checks
type AuthorizationService struct {
	permissionRepo *repositories.PermissionRepository
	userRepo       *repositories.UserRepository
	opaService     *OPAService
	auditService   *AuditService
	spicedbClient  *spicedb.Client
	config         *config.Config
	authzEngine    AuthorizationEngine

	// tenantSuspension, when set, makes authorize/batch and simulate report
	// every key as tenant_suspended for a suspended tenant (R1-GAPS row 27).
	tenantSuspension TenantSuspensionChecker
	// sodViolations, when set, lets a denial be explained as sod_conflict and
	// lets simulate list the SoD warnings touching a permission.
	sodViolations sodViolationLister
	// simAuditor receives one record per simulation; defaults to auditService.
	simAuditor simulationAuditor
}

// simulationAuditor is the slice of AuditService used to record simulations.
type simulationAuditor interface {
	LogUserAction(ctx context.Context, tenantID uuid.UUID, actorID, targetUserID *uuid.UUID, action string, success bool, details map[string]interface{})
}

// SetSimulationAuditor overrides where simulation audit records go.
func (s *AuthorizationService) SetSimulationAuditor(a simulationAuditor) { s.simAuditor = a }

// sodViolationLister is the slice of SoDService the decision explanation needs.
type sodViolationLister interface {
	ListViolationsForTenant(ctx context.Context, tenantID uuid.UUID, openOnly bool) ([]models.SoDViolation, error)
}

// batchDecisionEngine is the optional AuthorizationEngine extension that
// returns the reason for each deny. The production engine implements it;
// narrower test doubles fall back to the bool API.
type batchDecisionEngine interface {
	BatchCheckDecisions(ctx context.Context, userID, tenantID uuid.UUID, permissions []string) (map[string]models.PermissionDecision, error)
}

// SetTenantSuspensionChecker wires the tenant-suspension gate.
func (s *AuthorizationService) SetTenantSuspensionChecker(c TenantSuspensionChecker) {
	s.tenantSuspension = c
}

// SetSoDViolationLister wires the SoD violation lookup used to explain denials.
func (s *AuthorizationService) SetSoDViolationLister(l sodViolationLister) {
	s.sodViolations = l
}

// NewAuthorizationService creates a new authorization service
func NewAuthorizationService(
	permissionRepo *repositories.PermissionRepository,
	userRepo *repositories.UserRepository,
	opaService *OPAService,
	auditService *AuditService,
) *AuthorizationService {
	return &AuthorizationService{
		permissionRepo: permissionRepo,
		userRepo:       userRepo,
		opaService:     opaService,
		auditService:   auditService,
	}
}

// SetSpiceDBClient sets the SpiceDB client for ReBAC authorization
func (s *AuthorizationService) SetSpiceDBClient(client *spicedb.Client, cfg *config.Config) {
	s.spicedbClient = client
	s.config = cfg
	logger.Info("SpiceDB client wired to authorization service (primary engine)",
		zap.Bool("enabled", client != nil),
	)
}

// SetAuthorizationEngine wires the unified AuthorizationEngine. When set,
// AuthorizeBatch delegates to engine.BatchCheckPermissions() instead of
// querying PostgreSQL directly. This is the preferred production path.
func (s *AuthorizationService) SetAuthorizationEngine(engine AuthorizationEngine) {
	s.authzEngine = engine
}

// Authorize checks if a user has a specific permission
func (s *AuthorizationService) Authorize(ctx context.Context, req *models.AuthorizeRequest) (*models.AuthorizeResponse, error) {
	if req.UserID == uuid.Nil {
		return &models.AuthorizeResponse{
			Allowed: false,
			Reason:  "user ID is required",
		}, nil
	}

	if req.Permission == "" {
		return &models.AuthorizeResponse{
			Allowed: false,
			Reason:  "permission is required",
		}, nil
	}

	// SpiceDB is the primary authorization engine
	if s.spicedbClient != nil && s.config != nil {
		return s.authorizeSpiceDB(ctx, req)
	}

	// Fallback: RBAC + ABAC (only if SpiceDB not wired — should not happen in production)
	return s.authorizeRBAC(ctx, req)
}

// authorizeRBAC performs authorization using traditional RBAC + ABAC
func (s *AuthorizationService) authorizeRBAC(ctx context.Context, req *models.AuthorizeRequest) (*models.AuthorizeResponse, error) {
	// Check permission in database (role-based)
	allowed, err := s.checkPermission(ctx, req.UserID, req.TenantID, req.Permission)
	if err != nil {
		return nil, fmt.Errorf("failed to check permission: %w", err)
	}

	if allowed {
		return &models.AuthorizeResponse{
			Allowed: true,
			Reason:  "granted via role",
		}, nil
	}

	// OPA is deny-only and never grants: it is intentionally not consulted here.

	return &models.AuthorizeResponse{
		Allowed: false,
		Reason:  "permission denied",
	}, nil
}

// authorizeSpiceDB performs authorization using SpiceDB (ReBAC)
func (s *AuthorizationService) authorizeSpiceDB(ctx context.Context, req *models.AuthorizeRequest) (*models.AuthorizeResponse, error) {
	// Parse permission to determine object type and action
	objectType, objectID, action := s.parsePermission(req.Permission, req.ResourceType, req.ResourceID)

	// Check permission via SpiceDB
	allowed, err := s.spicedbClient.CheckPermission(ctx, req.TenantID, req.UserID, objectType, objectID, action)
	if err != nil {
		// SpiceDB failure - log and potentially fallback
		logger.Error("SpiceDB permission check failed",
			zap.Error(err),
			zap.String("permission", req.Permission),
			zap.String("user_id", req.UserID.String()),
		)

		// SECURITY: Fail-closed when SpiceDB check fails
		return nil, fmt.Errorf("SpiceDB authorization failed: %w", err)
	}

	reason := "granted via SpiceDB"
	if !allowed {
		reason = "denied by SpiceDB"
	}

	return &models.AuthorizeResponse{
		Allowed: allowed,
		Reason:  reason,
	}, nil
}

// parsePermission parses a permission string into SpiceDB object type, ID, and action.
// Uses the access_grant pattern consistent with AuthorizationEngine.
func (s *AuthorizationService) parsePermission(permission, resourceType, resourceID string) (objectType, objectID, action string) {
	// If resourceType and resourceID are provided, use them directly
	if resourceType != "" && resourceID != "" {
		return resourceType, resourceID, permission
	}

	// Parse permission format: "module:resource:action" -> access_grant pattern
	parts := strings.Split(permission, ":")
	if len(parts) == 3 {
		objectType = "access_grant"
		objectID = spicedb.PermissionToSpiceDBID(permission)
		action = "check"
		return
	}

	// Fallback: treat entire permission as action on tenant
	objectType = "tenant"
	objectID = "default"
	action = permission
	return
}

// AuthorizeBatch checks multiple permissions for a user and explains every
// denial (spec 23 §7: per-key reason). When an AuthorizationEngine is wired
// (preferred) it delegates to the engine, which queries SpiceDB as the
// authoritative source. Falls back to direct PostgreSQL queries for backward
// compatibility when no engine is set. Fail closed: any key the underlying
// check did not answer is a deny with reason "unknown".
func (s *AuthorizationService) AuthorizeBatch(ctx context.Context, req *models.BatchAuthorizeRequest) (*models.BatchAuthorizeResponse, error) {
	if req.UserID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}

	if len(req.Permissions) == 0 {
		return nil, fmt.Errorf("at least one permission is required")
	}

	decisions, err := s.decide(ctx, req.UserID, req.TenantID, req.Permissions)
	if err != nil {
		return nil, err
	}
	results := make(map[string]bool, len(decisions))
	for perm, d := range decisions {
		results[perm] = d.Allowed
	}
	return &models.BatchAuthorizeResponse{Results: results, Decisions: decisions}, nil
}

// decide produces one PermissionDecision per requested permission. It is the
// single decision point shared by authorize/batch and authorize/simulate, so
// the simulator can never disagree with the buttons the UI renders.
func (s *AuthorizationService) decide(ctx context.Context, userID, tenantID uuid.UUID, permissions []string) (map[string]models.PermissionDecision, error) {
	decisions := make(map[string]models.PermissionDecision, len(permissions))

	if s.tenantSuspension != nil && s.tenantSuspension.IsSuspended(ctx, tenantID) {
		for _, perm := range permissions {
			decisions[perm] = models.PermissionDecision{Reason: models.DecisionReasonTenantSuspended}
		}
		return decisions, nil
	}

	switch {
	case s.authzEngine != nil:
		// Preferred path: delegate to the unified AuthorizationEngine (SpiceDB).
		if de, ok := s.authzEngine.(batchDecisionEngine); ok {
			d, err := de.BatchCheckDecisions(ctx, userID, tenantID, permissions)
			if err != nil {
				return nil, err
			}
			decisions = d
		} else {
			results, err := s.authzEngine.BatchCheckPermissions(ctx, userID, tenantID, permissions)
			if err != nil {
				return nil, err
			}
			for perm, allowed := range results {
				d := models.PermissionDecision{Allowed: allowed}
				if !allowed {
					d.Reason = models.DecisionReasonPermissionDenied
				}
				decisions[perm] = d
			}
		}
	default:
		// Fallback path: query PostgreSQL directly.
		// Used only when no engine is wired (e.g., during startup or tests that
		// exercise the legacy code path). Not recommended for production.
		//
		// Get user's effective permissions once, scoped to the request's tenant.
		userPerms, err := s.permissionRepo.GetUserPermissions(ctx, userID, tenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to get user permissions: %w", err)
		}

		// SECURITY: Only honor wildcards that are explicitly assigned in the database.
		// Do NOT synthesize wildcard entries from regular permissions, as that would
		// grant all module/resource permissions to any user with a single permission.
		permMap := make(map[string]bool)
		for _, p := range userPerms {
			permMap[p.Name] = true
		}
		for _, perm := range permissions {
			d := models.PermissionDecision{Allowed: s.matchPermission(permMap, perm)}
			if !d.Allowed {
				d.Reason = models.DecisionReasonPermissionDenied
			}
			decisions[perm] = d
		}
	}

	s.explainDenials(ctx, userID, tenantID, permissions, decisions)
	return decisions, nil
}

// explainDenials normalises the decision map: every requested key is present,
// and every deny carries a reason (fail closed: an unanswered key is a deny
// with reason "unknown"). A plain permission_denied is refined to sod_conflict
// when the user has an open block-mode SoD violation touching the permission.
func (s *AuthorizationService) explainDenials(ctx context.Context, userID, tenantID uuid.UUID, permissions []string, decisions map[string]models.PermissionDecision) {
	var blocking []models.SoDViolation
	needSoD := false
	for _, perm := range permissions {
		if d, ok := decisions[perm]; ok && !d.Allowed && d.Reason == models.DecisionReasonPermissionDenied {
			needSoD = true
			break
		}
	}
	if needSoD && s.sodViolations != nil {
		if violations, err := s.sodViolations.ListViolationsForTenant(ctx, tenantID, true); err != nil {
			logger.Warn("SoD violation lookup failed; denials keep their base reason", zap.Error(err))
		} else {
			for _, v := range violations {
				if v.UserID == userID && v.Mode == models.SoDModeBlock {
					blocking = append(blocking, v)
				}
			}
		}
	}

	for _, perm := range permissions {
		d, ok := decisions[perm]
		switch {
		case !ok:
			d = models.PermissionDecision{Reason: models.DecisionReasonUnknown}
		case d.Allowed:
			d.Reason = ""
		case d.Reason == "":
			d.Reason = models.DecisionReasonUnknown
		}
		if !d.Allowed && d.Reason == models.DecisionReasonPermissionDenied {
			for _, v := range blocking {
				if v.PermissionA == perm || v.PermissionB == perm {
					d.Reason = models.DecisionReasonSoDConflict
					break
				}
			}
		}
		decisions[perm] = d
	}
}

// Simulate answers "can user X do Y, and why" for the policy simulator. The
// caller (handler) must already have verified that userID belongs to tenantID
// and that the caller is a tenant admin; Simulate never crosses tenants because
// every lookup is scoped to tenantID. Read-only: it writes nothing but the
// audit record of the simulation.
func (s *AuthorizationService) Simulate(ctx context.Context, actorID, userID, tenantID uuid.UUID, permission string) (*models.SimulateResponse, error) {
	if userID == uuid.Nil || permission == "" {
		return nil, fmt.Errorf("user ID and permission are required")
	}
	decisions, err := s.decide(ctx, userID, tenantID, []string{permission})
	if err != nil {
		return nil, err
	}
	resp := &models.SimulateResponse{UserID: userID, Permission: permission, Decision: decisions[permission]}

	if s.spicedbClient != nil {
		sim, simErr := s.spicedbClient.SimulatePermission(ctx, tenantID, userID, "access_grant", spicedb.PermissionToSpiceDBID(permission), "check")
		if simErr != nil {
			// The decision above stands; the trace is an explanation only.
			logger.Warn("authorize/simulate trace unavailable", zap.Error(simErr), zap.String("permission", permission))
		} else {
			resp.Trace = sim.Trace
			resp.Caveats = sim.Caveats
			if resp.Decision.Reason == models.DecisionReasonCaveatFailed && resp.Decision.Caveat == "" {
				for _, c := range sim.Caveats {
					if c.Result != "RESULT_TRUE" {
						resp.Decision.Caveat = c.Name
						break
					}
				}
			}
		}
	}

	if s.sodViolations != nil {
		if violations, vErr := s.sodViolations.ListViolationsForTenant(ctx, tenantID, true); vErr == nil {
			for _, v := range violations {
				if v.UserID == userID && (v.PermissionA == permission || v.PermissionB == permission) {
					resp.SoDWarnings = append(resp.SoDWarnings, v)
				}
			}
		}
	}

	s.auditSimulation(ctx, actorID, userID, tenantID, permission, resp.Decision)
	return resp, nil
}

// auditSimulation records every simulation (who simulated whom, which
// permission, what the verdict was) in the audit log and the security log.
func (s *AuthorizationService) auditSimulation(ctx context.Context, actorID, userID, tenantID uuid.UUID, permission string, d models.PermissionDecision) {
	logger.SecurityAudit.Info("authorize simulation",
		zap.String("event", "authz.simulate"),
		zap.String("tenant_id", tenantID.String()),
		zap.String("actor_id", actorID.String()),
		zap.String("target_user_id", userID.String()),
		zap.String("permission", permission),
		zap.Bool("allowed", d.Allowed),
		zap.String("reason", string(d.Reason)),
	)
	auditor := s.simAuditor
	if auditor == nil && s.auditService != nil {
		auditor = s.auditService
	}
	if auditor == nil {
		return
	}
	auditor.LogUserAction(ctx, tenantID, &actorID, &userID, "authz.simulate", true, map[string]interface{}{
		"permission": permission,
		"allowed":    d.Allowed,
		"reason":     string(d.Reason),
	})
}

// GetEffectivePermissions returns all effective permissions for a user scoped to their tenant.
func (s *AuthorizationService) GetEffectivePermissions(ctx context.Context, userID, tenantID uuid.UUID) (*models.EffectivePermissionsResponse, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}

	// Get permissions scoped to the caller's tenant.
	permissions, err := s.permissionRepo.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Get roles scoped to the caller's tenant.
	roles, err := s.permissionRepo.GetUserRoles(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Convert to response format
	permResponses := make([]models.PermissionResponse, len(permissions))
	for i, perm := range permissions {
		permResponses[i] = *perm.ToResponse()
	}

	return &models.EffectivePermissionsResponse{
		UserID:      userID,
		Permissions: permResponses,
		Roles:       roles,
	}, nil
}

// checkPermission checks if a user has a specific permission via roles, scoped to the given tenant.
func (s *AuthorizationService) checkPermission(ctx context.Context, userID, tenantID uuid.UUID, permission string) (bool, error) {
	// Get user's permissions scoped to tenantID to prevent cross-tenant privilege escalation.
	permissions, err := s.permissionRepo.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		return false, fmt.Errorf("checkPermission: %w", err)
	}

	// Build permission map
	// SECURITY: Only honor wildcards that are explicitly assigned in the database.
	// Do NOT synthesize wildcard entries from regular permissions.
	permMap := make(map[string]bool)
	for _, p := range permissions {
		permMap[p.Name] = true
	}

	return s.matchPermission(permMap, permission), nil
}

// matchPermission checks if a permission matches any in the permission map (supports wildcards)
func (s *AuthorizationService) matchPermission(permMap map[string]bool, permission string) bool {
	// Direct match
	if permMap[permission] {
		return true
	}

	// Superadmin wildcard
	if permMap["*"] {
		return true
	}

	// Parse permission: module:resource:action
	parts := strings.Split(permission, ":")
	if len(parts) != 3 {
		return false
	}

	module, resource, _ := parts[0], parts[1], parts[2]

	// Module wildcard: module:*
	if permMap[module+":*"] {
		return true
	}

	// Resource wildcard: module:resource:*
	if permMap[module+":"+resource+":*"] {
		return true
	}

	return false
}

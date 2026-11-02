// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// sodRuleRepo is the narrow interface SoDService depends on for rules.
type sodRuleRepo interface {
	ListActiveRulesForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.SoDRule, error)
	ListRulesForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.SoDRule, error)
	GetRuleByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.SoDRule, error)
	CreateRule(ctx context.Context, rule *models.SoDRule) error
	UpdateRule(ctx context.Context, id, tenantID uuid.UUID, req *models.UpdateSoDRuleRequest) (*models.SoDRule, error)
}

// sodViolationRepo is the narrow interface SoDService depends on for
// violations.
type sodViolationRepo interface {
	UpsertViolation(ctx context.Context, v *models.SoDViolation) error
	ListViolationsForTenant(ctx context.Context, tenantID uuid.UUID, openOnly bool) ([]models.SoDViolation, error)
}

// sodPermissionRepo is the narrow slice of PermissionRepository SoDService
// needs: the permission set a user currently holds, to check pairs against.
type sodPermissionRepo interface {
	GetUserPermissionNames(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error)
}

// SoDService implements the SoD (Separation of Duties) evaluation and
// rule-matrix management described in
// 23-authorization-rbac-abac-rebac.md §2.7/§5.2/§8.3 and
// 17-module-account.md §12/§5.1-§5.2.
//
// R1 scope: warn mode only, everywhere, regardless of a rule's own `mode`
// column — see EvaluateUser's doc comment. Block-mode enforcement
// (rejecting the role-assignment write itself) is explicitly deferred to
// the R2 (PreAccounting) / R3 (Accounting) per-module flips called out in
// the product roadmap and is NOT implemented by this service; the `mode`
// column and Violation.Mode snapshot exist so that flip is a data change
// later, not a further code change now.
type SoDService struct {
	ruleRepo       sodRuleRepo
	violationRepo  sodViolationRepo
	permissionRepo sodPermissionRepo

	// onRuleChange, when set, is invoked (non-blocking) with the tenant id
	// after a rule is created, updated or disabled so existing assignments are
	// re-evaluated against the new rule set (SoDReevaluator.ReevaluateTenantAsync).
	onRuleChange func(tenantID uuid.UUID)
}

// SetRuleChangeHook registers the rule-change re-evaluation trigger.
func (s *SoDService) SetRuleChangeHook(fn func(tenantID uuid.UUID)) {
	s.onRuleChange = fn
}

func (s *SoDService) notifyRuleChange(tenantID uuid.UUID) {
	if s.onRuleChange != nil {
		s.onRuleChange(tenantID)
	}
}

// NewSoDService is an exported function.
func NewSoDService(ruleRepo sodRuleRepo, violationRepo sodViolationRepo, permissionRepo sodPermissionRepo) *SoDService {
	return &SoDService{
		ruleRepo:       ruleRepo,
		violationRepo:  violationRepo,
		permissionRepo: permissionRepo,
	}
}

// EvaluateUser evaluates every active SoD rule visible to tenantID against
// userID's current permission set (the union of everything granted by
// their role assignments) and upserts an iam_sod_violations row for every
// rule where the user holds BOTH permissions of the pair.
//
// Called at two points, per §5.2:
//  1. Grant-time — on every role-assignment write (this is the "warn mode
//     logs + records a violation, never blocks" requirement: this method
//     NEVER returns an error that should abort the caller's write. A
//     lookup/DB failure while evaluating SoD is logged and swallowed —
//     the role-assignment write that triggered the evaluation has
//     already committed by the time this runs, and SoD's own R1 mode is
//     warn-only, so failing the *caller's* request over a failure in this
//     secondary, non-blocking check would be strictly worse than a
//     temporarily-missed detection.
//  2. Continuously — a scheduled job would call this per active user
//     (not implemented in this change; the roadmap's R1 scope is warn-
//     mode-on-write, the "flagged owner" continuous-reevaluation job is
//     explicitly listed as a nice-to-have in §5.2, not this task's ask).
//
// Returns the violations detected on THIS evaluation pass (for callers,
// like the internal /sod/evaluate endpoint, that want to report them
// synchronously) — this is distinct from "all open violations for the
// user", which ListViolationsForTenant answers.
func (s *SoDService) EvaluateUser(ctx context.Context, tenantID, userID uuid.UUID, roleIDs []uuid.UUID) ([]models.SoDViolation, error) {
	rules, err := s.ruleRepo.ListActiveRulesForTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("EvaluateUser: list rules: %w", err)
	}
	if len(rules) == 0 {
		return nil, nil
	}

	permNames, err := s.permissionRepo.GetUserPermissionNames(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("EvaluateUser: list user permissions: %w", err)
	}
	held := make(map[string]bool, len(permNames))
	for _, p := range permNames {
		held[p] = true
	}

	var violations []models.SoDViolation
	for _, rule := range rules {
		if !held[rule.PermissionA] || !held[rule.PermissionB] {
			continue
		}

		violation := models.SoDViolation{
			TenantID:    tenantID,
			UserID:      userID,
			RuleID:      rule.ID,
			PermissionA: rule.PermissionA,
			PermissionB: rule.PermissionB,
			Mode:        rule.Mode,
			RoleIDs:     roleIDs,
		}

		// Warn mode (the only mode any seeded rule uses in R1, and the
		// only mode this service enforces regardless of a future rule's
		// `mode` value — see type doc comment): log + record, never
		// block.
		logger.SecurityAudit.Warn("SoD violation detected (warn mode)",
			zap.String("event", "auth.sod.violation_detected"),
			zap.String("tenant_id", tenantID.String()),
			zap.String("user_id", userID.String()),
			zap.String("rule_id", rule.ID.String()),
			zap.String("permission_a", rule.PermissionA),
			zap.String("permission_b", rule.PermissionB),
			zap.String("mode", string(rule.Mode)),
		)

		if err := s.violationRepo.UpsertViolation(ctx, &violation); err != nil {
			logger.Warn("Failed to record SoD violation (non-fatal — warn mode never blocks the triggering write)",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", userID.String()),
				zap.String("rule_id", rule.ID.String()),
				zap.Error(err),
			)
			continue
		}

		violations = append(violations, violation)
	}

	return violations, nil
}

// EvaluateUserAsync runs EvaluateUser and swallows any error, logging it
// instead. This is the call shape every role-assignment write path uses
// (§5.2's "evaluation on EVERY role-assignment write ... never blocks") —
// callers that mutate a user's roles call this synchronously-but-
// non-fatally right after their own write commits; it deliberately has no
// error return so a caller can never accidentally propagate a SoD
// evaluation failure into their own request's response.
func (s *SoDService) EvaluateUserAsync(ctx context.Context, tenantID, userID uuid.UUID, roleIDs []uuid.UUID) {
	if s == nil {
		return
	}
	if _, err := s.EvaluateUser(ctx, tenantID, userID, roleIDs); err != nil {
		logger.Warn("SoD evaluation failed (non-fatal)",
			zap.String("tenant_id", tenantID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
	}
}

// ListRulesForTenant returns the full rule matrix visible to a tenant:
// their own rules plus every platform default, for the SoD Rules editor
// screen (GET /api/v1/account/sod-rules).
func (s *SoDService) ListRulesForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.SoDRule, error) {
	own, err := s.ruleRepo.ListRulesForTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListRulesForTenant: %w", err)
	}

	all, err := s.ruleRepo.ListActiveRulesForTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListRulesForTenant: %w", err)
	}

	seen := make(map[uuid.UUID]bool, len(own))
	out := make([]models.SoDRule, 0, len(own)+len(all))
	for _, r := range own {
		seen[r.ID] = true
		out = append(out, r)
	}
	for _, r := range all {
		if !seen[r.ID] {
			out = append(out, r)
		}
	}
	return out, nil
}

// CreateRule creates a tenant-owned SoD rule addition.
// account:sod:manage-gated (checked by the handler/route).
func (s *SoDService) CreateRule(ctx context.Context, tenantID uuid.UUID, req *models.CreateSoDRuleRequest, createdBy *uuid.UUID) (*models.SoDRule, error) {
	if req.PermissionA == req.PermissionB {
		return nil, fmt.Errorf("CreateRule: permission_a and permission_b must differ")
	}
	mode := req.Mode
	if mode == "" {
		mode = models.SoDModeWarn
	}

	rule := &models.SoDRule{
		TenantID:    &tenantID,
		Module:      req.Module,
		PermissionA: req.PermissionA,
		PermissionB: req.PermissionB,
		Mode:        mode,
		Description: req.Description,
		IsDefault:   false,
		CreatedBy:   createdBy,
	}
	if err := s.ruleRepo.CreateRule(ctx, rule); err != nil {
		return nil, fmt.Errorf("CreateRule: %w", err)
	}
	s.notifyRuleChange(tenantID)
	return rule, nil
}

// UpdateRule applies a partial update to a tenant-owned rule. Returns nil
// (no error) if the rule doesn't exist or isn't owned by the tenant — the
// handler maps that to 404.
//
// Disabling a PLATFORM DEFAULT rule (tenant_id IS NULL) is done by
// creating a tenant-scoped override row with the same permission pair and
// disabled_at set (see CreateDisablingOverride), not by calling
// UpdateRule against the default row's ID — a tenant can never mutate a
// platform default in place.
func (s *SoDService) UpdateRule(ctx context.Context, tenantID, ruleID uuid.UUID, req *models.UpdateSoDRuleRequest) (*models.SoDRule, error) {
	rule, err := s.ruleRepo.UpdateRule(ctx, ruleID, tenantID, req)
	if err != nil {
		return nil, fmt.Errorf("UpdateRule: %w", err)
	}
	if rule != nil {
		s.notifyRuleChange(tenantID)
	}
	return rule, nil
}

// CreateDisablingOverride lets a tenant "disable" a platform default rule
// by inserting a tenant-scoped, pre-disabled override row with the same
// permission pair (17-module-account.md §5.1: "tenant may add/disable").
func (s *SoDService) CreateDisablingOverride(ctx context.Context, tenantID uuid.UUID, defaultRule *models.SoDRule, createdBy *uuid.UUID) (*models.SoDRule, error) {
	now := time.Now().UTC()
	rule := &models.SoDRule{
		TenantID:    &tenantID,
		Module:      defaultRule.Module,
		PermissionA: defaultRule.PermissionA,
		PermissionB: defaultRule.PermissionB,
		Mode:        defaultRule.Mode,
		Description: defaultRule.Description,
		IsDefault:   false,
		CreatedBy:   createdBy,
		DisabledAt:  &now,
	}
	if err := s.ruleRepo.CreateRule(ctx, rule); err != nil {
		return nil, fmt.Errorf("CreateDisablingOverride: %w", err)
	}
	s.notifyRuleChange(tenantID)
	return rule, nil
}

// ListViolationsForTenant returns violations for the SoD violation report
// screen (GET /api/v1/account/sod-violations).
func (s *SoDService) ListViolationsForTenant(ctx context.Context, tenantID uuid.UUID, openOnly bool) ([]models.SoDViolation, error) {
	violations, err := s.violationRepo.ListViolationsForTenant(ctx, tenantID, openOnly)
	if err != nil {
		return nil, fmt.Errorf("ListViolationsForTenant: %w", err)
	}
	return violations, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// AdaptiveMFAEvaluator is the minimal interface for adaptive MFA decisions.
// It is satisfied by AdaptiveMFAEngine.
type AdaptiveMFAEvaluator interface {
	Evaluate(ctx context.Context, amCtx AdaptiveMFAContext) MFADecision
}

// ConditionalAccessService evaluates and manages conditional access policies.
type ConditionalAccessService struct {
	db          *pgxpool.Pool
	adaptiveMFA AdaptiveMFAEvaluator
}

// NewConditionalAccessService creates a new ConditionalAccessService.
func NewConditionalAccessService(db *pgxpool.Pool) *ConditionalAccessService {
	return &ConditionalAccessService{db: db}
}

// SetAdaptiveMFAEngine wires an adaptive MFA engine via setter injection so that
// conditional access policies can incorporate risk-based MFA decisions.
func (s *ConditionalAccessService) SetAdaptiveMFAEngine(engine AdaptiveMFAEvaluator) {
	s.adaptiveMFA = engine
}

// ---------------------------------------------------------------------------
// Policy CRUD
// ---------------------------------------------------------------------------

// Create persists a new conditional access policy.
func (s *ConditionalAccessService) Create(
	ctx context.Context,
	req *models.CreateCAPRequest,
	createdBy uuid.UUID,
) (*models.ConditionalAccessPolicy, error) {
	condJSON, err := json.Marshal(req.Conditions)
	if err != nil {
		return nil, fmt.Errorf("ConditionalAccessService.Create: marshal conditions: %w", err)
	}
	paramsJSON, err := json.Marshal(req.ActionParams)
	if err != nil {
		return nil, fmt.Errorf("ConditionalAccessService.Create: marshal params: %w", err)
	}

	priority := req.Priority
	if priority == 0 {
		priority = 100
	}
	isEnabled := true
	if req.IsEnabled != nil {
		isEnabled = *req.IsEnabled
	}

	query := `
		INSERT INTO iam_conditional_access_policies (
			tenant_id, name, description, priority, is_enabled,
			target_users, target_groups, target_roles, target_all_users,
			exclude_users, exclude_groups, conditions, action, action_params, created_by
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
		) RETURNING id, created_at, updated_at`

	var p models.ConditionalAccessPolicy
	err = s.db.QueryRow(ctx, query,
		req.TenantID, req.Name, req.Description, priority, isEnabled,
		uuidSliceToStringSlice(req.TargetUsers),
		uuidSliceToStringSlice(req.TargetGroups),
		req.TargetRoles,
		req.TargetAllUsers,
		uuidSliceToStringSlice(req.ExcludeUsers),
		uuidSliceToStringSlice(req.ExcludeGroups),
		condJSON, string(req.Action), paramsJSON, createdBy,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("ConditionalAccessService.Create: %w", err)
	}

	p.TenantID = req.TenantID
	p.Name = req.Name
	p.Description = req.Description
	p.Priority = priority
	p.IsEnabled = isEnabled
	p.TargetUsers = req.TargetUsers
	p.TargetGroups = req.TargetGroups
	p.TargetRoles = req.TargetRoles
	p.TargetAllUsers = req.TargetAllUsers
	p.ExcludeUsers = req.ExcludeUsers
	p.ExcludeGroups = req.ExcludeGroups
	p.Conditions = condJSON
	p.Action = req.Action
	p.ActionParams = paramsJSON
	p.CreatedBy = createdBy

	logger.Info("ConditionalAccessService: policy created",
		zap.String("policy_id", p.ID.String()),
		zap.String("name", p.Name),
		zap.String("action", string(p.Action)),
	)
	return &p, nil
}

// GetByID returns a single policy by primary key.
func (s *ConditionalAccessService) GetByID(ctx context.Context, id uuid.UUID) (*models.ConditionalAccessPolicy, error) {
	query := `
		SELECT id, tenant_id, name, description, priority, is_enabled,
		       target_users, target_groups, target_roles, target_all_users,
		       exclude_users, exclude_groups, conditions, action, action_params,
		       created_by, created_at, updated_at
		FROM iam_conditional_access_policies
		WHERE id = $1`

	p, err := scanPolicy(s.db.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("ConditionalAccessService.GetByID: %w", err)
	}
	return p, nil
}

// List returns all policies, optionally filtered by tenant.
func (s *ConditionalAccessService) List(ctx context.Context, tenantID *uuid.UUID) ([]models.ConditionalAccessPolicy, error) {
	query := `
		SELECT id, tenant_id, name, description, priority, is_enabled,
		       target_users, target_groups, target_roles, target_all_users,
		       exclude_users, exclude_groups, conditions, action, action_params,
		       created_by, created_at, updated_at
		FROM iam_conditional_access_policies
		WHERE ($1::uuid IS NULL OR tenant_id = $1 OR tenant_id IS NULL)
		ORDER BY priority ASC, created_at ASC`

	rows, err := s.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ConditionalAccessService.List: %w", err)
	}
	defer rows.Close()

	var policies []models.ConditionalAccessPolicy
	for rows.Next() {
		p, err := scanPolicyRow(rows)
		if err != nil {
			logger.Warn("ConditionalAccessService.List: scan error", zap.Error(err))
			continue
		}
		policies = append(policies, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ConditionalAccessService.List: rows: %w", err)
	}
	return policies, nil
}

// Update modifies an existing policy.
func (s *ConditionalAccessService) Update(
	ctx context.Context,
	id uuid.UUID,
	req *models.UpdateCAPRequest,
) (*models.ConditionalAccessPolicy, error) {
	existing, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("ConditionalAccessService.Update: fetch: %w", err)
	}

	// Apply partial updates
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Description != nil {
		existing.Description = *req.Description
	}
	if req.Priority != nil {
		existing.Priority = *req.Priority
	}
	if req.IsEnabled != nil {
		existing.IsEnabled = *req.IsEnabled
	}
	if req.TargetUsers != nil {
		existing.TargetUsers = req.TargetUsers
	}
	if req.TargetGroups != nil {
		existing.TargetGroups = req.TargetGroups
	}
	if req.TargetRoles != nil {
		existing.TargetRoles = req.TargetRoles
	}
	if req.TargetAllUsers != nil {
		existing.TargetAllUsers = *req.TargetAllUsers
	}
	if req.ExcludeUsers != nil {
		existing.ExcludeUsers = req.ExcludeUsers
	}
	if req.ExcludeGroups != nil {
		existing.ExcludeGroups = req.ExcludeGroups
	}
	if req.Conditions != nil {
		condJSON, err := json.Marshal(req.Conditions)
		if err != nil {
			return nil, fmt.Errorf("ConditionalAccessService.Update: marshal conditions: %w", err)
		}
		existing.Conditions = condJSON
	}
	if req.Action != nil {
		existing.Action = *req.Action
	}
	if req.ActionParams != nil {
		paramsJSON, err := json.Marshal(req.ActionParams)
		if err != nil {
			return nil, fmt.Errorf("ConditionalAccessService.Update: marshal params: %w", err)
		}
		existing.ActionParams = paramsJSON
	}

	updateQuery := `
		UPDATE iam_conditional_access_policies SET
			name=$1, description=$2, priority=$3, is_enabled=$4,
			target_users=$5, target_groups=$6, target_roles=$7, target_all_users=$8,
			exclude_users=$9, exclude_groups=$10, conditions=$11, action=$12, action_params=$13,
			updated_at=NOW()
		WHERE id=$14
		RETURNING updated_at`

	err = s.db.QueryRow(ctx, updateQuery,
		existing.Name, existing.Description, existing.Priority, existing.IsEnabled,
		uuidSliceToStringSlice(existing.TargetUsers),
		uuidSliceToStringSlice(existing.TargetGroups),
		existing.TargetRoles, existing.TargetAllUsers,
		uuidSliceToStringSlice(existing.ExcludeUsers),
		uuidSliceToStringSlice(existing.ExcludeGroups),
		existing.Conditions, string(existing.Action), existing.ActionParams,
		id,
	).Scan(&existing.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("ConditionalAccessService.Update: %w", err)
	}
	return existing, nil
}

// Delete removes a policy.
func (s *ConditionalAccessService) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx, `DELETE FROM iam_conditional_access_policies WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("ConditionalAccessService.Delete: %w", err)
	}
	return nil
}

// SetEnabled enables or disables a policy.
func (s *ConditionalAccessService) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	_, err := s.db.Exec(ctx,
		`UPDATE iam_conditional_access_policies SET is_enabled=$1, updated_at=NOW() WHERE id=$2`,
		enabled, id,
	)
	if err != nil {
		return fmt.Errorf("ConditionalAccessService.SetEnabled: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Policy evaluation
// ---------------------------------------------------------------------------

// EvaluateLogin evaluates all active policies for the given login context and
// returns the most restrictive matching action.  The precedence order is:
//
//	deny > require_reauthentication > require_mfa > restrict_session > allow
func (s *ConditionalAccessService) EvaluateLogin(
	ctx context.Context,
	evalCtx models.CAPEvaluationContext,
) (*models.CAPEvaluationResult, error) {
	policies, err := s.List(ctx, evalCtx.TenantID)
	if err != nil {
		return nil, fmt.Errorf("ConditionalAccessService.EvaluateLogin: %w", err)
	}

	result := &models.CAPEvaluationResult{
		Action: models.CAPActionAllow,
	}

	for i := range policies {
		p := &policies[i]
		if !p.IsEnabled {
			continue
		}
		if !s.subjectMatches(p, evalCtx) {
			continue
		}
		if !s.conditionsMatch(p, evalCtx) {
			continue
		}

		result.MatchedPolicies = append(result.MatchedPolicies, *p)

		// Apply the most restrictive action seen so far
		if actionPrecedence(p.Action) > actionPrecedence(result.Action) {
			result.Action = p.Action
			if p.Action == models.CAPActionDeny {
				result.DenyMessage = fmt.Sprintf("Access denied by policy: %s", p.Name)
			}
		}

		// Short-circuit on deny — nothing can override it
		if result.Action == models.CAPActionDeny {
			break
		}
	}

	// Write evaluation log (best-effort, non-fatal)
	_ = s.writeEvalLog(ctx, result, evalCtx)

	return result, nil
}

// Simulate runs a dry-run policy evaluation without writing a log entry.
func (s *ConditionalAccessService) Simulate(
	ctx context.Context,
	req *models.SimulateCAPRequest,
) (*models.CAPEvaluationResult, error) {
	policies, err := s.List(ctx, req.Context.TenantID)
	if err != nil {
		return nil, fmt.Errorf("ConditionalAccessService.Simulate: %w", err)
	}

	result := &models.CAPEvaluationResult{
		Action: models.CAPActionAllow,
	}

	for i := range policies {
		p := &policies[i]
		if !p.IsEnabled {
			continue
		}
		if !s.subjectMatches(p, req.Context) {
			continue
		}
		if !s.conditionsMatch(p, req.Context) {
			continue
		}
		result.MatchedPolicies = append(result.MatchedPolicies, *p)
		if actionPrecedence(p.Action) > actionPrecedence(result.Action) {
			result.Action = p.Action
			if p.Action == models.CAPActionDeny {
				result.DenyMessage = fmt.Sprintf("Access denied by policy: %s", p.Name)
			}
		}
		if result.Action == models.CAPActionDeny {
			break
		}
	}
	return result, nil
}

// ListEvaluationLog returns the audit trail for a user or tenant.
func (s *ConditionalAccessService) ListEvaluationLog(
	ctx context.Context,
	userID *uuid.UUID,
	tenantID *uuid.UUID,
	page, pageSize int,
) ([]map[string]interface{}, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	query := `
		SELECT id, policy_id, tenant_id, user_id, ip_address, user_agent,
		       risk_score, mfa_enabled, device_id, is_trusted, matched,
		       action_taken, deny_message, evaluated_at
		FROM iam_cap_evaluation_log
		WHERE ($1::uuid IS NULL OR user_id = $1)
		  AND ($2::uuid IS NULL OR tenant_id = $2)
		ORDER BY evaluated_at DESC
		LIMIT $3 OFFSET $4`

	rows, err := s.db.Query(ctx, query, userID, tenantID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("ConditionalAccessService.ListEvaluationLog: %w", err)
	}
	defer rows.Close()

	var entries []map[string]interface{}
	for rows.Next() {
		var (
			id, policyID, tenantIDVal, userIDVal, deviceIDVal *uuid.UUID
			ipAddr, userAgent, actionTaken, denyMsg           *string
			riskScore                                         *int
			mfaEnabled, isTrusted, matched                    *bool
			evaluatedAt                                       time.Time
		)
		if err := rows.Scan(&id, &policyID, &tenantIDVal, &userIDVal,
			&ipAddr, &userAgent, &riskScore, &mfaEnabled, &deviceIDVal,
			&isTrusted, &matched, &actionTaken, &denyMsg, &evaluatedAt); err != nil {
			continue
		}
		entries = append(entries, map[string]interface{}{
			"id": id, "policy_id": policyID, "tenant_id": tenantIDVal,
			"user_id": userIDVal, "ip_address": ipAddr, "user_agent": userAgent,
			"risk_score": riskScore, "mfa_enabled": mfaEnabled,
			"device_id": deviceIDVal, "is_trusted": isTrusted, "matched": matched,
			"action_taken": actionTaken, "deny_message": denyMsg, "evaluated_at": evaluatedAt,
		})
	}

	var total int64
	_ = s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_cap_evaluation_log WHERE ($1::uuid IS NULL OR user_id=$1) AND ($2::uuid IS NULL OR tenant_id=$2)`,
		userID, tenantID,
	).Scan(&total)

	return entries, total, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// subjectMatches returns true when the policy targets the given user/group/role.
func (s *ConditionalAccessService) subjectMatches(
	p *models.ConditionalAccessPolicy,
	ctx models.CAPEvaluationContext,
) bool {
	// Check exclusions first
	for _, eu := range p.ExcludeUsers {
		if eu == ctx.UserID {
			return false
		}
	}
	for _, eg := range p.ExcludeGroups {
		for _, ug := range ctx.UserGroups {
			if eg == ug {
				return false
			}
		}
	}

	if p.TargetAllUsers {
		return true
	}
	for _, tu := range p.TargetUsers {
		if tu == ctx.UserID {
			return true
		}
	}
	for _, tg := range p.TargetGroups {
		for _, ug := range ctx.UserGroups {
			if tg == ug {
				return true
			}
		}
	}
	for _, tr := range p.TargetRoles {
		for _, ur := range ctx.UserRoles {
			if tr == ur {
				return true
			}
		}
	}
	return false
}

// conditionsMatch evaluates the structured condition block of a policy.
func (s *ConditionalAccessService) conditionsMatch(
	p *models.ConditionalAccessPolicy,
	ctx models.CAPEvaluationContext,
) bool {
	if len(p.Conditions) == 0 {
		return true
	}
	var cond models.CAPConditions
	if err := json.Unmarshal(p.Conditions, &cond); err != nil {
		return true // Treat unparseable conditions as matching to avoid silent bypass
	}

	// IP range check
	if len(cond.IPRanges) > 0 && ctx.IPAddress != "" {
		ip := net.ParseIP(ctx.IPAddress)
		inRange := false
		for _, cidr := range cond.IPRanges {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if ip != nil && network.Contains(ip) {
				inRange = true
				break
			}
		}
		if !inRange {
			return false
		}
	}

	// Risk score check
	if cond.RiskLevelMin != nil && ctx.RiskScore < *cond.RiskLevelMin {
		return false
	}

	// MFA status check
	switch cond.MFAStatus {
	case "enrolled":
		if !ctx.MFAEnabled {
			return false
		}
	case "not_enrolled":
		if ctx.MFAEnabled {
			return false
		}
	}

	// Time range check
	if len(cond.TimeRanges) > 0 {
		now := time.Now()
		inWindow := false
		for _, tr := range cond.TimeRanges {
			if isInTimeRange(now, tr) {
				inWindow = true
				break
			}
		}
		if !inWindow {
			return false
		}
	}

	// Client app check
	if len(cond.ClientApps) > 0 && ctx.ClientApp != "" {
		found := false
		for _, app := range cond.ClientApps {
			if app == ctx.ClientApp {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// isInTimeRange checks whether the given time falls within a CAPTimeRange window.
func isInTimeRange(t time.Time, tr models.CAPTimeRange) bool {
	if len(tr.Days) > 0 {
		weekday := int(t.Weekday())
		dayOK := false
		for _, d := range tr.Days {
			if d == weekday {
				dayOK = true
				break
			}
		}
		if !dayOK {
			return false
		}
	}

	if tr.Start == "" || tr.End == "" {
		return true
	}

	now := fmt.Sprintf("%02d:%02d", t.Hour(), t.Minute())
	return now >= tr.Start && now <= tr.End
}

// actionPrecedence returns a numeric weight for comparing action severity.
// Higher = more restrictive.
func actionPrecedence(a models.CAPAction) int {
	switch a {
	case models.CAPActionAllow:
		return 0
	case models.CAPActionRestrictSession:
		return 1
	case models.CAPActionRequireMFA:
		return 2
	case models.CAPActionRequireReauth:
		return 3
	case models.CAPActionDeny:
		return 4
	}
	return 0
}

// writeEvalLog persists a CAP evaluation record (best-effort).
func (s *ConditionalAccessService) writeEvalLog(
	ctx context.Context,
	result *models.CAPEvaluationResult,
	evalCtx models.CAPEvaluationContext,
) error {
	var policyID *uuid.UUID
	if len(result.MatchedPolicies) > 0 {
		id := result.MatchedPolicies[0].ID
		policyID = &id
	}
	matched := len(result.MatchedPolicies) > 0
	action := string(result.Action)

	_, err := s.db.Exec(ctx, `
		INSERT INTO iam_cap_evaluation_log
		(policy_id, tenant_id, user_id, ip_address, user_agent, risk_score,
		 mfa_enabled, device_id, is_trusted, matched, action_taken, deny_message)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		policyID, evalCtx.TenantID, evalCtx.UserID,
		evalCtx.IPAddress, evalCtx.UserAgent, evalCtx.RiskScore,
		evalCtx.MFAEnabled, evalCtx.DeviceID, evalCtx.IsTrusted,
		matched, action, result.DenyMessage,
	)
	return err
}

// uuidSliceToStringSlice converts []uuid.UUID to []string for pgx array binding.
func uuidSliceToStringSlice(ids []uuid.UUID) []string {
	if len(ids) == 0 {
		return []string{}
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// ---------------------------------------------------------------------------
// Database scan helpers
// ---------------------------------------------------------------------------

// pgxRowScanner is a common interface satisfied by pgx.Row and pgx.Rows.
type pgxRowScanner interface {
	Scan(dest ...interface{}) error
}

func scanPolicy(row pgxRowScanner) (*models.ConditionalAccessPolicy, error) {
	return scanPolicyRow(row)
}

func scanPolicyRow(row pgxRowScanner) (*models.ConditionalAccessPolicy, error) {
	var p models.ConditionalAccessPolicy
	var targetUsers, targetGroups, excludeUsers, excludeGroups []string
	err := row.Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description,
		&p.Priority, &p.IsEnabled,
		&targetUsers, &targetGroups, &p.TargetRoles, &p.TargetAllUsers,
		&excludeUsers, &excludeGroups,
		&p.Conditions, &p.Action, &p.ActionParams,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	p.TargetUsers = parseUUIDs(targetUsers)
	p.TargetGroups = parseUUIDs(targetGroups)
	p.ExcludeUsers = parseUUIDs(excludeUsers)
	p.ExcludeGroups = parseUUIDs(excludeGroups)
	return &p, nil
}

func parseUUIDs(ss []string) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ss))
	for _, s := range ss {
		if id, err := uuid.Parse(s); err == nil {
			out = append(out, id)
		}
	}
	return out
}

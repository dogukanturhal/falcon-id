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
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// IDPRoutingResolution carries the full state of a routing-rule lookup so
// callers can distinguish "no rule for this domain" from "rule was
// disabled" from "underlying IDP was deactivated". The legacy
// ResolveIDPForEmail return collapsed all three into a nil pointer; the
// state-bearing variant ResolveIDPForEmailWithState surfaces the
// distinction.
type IDPRoutingResolution struct {
	// Rule is the matched rule with all joined fields populated, or nil
	// if no rule exists for the domain. NOT nil for the disabled /
	// inactive-provider cases.
	Rule *models.IDPRoutingRule

	// RuleDisabled is true when a rule exists but the tenant admin set
	// `is_enabled=false`. The rule pointer is still populated so the
	// caller can surface the rule ID / IDP name to the user or to the
	// audit log.
	RuleDisabled bool

	// ProviderInactive is true when a rule exists with `is_enabled=true`
	// but the underlying iam_identity_providers row has
	// `is_active=false`. Distinct from RuleDisabled because the
	// remediation paths differ (admin un-disables the rule vs admin
	// re-enables the IDP).
	ProviderInactive bool
}

// IsUsable reports whether the resolution returned an active, enabled
// rule that the caller can route the user through. Convenience wrapper
// around the boolean combination.
func (r *IDPRoutingResolution) IsUsable() bool {
	return r != nil && r.Rule != nil && !r.RuleDisabled && !r.ProviderInactive
}

// idpRoutingRepo is the persistence contract IDPRoutingService depends on.
// Defined as an interface (not the concrete *repositories.IDPRoutingRepository)
// so tests can inject a stub without standing up a real Postgres. The
// concrete repo type satisfies this interface structurally — no
// production wiring change.
type idpRoutingRepo interface {
	Create(ctx context.Context, rule *models.IDPRoutingRule) error
	GetByID(ctx context.Context, id, tenantID uuid.UUID) (*models.IDPRoutingRule, error)
	Update(ctx context.Context, rule *models.IDPRoutingRule) error
	Delete(ctx context.Context, id, tenantID uuid.UUID) error
	ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.IDPRoutingRule, error)
	FindByEmailDomain(ctx context.Context, tenantID uuid.UUID, domain string) (*models.IDPRoutingRule, error)
}

// IDPRoutingService is an exported identifier.
// IDPRoutingService handles IDP routing rule business logic.
type IDPRoutingService struct {
	repo idpRoutingRepo
}

// NewIDPRoutingService is an exported identifier.
// NewIDPRoutingService creates a new IDPRoutingService.
func NewIDPRoutingService(repo *repositories.IDPRoutingRepository) *IDPRoutingService {
	return &IDPRoutingService{repo: repo}
}

// CreateRule creates a new IDP routing rule.
func (s *IDPRoutingService) CreateRule(ctx context.Context, tenantID uuid.UUID, req *models.CreateIDPRoutingRuleRequest) (*models.IDPRoutingRule, error) {
	isEnabled := true
	if req.IsEnabled != nil {
		isEnabled = *req.IsEnabled
	}

	rule := &models.IDPRoutingRule{
		TenantID:           tenantID,
		IdentityProviderID: req.IdentityProviderID,
		RuleType:           req.RuleType,
		RuleValue:          strings.ToLower(strings.TrimSpace(req.RuleValue)),
		Priority:           req.Priority,
		IsEnabled:          isEnabled,
	}

	if err := s.repo.Create(ctx, rule); err != nil {
		return nil, fmt.Errorf("failed to create routing rule: %w", err)
	}

	return rule, nil
}

// UpdateRule updates an existing IDP routing rule.
func (s *IDPRoutingService) UpdateRule(ctx context.Context, id, tenantID uuid.UUID, req *models.UpdateIDPRoutingRuleRequest) (*models.IDPRoutingRule, error) {
	rule, err := s.repo.GetByID(ctx, id, tenantID)
	if err != nil {
		return nil, err
	}

	if req.IdentityProviderID != nil {
		rule.IdentityProviderID = *req.IdentityProviderID
	}
	if req.RuleType != nil {
		rule.RuleType = *req.RuleType
	}
	if req.RuleValue != nil {
		rule.RuleValue = strings.ToLower(strings.TrimSpace(*req.RuleValue))
	}
	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	if req.IsEnabled != nil {
		rule.IsEnabled = *req.IsEnabled
	}

	if err := s.repo.Update(ctx, rule); err != nil {
		return nil, err
	}

	return rule, nil
}

// DeleteRule deletes an IDP routing rule.
func (s *IDPRoutingService) DeleteRule(ctx context.Context, id, tenantID uuid.UUID) error {
	return s.repo.Delete(ctx, id, tenantID)
}

// ListRules returns all routing rules for a tenant.
func (s *IDPRoutingService) ListRules(ctx context.Context, tenantID uuid.UUID) ([]models.IDPRoutingRule, error) {
	return s.repo.ListByTenant(ctx, tenantID)
}

// ResolveIDPForEmail extracts the domain from an email and finds the
// matching IDP routing rule. Returns nil if no usable rule applies —
// either because no rule was created for the domain, the rule was
// disabled by the tenant admin, or the underlying IDP was deactivated.
//
// The disabled / inactive cases emit a structured warn log + metric
// signal (logger.Log "idp_routing.disabled_attempted" with rule_id +
// reason) so the SOC can correlate "user tried to use a disabled
// routing rule" against downstream login failures. Pre-2026-05-21 the
// repo silently filtered, hiding this signal entirely.
//
// Callers that need to distinguish the three states (no rule / rule
// disabled / provider inactive) for the user-facing flow should use
// ResolveIDPForEmailWithState — this legacy method preserves the
// "nil = unusable" contract that existing callers depend on.
func (s *IDPRoutingService) ResolveIDPForEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.IDPRoutingRule, error) {
	res, err := s.ResolveIDPForEmailWithState(ctx, tenantID, email)
	if err != nil {
		return nil, err
	}
	if res == nil || !res.IsUsable() {
		return nil, nil
	}
	return res.Rule, nil
}

// ResolveIDPForEmailWithState is the state-bearing variant of
// ResolveIDPForEmail. It returns a non-nil IDPRoutingResolution that
// callers can use to distinguish "no rule" from "rule disabled" from
// "provider inactive" — for example, the discover flow can surface
// "your domain is claimed but the routing rule is currently disabled,
// please contact your administrator" instead of falling through to
// the password form.
//
// Returns (nil, nil) only when the email is well-formed but no rule
// at all exists for the domain. Errors propagate from the email
// parse + repo read.
func (s *IDPRoutingService) ResolveIDPForEmailWithState(ctx context.Context, tenantID uuid.UUID, email string) (*IDPRoutingResolution, error) {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return nil, fmt.Errorf("invalid email format")
	}
	domain := strings.ToLower(parts[1])

	rule, err := s.repo.FindByEmailDomain(ctx, tenantID, domain)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, nil
	}

	res := &IDPRoutingResolution{
		Rule:             rule,
		RuleDisabled:     !rule.IsEnabled,
		ProviderInactive: !rule.ProviderIsActive,
	}

	if res.RuleDisabled || res.ProviderInactive {
		reason := "rule_disabled"
		if res.ProviderInactive && !res.RuleDisabled {
			reason = "provider_inactive"
		} else if res.RuleDisabled && res.ProviderInactive {
			reason = "rule_and_provider_disabled"
		}
		logger.Log.Warn("idp_routing.disabled_attempted",
			zap.String("tenant_id", tenantID.String()),
			zap.String("domain", domain),
			zap.String("rule_id", rule.ID.String()),
			zap.String("provider_id", rule.IdentityProviderID.String()),
			zap.String("reason", reason),
		)
	}

	return res, nil
}

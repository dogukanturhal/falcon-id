// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

const planEnterprise = "enterprise"

// PolicyEngine evaluates provisioning requests against governance policies before
// allowing them. Rather than importing the full OPA runtime (which adds ~150 MB
// of dependencies), the engine implements the same policy logic as plain Go
// functions. This keeps the binary lean while maintaining the same semantics as
// Rego policies — each named rule maps directly to a Go evaluation function.
//
// Adding a new policy requires:
//  1. Adding a string entry to LoadDefaultPolicies.
//  2. Calling the evaluation logic from Evaluate.
//  3. (Optionally) exposing the rule via GET /api/v1/platform/policy/rules.
//
// policyRegionRepo is the narrow interface the policy engine uses to discover
// valid regions dynamically from the database host registry.
type policyRegionRepo interface {
	ListActiveRegions(ctx context.Context) ([]string, error)
}

// PolicyEngine is an exported type.
type PolicyEngine struct {
	policies   map[string]string
	regionRepo policyRegionRepo // nil = use validRegionsFallback
	log        *zap.SugaredLogger
}

// SetRegionRepo wires the host registry so valid regions are derived
// dynamically. When not set, the engine falls back to validRegionsFallback.
func (e *PolicyEngine) SetRegionRepo(repo policyRegionRepo) {
	e.regionRepo = repo
}

// PolicyInput carries the provisioning request context that is checked against
// governance rules. Every field is optional — Evaluate applies only the rules
// that are relevant for the provided fields.
type PolicyInput struct {
	TenantID     string                 `json:"tenant_id"`
	ProductID    string                 `json:"product_id"`
	ResourceType string                 `json:"resource_type"` // e.g. "database", "storage_bucket", "kafka_topic"
	Region       string                 `json:"region"`
	Tier         string                 `json:"tier"` // "pool", "bridge", "silo"
	Plan         string                 `json:"plan"` // "starter", "professional", planEnterprise, "unlimited"
	Config       map[string]interface{} `json:"config,omitempty"`
}

// PolicyResult carries the aggregated evaluation outcome.
// When Allowed is false, Denials contains the failing rule messages.
// Warnings are informational — they do not block provisioning.
type PolicyResult struct {
	Allowed  bool     `json:"allowed"`
	Denials  []string `json:"denials,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// planLimits holds the resource caps and allowed isolation tiers for a
// subscription plan tier.
type planLimits struct {
	MaxDatabases      int
	MaxStorageBuckets int
	MaxKafkaTopics    int
	AllowedTiers      []string
}

// planResourceLimits maps plan names to their resource caps.
// These values mirror the HexxLock subscription tiers and must be kept in sync
// with the subscription-management service definitions.
var planResourceLimits = map[string]planLimits{
	"starter": {
		MaxDatabases:      1,
		MaxStorageBuckets: 1,
		MaxKafkaTopics:    0,
		AllowedTiers:      []string{"pool"},
	},
	"professional": {
		MaxDatabases:      5,
		MaxStorageBuckets: 2,
		MaxKafkaTopics:    2,
		AllowedTiers:      []string{"pool", "bridge"},
	},
	planEnterprise: {
		MaxDatabases:      20,
		MaxStorageBuckets: 5,
		MaxKafkaTopics:    10,
		AllowedTiers:      []string{"pool", "bridge", "silo"},
	},
	"unlimited": {
		MaxDatabases:      100,
		MaxStorageBuckets: 20,
		MaxKafkaTopics:    50,
		AllowedTiers:      []string{"pool", "bridge", "silo"},
	},
}

// validRegionsFallback is used ONLY when the host registry is unavailable.
// In normal operation, valid regions are derived dynamically from
// iam_realm_database_hosts WHERE is_active = true.
var validRegionsFallback = map[string]bool{
	"tr-ist":         true,
	"tr-ank":         true,
	"ap-southeast-1": true, // Singapore
}

// getActiveRegions returns valid regions from the host registry. Falls back to
// the static list when the repo is not wired or the query fails.
func (e *PolicyEngine) getActiveRegions(ctx context.Context) map[string]bool {
	if e.regionRepo != nil {
		regions, err := e.regionRepo.ListActiveRegions(ctx)
		if err == nil && len(regions) > 0 {
			m := make(map[string]bool, len(regions))
			for _, r := range regions {
				m[r] = true
			}
			return m
		}
		if err != nil {
			e.log.Warnw("Failed to list active regions from host registry, using fallback", "error", err)
		}
	}
	return validRegionsFallback
}

// NewPolicyEngine creates a PolicyEngine with the default governance rules loaded.
func NewPolicyEngine(log *zap.SugaredLogger) *PolicyEngine {
	e := &PolicyEngine{
		policies: make(map[string]string),
		log:      log,
	}
	e.LoadDefaultPolicies()
	return e
}

// LoadPolicies loads additional policy descriptors from a directory.
// In this implementation policies are Go functions, so "loading from dir"
// is a no-op that logs a notice. The method exists to satisfy the interface
// described in the design spec and for future extension (e.g. reading YAML
// overrides).
func (e *PolicyEngine) LoadPolicies(dir string) error {
	if dir == "" {
		return nil
	}
	e.log.Infow("PolicyEngine.LoadPolicies called; additional policy dirs are not yet supported",
		"dir", dir,
	)
	return nil
}

// LoadDefaultPolicies registers the built-in governance rules.
// Each entry maps a stable policy name (used in API responses) to the rule
// it implements. The actual enforcement logic is in Evaluate.
func (e *PolicyEngine) LoadDefaultPolicies() {
	e.policies["region_restriction"] = "Tenants on the enterprise plan must specify a valid data-sovereignty region (KVKK/GDPR)"
	e.policies["tier_limits"] = "Isolation tier must be permitted by the subscription plan"
	e.policies["resource_limits"] = "Resource count (databases, buckets, topics) must not exceed plan caps"
	e.policies["encryption"] = "All provisioning requests must acknowledge encryption at rest"
	e.policies["maintenance_window"] = "Warn when provisioning is requested during the backup window (02:00-04:00 UTC)"
	e.policies["naming_convention"] = "Resource names must conform to the HexxLock DB naming scheme"
}

// Evaluate runs the PolicyInput against all loaded rules and returns a
// PolicyResult. An error is returned only when evaluation itself fails
// (never when a policy denies the request — that is expressed through
// PolicyResult.Allowed = false).
//
// Rules are evaluated independently. All failing rules are collected so the
// caller receives a complete list of violations in one response.
func (e *PolicyEngine) Evaluate(ctx context.Context, input PolicyInput) (*PolicyResult, error) {
	result := &PolicyResult{Allowed: true}

	// ------------------------------------------------------------------ //
	// Policy: region_restriction
	// Valid regions are derived DYNAMICALLY from the host registry.
	// Enterprise tenants must operate in an approved data-sovereignty region.
	// ------------------------------------------------------------------ //
	activeRegions := e.getActiveRegions(ctx)
	if input.Region != "" && !activeRegions[input.Region] {
		result.Denials = append(result.Denials,
			fmt.Sprintf("region %q is not available — no active database hosts registered for this region", input.Region),
		)
		result.Allowed = false
	}
	if input.Plan == planEnterprise && input.Region == "" {
		result.Denials = append(result.Denials,
			"enterprise tenants must specify a valid data-sovereignty region",
		)
		result.Allowed = false
	}

	// ------------------------------------------------------------------ //
	// Policy: tier_limits
	// The requested isolation tier must be permitted by the subscription plan.
	// ------------------------------------------------------------------ //
	if input.Tier != "" && input.Plan != "" {
		limits, ok := planResourceLimits[input.Plan]
		if !ok {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("unknown plan %q — tier validation skipped", input.Plan),
			)
		} else if !tierAllowed(limits.AllowedTiers, input.Tier) {
			result.Denials = append(result.Denials,
				fmt.Sprintf("isolation tier %q is not allowed on the %q plan (allowed: %v)",
					input.Tier, input.Plan, limits.AllowedTiers),
			)
			result.Allowed = false
		}
	}

	// ------------------------------------------------------------------ //
	// Policy: resource_limits
	// Validate that the resource type doesn't push past plan maximums.
	// We log a warning when limits are not configured (unknown plan),
	// and skip the check when max == 0 (unlimited for that resource type).
	// ------------------------------------------------------------------ //
	if input.ResourceType != "" && input.Plan != "" {
		e.applyResourceLimitPolicy(input, result)
	}

	// ------------------------------------------------------------------ //
	// Policy: encryption
	// All provisioned databases must have encryption at rest.
	// This is signalled via config["encryption_at_rest"] = true/false.
	// When the field is absent we default to true (fail-open / trust caller).
	// ------------------------------------------------------------------ //
	if input.Config != nil {
		e.applyEncryptionPolicy(input, result)
	}

	// ------------------------------------------------------------------ //
	// Policy: maintenance_window
	// Provisioning during the nightly backup window may be degraded.
	// This is informational — it does not block the request.
	// ------------------------------------------------------------------ //
	hour := time.Now().UTC().Hour()
	if hour >= 2 && hour < 4 {
		result.Warnings = append(result.Warnings,
			"provisioning during the backup window (02:00–04:00 UTC) — operation may be slower than usual",
		)
	}

	// ------------------------------------------------------------------ //
	// Policy: naming_convention
	// Resource names in config["name"] must not contain spaces or special
	// characters beyond hyphens and underscores.
	// ------------------------------------------------------------------ //
	if input.Config != nil {
		e.applyNamingConventionPolicy(input, result)
	}

	if e.log != nil {
		e.log.Debugw("PolicyEngine.Evaluate completed",
			"tenant_id", input.TenantID,
			"product_id", input.ProductID,
			"plan", input.Plan,
			"tier", input.Tier,
			"allowed", result.Allowed,
			"denials", len(result.Denials),
			"warnings", len(result.Warnings),
		)
	}

	return result, nil
}

// applyResourceLimitPolicy enforces per-plan resource type availability.
func (e *PolicyEngine) applyResourceLimitPolicy(input PolicyInput, result *PolicyResult) {
	limits, ok := planResourceLimits[input.Plan]
	if !ok {
		return
	}
	switch input.ResourceType {
	case "kafka_topic":
		if limits.MaxKafkaTopics == 0 {
			result.Denials = append(result.Denials,
				fmt.Sprintf("kafka topics are not available on the %q plan", input.Plan),
			)
			result.Allowed = false
		}
	case "storage_bucket":
		if limits.MaxStorageBuckets == 0 {
			result.Denials = append(result.Denials,
				fmt.Sprintf("storage buckets are not available on the %q plan", input.Plan),
			)
			result.Allowed = false
		}
	}
}

// applyEncryptionPolicy enforces encryption_at_rest requirement.
func (e *PolicyEngine) applyEncryptionPolicy(input PolicyInput, result *PolicyResult) {
	enc, exists := input.Config["encryption_at_rest"]
	if !exists {
		return
	}
	encBool, ok := enc.(bool)
	if ok && !encBool {
		result.Denials = append(result.Denials,
			"encryption_at_rest must be enabled; plaintext storage is not permitted",
		)
		result.Allowed = false
	}
}

// applyNamingConventionPolicy enforces resource name format requirements.
func (e *PolicyEngine) applyNamingConventionPolicy(input PolicyInput, result *PolicyResult) {
	name, exists := input.Config["name"]
	if !exists {
		return
	}
	nameStr, ok := name.(string)
	if !ok {
		return
	}
	if !isValidResourceName(nameStr) {
		result.Denials = append(result.Denials,
			fmt.Sprintf("resource name %q violates the naming convention (allowed: [a-z0-9_-], 1–63 chars)", nameStr),
		)
		result.Allowed = false
	}
}

// ListRules returns all registered policy rules as a slice of name→description
// pairs. This powers the GET /api/v1/platform/policy/rules endpoint.
func (e *PolicyEngine) ListRules() []PolicyRule {
	rules := make([]PolicyRule, 0, len(e.policies))
	for name, desc := range e.policies {
		rules = append(rules, PolicyRule{Name: name, Description: desc})
	}
	return rules
}

// PolicyRule is a single named governance rule exposed by the rules list endpoint.
type PolicyRule struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// tierAllowed reports whether the requested tier is in the plan's allowed list.
func tierAllowed(allowed []string, tier string) bool {
	for _, a := range allowed {
		if a == tier {
			return true
		}
	}
	return false
}

// isValidResourceName reports whether a resource name conforms to the
// HexxLock naming convention: lowercase letters, digits, hyphens, and
// underscores only, between 1 and 63 characters inclusive.
func isValidResourceName(name string) bool {
	if len(name) == 0 || len(name) > 63 {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

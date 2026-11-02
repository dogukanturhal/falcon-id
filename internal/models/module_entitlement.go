// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ModuleEntitlementStatus is the lifecycle status of a tenant's entitlement
// to a single module (the product roadmap §4.1). Mirrored from
// subscription-management via tenant-management's
// example.tenant.modules.sync full-snapshot event.
//
// FAIL-CLOSED CONTRACT: any status value not in this list, or the absence
// of a row entirely for (tenant_id, module_code), MUST be treated by every
// caller as "not entitled" -- never as "allowed". See
// ModuleEntitlementStatus.IsGranting.
type ModuleEntitlementStatus string

const (
	// ModuleEntitlementStatusActive is a paid, current entitlement.
	ModuleEntitlementStatusActive ModuleEntitlementStatus = "active"
	// ModuleEntitlementStatusTrialing is an active self-serve trial
	// (§2.1a: exactly one module, never a bundle).
	ModuleEntitlementStatusTrialing ModuleEntitlementStatus = "trialing"
	// ModuleEntitlementStatusGrace is the post-trial/post-cancellation
	// read-only grace window (§2.1a: 7-day grace, export always available).
	ModuleEntitlementStatusGrace ModuleEntitlementStatus = "grace"
	// ModuleEntitlementStatusExpired means the entitlement has lapsed --
	// no access. A tenant module the producer stops mirroring should be
	// upserted as expired, never silently deleted, so trial-history
	// (ever_trialed/ever_subscribed) is preserved.
	ModuleEntitlementStatusExpired ModuleEntitlementStatus = "expired"
)

// validModuleEntitlementStatuses backs IsValid.
var validModuleEntitlementStatuses = map[ModuleEntitlementStatus]bool{
	ModuleEntitlementStatusActive:   true,
	ModuleEntitlementStatusTrialing: true,
	ModuleEntitlementStatusGrace:    true,
	ModuleEntitlementStatusExpired:  true,
}

// IsValid reports whether s is one of the four known statuses. Used at the
// Kafka/PUT ingestion boundary to reject unrecognized values rather than
// silently persisting them (fail-closed extends to "reject the unknown",
// not just "the DB CHECK constraint will catch it eventually").
func (s ModuleEntitlementStatus) IsValid() bool {
	return validModuleEntitlementStatuses[s]
}

// IsGranting reports whether this status alone means "the tenant can use
// this module right now": active, trialing and grace all grant access
// (grace is intended to be read-only, but that restriction is enforced by
// callers/UI on top of IsGranting, not by this method); expired never
// grants access, and neither does any unrecognized value.
func (s ModuleEntitlementStatus) IsGranting() bool {
	switch s {
	case ModuleEntitlementStatusActive, ModuleEntitlementStatusTrialing, ModuleEntitlementStatusGrace:
		return true
	default:
		return false
	}
}

// ModuleEntitlement is one tenant's entitlement to one module -- a row in
// iam_tenant_module_entitlements (migration 0014). Upserted idempotently by
// both the example.tenant.modules.sync Kafka consumer (per-tenant full
// snapshot) and PUT /internal/v1/tenants/{id}/module-entitlements
// (out-of-band ops/backfill path) through the same
// services.TenantEntitlementService.PutSnapshot, so the monotonic
// EventVersion guard is enforced exactly once, in exactly one place.
type ModuleEntitlement struct {
	ID       uuid.UUID `json:"-" db:"id"`
	TenantID uuid.UUID `json:"-" db:"tenant_id"`
	// ModuleCode is the module slug, e.g. "crm", "marketing".
	ModuleCode string                  `json:"code" db:"module_code"`
	Status     ModuleEntitlementStatus `json:"status" db:"status"`
	Seats      *int                    `json:"seats,omitempty" db:"seats"`
	ExpiresAt  *time.Time              `json:"expires_at,omitempty" db:"expires_at"`
	// Nullable for legacy snapshots: never infer a paid source or tier.
	Source   *string `json:"source" db:"source"`
	TierCode *string `json:"tier_code" db:"tier_code"`
	// ReadOnly marks a grace entitlement whose writes are blocked (reads
	// stay allowed). Mirrored from tenant-management; only meaningful with
	// status grace.
	ReadOnly bool `json:"read_only" db:"read_only"`

	// EverTrialed / EverSubscribed are mirrored from subscription-
	// management's authoritative trial_eligibility / tenant_subscription_items
	// history FOR THIS MODULE (§2.1a: trial eligibility is per-module,
	// never a bundle, never repeatable) via the same snapshot event.
	// Falcon-id deliberately never calls subscription-management
	// synchronously from the entitlements read path -- see
	// services.TenantEntitlementService's doc comment for the rationale.
	// Not serialized directly; surfaced via TrialEligible() in the
	// envelope's separate trial_eligibility map.
	EverTrialed    bool `json:"-" db:"ever_trialed"`
	EverSubscribed bool `json:"-" db:"ever_subscribed"`

	EventVersion    int64     `json:"-" db:"event_version"`
	SourceUpdatedAt time.Time `json:"-" db:"source_updated_at"`
	CreatedAt       time.Time `json:"-" db:"created_at"`
	UpdatedAt       time.Time `json:"-" db:"updated_at"`
}

// TrialEligible reports whether the tenant can still self-serve a trial for
// this module: never trialed AND never had a paid subscription for it,
// ever (the product roadmap §4.9 exit criterion: "a tenant that has subscribed
// before cannot get a second free trial").
func (m ModuleEntitlement) TrialEligible() bool {
	return m.TrialReason() == TrialReasonEligible
}

// TrialReason* are the values of the entitlements response's per-module
// `trial_reason` (spec 25 section 6 trial gate). trial_eligible is true
// exactly when the reason is TrialReasonEligible.
//
// module_not_ga (spec 25) is deliberately not produced here: whether a module
// is generally available lives in subscription-management's catalog, which
// falcon-id does not mirror; the BFF/catalog layer owns that reason.
const (
	TrialReasonEligible             = "eligible"
	TrialReasonBundleNotTrialable   = "bundle_not_trialable"
	TrialReasonTrialActive          = "trial_active"
	TrialReasonInGrace              = "in_grace"
	TrialReasonAlreadySubscribed    = "already_subscribed"
	TrialReasonAlreadyTrialed       = "already_trialed"
	TrialReasonComplimentary        = "complimentary"
	TrialReasonNotEligibleLegacyRow = "not_eligible"
)

// bundleModulePrefix marks bundle codes ("bundle-...") which are purchase-only
// (spec 25 ONB-1/section 6: one module, never a bundle, per tenant).
const bundleModulePrefix = "bundle-"

// TrialReason explains whether a self-serve trial may start for this module,
// evaluated in precedence order: current complimentary access, bundle, current trial, current grace, paid
// history, trial history. The snapshot carries no catalog data, so it never
// reports module_not_ga.
func (m ModuleEntitlement) TrialReason() string {
	switch {
	case m.Source != nil && *m.Source == "operator-comp" && m.Status.IsGranting() && (m.ExpiresAt == nil || m.ExpiresAt.After(time.Now())):
		// An operator grant is not a paid subscription, even when paid
		// history is sticky or the granting status is "active".
		return TrialReasonComplimentary
	case strings.HasPrefix(strings.ToLower(m.ModuleCode), bundleModulePrefix):
		return TrialReasonBundleNotTrialable
	case m.Status == ModuleEntitlementStatusTrialing:
		return TrialReasonTrialActive
	case m.Status == ModuleEntitlementStatusGrace:
		return TrialReasonInGrace
	case m.EverSubscribed || (m.Status == ModuleEntitlementStatusActive && (m.Source == nil || *m.Source != "operator-comp")):
		return TrialReasonAlreadySubscribed
	case m.EverTrialed:
		return TrialReasonAlreadyTrialed
	default:
		return TrialReasonEligible
	}
}

// TrialEndsAt is the trial end for a trialing row (the snapshot's
// expires_at), nil otherwise.
func (m ModuleEntitlement) TrialEndsAt() *time.Time {
	if m.Status == ModuleEntitlementStatusTrialing {
		return m.ExpiresAt
	}
	return nil
}

// GraceEndsAt is the end of the read-only grace window for a grace row (the
// snapshot's expires_at), nil otherwise.
func (m ModuleEntitlement) GraceEndsAt() *time.Time {
	if m.Status == ModuleEntitlementStatusGrace {
		return m.ExpiresAt
	}
	return nil
}

// TenantEntitlementFlags is the tenant-wide (not per-module) `flags` object
// in the GET /api/v1/tenant/entitlements envelope -- a row in
// iam_tenant_entitlement_flags (migration 0014).
//
// Limits (migration 0020) is the integer counterpart of Flags in the same
// row and snapshot: plan limits that a boolean cannot carry (e.g.
// "production_bom_depth": 3 | 10 | -1). -1 means unlimited. A nil Flags or
// Limits map on write means "not part of this snapshot": the stored value is
// kept (UpsertFlags COALESCEs), so a flags-only producer never wipes limits.
type TenantEntitlementFlags struct {
	TenantID        uuid.UUID        `db:"tenant_id"`
	Flags           map[string]bool  `db:"flags"`
	Limits          map[string]int64 `db:"limits"`
	EventVersion    int64            `db:"event_version"`
	SourceUpdatedAt time.Time        `db:"source_updated_at"`
}

// EntitlementLimitUnlimited is the Limits value meaning "no limit".
const EntitlementLimitUnlimited int64 = -1

// ValidateEntitlementLimits rejects empty keys and values below -1 (the
// unlimited sentinel). A nil map is valid (not part of the snapshot).
func ValidateEntitlementLimits(limits map[string]int64) error {
	for k, v := range limits {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("entitlement limit key must not be empty")
		}
		if v < EntitlementLimitUnlimited {
			return fmt.Errorf("entitlement limit %q must be >= -1 (got %d)", k, v)
		}
	}
	return nil
}

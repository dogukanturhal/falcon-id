// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// TenantType represents the type of tenant in the platform
type TenantType string

const (
	// TenantTypeCustomer is an exported identifier.
	TenantTypeCustomer TenantType = "customer" // Paying customers
	// TenantTypeInternal is an exported identifier.
	TenantTypeInternal TenantType = "internal" // HexxLock itself (dogfooding)
	// TenantTypeTrial is an exported identifier.
	TenantTypeTrial TenantType = "trial" // Trial accounts
	// TenantTypePartner is an exported identifier.
	TenantTypePartner TenantType = "partner" // System integrators / resellers
	// TenantTypeDemo is an exported identifier.
	TenantTypeDemo TenantType = "demo" // Demo/sandbox accounts
)

// Tenant represents a tenant organization
type Tenant struct {
	ID               uuid.UUID              `json:"id"`
	Name             string                 `json:"name"`
	Slug             string                 `json:"slug"`
	DisplayName      string                 `json:"display_name"`
	Domain           *string                `json:"domain,omitempty"`
	Status           string                 `json:"status"`
	Type             TenantType             `json:"type"`
	Plan             string                 `json:"plan"`
	BillingExempt    bool                   `json:"billing_exempt"`
	Settings         map[string]interface{} `json:"settings,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	BillingEmail     *string                `json:"billing_email,omitempty"`
	StripeCustomerID *string                `json:"stripe_customer_id,omitempty"`
	MaxUsers         int                    `json:"max_users"`
	MaxStorage       int64                  `json:"max_storage"`
	TrialEndsAt      *time.Time             `json:"trial_ends_at,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
	SuspendedAt      *time.Time             `json:"suspended_at,omitempty"`
	CancelledAt      *time.Time             `json:"cancelled_at,omitempty"`
	// Phase 2 settings fields (migration 0001_tenant_settings_phase2.sql)
	Timezone              string     `json:"timezone"`
	DefaultSenderDomainID *uuid.UUID `json:"default_sender_domain_id,omitempty"`
}

// IsInternalTenant returns true if this is the HexxLock internal tenant
func (t *Tenant) IsInternalTenant() bool {
	return t.Type == TenantTypeInternal
}

// HasUnlimitedUsers returns true if tenant has no user limit
func (t *Tenant) HasUnlimitedUsers() bool {
	return t.MaxUsers == -1
}

// HasUnlimitedStorage returns true if tenant has no storage limit
func (t *Tenant) HasUnlimitedStorage() bool {
	return t.MaxStorage == -1
}

// IsBillingRequired returns true if tenant requires billing
func (t *Tenant) IsBillingRequired() bool {
	return !t.BillingExempt && t.Type == TenantTypeCustomer
}

// CreateTenantRequest carries the fields needed to provision a new tenant.
// Used by the self-service signup flow and the platform admin API.
//
// Never bound from an HTTP request body (no handler calls ShouldBindJSON
// against it) — it is only ever constructed in Go by signup_service.go and
// cmd/signup_adapters.go — so the binding tags below are enforced by the
// package's own validator calls, not exposed as public request surface.
type CreateTenantRequest struct {
	// ID, when set, is used verbatim as the new iam_tenants row's primary
	// key instead of minting a fresh uuid.New(). This exists so the signup
	// flow can reconcile falcon-id's local tenant row with the ID that
	// tenant-management's /api/v1/tenants/register minted for the SAME
	// tenant (tenant-management is the sole system-of-record for plan/type
	// since ADR-0029 Phase 3 dropped iam_tenants.plan/type). Sharing one ID
	// across both systems means:
	//   - X-Tenant-ID-keyed downstream calls (quota-service, BFF headers)
	//     agree on which tenant they mean, and
	//   - falcon-id's reverse Kafka projection (internal/tenantprojection)
	//     lands tenant-management's status/metadata updates on this row
	//     instead of logging them as orphans (no row to update yet).
	// Left nil, behavior is unchanged: signupTenantCreatorAdapter mints a
	// fresh uuid.New(), exactly as before.
	ID          *uuid.UUID `json:"-"`
	Name        string     `json:"name" binding:"required,min=2,max=255"`
	Slug        string     `json:"slug" binding:"required,min=2,max=100"`
	DisplayName string     `json:"display_name"`
	Domain      string     `json:"domain,omitempty"`
	// Type is one of: customer, internal, trial, partner, demo, personal.
	Type string `json:"type" binding:"required"`
	// Plan is the billing plan identifier, e.g. "free", "starter", "pro".
	//
	// DEAD at the database layer as of ADR-0029 Phase 3.2
	// (the GitOps repository !699 dropped iam_tenants.plan): every read/write
	// path in internal/repositories/tenant_repository.go discards this
	// column. Left in place only for source compatibility with existing
	// callers; the actual plan now lives exclusively in tenant-management's
	// tenants.subscription_plan_id, set via the new registrar call in
	// provisionTenant (see signup_service.go).
	Plan          string `json:"plan"`
	BillingEmail  string `json:"billing_email,omitempty"`
	BillingExempt bool   `json:"billing_exempt"`
	MaxUsers      int    `json:"max_users"`
	MaxStorage    int64  `json:"max_storage"`
}

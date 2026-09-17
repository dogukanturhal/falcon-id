// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// IDPRoutingRule is an exported identifier.
// IDPRoutingRule represents an email-domain or IP-range based IDP auto-selection rule.
type IDPRoutingRule struct {
	ID                 uuid.UUID `json:"id" db:"id"`
	TenantID           uuid.UUID `json:"tenant_id" db:"tenant_id"`
	IdentityProviderID uuid.UUID `json:"identity_provider_id" db:"identity_provider_id"`
	RuleType           string    `json:"rule_type" db:"rule_type"`
	RuleValue          string    `json:"rule_value" db:"rule_value"`
	Priority           int       `json:"priority" db:"priority"`
	IsEnabled          bool      `json:"is_enabled" db:"is_enabled"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`

	// Joined fields (not stored in iam_idp_routing_rules)
	ProviderName        string `json:"provider_name,omitempty" db:"provider_name"`
	ProviderType        string `json:"provider_type,omitempty" db:"provider_type"`
	ProviderDisplayName string `json:"provider_display_name,omitempty" db:"provider_display_name"`
	// ProviderIsActive surfaces iam_identity_providers.is_active to the
	// caller so the routing service can distinguish "no rule exists"
	// from "rule exists but IDP was deactivated". Pre-2026-05-21 the
	// repo filtered on this column directly, hiding the state from
	// every caller; post-fix, repo returns the row and the service
	// branches (see internal/services/idp_routing_service.go).
	ProviderIsActive bool `json:"provider_is_active,omitempty" db:"provider_is_active"`
}

// CreateIDPRoutingRuleRequest is an exported identifier.
// CreateIDPRoutingRuleRequest is the DTO for creating a routing rule.
type CreateIDPRoutingRuleRequest struct {
	IdentityProviderID uuid.UUID `json:"identity_provider_id" binding:"required"`
	RuleType           string    `json:"rule_type" binding:"required,oneof=email_domain ip_range user_attribute"`
	RuleValue          string    `json:"rule_value" binding:"required,min=1,max=512"`
	Priority           int       `json:"priority"`
	IsEnabled          *bool     `json:"is_enabled"`
}

// UpdateIDPRoutingRuleRequest is an exported identifier.
// UpdateIDPRoutingRuleRequest is the DTO for updating a routing rule.
type UpdateIDPRoutingRuleRequest struct {
	IdentityProviderID *uuid.UUID `json:"identity_provider_id"`
	RuleType           *string    `json:"rule_type" binding:"omitempty,oneof=email_domain ip_range user_attribute"`
	RuleValue          *string    `json:"rule_value" binding:"omitempty,min=1,max=512"`
	Priority           *int       `json:"priority"`
	IsEnabled          *bool      `json:"is_enabled"`
}

// DiscoverIDPRequest is an exported identifier.
// DiscoverIDPRequest is the DTO for the IDP discovery endpoint.
type DiscoverIDPRequest struct {
	Email         string     `json:"email" binding:"required,email"`
	ApplicationID *uuid.UUID `json:"application_id"`
}

// AppIdentityProvider represents a per-app IDP enablement record.
type AppIdentityProvider struct {
	ID                 uuid.UUID `json:"id" db:"id"`
	ApplicationID      uuid.UUID `json:"application_id" db:"application_id"`
	IdentityProviderID uuid.UUID `json:"identity_provider_id" db:"identity_provider_id"`
	IsEnabled          bool      `json:"is_enabled" db:"is_enabled"`
	Priority           int       `json:"priority" db:"priority"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`

	// Joined fields
	ProviderName        string `json:"provider_name,omitempty" db:"provider_name"`
	ProviderType        string `json:"provider_type,omitempty" db:"provider_type"`
	ProviderDisplayName string `json:"provider_display_name,omitempty" db:"provider_display_name"`
}

// CreateAppIdentityProviderRequest is the DTO for enabling an IDP for an application.
type CreateAppIdentityProviderRequest struct {
	IdentityProviderID uuid.UUID `json:"identity_provider_id" binding:"required"`
	IsEnabled          *bool     `json:"is_enabled"`
	Priority           int       `json:"priority"`
}

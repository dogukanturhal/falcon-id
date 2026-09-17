// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// DiscoveryPolicy enumerates how authentication is handled for a claimed domain.
type DiscoveryPolicy string

const (
	// DiscoveryPolicyManaged routes users to the falcon-id password/MFA flow.
	DiscoveryPolicyManaged DiscoveryPolicy = "managed"
	// DiscoveryPolicyFederated redirects users to an external SAML/OIDC IdP.
	DiscoveryPolicyFederated DiscoveryPolicy = "federated"
	// DiscoveryPolicyConsumerPool is the fallback for unregistered domains.
	DiscoveryPolicyConsumerPool DiscoveryPolicy = "consumer_pool"
)

// TenantDomain maps an email domain to a tenant and defines how users
// authenticating with that domain are routed (managed, federated, or consumer pool).
// This table powers identifier-first realm discovery (HRD tier-1 pattern).
type TenantDomain struct {
	ID                 uuid.UUID  `json:"id" db:"id"`
	Domain             string     `json:"domain" db:"domain"`
	TenantID           uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Verified           bool       `json:"verified" db:"verified"`
	VerificationToken  *string    `json:"verification_token,omitempty" db:"verification_token"`
	VerificationMethod string     `json:"verification_method" db:"verification_method"`
	DiscoveryPolicy    string     `json:"discovery_policy" db:"discovery_policy"`
	FederatedIdpURL    *string    `json:"federated_idp_url,omitempty" db:"federated_idp_url"`
	FederatedIdpType   *string    `json:"federated_idp_type,omitempty" db:"federated_idp_type"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`
}

// RealmDiscoveryRequest is the input for the identifier-first realm discovery endpoint.
// The caller supplies the email entered on the login page; the response tells the UI
// which tenant to route to and which authentication methods are available.
type RealmDiscoveryRequest struct {
	LoginHint string `json:"login_hint" binding:"required,email"`
}

// RealmDiscoveryResponse is the output of POST /api/v1/auth/realm-discovery.
// It mirrors the shape used by Azure Entra ID's GetCredentialType endpoint and
// Auth0's organisation-aware Universal Login flow.
type RealmDiscoveryResponse struct {
	TenantID        uuid.UUID              `json:"tenant_id"`
	TenantName      string                 `json:"tenant_name"`
	TenantSlug      string                 `json:"tenant_slug"`
	DiscoveryPolicy string                 `json:"discovery_policy"`
	AuthMethods     []string               `json:"auth_methods"`
	FederatedIdpURL *string                `json:"federated_idp_url,omitempty"`
	MFARequired     bool                   `json:"mfa_required"`
	Branding        *map[string]interface{} `json:"branding,omitempty"`
}

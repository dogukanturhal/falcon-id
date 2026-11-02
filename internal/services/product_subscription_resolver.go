// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ProductClaim represents a product subscription claim included in JWT tokens.
// Services can verify product access by checking this array without round-trips.
type ProductClaim struct {
	ProductID   uuid.UUID `json:"pid"`
	ProductSlug string    `json:"slug"`
	PlanID      *string   `json:"plan,omitempty"`
	// State is "" (active), "provisioning", or "failed" — see
	// models.ProductSubscriptionClaim.State for the full contract.
	State string `json:"state,omitempty"`
}

// subscriptionInstanceRepo abstracts the product instance queries for subscription resolution.
type subscriptionInstanceRepo interface {
	// ListVisibleByTenant returns every instance the JWT products[] claim
	// should be aware of: active AND still-provisioning rows, so the
	// falcon-id-client gate can distinguish "provisioning" from "not
	// entitled at all". Deliberately excludes 'deleting'/'deleted'
	// (cancelled) rows — those must look identical to "never subscribed".
	ListVisibleByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ProductInstance, error)
}

// subscriptionProductRepo abstracts product lookups for subscription resolution.
type subscriptionProductRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Product, error)
}

// ProductSubscriptionResolver resolves active product subscriptions for a tenant.
// The resolved claims are included in JWT tokens so downstream services can verify
// product access without making round-trip calls to falcon-id.
type ProductSubscriptionResolver struct {
	instanceRepo subscriptionInstanceRepo
	productRepo  subscriptionProductRepo
}

// NewProductSubscriptionResolver creates a new resolver.
func NewProductSubscriptionResolver(
	instanceRepo subscriptionInstanceRepo,
	productRepo subscriptionProductRepo,
) *ProductSubscriptionResolver {
	return &ProductSubscriptionResolver{
		instanceRepo: instanceRepo,
		productRepo:  productRepo,
	}
}

// Resolve returns the product subscription claims for a tenant, including
// still-provisioning instances (State: "provisioning"/"failed") alongside
// active ones (State: ""). Cancelled/deleted rows are excluded by
// ListVisibleByTenant and so never appear here — see subscriptionInstanceRepo.
func (r *ProductSubscriptionResolver) Resolve(ctx context.Context, tenantID uuid.UUID) ([]ProductClaim, error) {
	instances, err := r.instanceRepo.ListVisibleByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	if len(instances) == 0 {
		return nil, nil
	}

	claims := make([]ProductClaim, 0, len(instances))
	for _, pi := range instances {
		product, err := r.productRepo.GetByID(ctx, pi.ProductID)
		if err != nil {
			// Skip products that can't be resolved (deleted, etc.)
			continue
		}

		claims = append(claims, ProductClaim{
			ProductID:   product.ID,
			ProductSlug: product.Slug,
			PlanID:      pi.PlanID,
			State:       claimStateForProvisioningState(pi.ProvisioningState),
		})
	}

	return claims, nil
}

// toProductSubscriptionClaims converts resolver output into the JWT claim
// shape (models.ProductSubscriptionClaim — json pid/slug/plan?/state?).
//
// This is the SINGLE conversion point shared by every token mint path:
// token_service.generateMinimalToken (v1), token_service's v2 SpiceDB mint,
// and OAuthProviderService.generateTokens (/oauth/token: authorization_code,
// refresh_token, token-exchange). Before it existed the OAuth path built the
// claim entries by hand as map[string]any and silently omitted `state`, so
// the falcon-id-client provisioning interstitial never fired for any
// OAuth-issued token (a provisioning tenant got the hard 403 instead).
// Routing all paths through one typed conversion means a new claim field
// cannot drift between them again.
//
// Returns nil for an empty input so callers can keep omitting the claim.
func toProductSubscriptionClaims(resolved []ProductClaim) []models.ProductSubscriptionClaim {
	if len(resolved) == 0 {
		return nil
	}
	out := make([]models.ProductSubscriptionClaim, 0, len(resolved))
	for _, pc := range resolved {
		out = append(out, models.ProductSubscriptionClaim{
			ProductID:   pc.ProductID,
			ProductSlug: pc.ProductSlug,
			PlanID:      pc.PlanID,
			State:       pc.State,
		})
	}
	return out
}

// claimStateForProvisioningState collapses the full ProvisioningState
// lifecycle down to the three values the JWT claim (and the downstream
// Next.js product gate) understand. See models.ProductSubscriptionClaim.State.
func claimStateForProvisioningState(s models.ProvisioningState) string {
	switch s {
	case models.ProvisioningStateActive:
		return ""
	case models.ProvisioningStateFailed:
		return "failed"
	default:
		// pending/creating/migrating/seeding/configuring_auth/
		// registering_service — anything non-terminal and non-active.
		return "provisioning"
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// realmDiscoveryDomainRepo is the persistence contract for tenant domain lookups.
// Defining it here (not imported from repositories) keeps the service testable
// without a real database and follows the project convention of interface-at-use.
type realmDiscoveryDomainRepo interface {
	FindByDomain(ctx context.Context, domain string) (*models.TenantDomain, error)
}

// realmDiscoveryTenantRepo is the persistence contract for tenant lookups by ID.
type realmDiscoveryTenantRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error)
}

// RealmDiscoveryService implements the identifier-first realm discovery pattern.
// Given an email address it determines the owning tenant and returns the
// authentication policy (managed password flow, federated redirect, or consumer pool).
//
// This is the tier-1 pattern used by Azure Entra ID (/common/GetCredentialType),
// Google (accounts.google.com), and Auth0 (Universal Login organisation flow).
type RealmDiscoveryService struct {
	domainRepo      realmDiscoveryDomainRepo
	tenantRepo      realmDiscoveryTenantRepo
	consumerTenantID uuid.UUID // fallback for unregistered domains
}

// NewRealmDiscoveryService constructs a RealmDiscoveryService.
// consumerTenantID is the fallback tenant returned when the email domain is not
// registered in tenant_domains; it should be the default public/consumer tenant.
func NewRealmDiscoveryService(
	domainRepo realmDiscoveryDomainRepo,
	tenantRepo realmDiscoveryTenantRepo,
	consumerTenantID uuid.UUID,
) *RealmDiscoveryService {
	return &RealmDiscoveryService{
		domainRepo:       domainRepo,
		tenantRepo:       tenantRepo,
		consumerTenantID: consumerTenantID,
	}
}

// Discover performs identifier-first realm discovery for the supplied login hint.
//
// Lookup order:
//  1. Extract domain from email.
//  2. Look up a verified record in tenant_domains.
//  3. If found: return tenant details + auth policy derived from discovery_policy.
//  4. If not found: return the consumer-pool fallback tenant.
func (s *RealmDiscoveryService) Discover(ctx context.Context, req *models.RealmDiscoveryRequest) (*models.RealmDiscoveryResponse, error) {
	email := strings.ToLower(strings.TrimSpace(req.LoginHint))

	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return nil, fmt.Errorf("realm discovery: invalid email address")
	}
	domain := parts[1]

	td, err := s.domainRepo.FindByDomain(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("realm discovery: domain lookup: %w", err)
	}

	if td != nil {
		return s.buildResponse(ctx, td)
	}

	// Domain is not registered — fall back to the consumer pool tenant.
	return s.consumerPoolResponse(ctx)
}

// buildResponse constructs the discovery response from a verified TenantDomain record.
func (s *RealmDiscoveryService) buildResponse(ctx context.Context, td *models.TenantDomain) (*models.RealmDiscoveryResponse, error) {
	tenant, err := s.tenantRepo.GetByID(ctx, td.TenantID)
	if err != nil {
		return nil, fmt.Errorf("realm discovery: load tenant: %w", err)
	}

	resp := &models.RealmDiscoveryResponse{
		TenantID:        td.TenantID,
		DiscoveryPolicy: td.DiscoveryPolicy,
	}
	if tenant != nil {
		resp.TenantName = tenant.Name
		resp.TenantSlug = tenant.Slug
	}

	switch models.DiscoveryPolicy(td.DiscoveryPolicy) {
	case models.DiscoveryPolicyFederated:
		resp.AuthMethods = []string{"saml_redirect"}
		resp.FederatedIdpURL = td.FederatedIdpURL

	case models.DiscoveryPolicyConsumerPool:
		resp.AuthMethods = []string{"password", "social"}

	default: // managed
		resp.AuthMethods = []string{"password"}
		// MFA enforcement is realm-level and resolved at login time; we report
		// false here so the login UI renders the password form immediately.
		// The auth flow will challenge for MFA after credential verification.
		resp.MFARequired = false
	}

	return resp, nil
}

// consumerPoolResponse returns the fallback response for unregistered domains.
// The consumer tenant accepts both password and social (OAuth) authentication.
func (s *RealmDiscoveryService) consumerPoolResponse(ctx context.Context) (*models.RealmDiscoveryResponse, error) {
	if s.consumerTenantID == uuid.Nil {
		// No consumer tenant configured — return a minimal anonymous response.
		return &models.RealmDiscoveryResponse{
			TenantID:        uuid.Nil,
			DiscoveryPolicy: string(models.DiscoveryPolicyConsumerPool),
			AuthMethods:     []string{"password", "social"},
		}, nil
	}

	tenant, err := s.tenantRepo.GetByID(ctx, s.consumerTenantID)
	if err != nil {
		// Non-fatal: return a response without tenant metadata rather than failing.
		return &models.RealmDiscoveryResponse{
			TenantID:        s.consumerTenantID,
			DiscoveryPolicy: string(models.DiscoveryPolicyConsumerPool),
			AuthMethods:     []string{"password", "social"},
		}, nil
	}

	resp := &models.RealmDiscoveryResponse{
		TenantID:        s.consumerTenantID,
		DiscoveryPolicy: string(models.DiscoveryPolicyConsumerPool),
		AuthMethods:     []string{"password", "social"},
	}
	if tenant != nil {
		resp.TenantName = tenant.Name
		resp.TenantSlug = tenant.Slug
	}
	return resp, nil
}

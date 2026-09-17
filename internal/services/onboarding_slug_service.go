// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// TenantManagementSlugUpdateResult is the subset of tenant-management's
// updated Tenant this caller needs.
type TenantManagementSlugUpdateResult struct {
	ID   uuid.UUID
	Slug string
}

// TenantManagementSlugUpdater renames an EXISTING tenant's slug in
// tenant-management (the system of record for tenant.slug). Distinct from
// TenantManagementRegistrar.Register, which only ever creates a brand-new
// tenant during signup: this call MUST go through tenant-management's
// authenticated /api/v1/internal/tenants* surface, since it mutates a
// tenant that already has real users and data.
type TenantManagementSlugUpdater interface {
	UpdateSlug(ctx context.Context, tenantID uuid.UUID, slug string) (*TenantManagementSlugUpdateResult, error)
}

// LocalTenantSlugWriter writes a confirmed slug into falcon-id's OWN
// iam_tenants row — the projection write-back TenantManagementSlugUpdater
// does NOT do (that call only pushes the slug out to tenant-management).
// Satisfied by *repositories.TenantRepository.UpdateSlug. Narrow single-
// method interface, same pattern as TenantManagementSlugUpdater, so
// ConfirmSlug can be unit-tested against a fake without a real DB.
type LocalTenantSlugWriter interface {
	UpdateSlug(ctx context.Context, tenantID uuid.UUID, slug string) error
}

// OnboardingSlugResult is returned by OnboardingSlugService.ConfirmSlug.
type OnboardingSlugResult struct {
	TenantID uuid.UUID
	Slug     string
	Host     string
}

// OnboardingSlugService backs the onboarding wizard's "choose your
// subdomain" step: PATCH /api/v1/onboarding/slug. It:
//
//  1. Validates the requested slug with the SAME format/reserved-word
//     rules that gate signup-time slug creation (models.IsValidSlug /
//     models.IsReservedSlug — see cmd/signup_adapters.go's identical
//     check), so a renamed slug can never collide with a reserved
//     operator namespace or brand name that a fresh signup couldn't have
//     picked either.
//  2. Persists the rename in tenant-management (the system of record),
//     which separately enforces uniqueness and the slug_confirmed_at
//     immutability gate — see platform-core's TenantService.Update.
//  3. Registers "<slug>.<TenantApexDomain>" in falcon-id's OWN host-
//     discovery as already-verified, via HostDiscoveryService.
//     RegisterVerifiedHost, so the tenant's subdomain resolves
//     immediately without a second, redundant domain-ownership dance
//     (the tenant already proved control of its own onboarding session;
//     there is no separate domain to verify — this is a HexxLock-owned
//     apex, not a customer-owned one, so this is NOT the same trust
//     boundary as domain-management's AddStorefrontSubdomain, which is
//     hardcoded to *.hexxlock.store and exists for CUSTOMER-owned
//     storefront domains).
//
// Step 3 runs BEFORE step 2 on purpose: RegisterVerifiedHost's
// cross-tenant ErrHostClaimed check is cheap and catches a hostname
// collision before tenant-management's write. Since tenant-management's
// own GetBySlug uniqueness check makes a same-string collision on both
// systems at once extremely unlikely (the only way host and slug can
// disagree is a stale/orphaned tenant_host row from a previous, unrelated
// registration), this ordering is a defense-in-depth cheap-check-first
// choice, not a transactional guarantee — there is no cross-service
// transaction spanning falcon-id and tenant-management here.
type OnboardingSlugService struct {
	slugUpdater     TenantManagementSlugUpdater
	localSlugWriter LocalTenantSlugWriter
	hostDiscovery   *HostDiscoveryService
	apexDomain      string
}

// NewOnboardingSlugService exported constructor.
func NewOnboardingSlugService(slugUpdater TenantManagementSlugUpdater, localSlugWriter LocalTenantSlugWriter, hostDiscovery *HostDiscoveryService, apexDomain string) *OnboardingSlugService {
	return &OnboardingSlugService{
		slugUpdater:     slugUpdater,
		localSlugWriter: localSlugWriter,
		hostDiscovery:   hostDiscovery,
		apexDomain:      apexDomain,
	}
}

// ConfirmSlug validates, persists, and activates a tenant's chosen
// subdomain slug. tenantID identifies the CALLER's own tenant — this
// service has no notion of acting on behalf of a different tenant, and
// the HTTP handler MUST NOT accept a caller-supplied tenant ID for this
// endpoint.
func (s *OnboardingSlugService) ConfirmSlug(ctx context.Context, tenantID uuid.UUID, rawSlug string) (*OnboardingSlugResult, error) {
	if s.slugUpdater == nil {
		return nil, fmt.Errorf("OnboardingSlugService: slugUpdater is nil")
	}
	if s.hostDiscovery == nil {
		return nil, fmt.Errorf("OnboardingSlugService: hostDiscovery is nil")
	}
	if s.localSlugWriter == nil {
		return nil, fmt.Errorf("OnboardingSlugService: localSlugWriter is nil")
	}

	// Same authoritative format + reserved-word gate signup already
	// applies (cmd/signup_adapters.go) — collapsed into one generic
	// error for the same slug-tenant-enumeration reason documented on
	// models.ReservedTenantSlugs.
	if !models.IsValidSlug(rawSlug) || models.IsReservedSlug(rawSlug) {
		return nil, fmt.Errorf("onboarding: slug unavailable")
	}

	host := rawSlug + "." + s.apexDomain
	canonicalURL := "https://" + host

	if _, err := s.hostDiscovery.RegisterVerifiedHost(ctx, &RegisterVerifiedHostRequest{
		TenantID:     tenantID,
		Host:         host,
		CanonicalURL: canonicalURL,
	}); err != nil {
		if err == ErrHostClaimed {
			return nil, fmt.Errorf("onboarding: slug unavailable")
		}
		return nil, fmt.Errorf("onboarding: register tenant host: %w", err)
	}

	// Local write-back, BEFORE the push to tenant-management: this is
	// the step that was entirely missing before this fix — nothing in
	// falcon-id ever wrote a confirmed slug into its own iam_tenants
	// row, which is what DiscoverBySlug reads (see its doc comment).
	// Runs after RegisterVerifiedHost (so a slug never gets written
	// locally for a host that failed to register) and before the
	// tenant-management push (so a local collision is caught, and
	// reported as the same "slug unavailable" condition, before
	// tenant-management's own row is renamed).
	if err := s.localSlugWriter.UpdateSlug(ctx, tenantID, rawSlug); err != nil {
		if errors.Is(err, repositories.ErrTenantSlugTaken) {
			return nil, fmt.Errorf("onboarding: slug unavailable")
		}
		return nil, fmt.Errorf("onboarding: persist local slug: %w", err)
	}

	updated, err := s.slugUpdater.UpdateSlug(ctx, tenantID, rawSlug)
	if err != nil {
		return nil, fmt.Errorf("onboarding: persist slug: %w", err)
	}

	return &OnboardingSlugResult{
		TenantID: updated.ID,
		Slug:     updated.Slug,
		Host:     host,
	}, nil
}

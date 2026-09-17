// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// TenantOnboardingStatus is the subset of tenant-management's Tenant this
// caller needs to answer "has this tenant already confirmed its onboarding
// slug?".
type TenantOnboardingStatus struct {
	SlugConfirmed bool
}

// TenantManagementStatusReader reads a tenant's onboarding-relevant status
// from tenant-management (the system of record for slug_confirmed_at).
// Distinct from TenantManagementSlugUpdater: this is a read-only call over
// the platform:tenants:read scope, reused as-is from svc-falcon-id's
// existing ServiceClientClaim grant — no new S2S grant is required.
type TenantManagementStatusReader interface {
	GetTenantOnboardingStatus(ctx context.Context, tenantID uuid.UUID) (*TenantOnboardingStatus, error)
}

// OnboardingStatusService backs the onboarding wizard's entry-time
// re-entry guard: GET /api/v1/auth/onboarding/status.
//
// Why this exists: the wizard previously keyed re-entry solely on a
// client-only draft.completedAt flag (see OnboardingWizard.tsx), which is
// not a real signal — clearing localStorage, a second device, or a second
// browser profile would all incorrectly re-show the wizard. tenant-
// management's slug_confirmed_at is the actual server-side signal (set
// once, immutability-gated — see TenantService.Update), but it is
// deliberately NOT reverse-projected into falcon-id's local iam_tenants
// via Kafka (ADR-0029 restricts that projection to status+metadata only),
// and it is deliberately NOT read from the hot GET /me/settings path
// (unacceptable cross-service coupling on a frequently-hit endpoint).
//
// This service instead does a single live read, scoped to the onboarding
// entry path specifically — called once per wizard-entry, not on every
// request — via the same client_credentials S2S pattern
// OnboardingSlugService already uses to WRITE the slug.
//
// nil-safe: constructed as nil in cmd/services.go when outbound S2S creds
// or TENANT_MANAGEMENT_INTERNAL_URL are unset (fresh initdb / dev-without-
// Vault boots), matching OnboardingSlugService's own fallback posture. In
// that case the /onboarding/status route is not mounted at all (see
// cmd/routes.go::registerOnboardingStatusRoute) rather than mounted behind
// a handler that would always fail.
type OnboardingStatusService struct {
	statusReader TenantManagementStatusReader
}

// NewOnboardingStatusService exported constructor.
func NewOnboardingStatusService(statusReader TenantManagementStatusReader) *OnboardingStatusService {
	return &OnboardingStatusService{statusReader: statusReader}
}

// GetStatus returns the CALLER's own tenant's onboarding status. Like
// OnboardingSlugService.ConfirmSlug, this has no notion of acting on
// behalf of a different tenant — the HTTP handler MUST NOT accept a
// caller-supplied tenant ID for this endpoint.
//
// Failure mode is intentionally fail-closed: any error from
// tenant-management (timeout, 5xx, network) is returned as-is to the
// caller rather than silently falling back to a client-side signal or
// treating the read failure as "not yet onboarded". The handler surfaces
// this as a transient error; the frontend must offer a manual (user-
// driven) retry — never an automatic retry loop, never a permanent
// dead-end block.
func (s *OnboardingStatusService) GetStatus(ctx context.Context, tenantID uuid.UUID) (*TenantOnboardingStatus, error) {
	if s.statusReader == nil {
		return nil, fmt.Errorf("OnboardingStatusService: statusReader is nil")
	}

	status, err := s.statusReader.GetTenantOnboardingStatus(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("onboarding: read tenant status: %w", err)
	}

	return status, nil
}

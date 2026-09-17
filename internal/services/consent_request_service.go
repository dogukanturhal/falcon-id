// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// adminConsentRequestRepo defines the repository methods required by ConsentRequestService.
type adminConsentRequestRepo interface {
	Create(ctx context.Context, req *models.AdminConsentRequest) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.AdminConsentRequest, error)
	Decide(ctx context.Context, id uuid.UUID, approverID uuid.UUID, status models.AdminConsentRequestStatus) error
	ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.AdminConsentRequest, error)
	ListByApplication(ctx context.Context, appID uuid.UUID) ([]models.AdminConsentRequest, error)
	ListPending(ctx context.Context, tenantID uuid.UUID) ([]models.AdminConsentRequest, error)
}

// consentGranter is an optional dependency that auto-grants admin consent when
// a consent request is approved.  AppConsentService satisfies this interface.
type consentGranter interface {
	GrantAdminConsent(ctx context.Context, appID, tenantID, consentedBy uuid.UUID, scopes []string) (*models.AppConsent, error)
}

// ConsentRequestService orchestrates the admin consent workflow.
type ConsentRequestService struct {
	repo           adminConsentRequestRepo
	consentGranter consentGranter // optional; set via SetConsentGranter
}

// NewConsentRequestService creates a new ConsentRequestService.
func NewConsentRequestService(repo adminConsentRequestRepo) *ConsentRequestService {
	return &ConsentRequestService{repo: repo}
}

// SetConsentGranter wires an optional consent granter so that approving a request
// also automatically calls GrantAdminConsent.
func (s *ConsentRequestService) SetConsentGranter(g consentGranter) {
	s.consentGranter = g
}

// CreateRequest submits a new consent request on behalf of a requester within a tenant.
func (s *ConsentRequestService) CreateRequest(
	ctx context.Context,
	tenantID uuid.UUID,
	requesterID uuid.UUID,
	input models.CreateAdminConsentRequestInput,
) (*models.AdminConsentRequest, error) {
	cr := &models.AdminConsentRequest{
		ApplicationID:   input.ApplicationID,
		TenantID:        tenantID,
		RequesterID:     requesterID,
		RequestedScopes: input.RequestedScopes,
		Justification:   input.Justification,
		Status:          models.AdminConsentRequestStatusPending,
	}

	if err := s.repo.Create(ctx, cr); err != nil {
		return nil, fmt.Errorf("ConsentRequestService.CreateRequest: %w", err)
	}
	return cr, nil
}

// ApproveRequest transitions a pending consent request to approved and,
// when a consentGranter is wired, automatically calls GrantAdminConsent.
func (s *ConsentRequestService) ApproveRequest(
	ctx context.Context,
	requestID uuid.UUID,
	approverID uuid.UUID,
) (*models.AdminConsentRequest, error) {
	cr, err := s.repo.GetByID(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("ConsentRequestService.ApproveRequest: %w", err)
	}
	if cr == nil {
		return nil, fmt.Errorf("ConsentRequestService.ApproveRequest: consent request not found")
	}
	if cr.Status != models.AdminConsentRequestStatusPending {
		return nil, fmt.Errorf("ConsentRequestService.ApproveRequest: request is already %s", cr.Status)
	}

	if err := s.repo.Decide(ctx, requestID, approverID, models.AdminConsentRequestStatusApproved); err != nil {
		return nil, fmt.Errorf("ConsentRequestService.ApproveRequest: %w", err)
	}

	// Refresh to pick up decided_at / approver_id populated by the database.
	cr, err = s.repo.GetByID(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("ConsentRequestService.ApproveRequest: reload: %w", err)
	}

	// Auto-grant admin consent when the granter is available.
	if s.consentGranter != nil {
		if _, grantErr := s.consentGranter.GrantAdminConsent(ctx, cr.ApplicationID, cr.TenantID, approverID, cr.RequestedScopes); grantErr != nil {
			// Non-fatal: the workflow request is already approved; the caller can
			// retry granting consent separately if this fails.
			_ = grantErr
		}
	}

	return cr, nil
}

// DenyRequest transitions a pending consent request to denied.
func (s *ConsentRequestService) DenyRequest(
	ctx context.Context,
	requestID uuid.UUID,
	approverID uuid.UUID,
) (*models.AdminConsentRequest, error) {
	cr, err := s.repo.GetByID(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("ConsentRequestService.DenyRequest: %w", err)
	}
	if cr == nil {
		return nil, fmt.Errorf("ConsentRequestService.DenyRequest: consent request not found")
	}
	if cr.Status != models.AdminConsentRequestStatusPending {
		return nil, fmt.Errorf("ConsentRequestService.DenyRequest: request is already %s", cr.Status)
	}

	if err := s.repo.Decide(ctx, requestID, approverID, models.AdminConsentRequestStatusDenied); err != nil {
		return nil, fmt.Errorf("ConsentRequestService.DenyRequest: %w", err)
	}

	cr, err = s.repo.GetByID(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("ConsentRequestService.DenyRequest: reload: %w", err)
	}
	return cr, nil
}

// ListPending returns all pending consent requests for a tenant.
func (s *ConsentRequestService) ListPending(ctx context.Context, tenantID uuid.UUID) ([]models.AdminConsentRequest, error) {
	results, err := s.repo.ListPending(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ConsentRequestService.ListPending: %w", err)
	}
	return results, nil
}

// ListByApplication returns all consent requests for an application.
func (s *ConsentRequestService) ListByApplication(ctx context.Context, appID uuid.UUID) ([]models.AdminConsentRequest, error) {
	results, err := s.repo.ListByApplication(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("ConsentRequestService.ListByApplication: %w", err)
	}
	return results, nil
}

// ListByTenant returns all consent requests for a tenant.
func (s *ConsentRequestService) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.AdminConsentRequest, error) {
	results, err := s.repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ConsentRequestService.ListByTenant: %w", err)
	}
	return results, nil
}

// GetRequest returns a single consent request by ID.
func (s *ConsentRequestService) GetRequest(ctx context.Context, id uuid.UUID) (*models.AdminConsentRequest, error) {
	cr, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("ConsentRequestService.GetRequest: %w", err)
	}
	if cr == nil {
		return nil, fmt.Errorf("ConsentRequestService.GetRequest: consent request not found")
	}
	return cr, nil
}

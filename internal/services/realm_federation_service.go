// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// realmFedRepo narrows the repository surface needed by RealmFederationService.
type realmFedRepo interface {
	Create(ctx context.Context, t *models.RealmFederationTrust) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.RealmFederationTrust, error)
	GetByRealms(ctx context.Context, sourceRealmID, targetRealmID uuid.UUID) (*models.RealmFederationTrust, error)
	List(ctx context.Context, filter models.FederationTrustListFilter) ([]*models.RealmFederationTrust, int64, error)
	Update(ctx context.Context, t *models.RealmFederationTrust) error
	Delete(ctx context.Context, id uuid.UUID) error
	AddAuditEntry(ctx context.Context, entry *models.RealmFederationAudit) error
}

// RealmFederationService manages cross-realm trust relationships.
type RealmFederationService struct {
	fedRepo      realmFedRepo
	auditService *AuditService
}

// NewRealmFederationService constructs a RealmFederationService.
func NewRealmFederationService(
	fedRepo *repositories.RealmFederationRepository,
	auditService *AuditService,
) *RealmFederationService {
	return &RealmFederationService{
		fedRepo:      fedRepo,
		auditService: auditService,
	}
}

// CreateTrust creates a pending federation trust between two realms.
func (s *RealmFederationService) CreateTrust(ctx context.Context, req *models.CreateFederationTrustRequest, requestedBy uuid.UUID) (*models.FederationTrustResponse, error) {
	if req.SourceRealmID == req.TargetRealmID {
		return nil, fmt.Errorf("source and target realms must be different")
	}

	// Prevent duplicate trusts in the same direction
	existing, err := s.fedRepo.GetByRealms(ctx, req.SourceRealmID, req.TargetRealmID)
	if err != nil {
		return nil, fmt.Errorf("RealmFederationService.CreateTrust: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("a federation trust already exists between these realms")
	}

	trustType := req.TrustType
	if trustType == "" {
		trustType = models.FederationTrustTypeUnidirectional
	}
	trustLevel := req.TrustLevel
	if trustLevel == "" {
		trustLevel = models.FederationTrustLevelLimited
	}

	trust := &models.RealmFederationTrust{
		SourceRealmID:         req.SourceRealmID,
		TargetRealmID:         req.TargetRealmID,
		TrustType:             trustType,
		TrustLevel:            trustLevel,
		AllowedTenantTypes:    req.AllowedTenantTypes,
		MaxGuestUsers:         req.MaxGuestUsers,
		RequireMFA:            req.RequireMFA,
		AllowedRoles:          req.AllowedRoles,
		TokenLifetimeOverride: req.TokenLifetimeOverride,
		ScopeRestrictions:     req.ScopeRestrictions,
		Status:                models.FederationTrustStatusPending,
		RequestedBy:           requestedBy,
	}
	if req.Description != "" {
		trust.Description = &req.Description
	}

	if err := s.fedRepo.Create(ctx, trust); err != nil {
		logger.Error("RealmFederationService.CreateTrust: failed to create trust", zap.Error(err))
		return nil, fmt.Errorf("failed to create federation trust")
	}

	s.writeAudit(ctx, trust.ID, requestedBy, "created", nil, trust)

	logger.Info("Realm federation trust created",
		zap.String("trust_id", trust.ID.String()),
		zap.String("source_realm", req.SourceRealmID.String()),
		zap.String("target_realm", req.TargetRealmID.String()),
	)

	return trust.ToResponse(), nil
}

// ListTrusts returns a paginated list of federation trusts.
func (s *RealmFederationService) ListTrusts(ctx context.Context, filter models.FederationTrustListFilter) (*models.FederationTrustListResponse, error) {
	trusts, total, err := s.fedRepo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("RealmFederationService.ListTrusts: %w", err)
	}

	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	page := filter.Page
	if page < 1 {
		page = 1
	}
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	responses := make([]*models.FederationTrustResponse, len(trusts))
	for i, t := range trusts {
		responses[i] = t.ToResponse()
	}

	return &models.FederationTrustListResponse{
		Trusts:     responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// GetTrust retrieves a single federation trust by ID.
func (s *RealmFederationService) GetTrust(ctx context.Context, id uuid.UUID) (*models.FederationTrustResponse, error) {
	trust, err := s.fedRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("RealmFederationService.GetTrust: %w", err)
	}
	if trust == nil {
		return nil, nil
	}
	return trust.ToResponse(), nil
}

// UpdateTrust applies mutable changes to a federation trust.
func (s *RealmFederationService) UpdateTrust(ctx context.Context, id uuid.UUID, req *models.UpdateFederationTrustRequest, actorID uuid.UUID) (*models.FederationTrustResponse, error) {
	trust, err := s.fedRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve trust")
	}
	if trust == nil {
		return nil, fmt.Errorf("federation trust not found")
	}

	if req.TrustType != nil {
		trust.TrustType = *req.TrustType
	}
	if req.TrustLevel != nil {
		trust.TrustLevel = *req.TrustLevel
	}
	if req.Description != nil {
		trust.Description = req.Description
	}
	if req.RequireMFA != nil {
		trust.RequireMFA = *req.RequireMFA
	}
	if req.MaxGuestUsers != nil {
		trust.MaxGuestUsers = req.MaxGuestUsers
	}
	if req.AllowedRoles != nil {
		trust.AllowedRoles = req.AllowedRoles
	}
	if req.TokenLifetimeOverride != nil {
		trust.TokenLifetimeOverride = req.TokenLifetimeOverride
	}
	if req.ScopeRestrictions != nil {
		trust.ScopeRestrictions = req.ScopeRestrictions
	}
	if req.AllowedTenantTypes != nil {
		trust.AllowedTenantTypes = req.AllowedTenantTypes
	}

	if err := s.fedRepo.Update(ctx, trust); err != nil {
		logger.Error("RealmFederationService.UpdateTrust: failed to update trust", zap.Error(err))
		return nil, fmt.Errorf("failed to update federation trust")
	}

	s.writeAudit(ctx, id, actorID, "updated", nil, trust)
	return trust.ToResponse(), nil
}

// ApproveTrust activates a pending federation trust.
func (s *RealmFederationService) ApproveTrust(ctx context.Context, id uuid.UUID, req *models.ApproveFederationTrustRequest, approvedBy uuid.UUID) (*models.FederationTrustResponse, error) {
	trust, err := s.fedRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve trust")
	}
	if trust == nil {
		return nil, fmt.Errorf("federation trust not found")
	}
	if trust.Status != models.FederationTrustStatusPending {
		return nil, fmt.Errorf("only pending trusts can be approved (current status: %s)", trust.Status)
	}

	now := time.Now()
	trust.Status = models.FederationTrustStatusActive
	trust.ApprovedBy = &approvedBy
	trust.EstablishedAt = &now

	if err := s.fedRepo.Update(ctx, trust); err != nil {
		logger.Error("RealmFederationService.ApproveTrust: failed to update trust", zap.Error(err))
		return nil, fmt.Errorf("failed to approve trust")
	}

	s.writeAuditWithReason(ctx, id, approvedBy, "approved", nil, trust, req.Reason)

	logger.Info("Realm federation trust approved",
		zap.String("trust_id", id.String()),
		zap.String("approved_by", approvedBy.String()),
	)

	return trust.ToResponse(), nil
}

// SuspendTrust suspends an active federation trust.
func (s *RealmFederationService) SuspendTrust(ctx context.Context, id uuid.UUID, req *models.SuspendFederationTrustRequest, actorID uuid.UUID) (*models.FederationTrustResponse, error) {
	trust, err := s.fedRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve trust")
	}
	if trust == nil {
		return nil, fmt.Errorf("federation trust not found")
	}
	if trust.Status != models.FederationTrustStatusActive {
		return nil, fmt.Errorf("only active trusts can be suspended")
	}

	trust.Status = models.FederationTrustStatusSuspended
	if err := s.fedRepo.Update(ctx, trust); err != nil {
		logger.Error("RealmFederationService.SuspendTrust: failed to update trust", zap.Error(err))
		return nil, fmt.Errorf("failed to suspend trust")
	}

	s.writeAuditWithReason(ctx, id, actorID, "suspended", nil, trust, req.Reason)

	logger.Info("Realm federation trust suspended",
		zap.String("trust_id", id.String()),
	)
	return trust.ToResponse(), nil
}

// DeleteTrust hard-deletes a federation trust.
func (s *RealmFederationService) DeleteTrust(ctx context.Context, id uuid.UUID, actorID uuid.UUID) error {
	trust, err := s.fedRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to retrieve trust")
	}
	if trust == nil {
		return fmt.Errorf("federation trust not found")
	}

	if err := s.fedRepo.Delete(ctx, id); err != nil {
		logger.Error("RealmFederationService.DeleteTrust: failed to delete trust", zap.Error(err))
		return fmt.Errorf("failed to delete federation trust")
	}

	logger.Info("Realm federation trust deleted",
		zap.String("trust_id", id.String()),
		zap.String("actor_id", actorID.String()),
	)
	return nil
}

// writeAudit is a convenience wrapper for trust mutation events without a reason.
func (s *RealmFederationService) writeAudit(ctx context.Context, trustID, actorID uuid.UUID, action string, oldVal, newVal interface{}) {
	s.writeAuditWithReason(ctx, trustID, actorID, action, oldVal, newVal, "")
}

// writeAuditWithReason appends an audit entry, swallowing errors to avoid blocking mutations.
func (s *RealmFederationService) writeAuditWithReason(ctx context.Context, trustID, actorID uuid.UUID, action string, _, _ interface{}, reason string) {
	entry := &models.RealmFederationAudit{
		TrustID: trustID,
		ActorID: actorID,
		Action:  action,
	}
	if reason != "" {
		entry.Reason = &reason
	}
	if err := s.fedRepo.AddAuditEntry(ctx, entry); err != nil {
		logger.Warn("RealmFederationService: failed to write audit entry",
			zap.String("action", action), zap.Error(err))
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Repository interfaces
// ---------------------------------------------------------------------------

// accessReviewRepo is the persistence contract for campaigns and review items.
type accessReviewRepo interface {
	CreateCampaign(ctx context.Context, c *models.AccessReviewCampaign) error
	GetCampaignByID(ctx context.Context, campaignID, tenantID uuid.UUID) (*models.AccessReviewCampaign, error)
	ListCampaigns(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]*models.AccessReviewCampaign, int64, error)
	UpdateCampaignStatus(ctx context.Context, campaignID uuid.UUID, status models.AccessReviewCampaignStatus) error
	CreateReviewItems(ctx context.Context, items []*models.AccessReviewItem) error
	GetReviewItem(ctx context.Context, itemID, tenantID uuid.UUID) (*models.AccessReviewItem, error)
	ListPendingItems(ctx context.Context, reviewerID, tenantID uuid.UUID) ([]*models.AccessReviewItem, error)
	SubmitDecision(ctx context.Context, itemID uuid.UUID, decision models.ReviewDecision, justification string) error
	GetCampaignStats(ctx context.Context, campaignID uuid.UUID) (*models.AccessReviewCampaignStats, error)
	ListExpiredPendingItems(ctx context.Context, campaignID uuid.UUID) ([]*models.AccessReviewItem, error)
}

// accessReviewRoleRepo provides the role-assignment snapshot used to seed review items.
type accessReviewRoleRepo interface {
	// ListUserRoleAssignments returns (userID, roleID, roleName) triples for the given tenant.
	ListUserRoleAssignments(ctx context.Context, tenantID uuid.UUID) ([]UserRoleAssignment, error)
}

// accessReviewGroupRepo provides group-membership snapshots for seeding review items.
type accessReviewGroupRepo interface {
	// ListUserGroupMemberships returns (userID, groupID, groupName) triples for the given tenant.
	ListUserGroupMemberships(ctx context.Context, tenantID uuid.UUID) ([]UserGroupMembership, error)
}

// UserRoleAssignment is a DTO representing a single user-to-role binding.
type UserRoleAssignment struct {
	UserID   uuid.UUID
	RoleID   uuid.UUID
	RoleName string
}

// UserGroupMembership is a DTO representing a single user-to-group binding.
type UserGroupMembership struct {
	UserID    uuid.UUID
	GroupID   uuid.UUID
	GroupName string
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// AccessReviewService orchestrates access review campaigns: creation, item
// seeding, decision submission, and finalization.
type AccessReviewService struct {
	repo         accessReviewRepo
	roleRepo     accessReviewRoleRepo
	groupRepo    accessReviewGroupRepo
	auditService *AuditService
	logger       *zap.Logger
}

// NewAccessReviewService creates a new AccessReviewService.
func NewAccessReviewService(
	repo accessReviewRepo,
	roleRepo accessReviewRoleRepo,
	groupRepo accessReviewGroupRepo,
	auditService *AuditService,
	logger *zap.Logger,
) *AccessReviewService {
	return &AccessReviewService{
		repo:         repo,
		roleRepo:     roleRepo,
		groupRepo:    groupRepo,
		auditService: auditService,
		logger:       logger,
	}
}

// CreateCampaign creates a new access review campaign and seeds review items from the
// current role/group assignments in the tenant.
func (s *AccessReviewService) CreateCampaign(
	ctx context.Context,
	tenantID, createdBy uuid.UUID,
	req *models.CreateAccessReviewRequest,
) (*models.AccessReviewCampaign, error) {
	if req.DurationDays <= 0 || req.DurationDays > 365 {
		return nil, fmt.Errorf("duration_days must be between 1 and 365")
	}

	validResourceTypes := map[string]bool{auditResourceTypeRole: true, "group": true, "permission": true}
	if !validResourceTypes[req.ResourceType] {
		return nil, fmt.Errorf("invalid resource_type %q: must be one of role, group, permission", req.ResourceType)
	}

	startsAt, err := time.Parse(time.RFC3339, req.StartsAt)
	if err != nil {
		return nil, fmt.Errorf("invalid starts_at format, expected RFC3339: %w", err)
	}
	endsAt := startsAt.Add(time.Duration(req.DurationDays) * 24 * time.Hour)

	campaign := &models.AccessReviewCampaign{
		TenantID:     tenantID,
		Name:         req.Name,
		Description:  req.Description,
		ResourceType: req.ResourceType,
		ReviewerType: req.ReviewerType,
		Frequency:    req.Frequency,
		DurationDays: req.DurationDays,
		AutoRevoke:   req.AutoRevoke,
		Status:       models.CampaignStatusActive,
		StartsAt:     startsAt,
		EndsAt:       endsAt,
		CreatedBy:    createdBy,
	}

	if err := s.repo.CreateCampaign(ctx, campaign); err != nil {
		return nil, fmt.Errorf("AccessReviewService.CreateCampaign persist: %w", err)
	}

	// Seed review items based on current assignments.
	items, err := s.generateReviewItems(ctx, campaign)
	if err != nil {
		s.logger.Warn("Failed to generate review items; campaign created without items",
			zap.String("campaign_id", campaign.ID.String()),
			zap.Error(err),
		)
	} else if len(items) > 0 {
		if err := s.repo.CreateReviewItems(ctx, items); err != nil {
			return nil, fmt.Errorf("AccessReviewService.CreateCampaign seed items: %w", err)
		}
	}

	s.logger.Info("Access review campaign created",
		zap.String("campaign_id", campaign.ID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("resource_type", req.ResourceType),
		zap.Int("items_seeded", len(items)),
	)

	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, &createdBy, nil,
			"access_review_campaign_created", true, map[string]interface{}{
				"campaign_id":   campaign.ID.String(),
				"campaign_name": campaign.Name,
				"resource_type": campaign.ResourceType,
				"items_seeded":  len(items),
			})
	}

	return campaign, nil
}

// generateReviewItems snapshots current role/group memberships and produces
// one review item per (user, resource) pair.
func (s *AccessReviewService) generateReviewItems(ctx context.Context, campaign *models.AccessReviewCampaign) ([]*models.AccessReviewItem, error) {
	switch campaign.ResourceType {
	case auditResourceTypeRole:
		return s.generateRoleReviewItems(ctx, campaign)
	case "group":
		return s.generateGroupReviewItems(ctx, campaign)
	case "permission":
		// Permission-level review falls back to role assignments as a proxy.
		return s.generateRoleReviewItems(ctx, campaign)
	default:
		return nil, fmt.Errorf("unknown resource_type %q", campaign.ResourceType)
	}
}

func (s *AccessReviewService) generateRoleReviewItems(ctx context.Context, campaign *models.AccessReviewCampaign) ([]*models.AccessReviewItem, error) {
	if s.roleRepo == nil {
		return nil, nil
	}
	assignments, err := s.roleRepo.ListUserRoleAssignments(ctx, campaign.TenantID)
	if err != nil {
		return nil, fmt.Errorf("generateRoleReviewItems: %w", err)
	}

	items := make([]*models.AccessReviewItem, 0, len(assignments))
	for _, a := range assignments {
		// For reviewer_type "self", the user reviews their own access.
		reviewerID := campaign.CreatedBy // default: campaign owner reviews
		if campaign.ReviewerType == "self" {
			reviewerID = a.UserID
		}
		items = append(items, &models.AccessReviewItem{
			CampaignID:   campaign.ID,
			TenantID:     campaign.TenantID,
			UserID:       a.UserID,
			ResourceType: auditResourceTypeRole,
			ResourceID:   a.RoleID,
			ResourceName: a.RoleName,
			ReviewerID:   reviewerID,
			Decision:     models.DecisionPending,
		})
	}
	return items, nil
}

func (s *AccessReviewService) generateGroupReviewItems(ctx context.Context, campaign *models.AccessReviewCampaign) ([]*models.AccessReviewItem, error) {
	if s.groupRepo == nil {
		return nil, nil
	}
	memberships, err := s.groupRepo.ListUserGroupMemberships(ctx, campaign.TenantID)
	if err != nil {
		return nil, fmt.Errorf("generateGroupReviewItems: %w", err)
	}

	items := make([]*models.AccessReviewItem, 0, len(memberships))
	for _, m := range memberships {
		reviewerID := campaign.CreatedBy
		if campaign.ReviewerType == "self" {
			reviewerID = m.UserID
		}
		items = append(items, &models.AccessReviewItem{
			CampaignID:   campaign.ID,
			TenantID:     campaign.TenantID,
			UserID:       m.UserID,
			ResourceType: "group",
			ResourceID:   m.GroupID,
			ResourceName: m.GroupName,
			ReviewerID:   reviewerID,
			Decision:     models.DecisionPending,
		})
	}
	return items, nil
}

// SubmitDecision records an approve/deny decision on a review item. The caller
// must be the assigned reviewer for the item.
func (s *AccessReviewService) SubmitDecision(
	ctx context.Context,
	tenantID, reviewerID, itemID uuid.UUID,
	req *models.SubmitDecisionRequest,
) error {
	item, err := s.repo.GetReviewItem(ctx, itemID, tenantID)
	if err != nil {
		return fmt.Errorf("AccessReviewService.SubmitDecision: %w", err)
	}
	if item == nil {
		return fmt.Errorf("review item %s not found", itemID)
	}

	if item.ReviewerID != reviewerID {
		return fmt.Errorf("reviewer mismatch: item %s is assigned to a different reviewer", itemID)
	}

	if item.Decision != models.DecisionPending {
		return fmt.Errorf("item %s has already been decided (%s)", itemID, item.Decision)
	}

	if err := s.repo.SubmitDecision(ctx, itemID, req.Decision, req.Justification); err != nil {
		return fmt.Errorf("AccessReviewService.SubmitDecision persist: %w", err)
	}

	s.logger.Info("Access review decision submitted",
		zap.String("item_id", itemID.String()),
		zap.String("decision", string(req.Decision)),
		zap.String("reviewer_id", reviewerID.String()),
	)

	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, &reviewerID, &item.UserID,
			"access_review_decision_submitted", true, map[string]interface{}{
				"item_id":       itemID.String(),
				"campaign_id":   item.CampaignID.String(),
				"decision":      string(req.Decision),
				"justification": req.Justification,
				"resource_type": item.ResourceType,
				"resource_id":   item.ResourceID.String(),
			})
	}

	return nil
}

// FinalizeCampaign closes a campaign: if auto_revoke is set, pending items are
// marked expired (triggering downstream revocations in a real system). The
// campaign status is then set to "completed".
func (s *AccessReviewService) FinalizeCampaign(ctx context.Context, campaignID, tenantID uuid.UUID) error {
	campaign, err := s.repo.GetCampaignByID(ctx, campaignID, tenantID)
	if err != nil {
		return fmt.Errorf("AccessReviewService.FinalizeCampaign: %w", err)
	}
	if campaign == nil {
		return fmt.Errorf("campaign %s not found", campaignID)
	}

	if campaign.Status == models.CampaignStatusCompleted {
		return fmt.Errorf("campaign %s is already completed", campaignID)
	}
	if campaign.Status == models.CampaignStatusCancelled {
		return fmt.Errorf("campaign %s is cancelled and cannot be finalized", campaignID)
	}

	if campaign.AutoRevoke {
		pending, err := s.repo.ListExpiredPendingItems(ctx, campaignID)
		if err != nil {
			return fmt.Errorf("AccessReviewService.FinalizeCampaign list pending: %w", err)
		}

		for _, item := range pending {
			if err := s.repo.SubmitDecision(ctx, item.ID, models.DecisionExpired, "auto-expired on campaign finalization"); err != nil {
				s.logger.Warn("Failed to expire pending review item",
					zap.String("item_id", item.ID.String()),
					zap.Error(err),
				)
			}
		}

		s.logger.Info("Auto-expired pending review items",
			zap.String("campaign_id", campaignID.String()),
			zap.Int("count", len(pending)),
		)
	}

	if err := s.repo.UpdateCampaignStatus(ctx, campaignID, models.CampaignStatusCompleted); err != nil {
		return fmt.Errorf("AccessReviewService.FinalizeCampaign update status: %w", err)
	}

	s.logger.Info("Access review campaign finalized",
		zap.String("campaign_id", campaignID.String()),
		zap.Bool("auto_revoke", campaign.AutoRevoke),
	)

	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, nil, nil,
			"access_review_campaign_finalized", true, map[string]interface{}{
				"campaign_id": campaignID.String(),
				"auto_revoke": campaign.AutoRevoke,
			})
	}

	return nil
}

// GetCampaignDetails returns the campaign together with aggregate stats.
func (s *AccessReviewService) GetCampaignDetails(ctx context.Context, campaignID, tenantID uuid.UUID) (*models.AccessReviewCampaignResponse, error) {
	campaign, err := s.repo.GetCampaignByID(ctx, campaignID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("AccessReviewService.GetCampaignDetails: %w", err)
	}
	if campaign == nil {
		return nil, nil
	}

	stats, err := s.repo.GetCampaignStats(ctx, campaignID)
	if err != nil {
		// Non-fatal: return campaign without stats.
		s.logger.Warn("Failed to retrieve campaign stats",
			zap.String("campaign_id", campaignID.String()),
			zap.Error(err),
		)
		return &models.AccessReviewCampaignResponse{AccessReviewCampaign: campaign}, nil
	}

	return &models.AccessReviewCampaignResponse{
		AccessReviewCampaign: campaign,
		Stats:                stats,
	}, nil
}

// ListCampaigns returns a paginated list of campaigns for a tenant.
func (s *AccessReviewService) ListCampaigns(
	ctx context.Context,
	tenantID uuid.UUID,
	status string,
	page, pageSize int,
) ([]*models.AccessReviewCampaign, int64, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}

	campaigns, total, err := s.repo.ListCampaigns(ctx, tenantID, status, page, pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("AccessReviewService.ListCampaigns: %w", err)
	}
	return campaigns, total, nil
}

// ListPendingItems returns all pending review items assigned to the given reviewer.
func (s *AccessReviewService) ListPendingItems(
	ctx context.Context,
	reviewerID, tenantID uuid.UUID,
) ([]*models.AccessReviewItem, error) {
	items, err := s.repo.ListPendingItems(ctx, reviewerID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("AccessReviewService.ListPendingItems: %w", err)
	}
	return items, nil
}

// GetOverdueCampaigns returns all active campaigns that have passed their end
// date without being finalized or completed.
func (s *AccessReviewService) GetOverdueCampaigns(ctx context.Context) ([]*models.AccessReviewCampaign, error) {
	// Use a zero-value tenantID to signal a cross-tenant query via ListCampaigns.
	// We fetch all active campaigns using a large page size to avoid pagination issues
	// in the background job context.
	campaigns, _, err := s.repo.ListCampaigns(ctx, uuid.Nil, string(models.CampaignStatusActive), 1, 10000)
	if err != nil {
		return nil, fmt.Errorf("GetOverdueCampaigns: failed to list active campaigns: %w", err)
	}

	now := time.Now()
	var overdue []*models.AccessReviewCampaign
	for _, c := range campaigns {
		if c.EndsAt.Before(now) {
			overdue = append(overdue, c)
		}
	}
	return overdue, nil
}

// AutoFinalizeOverdue is a background job method that finalizes all campaigns
// whose end date has passed. For each overdue campaign, it calls FinalizeCampaign
// which respects the campaign's auto_revoke setting. Returns the count of
// successfully finalized campaigns.
func (s *AccessReviewService) AutoFinalizeOverdue(ctx context.Context) (int, error) {
	overdue, err := s.GetOverdueCampaigns(ctx)
	if err != nil {
		return 0, fmt.Errorf("AutoFinalizeOverdue: %w", err)
	}

	finalized := 0
	for _, campaign := range overdue {
		if err := s.FinalizeCampaign(ctx, campaign.ID, campaign.TenantID); err != nil {
			s.logger.Warn("Failed to auto-finalize overdue campaign",
				zap.String("campaign_id", campaign.ID.String()),
				zap.Error(err),
			)
			continue
		}

		if s.auditService != nil {
			s.auditService.LogUserAction(ctx, campaign.TenantID, nil, nil,
				"access_review.auto_finalized", true, map[string]interface{}{
					"campaign_id": campaign.ID.String(),
					"reason":      "overdue_deadline",
				})
		}

		finalized++
	}

	return finalized, nil
}

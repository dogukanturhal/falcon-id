// SPDX-License-Identifier: AGPL-3.0-or-later

// Package models defines domain models and data structures.
package models

import (
	"time"

	"github.com/google/uuid"
)

// AccessReviewCampaignStatus represents the lifecycle state of a campaign.
type AccessReviewCampaignStatus string

const (
	// CampaignStatusPending is an exported identifier.
	CampaignStatusPending AccessReviewCampaignStatus = "pending"
	// CampaignStatusActive is an exported identifier.
	CampaignStatusActive AccessReviewCampaignStatus = "active"
	// CampaignStatusCompleted is an exported identifier.
	CampaignStatusCompleted AccessReviewCampaignStatus = "completed"
	// CampaignStatusCancelled is an exported identifier.
	CampaignStatusCancelled AccessReviewCampaignStatus = "cancelled"
)

// ReviewDecision represents the outcome of a reviewer's decision on an item.
type ReviewDecision string

const (
	// DecisionPending is an exported identifier.
	DecisionPending ReviewDecision = "pending"
	// DecisionApproved is an exported identifier.
	DecisionApproved ReviewDecision = "approved"
	// DecisionDenied is an exported identifier.
	DecisionDenied ReviewDecision = "denied"
	// DecisionExpired is an exported identifier.
	DecisionExpired ReviewDecision = "expired"
)

// AccessReviewCampaign is the top-level container for an access review cycle.
type AccessReviewCampaign struct {
	ID           uuid.UUID                  `json:"id" db:"id"`
	TenantID     uuid.UUID                  `json:"tenant_id" db:"tenant_id"`
	Name         string                     `json:"name" db:"name"`
	Description  string                     `json:"description" db:"description"`
	ResourceType string                     `json:"resource_type" db:"resource_type"` // "role", "group", "permission"
	ReviewerType string                     `json:"reviewer_type" db:"reviewer_type"` // "manager", "resource_owner", "self"
	Frequency    string                     `json:"frequency" db:"frequency"`         // "one_time", "quarterly", "annual"
	DurationDays int                        `json:"duration_days" db:"duration_days"`
	AutoRevoke   bool                       `json:"auto_revoke" db:"auto_revoke"`
	Status       AccessReviewCampaignStatus `json:"status" db:"status"`
	StartsAt     time.Time                  `json:"starts_at" db:"starts_at"`
	EndsAt       time.Time                  `json:"ends_at" db:"ends_at"`
	CreatedBy    uuid.UUID                  `json:"created_by" db:"created_by"`
	CreatedAt    time.Time                  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time                  `json:"updated_at" db:"updated_at"`
}

// AccessReviewItem represents a single access assertion that a reviewer must decide on.
type AccessReviewItem struct {
	ID            uuid.UUID      `json:"id" db:"id"`
	CampaignID    uuid.UUID      `json:"campaign_id" db:"campaign_id"`
	TenantID      uuid.UUID      `json:"tenant_id" db:"tenant_id"`
	UserID        uuid.UUID      `json:"user_id" db:"user_id"`
	ResourceType  string         `json:"resource_type" db:"resource_type"`
	ResourceID    uuid.UUID      `json:"resource_id" db:"resource_id"`
	ResourceName  string         `json:"resource_name" db:"resource_name"`
	ReviewerID    uuid.UUID      `json:"reviewer_id" db:"reviewer_id"`
	Decision      ReviewDecision `json:"decision" db:"decision"`
	Justification string         `json:"justification" db:"justification"`
	DecidedAt     *time.Time     `json:"decided_at" db:"decided_at"`
	CreatedAt     time.Time      `json:"created_at" db:"created_at"`
}

// AccessReviewCampaignStats holds aggregate counts for a campaign.
type AccessReviewCampaignStats struct {
	TotalItems    int `json:"total_items"`
	PendingItems  int `json:"pending_items"`
	ApprovedItems int `json:"approved_items"`
	DeniedItems   int `json:"denied_items"`
	ExpiredItems  int `json:"expired_items"`
}

// CreateAccessReviewRequest is the DTO for creating a new campaign.
type CreateAccessReviewRequest struct {
	Name         string `json:"name" binding:"required,min=1,max=255"`
	Description  string `json:"description"`
	ResourceType string `json:"resource_type" binding:"required,oneof=role group permission"`
	ReviewerType string `json:"reviewer_type" binding:"required,oneof=manager resource_owner self"`
	Frequency    string `json:"frequency" binding:"required,oneof=one_time quarterly annual"`
	DurationDays int    `json:"duration_days" binding:"required,min=1,max=365"`
	AutoRevoke   bool   `json:"auto_revoke"`
	StartsAt     string `json:"starts_at" binding:"required"` // RFC3339
}

// SubmitDecisionRequest is the DTO for approving or denying a review item.
type SubmitDecisionRequest struct {
	Decision      ReviewDecision `json:"decision" binding:"required,oneof=approved denied"`
	Justification string         `json:"justification"`
}

// AccessReviewCampaignResponse is the full campaign response including stats.
type AccessReviewCampaignResponse struct {
	*AccessReviewCampaign
	Stats *AccessReviewCampaignStats `json:"stats,omitempty"`
}

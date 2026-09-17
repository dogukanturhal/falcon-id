// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ProvisioningState represents the lifecycle state of a product instance.
type ProvisioningState string

const (
	// ProvisioningStatePending is an exported identifier.
	ProvisioningStatePending ProvisioningState = "pending"
	// ProvisioningStateCreating is an exported identifier.
	ProvisioningStateCreating ProvisioningState = "creating"
	// ProvisioningStateMigrating is an exported identifier.
	ProvisioningStateMigrating ProvisioningState = "migrating"
	// ProvisioningStateSeeding is an exported identifier.
	ProvisioningStateSeeding ProvisioningState = "seeding"
	// ProvisioningStateConfiguringAuth is an exported identifier.
	ProvisioningStateConfiguringAuth ProvisioningState = "configuring_auth"
	// ProvisioningStateRegisteringService is an exported identifier.
	ProvisioningStateRegisteringService ProvisioningState = "registering_service"
	// ProvisioningStateActive is an exported identifier.
	ProvisioningStateActive ProvisioningState = "active"
	// ProvisioningStateFailed is an exported identifier.
	ProvisioningStateFailed ProvisioningState = "failed"
	// ProvisioningStateDeleting is an exported identifier.
	ProvisioningStateDeleting ProvisioningState = "deleting"
	// ProvisioningStateDeleted is an exported identifier.
	ProvisioningStateDeleted ProvisioningState = "deleted"
)

// ProvisioningSteps defines the ordered list of provisioning steps for
// forward progress.  The reconciler uses this to determine the next step.
var ProvisioningSteps = []ProvisioningState{
	ProvisioningStatePending,
	ProvisioningStateCreating,
	ProvisioningStateMigrating,
	ProvisioningStateSeeding,
	ProvisioningStateConfiguringAuth,
	ProvisioningStateRegisteringService,
	ProvisioningStateActive,
}

// IsTerminal returns true if the state cannot transition forward.
func (s ProvisioningState) IsTerminal() bool {
	return s == ProvisioningStateActive || s == ProvisioningStateFailed || s == ProvisioningStateDeleted
}

// ProductInstance represents a provisioned product for a specific tenant.
// Each row in iam_product_instances tracks the full provisioning lifecycle.
type ProductInstance struct {
	ID                   uuid.UUID         `json:"id" db:"id"`
	TenantID             uuid.UUID         `json:"tenant_id" db:"tenant_id"`
	ProductID            uuid.UUID         `json:"product_id" db:"product_id"`
	PlanID               *string           `json:"plan_id,omitempty" db:"plan_id"`
	ProvisioningState    ProvisioningState `json:"provisioning_state" db:"provisioning_state"`
	DatabaseHost         *string           `json:"database_host,omitempty" db:"database_host"`
	DatabaseName         *string           `json:"database_name,omitempty" db:"database_name"`
	DatabaseSchema       *string           `json:"database_schema,omitempty" db:"database_schema"`
	DatabaseUsername     *string           `json:"database_username,omitempty" db:"database_username"`
	ConnectionStringEnc  []byte            `json:"-" db:"connection_string_enc"`
	LastMigrationVersion int               `json:"last_migration_version" db:"last_migration_version"`
	CurrentStep          *string           `json:"current_step,omitempty" db:"current_step"`
	CompletedSteps       []string          `json:"completed_steps" db:"completed_steps"`
	FailureReason        *string           `json:"failure_reason,omitempty" db:"failure_reason"`
	RetryCount           int               `json:"retry_count" db:"retry_count"`
	MaxRetriesExhausted  bool              `json:"max_retries_exhausted" db:"max_retries_exhausted"`
	NextRetryAt          *time.Time        `json:"next_retry_at,omitempty" db:"next_retry_at"`
	ProvisionedAt        *time.Time        `json:"provisioned_at,omitempty" db:"provisioned_at"`
	CreatedAt            time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at" db:"updated_at"`
}

// IsActive returns true when the instance is fully provisioned and operational.
func (pi *ProductInstance) IsActive() bool {
	return pi.ProvisioningState == ProvisioningStateActive
}

// IsFailed returns true when the provisioning has failed.
func (pi *ProductInstance) IsFailed() bool {
	return pi.ProvisioningState == ProvisioningStateFailed
}

// ==================== Request DTOs ====================

// CreateProductInstanceRequest is the payload for provisioning a product for a tenant.
type CreateProductInstanceRequest struct {
	TenantID uuid.UUID `json:"tenant_id" binding:"required"`
	PlanID   *string   `json:"plan_id"`
}

// ==================== Response DTOs ====================

// ProductInstanceResponse is the API representation of a product instance.
type ProductInstanceResponse struct {
	ID                  uuid.UUID         `json:"id"`
	TenantID            uuid.UUID         `json:"tenant_id"`
	ProductID           uuid.UUID         `json:"product_id"`
	PlanID              *string           `json:"plan_id,omitempty"`
	ProvisioningState   ProvisioningState `json:"provisioning_state"`
	DatabaseHost        *string           `json:"database_host,omitempty"`
	DatabaseName        *string           `json:"database_name,omitempty"`
	CurrentStep         *string           `json:"current_step,omitempty"`
	CompletedSteps      []string          `json:"completed_steps"`
	FailureReason       *string           `json:"failure_reason,omitempty"`
	RetryCount          int               `json:"retry_count"`
	MaxRetriesExhausted bool              `json:"max_retries_exhausted"`
	NextRetryAt         *time.Time        `json:"next_retry_at,omitempty"`
	ProvisionedAt       *time.Time        `json:"provisioned_at,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

// ProductInstanceListResponse is the paginated list of product instances.
type ProductInstanceListResponse struct {
	Instances  []ProductInstanceResponse `json:"instances"`
	Total      int64                     `json:"total"`
	Page       int                       `json:"page"`
	PageSize   int                       `json:"page_size"`
	TotalPages int                       `json:"total_pages"`
}

// ToResponse converts a ProductInstance to its API representation.
func (pi *ProductInstance) ToResponse() *ProductInstanceResponse {
	steps := make([]string, 0, len(pi.CompletedSteps))
	steps = append(steps, pi.CompletedSteps...)
	return &ProductInstanceResponse{
		ID:                  pi.ID,
		TenantID:            pi.TenantID,
		ProductID:           pi.ProductID,
		PlanID:              pi.PlanID,
		ProvisioningState:   pi.ProvisioningState,
		DatabaseHost:        pi.DatabaseHost,
		DatabaseName:        pi.DatabaseName,
		CurrentStep:         pi.CurrentStep,
		CompletedSteps:      steps,
		FailureReason:       pi.FailureReason,
		RetryCount:          pi.RetryCount,
		MaxRetriesExhausted: pi.MaxRetriesExhausted,
		NextRetryAt:         pi.NextRetryAt,
		ProvisionedAt:       pi.ProvisionedAt,
		CreatedAt:           pi.CreatedAt,
		UpdatedAt:           pi.UpdatedAt,
	}
}

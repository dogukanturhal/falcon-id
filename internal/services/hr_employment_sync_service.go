// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

var (
	ErrInvalidHREmploymentScope        = errors.New("invalid HR sync scope")
	ErrInvalidHREmploymentDesiredState = errors.New("invalid HR employment desired state")
)

// HREmploymentSyncService applies only source-owned employment facts. It never changes a regular user's seat or roles.
type HREmploymentSyncService struct { sync *repositories.HREmploymentSyncRepository; users *repositories.UserRepository; userService *UserService; memberships *repositories.UserMembershipRepository; provisioner *TemplateRoleProvisioner; bootstrap *TenantBootstrapService }
func NewHREmploymentSyncService(sync *repositories.HREmploymentSyncRepository, users *repositories.UserRepository, userService *UserService, memberships *repositories.UserMembershipRepository, provisioner *TemplateRoleProvisioner, bootstrap *TenantBootstrapService) *HREmploymentSyncService { return &HREmploymentSyncService{sync: sync, users: users, userService: userService, memberships: memberships, provisioner: provisioner, bootstrap: bootstrap} }

func (s *HREmploymentSyncService) ApplyScope(ctx context.Context, tenantID uuid.UUID, scope models.HREmploymentScope) (bool, error) {
	if scope.LegalEntityID == uuid.Nil || scope.ScopeVersion < 1 || (scope.Mode != "disabled" && scope.Mode != "manual" && scope.Mode != "automatic") { return false, ErrInvalidHREmploymentScope }
	return s.sync.ApplyScope(ctx, tenantID, scope)
}

func outcome(name, reason string, linked, candidate *uuid.UUID) models.HREmploymentSyncOutcome { return models.HREmploymentSyncOutcome{Outcome:name, Reason:reason, LinkedIAMUserID:linked, CandidateIAMUserID:candidate} }

func (s *HREmploymentSyncService) tenantUser(ctx context.Context, tenantID, userID uuid.UUID) (*models.User, error) {
	u, err := s.users.GetByIDInTenant(ctx, tenantID, userID); if err != nil || u == nil { return u, err }
	m, err := s.memberships.GetByTenantAndUser(ctx, tenantID, userID)
	if err != nil { return nil, err }
	if m == nil { return nil, nil }
	return u, nil
}

func (s *HREmploymentSyncService) ApplyDesired(ctx context.Context, tenantID, employeeID uuid.UUID, d models.HREmploymentDesiredState) (result models.HREmploymentSyncOutcome, err error) {
	if employeeID == uuid.Nil || d.EventID == uuid.Nil || d.LegalEntityID == uuid.Nil || d.ContractVersion != 1 || d.RelationshipVersion < 1 || d.ScopeVersion < 1 || (d.DesiredState != "active" && d.DesiredState != "terminated") || (d.ManualApproved && (d.ManualReviewActorID == nil || strings.TrimSpace(d.ManualReviewReason) == "")) { return outcome("failed", "invalid_desired_state", nil, nil), ErrInvalidHREmploymentDesiredState }
	claimed, prior, err := s.sync.ClaimReceipt(ctx, d.EventID, tenantID, employeeID, d); if err != nil { if errors.Is(err, repositories.ErrHREmploymentSyncEventPayloadConflict) { return outcome("conflict", "event_id_payload_conflict", nil, nil), err }; return outcome("failed", "receipt_claim_failed", nil, nil), err }; if !claimed { if prior == nil { return outcome("processing", "event_receipt_unavailable", nil, nil), nil }; return *prior, nil }
	defer func() { if err == nil { _ = s.sync.RecordReceipt(ctx, d.EventID, tenantID, employeeID, d, result) } }()
	reserved, err := s.sync.Reserve(ctx, tenantID, employeeID, d)
	if err != nil { return outcome("failed", "scope_unavailable", nil, nil), err }
	if !reserved { return outcome("stale_or_scope_ignored", "scope_disabled_manual_or_stale", nil, nil), nil }
	if d.DesiredState == "terminated" {
		applied, err := s.sync.ApplyLink(ctx, tenantID, employeeID, d, nil, nil, false)
		if err != nil { return outcome("failed", "termination_record_failed", nil, nil), err }
		if !applied { return outcome("stale", "relationship_version", nil, nil), nil }
		userID, err := s.sync.OwnedUserReadyForOffboarding(ctx, tenantID, employeeID, d.LegalEntityID)
		if err != nil { return outcome("failed", "offboarding_provenance_lookup_failed", nil, nil), err }
		if userID == nil { return outcome("terminated_scoped", "ownership_unknown_or_other_hr_employment_active", nil, nil), nil }
		knownRoleOwnership, hasNonHROwnedRoles, err := s.sync.HasNonHROwnedRoles(ctx, tenantID, employeeID, d.LegalEntityID, *userID)
		if err != nil { return outcome("failed", "offboarding_role_provenance_lookup_failed", userID, nil), err }
		if !knownRoleOwnership || hasNonHROwnedRoles { return outcome("review_required", "manual_or_unproven_roles_preserved", userID, nil), nil }
		changed, err := s.memberships.DeactivateEmployee(ctx, tenantID, *userID)
		if err != nil { return outcome("failed", "owned_membership_offboarding_failed", userID, nil), err }
		if !changed { return outcome("review_required", "owned_membership_missing_or_already_inactive", userID, nil), nil }
		if err := s.bootstrap.SyncUserAccess(ctx, tenantID, *userID, false, false, nil); err != nil { return outcome("failed", "owned_access_revocation_failed", userID, nil), err }
		return outcome("offboarded_hr_owned_membership", "", userID, nil), nil
	}

	workEmail := models.CanonicalInvitationEmail(strings.TrimSpace(d.WorkEmail))
	var userID *uuid.UUID
	var ownedRoleID *uuid.UUID
	owned := false
	provisionedUserID, provisionedRoleID, receiptErr := s.sync.ProvisionedAccount(ctx, d.EventID, tenantID); if receiptErr != nil { return outcome("failed", "receipt_lookup_failed", nil, nil), receiptErr }
	if provisionedUserID != nil {
		if provisionedRoleID == nil { return outcome("review_required", "provisioned_role_provenance_missing", provisionedUserID, nil), nil }
		userID, ownedRoleID, owned = provisionedUserID, provisionedRoleID, true
	} else if d.IAMUserID != nil {
		u, err := s.tenantUser(ctx, tenantID, *d.IAMUserID); if err != nil { return outcome("failed", "immutable_iam_lookup_failed", nil, nil), err }
		if u == nil { _ = s.sync.RecordFailure(ctx, tenantID, employeeID, d, "immutable_iam_id_not_tenant_member"); return outcome("review_required", "immutable_iam_id_not_tenant_member", nil, nil), nil }
		userID = &u.ID
	} else if d.ConfirmedIAMUserID != nil {
		u, err := s.tenantUser(ctx, tenantID, *d.ConfirmedIAMUserID); if err != nil { return outcome("failed", "candidate_lookup_failed", nil, nil), err }
		if u == nil || !u.IsEmailVerified || workEmail == "" || models.CanonicalInvitationEmail(u.Email) != workEmail { _ = s.sync.RecordFailure(ctx, tenantID, employeeID, d, "confirmed_candidate_email_or_membership_mismatch"); return outcome("candidate_rejected", "confirmed_candidate_email_or_membership_mismatch", nil, d.ConfirmedIAMUserID), nil }
		userID = &u.ID
	} else if workEmail != "" {
		u, err := s.users.GetByEmailInTenant(ctx, tenantID, workEmail); if err != nil { return outcome("failed", "email_lookup_failed", nil, nil), err }
		if u != nil && u.IsEmailVerified { _ = s.sync.RecordFailure(ctx, tenantID, employeeID, d, "verified_email_candidate_requires_confirmation"); return outcome("candidate_required", "verified_email_candidate_requires_confirmation", nil, &u.ID), nil }
		if u != nil { _ = s.sync.RecordFailure(ctx, tenantID, employeeID, d, "unverified_email_conflict_requires_review"); return outcome("review_required", "unverified_email_conflict_requires_review", nil, &u.ID), nil }
	}
	if userID == nil {
		if workEmail == "" { _ = s.sync.RecordFailure(ctx, tenantID, employeeID, d, "work_email_required"); return outcome("failed", "work_email_required", nil, nil), nil }
		role, err := s.provisioner.InstantiateForTenant(ctx, tenantID, "hr:employee", "", nil); if err != nil || role == nil { return outcome("failed", "employee_template_unavailable", nil, nil), fmt.Errorf("employee template: %w", err) }
		created, err := s.userService.CreateSeatFree(ctx, &models.CreateUserRequest{TenantID: tenantID, Username: workEmail, Email: workEmail}, nil); if err != nil || created == nil { return outcome("failed", "provisioning_failed", nil, nil), err }
		if err := s.sync.MarkProvisioned(ctx, d.EventID, tenantID, created.ID, role.ID); err != nil { return outcome("failed", "provisioning_receipt_failed", nil, nil), err }
		resourceType := "user"; audit := &models.AuditLog{TenantID: tenantID, TargetUserID: &created.ID, Action: "hr_employment_sync_provisioned", ResourceType: &resourceType, ResourceID: &created.ID, Details: map[string]interface{}{"result":"success", "seat_class":"employee", "role_template":"hr:employee"}, Success:true}
		if err := s.memberships.ProvisionEmployeeTx(ctx, tenantID, created.ID, role.ID, audit); err != nil { return outcome("failed", "membership_provisioning_failed", nil, nil), err }
		if err := s.bootstrap.SyncUserAccess(ctx, tenantID, created.ID, true, false, []uuid.UUID{role.ID}); err != nil { return outcome("failed", "authorization_sync_failed", nil, nil), err }
		userID, ownedRoleID, owned = &created.ID, &role.ID, true
	}
	applied, err := s.sync.ApplyLink(ctx, tenantID, employeeID, d, userID, ownedRoleID, owned); if err != nil { return outcome("failed", "link_persistence_failed", userID, nil), err }; if !applied { if owned { _, _ = s.memberships.DeactivateEmployee(ctx, tenantID, *userID); _ = s.bootstrap.SyncUserAccess(ctx, tenantID, *userID, false, false, nil) }; return outcome("stale_or_scope_ignored", "scope_changed_before_final_apply", userID, nil), nil }
	return outcome("linked", "", userID, nil), nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/jackc/pgx/v5"
)

var (
	ErrHREmploymentSyncScopeVersionConflict = errors.New("HR sync scope version payload conflict")
	ErrHREmploymentSyncEventPayloadConflict = errors.New("HR sync event id payload collision")
)

func receiptFingerprint(d models.HREmploymentDesiredState) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf(
		"%d|%s|%d|%d|%s|%s|%v|%v|%v|%v|%v|%v|%s",
		d.ContractVersion, d.LegalEntityID, d.RelationshipVersion, d.ScopeVersion,
		d.DesiredState, d.WorkEmail, d.IAMUserID, d.ConfirmedIAMUserID,
		d.DepartmentID, d.ManagerEmployeeID, d.ManualApproved, d.ManualReviewActorID,
		d.ManualReviewReason,
	))))
}

// HREmploymentSyncRepository owns only HR provenance; it never changes manual memberships or role rows.
// Every operation uses WithTenantScope because this S2S route derives tenant identity from :id,
// after request middleware has already opened its unrelated transaction.
type HREmploymentSyncRepository struct {
	db DBTX
}

func NewHREmploymentSyncRepository(db DBTX) *HREmploymentSyncRepository {
	return &HREmploymentSyncRepository{db: db}
}

func (r *HREmploymentSyncRepository) ApplyScope(ctx context.Context, tenantID uuid.UUID, s models.HREmploymentScope) (bool, error) {
	applied := false
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO iam_hr_sync_scopes (tenant_id, legal_entity_id, mode, enabled, version, updated_at)
VALUES ($1,$2,$3,$4,$5,now()) ON CONFLICT (tenant_id, legal_entity_id) DO UPDATE SET mode=excluded.mode, enabled=excluded.enabled, version=excluded.version, updated_at=now()
WHERE iam_hr_sync_scopes.version < excluded.version`, tenantID, s.LegalEntityID, s.Mode, s.Enabled, s.ScopeVersion)
		if err != nil {
			return fmt.Errorf("apply scope: %w", err)
		}
		if tag.RowsAffected() == 1 {
			applied = true
			return nil
		}
		var mode string
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT mode, enabled FROM iam_hr_sync_scopes WHERE tenant_id=$1 AND legal_entity_id=$2 AND version=$3`, tenantID, s.LegalEntityID, s.ScopeVersion).Scan(&mode, &enabled); err != nil {
			return fmt.Errorf("apply scope replay: %w", err)
		}
		if mode != s.Mode || enabled != s.Enabled {
			return ErrHREmploymentSyncScopeVersionConflict
		}
		return nil
	})
	return applied, err
}

func (r *HREmploymentSyncRepository) ApplyLink(ctx context.Context, tenantID, employeeID uuid.UUID, d models.HREmploymentDesiredState, userID, ownedRoleID *uuid.UUID, ownedAccount bool) (bool, error) {
	applied := false
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO iam_hr_employment_links (tenant_id, legal_entity_id, employee_id, iam_user_id, hr_owned_role_id, contract_version, relationship_version, scope_version, state, department_id, manager_employee_id, account_hr_owned, manual_approved, manual_review_actor_id, manual_review_reason, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NULLIF($15,''),now()) ON CONFLICT (tenant_id, legal_entity_id, employee_id) DO UPDATE SET iam_user_id=COALESCE(excluded.iam_user_id, iam_hr_employment_links.iam_user_id), hr_owned_role_id=COALESCE(excluded.hr_owned_role_id, iam_hr_employment_links.hr_owned_role_id), contract_version=excluded.contract_version, relationship_version=excluded.relationship_version, scope_version=excluded.scope_version, state=excluded.state, department_id=excluded.department_id, manager_employee_id=excluded.manager_employee_id, account_hr_owned=iam_hr_employment_links.account_hr_owned OR excluded.account_hr_owned, manual_approved=excluded.manual_approved, manual_review_actor_id=excluded.manual_review_actor_id, manual_review_reason=excluded.manual_review_reason, updated_at=now()
WHERE (iam_hr_employment_links.relationship_version < excluded.relationship_version OR (iam_hr_employment_links.relationship_version = excluded.relationship_version AND iam_hr_employment_links.state = 'pending')) AND EXISTS (SELECT 1 FROM iam_hr_sync_scopes s WHERE s.tenant_id=$1 AND s.legal_entity_id=$2 AND s.version=$8 AND s.enabled AND (s.mode='automatic' OR (s.mode='manual' AND $13)))`, tenantID, d.LegalEntityID, employeeID, userID, ownedRoleID, d.ContractVersion, d.RelationshipVersion, d.ScopeVersion, d.DesiredState, d.DepartmentID, d.ManagerEmployeeID, ownedAccount, d.ManualApproved, d.ManualReviewActorID, d.ManualReviewReason)
		if err != nil {
			return fmt.Errorf("apply link: %w", err)
		}
		applied = tag.RowsAffected() == 1
		return nil
	})
	return applied, err
}

// OwnedUserReadyForOffboarding returns a user only when Falcon created the account
// and no active HR employment remains in the same tenant.
func (r *HREmploymentSyncRepository) OwnedUserReadyForOffboarding(ctx context.Context, tenantID, employeeID, legalEntityID uuid.UUID) (*uuid.UUID, error) {
	var userID uuid.UUID
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT iam_user_id FROM iam_hr_employment_links l WHERE l.tenant_id=$1 AND l.legal_entity_id=$2 AND l.employee_id=$3 AND l.state='terminated' AND l.account_hr_owned=true AND l.iam_user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM iam_hr_employment_links active WHERE active.tenant_id=l.tenant_id AND active.iam_user_id=l.iam_user_id AND active.state='active')`, tenantID, legalEntityID, employeeID).Scan(&userID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("owned user ready for offboarding: %w", err)
	}
	return &userID, nil
}

// HasNonHROwnedRoles distinguishes an absent provenance role ID from an empty
// role set. Missing provenance is unsafe to offboard; a role-ID mismatch is a
// preserved manual/effective role binding.
func (r *HREmploymentSyncRepository) HasNonHROwnedRoles(ctx context.Context, tenantID, employeeID, legalEntityID, userID uuid.UUID) (knownOwnership, hasNonHROwned bool, err error) {
	var ownedRoleID *uuid.UUID
	err = WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT hr_owned_role_id FROM iam_hr_employment_links WHERE tenant_id=$1 AND legal_entity_id=$2 AND employee_id=$3 AND iam_user_id=$4 AND account_hr_owned=true`, tenantID, legalEntityID, employeeID, userID).Scan(&ownedRoleID); err != nil {
			return err
		}
		if ownedRoleID == nil {
			return nil
		}
		knownOwnership = true
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM iam_user_roles ur JOIN iam_roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND r.tenant_id=$2 AND ur.role_id <> $3 AND (ur.expires_at IS NULL OR ur.expires_at > now()))`, userID, tenantID, *ownedRoleID).Scan(&hasNonHROwned)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	return knownOwnership, hasNonHROwned, err
}

// Reserve serializes the scope and employment version before any external side effect.
func (r *HREmploymentSyncRepository) Reserve(ctx context.Context, tenantID, employeeID uuid.UUID, d models.HREmploymentDesiredState) (bool, error) {
	reserved := false
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT enabled AND (mode = 'automatic' OR (mode = 'manual' AND $4)) AND version = $3 FROM iam_hr_sync_scopes WHERE tenant_id=$1 AND legal_entity_id=$2 FOR UPDATE`, tenantID, d.LegalEntityID, d.ScopeVersion, d.ManualApproved).Scan(&enabled); err != nil {
			return err
		}
		if !enabled {
			return nil
		}
		var current int64
		var state string
		err := tx.QueryRow(ctx, `SELECT relationship_version, state FROM iam_hr_employment_links WHERE tenant_id=$1 AND legal_entity_id=$2 AND employee_id=$3 FOR UPDATE`, tenantID, d.LegalEntityID, employeeID).Scan(&current, &state)
		if err == nil && (current > d.RelationshipVersion || (current == d.RelationshipVersion && state != "pending")) {
			return nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO iam_hr_employment_links (tenant_id, legal_entity_id, employee_id, contract_version, relationship_version, scope_version, state, manual_approved, manual_review_actor_id, manual_review_reason, updated_at) VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8,NULLIF($9,''),now()) ON CONFLICT (tenant_id, legal_entity_id, employee_id) DO UPDATE SET contract_version=excluded.contract_version, relationship_version=excluded.relationship_version, scope_version=excluded.scope_version, state='pending', manual_approved=excluded.manual_approved, manual_review_actor_id=excluded.manual_review_actor_id, manual_review_reason=excluded.manual_review_reason, updated_at=now() WHERE iam_hr_employment_links.relationship_version < excluded.relationship_version`, tenantID, d.LegalEntityID, employeeID, d.ContractVersion, d.RelationshipVersion, d.ScopeVersion, d.ManualApproved, d.ManualReviewActorID, d.ManualReviewReason); err != nil {
			return err
		}
		reserved = true
		return nil
	})
	return reserved, err
}

func (r *HREmploymentSyncRepository) ClaimReceipt(ctx context.Context, eventID, tenantID, employeeID uuid.UUID, d models.HREmploymentDesiredState) (bool, *models.HREmploymentSyncOutcome, error) {
	claimed := false
	var prior *models.HREmploymentSyncOutcome
	fingerprint := receiptFingerprint(d)
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO iam_hr_sync_receipts (event_id,tenant_id,legal_entity_id,employee_id,contract_version,relationship_version,scope_version,payload_fingerprint,manual_approved,manual_review_actor_id,manual_review_reason,outcome) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULLIF($11,''),'processing') ON CONFLICT (event_id) DO NOTHING`, eventID, tenantID, d.LegalEntityID, employeeID, d.ContractVersion, d.RelationshipVersion, d.ScopeVersion, fingerprint, d.ManualApproved, d.ManualReviewActorID, d.ManualReviewReason)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			claimed = true
			return nil
		}
		out := &models.HREmploymentSyncOutcome{}
		var same bool
		if err := tx.QueryRow(ctx, `SELECT tenant_id=$2 AND legal_entity_id=$3 AND employee_id=$4 AND contract_version=$5 AND relationship_version=$6 AND scope_version=$7 AND payload_fingerprint=$8, outcome, linked_iam_user_id, candidate_iam_user_id, COALESCE(reason,'') FROM iam_hr_sync_receipts WHERE event_id=$1`, eventID, tenantID, d.LegalEntityID, employeeID, d.ContractVersion, d.RelationshipVersion, d.ScopeVersion, fingerprint).Scan(&same, &out.Outcome, &out.LinkedIAMUserID, &out.CandidateIAMUserID, &out.Reason); err != nil {
			return err
		}
		if !same {
			return ErrHREmploymentSyncEventPayloadConflict
		}
		if out.Outcome == "processing" {
			tag, err = tx.Exec(ctx, `UPDATE iam_hr_sync_receipts SET lease_until=now()+interval '5 minutes', attempts=attempts+1, updated_at=now() WHERE event_id=$1 AND lease_until <= now()`, eventID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				claimed = true
				return nil
			}
		}
		prior = out
		return nil
	})
	return claimed, prior, err
}

func (r *HREmploymentSyncRepository) RecordReceipt(ctx context.Context, eventID, tenantID, employeeID uuid.UUID, d models.HREmploymentDesiredState, out models.HREmploymentSyncOutcome) error {
	return WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE iam_hr_sync_receipts SET outcome=$2, stage='complete', linked_iam_user_id=$3, candidate_iam_user_id=$4, reason=NULLIF($5,''), lease_until=now(), updated_at=now() WHERE event_id=$1 AND tenant_id=$6 AND legal_entity_id=$7 AND employee_id=$8`, eventID, out.Outcome, out.LinkedIAMUserID, out.CandidateIAMUserID, out.Reason, tenantID, d.LegalEntityID, employeeID)
		return err
	})
}

func (r *HREmploymentSyncRepository) ProvisionedAccount(ctx context.Context, eventID, tenantID uuid.UUID) (*uuid.UUID, *uuid.UUID, error) {
	var userID, roleID *uuid.UUID
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT provisioned_iam_user_id, provisioned_hr_role_id FROM iam_hr_sync_receipts WHERE event_id=$1 AND tenant_id=$2`, eventID, tenantID).Scan(&userID, &roleID)
	})
	return userID, roleID, err
}

func (r *HREmploymentSyncRepository) MarkProvisioned(ctx context.Context, eventID, tenantID, userID, roleID uuid.UUID) error {
	return WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE iam_hr_sync_receipts SET provisioned_iam_user_id=$2, provisioned_hr_role_id=$3, stage='provisioned', lease_until=now()+interval '5 minutes', updated_at=now() WHERE event_id=$1 AND tenant_id=$4 AND provisioned_iam_user_id IS NULL`, eventID, userID, roleID, tenantID)
		return err
	})
}

func (r *HREmploymentSyncRepository) RecordFailure(ctx context.Context, tenantID, employeeID uuid.UUID, d models.HREmploymentDesiredState, code string) error {
	return WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO iam_hr_sync_failures (id, tenant_id, legal_entity_id, employee_id, contract_version, relationship_version, failure_code, attempts, next_attempt_at, created_at) VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,1,now() + interval '1 minute',now()) ON CONFLICT (tenant_id, legal_entity_id, employee_id, relationship_version) DO UPDATE SET attempts=iam_hr_sync_failures.attempts+1, failure_code=excluded.failure_code, next_attempt_at=now() + interval '1 minute'`, tenantID, d.LegalEntityID, employeeID, d.ContractVersion, d.RelationshipVersion, code)
		return err
	})
}

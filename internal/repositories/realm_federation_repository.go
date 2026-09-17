// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// RealmFederationRepositoryInterface declares the operations on federation trusts.
type RealmFederationRepositoryInterface interface {
	Create(ctx context.Context, t *models.RealmFederationTrust) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.RealmFederationTrust, error)
	GetByRealms(ctx context.Context, sourceRealmID, targetRealmID uuid.UUID) (*models.RealmFederationTrust, error)
	List(ctx context.Context, filter models.FederationTrustListFilter) ([]*models.RealmFederationTrust, int64, error)
	Update(ctx context.Context, t *models.RealmFederationTrust) error
	Delete(ctx context.Context, id uuid.UUID) error
	AddAuditEntry(ctx context.Context, entry *models.RealmFederationAudit) error
}

// RealmFederationRepository provides database access for realm federation trusts.
type RealmFederationRepository struct {
	db DBPool
}

// NewRealmFederationRepository constructs a RealmFederationRepository.
func NewRealmFederationRepository(db *pgxpool.Pool) *RealmFederationRepository {
	return &RealmFederationRepository{db: db}
}

const federationTrustSelectColumns = `
	id, source_realm_id, target_realm_id,
	trust_type, trust_level,
	allowed_tenant_types, max_guest_users, require_mfa, allowed_roles,
	token_lifetime_override, scope_restrictions,
	status, established_at, requested_by, approved_by,
	description, metadata, created_at, updated_at`

func scanFederationTrust(row pgx.Row, t *models.RealmFederationTrust) error {
	return row.Scan(
		&t.ID, &t.SourceRealmID, &t.TargetRealmID,
		&t.TrustType, &t.TrustLevel,
		&t.AllowedTenantTypes, &t.MaxGuestUsers, &t.RequireMFA, &t.AllowedRoles,
		&t.TokenLifetimeOverride, &t.ScopeRestrictions,
		&t.Status, &t.EstablishedAt, &t.RequestedBy, &t.ApprovedBy,
		&t.Description, &t.Metadata, &t.CreatedAt, &t.UpdatedAt,
	)
}

// Create inserts a new federation trust record.
func (r *RealmFederationRepository) Create(ctx context.Context, t *models.RealmFederationTrust) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	query := `
		INSERT INTO iam_realm_federation_trusts (
			id, source_realm_id, target_realm_id,
			trust_type, trust_level,
			allowed_tenant_types, max_guest_users, require_mfa, allowed_roles,
			token_lifetime_override, scope_restrictions,
			status, requested_by, description, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING established_at, created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		t.ID, t.SourceRealmID, t.TargetRealmID,
		t.TrustType, t.TrustLevel,
		t.AllowedTenantTypes, t.MaxGuestUsers, t.RequireMFA, t.AllowedRoles,
		t.TokenLifetimeOverride, t.ScopeRestrictions,
		t.Status, t.RequestedBy, t.Description, t.Metadata,
	).Scan(&t.EstablishedAt, &t.CreatedAt, &t.UpdatedAt)
}

// GetByID retrieves a trust by primary key.  Returns (nil, nil) when not found.
func (r *RealmFederationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.RealmFederationTrust, error) {
	t := &models.RealmFederationTrust{}
	err := scanFederationTrust(
		r.db.QueryRow(ctx,
			`SELECT `+federationTrustSelectColumns+` FROM iam_realm_federation_trusts WHERE id = $1`,
			id,
		), t,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("RealmFederationRepository.GetByID: %w", err)
	}
	return t, nil
}

// GetByRealms retrieves a trust by the realm pair.
func (r *RealmFederationRepository) GetByRealms(ctx context.Context, sourceRealmID, targetRealmID uuid.UUID) (*models.RealmFederationTrust, error) {
	t := &models.RealmFederationTrust{}
	err := scanFederationTrust(
		r.db.QueryRow(ctx,
			`SELECT `+federationTrustSelectColumns+
				` FROM iam_realm_federation_trusts WHERE source_realm_id = $1 AND target_realm_id = $2`,
			sourceRealmID, targetRealmID,
		), t,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("RealmFederationRepository.GetByRealms: %w", err)
	}
	return t, nil
}

// List returns a filtered, paginated slice of federation trusts.
func (r *RealmFederationRepository) List(ctx context.Context, filter models.FederationTrustListFilter) ([]*models.RealmFederationTrust, int64, error) {
	args := []interface{}{}
	where := "WHERE 1=1"
	argIdx := 1

	if filter.SourceRealmID != nil {
		where += fmt.Sprintf(" AND source_realm_id = $%d", argIdx)
		args = append(args, *filter.SourceRealmID)
		argIdx++
	}
	if filter.TargetRealmID != nil {
		where += fmt.Sprintf(" AND target_realm_id = $%d", argIdx)
		args = append(args, *filter.TargetRealmID)
		argIdx++
	}
	if filter.Status != nil {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, *filter.Status)
		argIdx++
	}

	var total int64
	if err := r.db.QueryRow(ctx,
		"SELECT COUNT(*) FROM iam_realm_federation_trusts "+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("RealmFederationRepository.List count: %w", err)
	}

	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	listQuery := `SELECT ` + federationTrustSelectColumns + ` FROM iam_realm_federation_trusts ` +
		where + fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, argIdx, argIdx+1)
	args = append(args, pageSize, offset)

	rows, err := r.db.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("RealmFederationRepository.List query: %w", err)
	}
	defer rows.Close()

	var trusts []*models.RealmFederationTrust
	for rows.Next() {
		t := &models.RealmFederationTrust{}
		if err := rows.Scan(
			&t.ID, &t.SourceRealmID, &t.TargetRealmID,
			&t.TrustType, &t.TrustLevel,
			&t.AllowedTenantTypes, &t.MaxGuestUsers, &t.RequireMFA, &t.AllowedRoles,
			&t.TokenLifetimeOverride, &t.ScopeRestrictions,
			&t.Status, &t.EstablishedAt, &t.RequestedBy, &t.ApprovedBy,
			&t.Description, &t.Metadata, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("RealmFederationRepository.List scan: %w", err)
		}
		trusts = append(trusts, t)
	}
	return trusts, total, rows.Err()
}

// Update persists mutable fields of a federation trust.
func (r *RealmFederationRepository) Update(ctx context.Context, t *models.RealmFederationTrust) error {
	query := `
		UPDATE iam_realm_federation_trusts SET
			trust_type             = $1,
			trust_level            = $2,
			allowed_tenant_types   = $3,
			max_guest_users        = $4,
			require_mfa            = $5,
			allowed_roles          = $6,
			token_lifetime_override = $7,
			scope_restrictions     = $8,
			status                 = $9,
			established_at         = $10,
			approved_by            = $11,
			description            = $12,
			metadata               = $13,
			updated_at             = NOW()
		WHERE id = $14
		RETURNING updated_at`

	err := r.db.QueryRow(ctx, query,
		t.TrustType, t.TrustLevel,
		t.AllowedTenantTypes, t.MaxGuestUsers,
		t.RequireMFA, t.AllowedRoles,
		t.TokenLifetimeOverride, t.ScopeRestrictions,
		t.Status, t.EstablishedAt, t.ApprovedBy,
		t.Description, t.Metadata,
		t.ID,
	).Scan(&t.UpdatedAt)
	if err != nil {
		return fmt.Errorf("RealmFederationRepository.Update: %w", err)
	}
	return nil
}

// Delete hard-deletes a federation trust (cascades to audit records).
func (r *RealmFederationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM iam_realm_federation_trusts WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("RealmFederationRepository.Delete: %w", err)
	}
	return nil
}

// AddAuditEntry appends an immutable audit record for a trust change.
func (r *RealmFederationRepository) AddAuditEntry(ctx context.Context, entry *models.RealmFederationAudit) error {
	if entry.ID == uuid.Nil {
		entry.ID = uuid.New()
	}
	query := `
		INSERT INTO iam_realm_federation_audit (id, trust_id, actor_id, action, old_value, new_value, ip_address, reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at`

	return r.db.QueryRow(ctx, query,
		entry.ID, entry.TrustID, entry.ActorID, entry.Action,
		entry.OldValue, entry.NewValue, entry.IPAddress, entry.Reason,
	).Scan(&entry.CreatedAt)
}

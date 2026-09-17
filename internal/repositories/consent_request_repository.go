// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ConsentRequestRepository handles database operations for admin consent workflow requests.
type ConsentRequestRepository struct {
	pool *pgxpool.Pool
}

// NewConsentRequestRepository creates a new ConsentRequestRepository.
func NewConsentRequestRepository(pool *pgxpool.Pool) *ConsentRequestRepository {
	return &ConsentRequestRepository{pool: pool}
}

const consentRequestColumns = `id, application_id, tenant_id, requester_id, approver_id, requested_scopes, justification, status, decided_at, created_at`

func scanAdminConsentRequest(row pgx.Row) (*models.AdminConsentRequest, error) {
	var cr models.AdminConsentRequest
	err := row.Scan(
		&cr.ID,
		&cr.ApplicationID,
		&cr.TenantID,
		&cr.RequesterID,
		&cr.ApproverID,
		&cr.RequestedScopes,
		&cr.Justification,
		&cr.Status,
		&cr.DecidedAt,
		&cr.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &cr, nil
}

func scanAdminConsentRequestRows(rows pgx.Rows) (*models.AdminConsentRequest, error) {
	var cr models.AdminConsentRequest
	err := rows.Scan(
		&cr.ID,
		&cr.ApplicationID,
		&cr.TenantID,
		&cr.RequesterID,
		&cr.ApproverID,
		&cr.RequestedScopes,
		&cr.Justification,
		&cr.Status,
		&cr.DecidedAt,
		&cr.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &cr, nil
}

// Create inserts a new admin consent request record.
func (r *ConsentRequestRepository) Create(ctx context.Context, req *models.AdminConsentRequest) error {
	if req.ID == uuid.Nil {
		req.ID = uuid.New()
	}
	if req.RequestedScopes == nil {
		req.RequestedScopes = []string{}
	}
	if req.Status == "" {
		req.Status = models.AdminConsentRequestStatusPending
	}

	query := fmt.Sprintf(`
		INSERT INTO iam_consent_requests
			(id, application_id, tenant_id, requester_id, requested_scopes, justification, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING %s`, consentRequestColumns)

	row := r.pool.QueryRow(ctx, query,
		req.ID,
		req.ApplicationID,
		req.TenantID,
		req.RequesterID,
		req.RequestedScopes,
		req.Justification,
		req.Status,
	)

	scanned, err := scanAdminConsentRequest(row)
	if err != nil {
		return fmt.Errorf("ConsentRequestRepository.Create: %w", err)
	}
	*req = *scanned
	return nil
}

// GetByID returns an admin consent request by its primary key.
func (r *ConsentRequestRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AdminConsentRequest, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_consent_requests WHERE id = $1`, consentRequestColumns)

	row := r.pool.QueryRow(ctx, query, id)
	cr, err := scanAdminConsentRequest(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ConsentRequestRepository.GetByID: %w", err)
	}
	return cr, nil
}

// Decide updates the status, approver_id, and decided_at of a consent request.
func (r *ConsentRequestRepository) Decide(ctx context.Context, id uuid.UUID, approverID uuid.UUID, status models.AdminConsentRequestStatus) error {
	now := time.Now()
	tag, err := r.pool.Exec(ctx,
		`UPDATE iam_consent_requests
		 SET status = $2, approver_id = $3, decided_at = $4
		 WHERE id = $1`,
		id, status, approverID, now,
	)
	if err != nil {
		return fmt.Errorf("ConsentRequestRepository.Decide: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ConsentRequestRepository.Decide: consent request not found")
	}
	return nil
}

// ListByTenant returns all consent requests for a tenant, newest first.
func (r *ConsentRequestRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.AdminConsentRequest, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM iam_consent_requests
		WHERE tenant_id = $1
		ORDER BY created_at DESC`, consentRequestColumns)

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ConsentRequestRepository.ListByTenant: %w", err)
	}
	defer rows.Close()

	var results []models.AdminConsentRequest
	for rows.Next() {
		cr, err := scanAdminConsentRequestRows(rows)
		if err != nil {
			return nil, fmt.Errorf("ConsentRequestRepository.ListByTenant scan: %w", err)
		}
		results = append(results, *cr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ConsentRequestRepository.ListByTenant rows: %w", err)
	}
	return results, nil
}

// ListByApplication returns all consent requests for an application, newest first.
func (r *ConsentRequestRepository) ListByApplication(ctx context.Context, appID uuid.UUID) ([]models.AdminConsentRequest, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM iam_consent_requests
		WHERE application_id = $1
		ORDER BY created_at DESC`, consentRequestColumns)

	rows, err := r.pool.Query(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("ConsentRequestRepository.ListByApplication: %w", err)
	}
	defer rows.Close()

	var results []models.AdminConsentRequest
	for rows.Next() {
		cr, err := scanAdminConsentRequestRows(rows)
		if err != nil {
			return nil, fmt.Errorf("ConsentRequestRepository.ListByApplication scan: %w", err)
		}
		results = append(results, *cr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ConsentRequestRepository.ListByApplication rows: %w", err)
	}
	return results, nil
}

// ListPending returns all pending consent requests for a tenant, oldest first.
func (r *ConsentRequestRepository) ListPending(ctx context.Context, tenantID uuid.UUID) ([]models.AdminConsentRequest, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM iam_consent_requests
		WHERE tenant_id = $1 AND status = 'pending'
		ORDER BY created_at ASC`, consentRequestColumns)

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ConsentRequestRepository.ListPending: %w", err)
	}
	defer rows.Close()

	var results []models.AdminConsentRequest
	for rows.Next() {
		cr, err := scanAdminConsentRequestRows(rows)
		if err != nil {
			return nil, fmt.Errorf("ConsentRequestRepository.ListPending scan: %w", err)
		}
		results = append(results, *cr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ConsentRequestRepository.ListPending rows: %w", err)
	}
	return results, nil
}

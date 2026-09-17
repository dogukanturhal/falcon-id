// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LicenseRepository handles license database operations.
type LicenseRepository struct {
	db *pgxpool.Pool
}

// NewLicenseRepository creates a new license repository.
func NewLicenseRepository(db *pgxpool.Pool) *LicenseRepository {
	return &LicenseRepository{db: db}
}

// Create inserts a new license into the database.
func (r *LicenseRepository) Create(ctx context.Context, license *models.License) error {
	if license.ID == uuid.Nil {
		license.ID = uuid.New()
	}

	featuresJSON, _ := json.Marshal(license.Features)
	metadataJSON, _ := json.Marshal(license.Metadata)

	query := `
		INSERT INTO iam_licenses (
			id, product_id, tenant_id, license_key, type, status,
			max_seats, used_seats, features, metadata, issued_at, expires_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING created_at, updated_at
	`

	err := r.db.QueryRow(ctx, query,
		license.ID,
		license.ProductID,
		license.TenantID,
		license.LicenseKey,
		license.Type,
		license.Status,
		license.MaxSeats,
		license.UsedSeats,
		featuresJSON,
		metadataJSON,
		license.IssuedAt,
		license.ExpiresAt,
		license.CreatedBy,
	).Scan(&license.CreatedAt, &license.UpdatedAt)
	if err != nil {
		return fmt.Errorf("LicenseRepository.Create: %w", err)
	}
	return nil
}

// GetByID retrieves a license by its UUID.
func (r *LicenseRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.License, error) {
	query := `
		SELECT id, product_id, tenant_id, license_key, type, status,
		       max_seats, used_seats, features, metadata,
		       issued_at, expires_at, suspended_at, revoked_at, revoked_by,
		       created_by, created_at, updated_at
		FROM iam_licenses
		WHERE id = $1
	`
	return r.scanLicense(ctx, query, id)
}

// GetByLicenseKey retrieves a license by its license key string.
func (r *LicenseRepository) GetByLicenseKey(ctx context.Context, key string) (*models.License, error) {
	query := `
		SELECT id, product_id, tenant_id, license_key, type, status,
		       max_seats, used_seats, features, metadata,
		       issued_at, expires_at, suspended_at, revoked_at, revoked_by,
		       created_by, created_at, updated_at
		FROM iam_licenses
		WHERE license_key = $1
	`
	return r.scanLicense(ctx, query, key)
}

// scanLicense scans a single license row.
func (r *LicenseRepository) scanLicense(ctx context.Context, query string, arg interface{}) (*models.License, error) {
	var l models.License
	var featuresJSON, metadataJSON []byte

	err := r.db.QueryRow(ctx, query, arg).Scan(
		&l.ID, &l.ProductID, &l.TenantID, &l.LicenseKey,
		&l.Type, &l.Status,
		&l.MaxSeats, &l.UsedSeats,
		&featuresJSON, &metadataJSON,
		&l.IssuedAt, &l.ExpiresAt, &l.SuspendedAt, &l.RevokedAt, &l.RevokedBy,
		&l.CreatedBy, &l.CreatedAt, &l.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("LicenseRepository.scanLicense: %w", err)
	}

	if featuresJSON != nil {
		_ = json.Unmarshal(featuresJSON, &l.Features)
	}
	if metadataJSON != nil {
		_ = json.Unmarshal(metadataJSON, &l.Metadata)
	}

	return &l, nil
}

// List returns a paginated list of licenses with optional filters.
func (r *LicenseRepository) List(
	ctx context.Context,
	page, pageSize int,
	productID, tenantID *uuid.UUID,
	status, licenseType string,
) ([]models.License, int64, error) {
	offset := (page - 1) * pageSize

	baseQuery := "FROM iam_licenses WHERE 1=1"
	args := []interface{}{}
	argIndex := 1

	if productID != nil {
		baseQuery += fmt.Sprintf(" AND product_id = $%d", argIndex)
		args = append(args, *productID)
		argIndex++
	}
	if tenantID != nil {
		baseQuery += fmt.Sprintf(" AND tenant_id = $%d", argIndex)
		args = append(args, *tenantID)
		argIndex++
	}
	if status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, status)
		argIndex++
	}
	if licenseType != "" {
		baseQuery += fmt.Sprintf(" AND type = $%d", argIndex)
		args = append(args, licenseType)
		argIndex++
	}

	var total int64
	if err := r.db.QueryRow(ctx, "SELECT COUNT(*) "+baseQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("LicenseRepository.List count: %w", err)
	}

	selectQuery := fmt.Sprintf(`
		SELECT id, product_id, tenant_id, license_key, type, status,
		       max_seats, used_seats, features, metadata,
		       issued_at, expires_at, suspended_at, revoked_at, revoked_by,
		       created_by, created_at, updated_at
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`,
		baseQuery, argIndex, argIndex+1)
	args = append(args, pageSize, offset)

	rows, err := r.db.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("LicenseRepository.List query: %w", err)
	}
	defer rows.Close()

	var licenses []models.License
	for rows.Next() {
		var l models.License
		var featuresJSON, metadataJSON []byte

		if err := rows.Scan(
			&l.ID, &l.ProductID, &l.TenantID, &l.LicenseKey,
			&l.Type, &l.Status,
			&l.MaxSeats, &l.UsedSeats,
			&featuresJSON, &metadataJSON,
			&l.IssuedAt, &l.ExpiresAt, &l.SuspendedAt, &l.RevokedAt, &l.RevokedBy,
			&l.CreatedBy, &l.CreatedAt, &l.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("LicenseRepository.List scan: %w", err)
		}

		if featuresJSON != nil {
			_ = json.Unmarshal(featuresJSON, &l.Features)
		}
		if metadataJSON != nil {
			_ = json.Unmarshal(metadataJSON, &l.Metadata)
		}

		licenses = append(licenses, l)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("LicenseRepository.List rows: %w", err)
	}

	return licenses, total, nil
}

// Update applies partial updates to a license and returns the updated record.
func (r *LicenseRepository) Update(ctx context.Context, id uuid.UUID, req *models.UpdateLicenseRequest) (*models.License, error) {
	setClauses := []string{}
	args := []interface{}{}
	argIndex := 1

	if req.Type != nil {
		setClauses = append(setClauses, fmt.Sprintf("type = $%d", argIndex))
		args = append(args, *req.Type)
		argIndex++
	}
	if req.Status != nil {
		setClauses = append(setClauses, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, *req.Status)
		argIndex++
	}
	if req.MaxSeats != nil {
		setClauses = append(setClauses, fmt.Sprintf("max_seats = $%d", argIndex))
		args = append(args, *req.MaxSeats)
		argIndex++
	}
	if req.ExpiresAt != nil {
		setClauses = append(setClauses, fmt.Sprintf("expires_at = $%d", argIndex))
		args = append(args, *req.ExpiresAt)
		argIndex++
	}
	if req.Features != nil {
		featuresJSON, _ := json.Marshal(req.Features)
		setClauses = append(setClauses, fmt.Sprintf("features = $%d", argIndex))
		args = append(args, featuresJSON)
		argIndex++
	}
	if req.Metadata != nil {
		metadataJSON, _ := json.Marshal(req.Metadata)
		setClauses = append(setClauses, fmt.Sprintf("metadata = $%d", argIndex))
		args = append(args, metadataJSON)
		argIndex++
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	setClauses = append(setClauses, "updated_at = NOW()")
	args = append(args, id)

	query := fmt.Sprintf(`
		UPDATE iam_licenses
		SET %s
		WHERE id = $%d
		RETURNING id, product_id, tenant_id, license_key, type, status,
		          max_seats, used_seats, features, metadata,
		          issued_at, expires_at, suspended_at, revoked_at, revoked_by,
		          created_by, created_at, updated_at`,
		strings.Join(setClauses, ", "), argIndex)

	var l models.License
	var featuresJSON, metadataJSON []byte

	err := r.db.QueryRow(ctx, query, args...).Scan(
		&l.ID, &l.ProductID, &l.TenantID, &l.LicenseKey,
		&l.Type, &l.Status,
		&l.MaxSeats, &l.UsedSeats,
		&featuresJSON, &metadataJSON,
		&l.IssuedAt, &l.ExpiresAt, &l.SuspendedAt, &l.RevokedAt, &l.RevokedBy,
		&l.CreatedBy, &l.CreatedAt, &l.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("LicenseRepository.Update: %w", err)
	}

	if featuresJSON != nil {
		_ = json.Unmarshal(featuresJSON, &l.Features)
	}
	if metadataJSON != nil {
		_ = json.Unmarshal(metadataJSON, &l.Metadata)
	}

	return &l, nil
}

// UpdateStatus sets a license's status field.
func (r *LicenseRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := r.db.Exec(ctx,
		"UPDATE iam_licenses SET status = $1, updated_at = NOW() WHERE id = $2",
		status, id,
	)
	if err != nil {
		return fmt.Errorf("LicenseRepository.UpdateStatus: %w", err)
	}
	return nil
}

// Suspend sets a license's status to 'suspended' and stamps suspended_at.
func (r *LicenseRepository) Suspend(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		"UPDATE iam_licenses SET status = 'suspended', suspended_at = NOW(), updated_at = NOW() WHERE id = $1",
		id,
	)
	if err != nil {
		return fmt.Errorf("LicenseRepository.Suspend: %w", err)
	}
	return nil
}

// Revoke permanently cancels a license.
func (r *LicenseRepository) Revoke(ctx context.Context, id uuid.UUID, revokedBy uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		"UPDATE iam_licenses SET status = 'revoked', revoked_at = NOW(), revoked_by = $1, updated_at = NOW() WHERE id = $2",
		revokedBy, id,
	)
	if err != nil {
		return fmt.Errorf("LicenseRepository.Revoke: %w", err)
	}
	return nil
}

// IncrementUsedSeats atomically increments the used seat count.
//
// Deprecated: Use AtomicIncrementSeat for race-condition-safe seat management.
func (r *LicenseRepository) IncrementUsedSeats(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		"UPDATE iam_licenses SET used_seats = used_seats + 1, updated_at = NOW() WHERE id = $1",
		id,
	)
	if err != nil {
		return fmt.Errorf("LicenseRepository.IncrementUsedSeats: %w", err)
	}
	return nil
}

// AtomicIncrementSeat atomically increments used_seats only if under the max_seats limit.
// Returns true if the seat was successfully claimed, false if the limit was reached.
// This eliminates the TOCTOU race condition in seat management.
func (r *LicenseRepository) AtomicIncrementSeat(ctx context.Context, id uuid.UUID) (bool, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE iam_licenses
		 SET used_seats = used_seats + 1, updated_at = NOW()
		 WHERE id = $1 AND status = 'active' AND used_seats < max_seats`,
		id,
	)
	if err != nil {
		return false, fmt.Errorf("LicenseRepository.AtomicIncrementSeat: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// GetActivationByID retrieves an activation by its ID, returning the license_id for seat management.
func (r *LicenseRepository) GetActivationByID(ctx context.Context, id uuid.UUID) (*models.LicenseActivation, error) {
	query := `
		SELECT id, license_id, machine_id, device_name, ip_address, user_agent,
		       activated_at, last_validated_at, deactivated_at, status
		FROM iam_license_activations
		WHERE id = $1
	`

	var a models.LicenseActivation
	err := r.db.QueryRow(ctx, query, id).Scan(
		&a.ID, &a.LicenseID, &a.MachineID, &a.DeviceName, &a.IPAddress, &a.UserAgent,
		&a.ActivatedAt, &a.LastValidatedAt, &a.DeactivatedAt, &a.Status,
	)
	if err != nil {
		return nil, fmt.Errorf("LicenseRepository.GetActivationByID: %w", err)
	}

	return &a, nil
}

// DecrementUsedSeats atomically decrements the used seat count (minimum 0).
func (r *LicenseRepository) DecrementUsedSeats(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		"UPDATE iam_licenses SET used_seats = GREATEST(used_seats - 1, 0), updated_at = NOW() WHERE id = $1",
		id,
	)
	if err != nil {
		return fmt.Errorf("LicenseRepository.DecrementUsedSeats: %w", err)
	}
	return nil
}

// CreateActivation inserts a new license activation record.
func (r *LicenseRepository) CreateActivation(ctx context.Context, activation *models.LicenseActivation) error {
	if activation.ID == uuid.Nil {
		activation.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_license_activations (
			id, license_id, machine_id, device_name, ip_address, user_agent, status
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING activated_at, last_validated_at
	`

	err := r.db.QueryRow(ctx, query,
		activation.ID,
		activation.LicenseID,
		activation.MachineID,
		activation.DeviceName,
		activation.IPAddress,
		activation.UserAgent,
		activation.Status,
	).Scan(&activation.ActivatedAt, &activation.LastValidatedAt)
	if err != nil {
		return fmt.Errorf("LicenseRepository.CreateActivation: %w", err)
	}
	return nil
}

// AtomicClaimSeatAndActivate wraps the seat increment and activation creation
// in a single database transaction, ensuring atomicity. If either operation fails,
// the entire transaction is rolled back — no seat is permanently inflated.
func (r *LicenseRepository) AtomicClaimSeatAndActivate(ctx context.Context, licenseID uuid.UUID, activation *models.LicenseActivation) (bool, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("LicenseRepository.AtomicClaimSeatAndActivate: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op if already committed

	// Step 1: Atomically claim a seat within the transaction.
	tag, err := tx.Exec(ctx,
		`UPDATE iam_licenses
		 SET used_seats = used_seats + 1, updated_at = NOW()
		 WHERE id = $1 AND status = 'active' AND used_seats < max_seats`,
		licenseID,
	)
	if err != nil {
		return false, fmt.Errorf("LicenseRepository.AtomicClaimSeatAndActivate: increment seat: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil // no seat available
	}

	// Step 2: Create the activation record within the same transaction.
	if activation.ID == uuid.Nil {
		activation.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_license_activations (
			id, license_id, machine_id, device_name, ip_address, user_agent, status
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING activated_at, last_validated_at
	`
	err = tx.QueryRow(ctx, query,
		activation.ID,
		activation.LicenseID,
		activation.MachineID,
		activation.DeviceName,
		activation.IPAddress,
		activation.UserAgent,
		activation.Status,
	).Scan(&activation.ActivatedAt, &activation.LastValidatedAt)
	if err != nil {
		// Transaction will be rolled back by defer — seat increment is automatically reverted.
		return false, fmt.Errorf("LicenseRepository.AtomicClaimSeatAndActivate: create activation: %w", err)
	}

	// Commit the transaction — both seat and activation are persisted atomically.
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("LicenseRepository.AtomicClaimSeatAndActivate: commit: %w", err)
	}

	return true, nil
}

// GetActivation retrieves an activation by license ID and machine ID.
func (r *LicenseRepository) GetActivation(ctx context.Context, licenseID uuid.UUID, machineID string) (*models.LicenseActivation, error) {
	query := `
		SELECT id, license_id, machine_id, device_name, ip_address, user_agent,
		       activated_at, last_validated_at, deactivated_at, status
		FROM iam_license_activations
		WHERE license_id = $1 AND machine_id = $2
	`

	var a models.LicenseActivation
	err := r.db.QueryRow(ctx, query, licenseID, machineID).Scan(
		&a.ID, &a.LicenseID, &a.MachineID, &a.DeviceName, &a.IPAddress, &a.UserAgent,
		&a.ActivatedAt, &a.LastValidatedAt, &a.DeactivatedAt, &a.Status,
	)
	if err != nil {
		return nil, fmt.Errorf("LicenseRepository.GetActivation: %w", err)
	}

	return &a, nil
}

// ListActivations returns all activations for a license.
func (r *LicenseRepository) ListActivations(ctx context.Context, licenseID uuid.UUID) ([]models.LicenseActivation, error) {
	query := `
		SELECT id, license_id, machine_id, device_name, ip_address, user_agent,
		       activated_at, last_validated_at, deactivated_at, status
		FROM iam_license_activations
		WHERE license_id = $1
		ORDER BY activated_at DESC
	`

	rows, err := r.db.Query(ctx, query, licenseID)
	if err != nil {
		return nil, fmt.Errorf("LicenseRepository.ListActivations: %w", err)
	}
	defer rows.Close()

	var activations []models.LicenseActivation
	for rows.Next() {
		var a models.LicenseActivation
		if err := rows.Scan(
			&a.ID, &a.LicenseID, &a.MachineID, &a.DeviceName, &a.IPAddress, &a.UserAgent,
			&a.ActivatedAt, &a.LastValidatedAt, &a.DeactivatedAt, &a.Status,
		); err != nil {
			return nil, fmt.Errorf("LicenseRepository.ListActivations scan: %w", err)
		}
		activations = append(activations, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("LicenseRepository.ListActivations rows: %w", err)
	}

	return activations, nil
}

// UpdateActivationLastValidated stamps last_validated_at to now for a given activation.
func (r *LicenseRepository) UpdateActivationLastValidated(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		"UPDATE iam_license_activations SET last_validated_at = NOW() WHERE id = $1",
		id,
	)
	if err != nil {
		return fmt.Errorf("LicenseRepository.UpdateActivationLastValidated: %w", err)
	}
	return nil
}

// DeactivateActivation marks an activation as deactivated.
func (r *LicenseRepository) DeactivateActivation(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		"UPDATE iam_license_activations SET status = 'deactivated', deactivated_at = NOW() WHERE id = $1",
		id,
	)
	if err != nil {
		return fmt.Errorf("LicenseRepository.DeactivateActivation: %w", err)
	}
	return nil
}

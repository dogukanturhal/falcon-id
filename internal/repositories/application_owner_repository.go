// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ApplicationOwnerRepository handles persistence of application ownership records.
type ApplicationOwnerRepository struct {
	pool *pgxpool.Pool
}

// NewApplicationOwnerRepository creates a new ApplicationOwnerRepository.
func NewApplicationOwnerRepository(pool *pgxpool.Pool) *ApplicationOwnerRepository {
	return &ApplicationOwnerRepository{pool: pool}
}

const applicationOwnerColumns = `id, application_id, owner_id, owner_type, role, added_by, created_at`

func scanApplicationOwner(row interface {
	Scan(dest ...any) error
},
) (*models.ApplicationOwner, error) {
	var o models.ApplicationOwner
	err := row.Scan(
		&o.ID, &o.ApplicationID, &o.OwnerID,
		&o.OwnerType, &o.Role,
		&o.AddedBy, &o.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// Add inserts a new owner record for an application, returning the DB-assigned
// created_at timestamp. A new UUID is assigned to o.ID if it is nil.
func (r *ApplicationOwnerRepository) Add(ctx context.Context, o *models.ApplicationOwner) error {
	if o.ID == uuid.Nil {
		o.ID = uuid.New()
	}

	err := r.pool.QueryRow(ctx, `
		INSERT INTO iam_application_owners (id, application_id, owner_id, owner_type, role, added_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at`,
		o.ID, o.ApplicationID, o.OwnerID, o.OwnerType, o.Role, o.AddedBy,
	).Scan(&o.CreatedAt)
	if err != nil {
		return fmt.Errorf("ApplicationOwnerRepository.Add: %w", err)
	}
	return nil
}

// Remove deletes the ownership record identified by (appID, ownerID).
// Returns an error if no matching record exists.
func (r *ApplicationOwnerRepository) Remove(ctx context.Context, appID, ownerID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM iam_application_owners
		WHERE application_id = $1 AND owner_id = $2`,
		appID, ownerID,
	)
	if err != nil {
		return fmt.Errorf("ApplicationOwnerRepository.Remove: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ApplicationOwnerRepository.Remove: owner not found")
	}
	return nil
}

// ListByApp returns all owners of an application ordered by creation time (oldest first).
func (r *ApplicationOwnerRepository) ListByApp(ctx context.Context, appID uuid.UUID) ([]models.ApplicationOwner, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+applicationOwnerColumns+`
		FROM iam_application_owners
		WHERE application_id = $1
		ORDER BY created_at ASC`,
		appID,
	)
	if err != nil {
		return nil, fmt.Errorf("ApplicationOwnerRepository.ListByApp: %w", err)
	}
	defer rows.Close()

	var owners []models.ApplicationOwner
	for rows.Next() {
		o, err := scanApplicationOwner(rows)
		if err != nil {
			return nil, fmt.Errorf("ApplicationOwnerRepository.ListByApp scan: %w", err)
		}
		owners = append(owners, *o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ApplicationOwnerRepository.ListByApp rows: %w", err)
	}
	return owners, nil
}

// IsOwner reports whether the given userID appears in the owners table for appID.
func (r *ApplicationOwnerRepository) IsOwner(ctx context.Context, appID, userID uuid.UUID) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM iam_application_owners
			WHERE application_id = $1 AND owner_id = $2
		)`,
		appID, userID,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("ApplicationOwnerRepository.IsOwner: %w", err)
	}
	return exists, nil
}

// CountByApp returns the total number of owners registered for an application.
func (r *ApplicationOwnerRepository) CountByApp(ctx context.Context, appID uuid.UUID) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM iam_application_owners WHERE application_id = $1`,
		appID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("ApplicationOwnerRepository.CountByApp: %w", err)
	}
	return count, nil
}

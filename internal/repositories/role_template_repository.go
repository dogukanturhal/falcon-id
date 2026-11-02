// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/productslug"
)

// RoleTemplateRepository is the persistence layer for iam_role_templates
// (migration 0012). Rows are append-only per (key, version) — there is
// deliberately no Update method: a new version is always a new row (see
// RoleTemplateDefinition's doc comment on RegisterModuleRequest).
type RoleTemplateRepository struct {
	db DBPool
}

// NewRoleTemplateRepository constructs a RoleTemplateRepository.
func NewRoleTemplateRepository(db *pgxpool.Pool) *RoleTemplateRepository {
	return &RoleTemplateRepository{db: db}
}

func scanRoleTemplate(row pgx.Row) (*models.RoleTemplate, error) {
	t := &models.RoleTemplate{}
	var nameI18n, descI18n, perms, relations []byte
	err := row.Scan(
		&t.ID, &t.Key, &t.Version, &t.Module, &t.Name, &nameI18n,
		&t.Description, &descI18n, &perms, &relations, &t.IsActive,
		&t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(nameI18n) > 0 {
		if err := json.Unmarshal(nameI18n, &t.NameI18n); err != nil {
			return nil, fmt.Errorf("unmarshal name_i18n: %w", err)
		}
	}
	if len(descI18n) > 0 {
		if err := json.Unmarshal(descI18n, &t.DescriptionI18n); err != nil {
			return nil, fmt.Errorf("unmarshal description_i18n: %w", err)
		}
	}
	if len(perms) > 0 {
		if err := json.Unmarshal(perms, &t.Permissions); err != nil {
			return nil, fmt.Errorf("unmarshal permissions: %w", err)
		}
	}
	if len(relations) > 0 {
		if err := json.Unmarshal(relations, &t.SpiceDBRelations); err != nil {
			return nil, fmt.Errorf("unmarshal spicedb_relations: %w", err)
		}
	}
	return t, nil
}

const roleTemplateColumns = `id, key, version, module, name, name_i18n, description, description_i18n, permissions, spicedb_relations, is_active, created_at, updated_at`

// Create inserts a new (key, version) row. Returns a wrapped pgx unique
// violation error (callers should treat this as "version already exists for
// this key" — the validator is expected to have already checked monotonicity,
// so this is a defense-in-depth race guard, not the primary check).
func (r *RoleTemplateRepository) Create(ctx context.Context, t *models.RoleTemplate) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	nameI18n, err := json.Marshal(nonNilMap(t.NameI18n))
	if err != nil {
		return fmt.Errorf("marshal name_i18n: %w", err)
	}
	descI18n, err := json.Marshal(nonNilMap(t.DescriptionI18n))
	if err != nil {
		return fmt.Errorf("marshal description_i18n: %w", err)
	}
	perms, err := json.Marshal(nonNilSlice(t.Permissions))
	if err != nil {
		return fmt.Errorf("marshal permissions: %w", err)
	}
	relations, err := json.Marshal(nonNilRelations(t.SpiceDBRelations))
	if err != nil {
		return fmt.Errorf("marshal spicedb_relations: %w", err)
	}

	query := `
		INSERT INTO iam_role_templates (id, key, version, module, name, name_i18n, description, description_i18n, permissions, spicedb_relations, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING created_at, updated_at`

	// New versions are always registered active; deactivation (e.g. a
	// module retiring a template) is a separate, explicit operation this
	// repository does not yet expose.
	t.IsActive = true

	return r.db.QueryRow(ctx, query,
		t.ID, t.Key, t.Version, t.Module, t.Name, nameI18n, t.Description, descI18n, perms, relations, t.IsActive,
	).Scan(&t.CreatedAt, &t.UpdatedAt)
}

// GetLatestByKey returns the highest-version row for key, or nil if the key
// has never been registered.
func (r *RoleTemplateRepository) GetLatestByKey(ctx context.Context, key string) (*models.RoleTemplate, error) {
	query := `SELECT ` + roleTemplateColumns + ` FROM iam_role_templates WHERE key = $1 ORDER BY version DESC LIMIT 1`
	t, err := scanRoleTemplate(r.db.QueryRow(ctx, query, key))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetLatestByKey: %w", err)
	}
	return t, nil
}

// GetByKeyVersion returns one specific version, or nil if not found.
func (r *RoleTemplateRepository) GetByKeyVersion(ctx context.Context, key string, version int) (*models.RoleTemplate, error) {
	query := `SELECT ` + roleTemplateColumns + ` FROM iam_role_templates WHERE key = $1 AND version = $2`
	t, err := scanRoleTemplate(r.db.QueryRow(ctx, query, key, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByKeyVersion: %w", err)
	}
	return t, nil
}

// ListLatestActiveByModules returns the latest active version of every
// template key belonging to any of modules. Used by
// GET /api/v1/role-templates to list templates for a tenant's entitled
// modules.
func (r *RoleTemplateRepository) ListLatestActiveByModules(ctx context.Context, modules []string) ([]models.RoleTemplate, error) {
	if len(modules) == 0 {
		return nil, nil
	}
	query := `
		SELECT ` + roleTemplateColumns + `
		FROM (
			SELECT *, ROW_NUMBER() OVER (PARTITION BY key ORDER BY version DESC) AS rn
			FROM iam_role_templates
			WHERE module = ANY($1) AND is_active = TRUE
		) latest
		WHERE rn = 1
		ORDER BY module, key`

	rows, err := r.db.Query(ctx, query, productslug.Expand(modules))
	if err != nil {
		return nil, fmt.Errorf("ListLatestActiveByModules: %w", err)
	}
	defer rows.Close()

	var out []models.RoleTemplate
	for rows.Next() {
		t, err := scanRoleTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("ListLatestActiveByModules scan: %w", err)
		}
		out = append(out, *t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListLatestActiveByModules rows: %w", err)
	}
	return out, nil
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func nonNilSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilRelations(s []models.RoleTemplateSpiceDBRelation) []models.RoleTemplateSpiceDBRelation {
	if s == nil {
		return []models.RoleTemplateSpiceDBRelation{}
	}
	return s
}

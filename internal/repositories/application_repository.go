// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ApplicationRepository handles application object database operations.
type ApplicationRepository struct {
	pool DBTX
}

// NewApplicationRepository creates a new ApplicationRepository.
func NewApplicationRepository(pool *pgxpool.Pool) *ApplicationRepository {
	return &ApplicationRepository{pool: pool}
}

const applicationColumns = `id, display_name, slug, description, logo_url, homepage_url,
	privacy_policy_url, terms_of_service_url, app_type, publisher_type, is_platform_app,
	sign_in_audience, redirect_uris, post_logout_uris, allowed_grant_types, default_scopes,
	access_token_lifetime, refresh_token_lifetime, id_token_lifetime,
	is_public, require_pkce, preauthorized, status, tags, metadata,
	publisher_verified, publisher_verified_at, publisher_domain,
	created_by, created_at, updated_at, deleted_at, purge_after,
	stale_since, last_sign_in_at`

func scanApplication(scanner interface {
	Scan(dest ...interface{}) error
},
) (*models.Application, error) {
	var app models.Application
	err := scanner.Scan(
		&app.ID, &app.DisplayName, &app.Slug, &app.Description,
		&app.LogoURL, &app.HomepageURL, &app.PrivacyPolicyURL, &app.TermsOfServiceURL,
		&app.AppType, &app.PublisherType, &app.IsPlatformApp,
		&app.SignInAudience, &app.RedirectURIs, &app.PostLogoutURIs,
		&app.AllowedGrantTypes, &app.DefaultScopes,
		&app.AccessTokenLifetime, &app.RefreshTokenLifetime, &app.IDTokenLifetime,
		&app.IsPublic, &app.RequirePKCE, &app.Preauthorized,
		&app.Status, &app.Tags, &app.Metadata,
		&app.PublisherVerified, &app.PublisherVerifiedAt, &app.PublisherDomain,
		&app.CreatedBy, &app.CreatedAt, &app.UpdatedAt,
		&app.DeletedAt, &app.PurgeAfter,
		&app.StaleSince, &app.LastSignInAt,
	)
	if err != nil {
		return nil, err
	}
	return &app, nil
}

// Create inserts a new application object.
func (r *ApplicationRepository) Create(ctx context.Context, app *models.Application) error {
	if app.ID == uuid.Nil {
		app.ID = uuid.New()
	}

	query := fmt.Sprintf(`
		INSERT INTO iam_applications (%s)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31)
		RETURNING created_at, updated_at`, applicationColumns)

	err := r.pool.QueryRow(ctx, query,
		app.ID, app.DisplayName, app.Slug, app.Description,
		app.LogoURL, app.HomepageURL, app.PrivacyPolicyURL, app.TermsOfServiceURL,
		app.AppType, app.PublisherType, app.IsPlatformApp,
		app.SignInAudience, app.RedirectURIs, app.PostLogoutURIs,
		app.AllowedGrantTypes, app.DefaultScopes,
		app.AccessTokenLifetime, app.RefreshTokenLifetime, app.IDTokenLifetime,
		app.IsPublic, app.RequirePKCE, app.Preauthorized,
		app.Status, app.Tags, app.Metadata,
		app.PublisherVerified, app.PublisherVerifiedAt, app.PublisherDomain,
		app.CreatedBy, app.CreatedAt, app.UpdatedAt,
	).Scan(&app.CreatedAt, &app.UpdatedAt)
	if err != nil {
		return fmt.Errorf("ApplicationRepository.Create: %w", err)
	}
	return nil
}

// GetByID retrieves an application by UUID, excluding soft-deleted records.
func (r *ApplicationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Application, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_applications WHERE id = $1 AND deleted_at IS NULL`, applicationColumns)
	app, err := scanApplication(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("ApplicationRepository.GetByID: %w", err)
	}
	return app, nil
}

// GetByIDIncludeDeleted retrieves an application by UUID regardless of soft-delete status.
func (r *ApplicationRepository) GetByIDIncludeDeleted(ctx context.Context, id uuid.UUID) (*models.Application, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_applications WHERE id = $1`, applicationColumns)
	app, err := scanApplication(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("ApplicationRepository.GetByIDIncludeDeleted: %w", err)
	}
	return app, nil
}

// GetBySlug retrieves an application by slug, excluding soft-deleted records.
func (r *ApplicationRepository) GetBySlug(ctx context.Context, slug string) (*models.Application, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_applications WHERE slug = $1 AND deleted_at IS NULL`, applicationColumns)
	app, err := scanApplication(r.pool.QueryRow(ctx, query, slug))
	if err != nil {
		return nil, fmt.Errorf("ApplicationRepository.GetBySlug: %w", err)
	}
	return app, nil
}

// List returns a paginated list of applications with optional filters.
func (r *ApplicationRepository) List(
	ctx context.Context,
	page, pageSize int,
	status string,
	publisherType string,
	isPlatformApp *bool,
) ([]models.Application, int64, error) {
	offset := (page - 1) * pageSize

	baseQuery := "FROM iam_applications WHERE deleted_at IS NULL"
	args := []interface{}{}
	argIndex := 1

	if status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, status)
		argIndex++
	}
	if publisherType != "" {
		baseQuery += fmt.Sprintf(" AND publisher_type = $%d", argIndex)
		args = append(args, publisherType)
		argIndex++
	}
	if isPlatformApp != nil {
		baseQuery += fmt.Sprintf(" AND is_platform_app = $%d", argIndex)
		args = append(args, *isPlatformApp)
		argIndex++
	}

	var total int64
	if err := r.pool.QueryRow(ctx, "SELECT COUNT(*) "+baseQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("ApplicationRepository.List count: %w", err)
	}

	selectQuery := fmt.Sprintf(`SELECT %s %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		applicationColumns, baseQuery, argIndex, argIndex+1)
	args = append(args, pageSize, offset)

	rows, err := r.pool.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("ApplicationRepository.List query: %w", err)
	}
	defer rows.Close()

	var apps []models.Application
	for rows.Next() {
		app, err := scanApplication(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("ApplicationRepository.List scan: %w", err)
		}
		apps = append(apps, *app)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ApplicationRepository.List rows: %w", err)
	}

	return apps, total, nil
}

// buildApplicationSetClauses constructs the SET clause fragments and positional
// argument list for a partial application update. argIndex must start at 1 and
// is incremented for each appended field.
func buildApplicationSetClauses(req *models.UpdateApplicationRequest) ([]string, []interface{}) {
	type scalarField struct {
		col string
		val interface{}
	}
	// Collect non-nil scalar string/bool/int fields.
	var scalars []scalarField
	if req.DisplayName != nil {
		scalars = append(scalars, scalarField{"display_name", *req.DisplayName})
	}
	if req.Description != nil {
		scalars = append(scalars, scalarField{"description", *req.Description})
	}
	if req.LogoURL != nil {
		scalars = append(scalars, scalarField{"logo_url", *req.LogoURL})
	}
	if req.HomepageURL != nil {
		scalars = append(scalars, scalarField{"homepage_url", *req.HomepageURL})
	}
	if req.PrivacyPolicyURL != nil {
		scalars = append(scalars, scalarField{"privacy_policy_url", *req.PrivacyPolicyURL})
	}
	if req.TermsOfServiceURL != nil {
		scalars = append(scalars, scalarField{"terms_of_service_url", *req.TermsOfServiceURL})
	}
	if req.AppType != nil {
		scalars = append(scalars, scalarField{"app_type", *req.AppType})
	}
	if req.PublisherType != nil {
		scalars = append(scalars, scalarField{"publisher_type", *req.PublisherType})
	}
	if req.SignInAudience != nil {
		scalars = append(scalars, scalarField{"sign_in_audience", *req.SignInAudience})
	}
	if req.AccessTokenLifetime != nil {
		scalars = append(scalars, scalarField{"access_token_lifetime", *req.AccessTokenLifetime})
	}
	if req.RefreshTokenLifetime != nil {
		scalars = append(scalars, scalarField{"refresh_token_lifetime", *req.RefreshTokenLifetime})
	}
	if req.IDTokenLifetime != nil {
		scalars = append(scalars, scalarField{"id_token_lifetime", *req.IDTokenLifetime})
	}
	if req.IsPublic != nil {
		scalars = append(scalars, scalarField{"is_public", *req.IsPublic})
	}
	if req.RequirePKCE != nil {
		scalars = append(scalars, scalarField{"require_pkce", *req.RequirePKCE})
	}
	if req.Preauthorized != nil {
		scalars = append(scalars, scalarField{"preauthorized", *req.Preauthorized})
	}
	if req.Status != nil {
		scalars = append(scalars, scalarField{"status", *req.Status})
	}

	setClauses := make([]string, 0, len(scalars)+5)
	args := make([]interface{}, 0, len(scalars)+5)
	pos := 1

	for _, f := range scalars {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", f.col, pos))
		args = append(args, f.val)
		pos++
	}

	// Slice/array fields passed by value (not dereferenced).
	if req.RedirectURIs != nil {
		setClauses = append(setClauses, fmt.Sprintf("redirect_uris = $%d", pos))
		args = append(args, req.RedirectURIs)
		pos++
	}
	if req.PostLogoutURIs != nil {
		setClauses = append(setClauses, fmt.Sprintf("post_logout_uris = $%d", pos))
		args = append(args, req.PostLogoutURIs)
		pos++
	}
	if req.AllowedGrantTypes != nil {
		setClauses = append(setClauses, fmt.Sprintf("allowed_grant_types = $%d", pos))
		args = append(args, req.AllowedGrantTypes)
		pos++
	}
	if req.DefaultScopes != nil {
		setClauses = append(setClauses, fmt.Sprintf("default_scopes = $%d", pos))
		args = append(args, req.DefaultScopes)
		pos++
	}
	if req.Tags != nil {
		setClauses = append(setClauses, fmt.Sprintf("tags = $%d", pos))
		args = append(args, req.Tags)
	}

	return setClauses, args
}

// Update applies partial updates to an application.
func (r *ApplicationRepository) Update(ctx context.Context, id uuid.UUID, req *models.UpdateApplicationRequest) (*models.Application, error) {
	setClauses, args := buildApplicationSetClauses(req)

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	setClauses = append(setClauses, "updated_at = NOW()")
	argIndex := len(args) + 1
	args = append(args, id)

	query := fmt.Sprintf(`
		UPDATE iam_applications SET %s WHERE id = $%d
		RETURNING %s`,
		strings.Join(setClauses, ", "), argIndex, applicationColumns)

	app, err := scanApplication(r.pool.QueryRow(ctx, query, args...))
	if err != nil {
		return nil, fmt.Errorf("ApplicationRepository.Update: %w", err)
	}
	return app, nil
}

// Delete removes an application by ID.
func (r *ApplicationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, "DELETE FROM iam_applications WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("ApplicationRepository.Delete: %w", err)
	}
	return nil
}

// GetPreauthorized returns all preauthorized, active, non-deleted applications.
func (r *ApplicationRepository) GetPreauthorized(ctx context.Context) ([]models.Application, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_applications WHERE preauthorized = true AND status = 'active' AND deleted_at IS NULL ORDER BY created_at`, applicationColumns)

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ApplicationRepository.GetPreauthorized: %w", err)
	}
	defer rows.Close()

	var apps []models.Application
	for rows.Next() {
		app, err := scanApplication(rows)
		if err != nil {
			return nil, fmt.Errorf("ApplicationRepository.GetPreauthorized scan: %w", err)
		}
		apps = append(apps, *app)
	}
	return apps, rows.Err()
}

// CountServicePrincipals returns the number of SPs for an application.
func (r *ApplicationRepository) CountServicePrincipals(ctx context.Context, appID uuid.UUID) (int64, error) {
	var count int64
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_service_principals WHERE application_id = $1`, appID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("ApplicationRepository.CountServicePrincipals: %w", err)
	}
	return count, nil
}

// GetAppRoles returns the raw JSONB bytes of the app_roles column for an application.
// This allows the AppRoleService to validate role IDs without altering the Application scan.
func (r *ApplicationRepository) GetAppRoles(ctx context.Context, appID uuid.UUID) ([]byte, error) {
	var raw []byte
	err := r.pool.QueryRow(ctx,
		"SELECT COALESCE(app_roles, '[]'::jsonb) FROM iam_applications WHERE id = $1", appID,
	).Scan(&raw)
	if err != nil {
		return nil, fmt.Errorf("ApplicationRepository.GetAppRoles: %w", err)
	}
	return raw, nil
}

// UpdatePublisherVerification sets publisher verification fields on an application.
func (r *ApplicationRepository) UpdatePublisherVerification(ctx context.Context, id uuid.UUID, verified bool, domain *string) error {
	query := `UPDATE iam_applications SET publisher_verified = $1, publisher_domain = $2, updated_at = NOW()`
	args := []interface{}{verified, domain}
	if verified {
		query += `, publisher_verified_at = NOW()`
	} else {
		query += `, publisher_verified_at = NULL`
	}
	query += fmt.Sprintf(` WHERE id = $%d`, len(args)+1)
	args = append(args, id)

	_, err := r.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("ApplicationRepository.UpdatePublisherVerification: %w", err)
	}
	return nil
}

// SoftDelete marks an application as deleted and sets purge_after to 30 days from now.
func (r *ApplicationRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_applications
		 SET deleted_at = NOW(), purge_after = NOW() + INTERVAL '30 days', updated_at = NOW()
		 WHERE id = $1 AND deleted_at IS NULL`,
		id,
	)
	if err != nil {
		return fmt.Errorf("ApplicationRepository.SoftDelete: %w", err)
	}
	return nil
}

// Restore clears the soft-delete timestamps on an application, but only if the
// purge window has not yet elapsed.
func (r *ApplicationRepository) Restore(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE iam_applications
		 SET deleted_at = NULL, purge_after = NULL, updated_at = NOW()
		 WHERE id = $1 AND deleted_at IS NOT NULL AND purge_after > NOW()`,
		id,
	)
	if err != nil {
		return fmt.Errorf("ApplicationRepository.Restore: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ApplicationRepository.Restore: application not found, already restored, or purge window has elapsed")
	}
	return nil
}

// PurgeExpired hard-deletes all applications whose purge_after timestamp has passed.
// Returns the number of rows deleted.
func (r *ApplicationRepository) PurgeExpired(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM iam_applications
		 WHERE purge_after IS NOT NULL AND purge_after < NOW()`,
	)
	if err != nil {
		return 0, fmt.Errorf("ApplicationRepository.PurgeExpired: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ListDeleted returns all soft-deleted applications that have not yet been purged.
func (r *ApplicationRepository) ListDeleted(ctx context.Context) ([]models.Application, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM iam_applications
		 WHERE deleted_at IS NOT NULL AND purge_after > NOW()
		 ORDER BY deleted_at DESC`,
		applicationColumns,
	)

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ApplicationRepository.ListDeleted: %w", err)
	}
	defer rows.Close()

	var apps []models.Application
	for rows.Next() {
		app, err := scanApplication(rows)
		if err != nil {
			return nil, fmt.Errorf("ApplicationRepository.ListDeleted scan: %w", err)
		}
		apps = append(apps, *app)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ApplicationRepository.ListDeleted rows: %w", err)
	}
	return apps, nil
}

// ListActive returns all non-deleted applications with status 'active', ordered by creation time.
// Platform apps and preauthorized apps are included; callers can filter as needed.
func (r *ApplicationRepository) ListActive(ctx context.Context) ([]models.Application, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM iam_applications WHERE status = 'active' AND deleted_at IS NULL ORDER BY created_at ASC`,
		applicationColumns,
	)

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ApplicationRepository.ListActive: %w", err)
	}
	defer rows.Close()

	var apps []models.Application
	for rows.Next() {
		app, err := scanApplication(rows)
		if err != nil {
			return nil, fmt.Errorf("ApplicationRepository.ListActive scan: %w", err)
		}
		apps = append(apps, *app)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ApplicationRepository.ListActive rows: %w", err)
	}
	return apps, nil
}

// MarkStale sets stale_since on an application to record when it was first detected as stale.
// If stale_since is already set, it is left unchanged (first detection wins).
func (r *ApplicationRepository) MarkStale(ctx context.Context, appID uuid.UUID, since time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_applications SET stale_since = $1, updated_at = NOW() WHERE id = $2 AND stale_since IS NULL`,
		since, appID,
	)
	if err != nil {
		return fmt.Errorf("ApplicationRepository.MarkStale: %w", err)
	}
	return nil
}

// ClearStale removes the stale_since marker on an application when it regains activity.
func (r *ApplicationRepository) ClearStale(ctx context.Context, appID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_applications SET stale_since = NULL, updated_at = NOW() WHERE id = $1`,
		appID,
	)
	if err != nil {
		return fmt.Errorf("ApplicationRepository.ClearStale: %w", err)
	}
	return nil
}

// UpdateLastSignIn records the most recent sign-in timestamp for an application.
// Call this whenever a token is issued to an SP of this application.
func (r *ApplicationRepository) UpdateLastSignIn(ctx context.Context, appID uuid.UUID, t time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_applications SET last_sign_in_at = $1, updated_at = NOW() WHERE id = $2`,
		t, appID,
	)
	if err != nil {
		return fmt.Errorf("ApplicationRepository.UpdateLastSignIn: %w", err)
	}
	return nil
}

// GetServicePrincipalCount returns the number of active (non-deleted) service principals
// provisioned for a given application across all tenants.
func (r *ApplicationRepository) GetServicePrincipalCount(ctx context.Context, appID uuid.UUID) (int64, error) {
	var count int64
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_service_principals WHERE application_id = $1 AND deleted_at IS NULL`,
		appID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("ApplicationRepository.GetServicePrincipalCount: %w", err)
	}
	return count, nil
}

// SoftDeleteSP marks a service principal as deleted and sets purge_after to 30 days from now.
func (r *ApplicationRepository) SoftDeleteSP(ctx context.Context, spID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_service_principals
		 SET deleted_at = NOW(), purge_after = NOW() + INTERVAL '30 days', updated_at = NOW()
		 WHERE id = $1 AND deleted_at IS NULL`,
		spID,
	)
	if err != nil {
		return fmt.Errorf("ApplicationRepository.SoftDeleteSP: %w", err)
	}
	return nil
}

// RestoreSP clears the soft-delete timestamps on a service principal, but only
// if the purge window has not yet elapsed.
func (r *ApplicationRepository) RestoreSP(ctx context.Context, spID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE iam_service_principals
		 SET deleted_at = NULL, purge_after = NULL, updated_at = NOW()
		 WHERE id = $1 AND deleted_at IS NOT NULL AND purge_after > NOW()`,
		spID,
	)
	if err != nil {
		return fmt.Errorf("ApplicationRepository.RestoreSP: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ApplicationRepository.RestoreSP: service principal not found, already restored, or purge window has elapsed")
	}
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RouteManifestEntry is the domain model for a single row in iam_route_manifests.
type RouteManifestEntry struct {
	ID           uuid.UUID `json:"id"`
	ServiceSlug  string    `json:"service_slug"`
	URIPrefix    string    `json:"uri_prefix"`
	UpstreamHost string    `json:"upstream_host"`
	UpstreamPort int       `json:"upstream_port"`
	Methods      []string  `json:"methods"`
	RequireAuth  bool      `json:"require_auth"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RouteManifestRepository manages iam_route_manifests persistence.
type RouteManifestRepository struct {
	pool *pgxpool.Pool
}

// NewRouteManifestRepository creates a new repository backed by pool.
func NewRouteManifestRepository(pool *pgxpool.Pool) *RouteManifestRepository {
	return &RouteManifestRepository{pool: pool}
}

// UpsertBatch inserts or updates a batch of route manifest entries for a given
// service.  Each entry is identified by (service_slug, uri_prefix); on conflict
// the upstream host/port, methods, require_auth, and updated_at are refreshed.
//
// Returns the number of rows inserted and the number of rows updated.
func (r *RouteManifestRepository) UpsertBatch(ctx context.Context, entries []RouteManifestEntry) (inserted, updated int, err error) {
	if len(entries) == 0 {
		return 0, 0, nil
	}

	query := `
		INSERT INTO iam_route_manifests (
			service_slug, uri_prefix, upstream_host, upstream_port,
			methods, require_auth, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
		ON CONFLICT (service_slug, uri_prefix) DO UPDATE SET
			upstream_host = EXCLUDED.upstream_host,
			upstream_port = EXCLUDED.upstream_port,
			methods       = EXCLUDED.methods,
			require_auth  = EXCLUDED.require_auth,
			updated_at    = EXCLUDED.updated_at
		RETURNING (xmax = 0) AS is_new`

	now := time.Now().UTC()

	for _, e := range entries {
		methods := e.Methods
		if len(methods) == 0 {
			methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
		}

		var isNew bool
		scanErr := r.pool.QueryRow(ctx, query,
			e.ServiceSlug, e.URIPrefix, e.UpstreamHost, e.UpstreamPort,
			methods, e.RequireAuth, now,
		).Scan(&isNew)
		if scanErr != nil {
			return inserted, updated, fmt.Errorf("UpsertBatch: upsert %q %q: %w", e.ServiceSlug, e.URIPrefix, scanErr)
		}
		if isNew {
			inserted++
		} else {
			updated++
		}
	}

	return inserted, updated, nil
}

// ListByService returns all route manifest entries registered for serviceSlug.
func (r *RouteManifestRepository) ListByService(ctx context.Context, serviceSlug string) ([]RouteManifestEntry, error) {
	query := `
		SELECT id, service_slug, uri_prefix, upstream_host, upstream_port,
		       methods, require_auth, created_at, updated_at
		FROM iam_route_manifests
		WHERE service_slug = $1
		ORDER BY uri_prefix`

	rows, err := r.pool.Query(ctx, query, serviceSlug)
	if err != nil {
		return nil, fmt.Errorf("ListByService: %w", err)
	}
	defer rows.Close()

	var entries []RouteManifestEntry
	for rows.Next() {
		var e RouteManifestEntry
		if err := rows.Scan(
			&e.ID, &e.ServiceSlug, &e.URIPrefix, &e.UpstreamHost, &e.UpstreamPort,
			&e.Methods, &e.RequireAuth, &e.CreatedAt, &e.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("ListByService: scan: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListByService: rows: %w", err)
	}

	return entries, nil
}

// ListAll returns all route manifest entries across every service, ordered by
// service slug then URI prefix.  Used by the platform-admin inspection endpoint.
func (r *RouteManifestRepository) ListAll(ctx context.Context) ([]RouteManifestEntry, error) {
	query := `
		SELECT id, service_slug, uri_prefix, upstream_host, upstream_port,
		       methods, require_auth, created_at, updated_at
		FROM iam_route_manifests
		ORDER BY service_slug, uri_prefix`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ListAll: %w", err)
	}
	defer rows.Close()

	var entries []RouteManifestEntry
	for rows.Next() {
		var e RouteManifestEntry
		if err := rows.Scan(
			&e.ID, &e.ServiceSlug, &e.URIPrefix, &e.UpstreamHost, &e.UpstreamPort,
			&e.Methods, &e.RequireAuth, &e.CreatedAt, &e.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("ListAll: scan: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListAll: rows: %w", err)
	}

	return entries, nil
}

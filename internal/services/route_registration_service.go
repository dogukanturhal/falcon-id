// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/apisix"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// apisixClient is the interface the RouteRegistrationService uses to communicate
// with the APISIX Admin API.  It is deliberately narrow so tests can inject a
// lightweight fake without depending on the concrete apisix.Client type.
type apisixClient interface {
	CreateRoute(ctx context.Context, route *apisix.Route) (string, error)
	DeleteRoute(ctx context.Context, routeID string) error
	CreateUpstream(ctx context.Context, upstream *apisix.Upstream) (string, error)
	DeleteUpstream(ctx context.Context, upstreamID string) error
}

// RouteRegistrationService translates product manifest EndpointSpecs into
// APISIX routes and upstreams, and persists the resulting IDs in the
// iam_apisix_routes table so they can be cleaned up on deprovisioning.
type RouteRegistrationService struct {
	apisixClient apisixClient
	db           *pgxpool.Pool
}

// NewRouteRegistrationService creates a new RouteRegistrationService.
// db is the primary IAM database pool used to persist and query endpoint records.
// client is the APISIX Admin API client.
func NewRouteRegistrationService(db *pgxpool.Pool, client apisixClient) *RouteRegistrationService {
	return &RouteRegistrationService{
		apisixClient: client,
		db:           db,
	}
}

// RegisterRoutes parses the product manifest, creates APISIX upstreams and routes
// for each defined endpoint, and persists the route/upstream IDs in
// iam_apisix_routes so they can be removed during deprovisioning.
//
// If the manifest defines no endpoints the step is skipped gracefully.
// Route and upstream IDs follow the pattern:
//
//	upstream: {productSlug}-{instanceID}-upstream
//	route:    {productSlug}-{endpointName}-{instanceID}
func (s *RouteRegistrationService) RegisterRoutes(
	ctx context.Context,
	instance *models.ProductInstance,
	product *models.Product,
) error {
	manifest, err := product.ParseManifest()
	if err != nil {
		return fmt.Errorf("RouteRegistrationService.RegisterRoutes: parse manifest: %w", err)
	}

	if manifest == nil || len(manifest.Endpoints) == 0 {
		logger.Log.Info("No endpoints in manifest, skipping route registration",
			zap.String("instance_id", instance.ID.String()),
			zap.String("product_slug", product.Slug),
		)
		return nil
	}

	for i, ep := range manifest.Endpoints {
		if err := s.registerEndpoint(ctx, instance, product, ep, i); err != nil {
			return fmt.Errorf("RouteRegistrationService.RegisterRoutes: endpoint %q: %w", ep.Path, err)
		}
	}

	logger.Log.Info("APISIX routes registered for product instance",
		zap.String("instance_id", instance.ID.String()),
		zap.String("product_slug", product.Slug),
		zap.Int("endpoint_count", len(manifest.Endpoints)),
	)

	return nil
}

// registerEndpoint creates a single upstream + route pair for one EndpointSpec
// and records the result in iam_apisix_routes.
func (s *RouteRegistrationService) registerEndpoint(
	ctx context.Context,
	instance *models.ProductInstance,
	product *models.Product,
	ep models.EndpointSpec,
	index int,
) error {
	// Derive a stable, readable name for the endpoint.
	// Use a sanitised combination of the product slug, HTTP method, and index so
	// that endpoint names are unique even when two endpoints share the same path.
	endpointName := buildEndpointName(product.Slug, ep.Method, ep.Path, index)

	// Determine the upstream host.  The manifest can specify a per-endpoint
	// UpstreamHost; if absent we fall back to a conventional service name
	// derived from the product slug.
	upstreamHost := ep.UpstreamHost
	if upstreamHost == "" {
		upstreamHost = defaultUpstreamHost(product.Slug)
	}

	// Create or replace the upstream.
	upstreamID := buildUpstreamID(product.Slug, instance.ID, index)
	upstream := &apisix.Upstream{
		ID:    upstreamID,
		Name:  upstreamID,
		Type:  "roundrobin",
		Nodes: map[string]int{upstreamHost: 1},
	}

	createdUpstreamID, err := s.apisixClient.CreateUpstream(ctx, upstream)
	if err != nil {
		return fmt.Errorf("create upstream: %w", err)
	}

	logger.Log.Debug("APISIX upstream created",
		zap.String("upstream_id", createdUpstreamID),
		zap.String("host", upstreamHost),
	)

	// Build the route URI.  If the endpoint spec provides a RoutePrefix, honour
	// it; otherwise generate a wildcard prefix from the product slug.
	routeURI := ep.RoutePrefix
	if routeURI == "" {
		routeURI = buildRouteURI(product.Slug, ep.Path)
	}

	// Build the APISIX route.
	routeID := buildRouteID(product.Slug, endpointName, instance.ID)
	plugins := buildPlugins(ep)

	route := &apisix.Route{
		ID:   routeID,
		Name: routeID,
		URI:  routeURI,
		Methods: []string{
			strings.ToUpper(ep.Method),
		},
		Upstream: &apisix.Upstream{
			Type:  "roundrobin",
			Nodes: map[string]int{upstreamHost: 1},
		},
		Plugins: plugins,
		Status:  1, // 1 = enabled
		Labels: map[string]string{
			"product":    product.Slug,
			"instance":   instance.ID.String(),
			"tenant":     instance.TenantID.String(),
			"managed_by": serviceNameFalconID,
		},
	}

	createdRouteID, err := s.apisixClient.CreateRoute(ctx, route)
	if err != nil {
		// Best-effort cleanup of the upstream we just created to avoid orphans.
		_ = s.apisixClient.DeleteUpstream(ctx, createdUpstreamID)
		return fmt.Errorf("create route: %w", err)
	}

	logger.Log.Debug("APISIX route created",
		zap.String("route_id", createdRouteID),
		zap.String("uri", routeURI),
		zap.String("method", ep.Method),
	)

	// Persist the mapping so DeregisterRoutes can look it up later.
	if err := s.persistEndpoint(ctx, instance, product, ep, routeURI, upstreamHost, createdRouteID, createdUpstreamID); err != nil {
		// Clean up the APISIX resources we just registered to avoid leaks.
		_ = s.apisixClient.DeleteRoute(ctx, createdRouteID)
		_ = s.apisixClient.DeleteUpstream(ctx, createdUpstreamID)
		return fmt.Errorf("persist endpoint record: %w", err)
	}

	return nil
}

// persistEndpoint inserts a row into iam_apisix_routes recording the APISIX
// route and upstream IDs for later cleanup.
func (s *RouteRegistrationService) persistEndpoint(
	ctx context.Context,
	instance *models.ProductInstance,
	product *models.Product,
	ep models.EndpointSpec,
	routeURI string,
	upstreamHost string,
	routeID string,
	upstreamID string,
) error {
	const q = `
		INSERT INTO iam_apisix_routes (
			instance_id, product_id, tenant_id,
			endpoint_path, endpoint_method,
			apisix_route_id, apisix_upstream_id,
			upstream_host, route_uri, status
		) VALUES (
			$1, $2, $3,
			$4, $5,
			$6, $7,
			$8, $9, 'active'
		)
		ON CONFLICT DO NOTHING`

	_, err := s.db.Exec(ctx, q,
		instance.ID,
		product.ID,
		instance.TenantID,
		ep.Path,
		strings.ToUpper(ep.Method),
		routeID,
		upstreamID,
		upstreamHost,
		routeURI,
	)
	if err != nil {
		return fmt.Errorf("RouteRegistrationService.persistEndpoint: %w", err)
	}
	return nil
}

// DeregisterRoutes reads all active endpoint records for the given instance from
// iam_apisix_routes, deletes the corresponding APISIX routes and upstreams,
// and marks the database rows as deleted.
//
// Errors from APISIX are logged but do not abort the cleanup — a partially
// removed route should not prevent the instance from being marked deleted.
func (s *RouteRegistrationService) DeregisterRoutes(ctx context.Context, instanceID uuid.UUID) error {
	rows, err := s.fetchEndpoints(ctx, instanceID)
	if err != nil {
		return fmt.Errorf("RouteRegistrationService.DeregisterRoutes: fetch endpoints: %w", err)
	}

	if len(rows) == 0 {
		logger.Log.Debug("No service endpoints to deregister",
			zap.String("instance_id", instanceID.String()),
		)
		return nil
	}

	var firstErr error

	for _, row := range rows {
		if row.apisixRouteID != "" {
			if err := s.apisixClient.DeleteRoute(ctx, row.apisixRouteID); err != nil {
				logger.Log.Error("Failed to delete APISIX route",
					zap.String("route_id", row.apisixRouteID),
					zap.String("instance_id", instanceID.String()),
					zap.Error(err),
				)
				if firstErr == nil {
					firstErr = err
				}
			} else {
				logger.Log.Debug("APISIX route deleted",
					zap.String("route_id", row.apisixRouteID),
				)
			}
		}

		if row.apisixUpstreamID != "" {
			if err := s.apisixClient.DeleteUpstream(ctx, row.apisixUpstreamID); err != nil {
				logger.Log.Error("Failed to delete APISIX upstream",
					zap.String("upstream_id", row.apisixUpstreamID),
					zap.String("instance_id", instanceID.String()),
					zap.Error(err),
				)
				if firstErr == nil {
					firstErr = err
				}
			} else {
				logger.Log.Debug("APISIX upstream deleted",
					zap.String("upstream_id", row.apisixUpstreamID),
				)
			}
		}
	}

	// Mark all endpoint rows for this instance as deleted regardless of APISIX errors.
	if err := s.markEndpointsDeleted(ctx, instanceID); err != nil {
		return fmt.Errorf("RouteRegistrationService.DeregisterRoutes: mark deleted: %w", err)
	}

	if firstErr != nil {
		// Return the first APISIX error as a warning — the DB records are cleaned up.
		logger.Log.Warn("Some APISIX resources could not be deleted during deregistration",
			zap.String("instance_id", instanceID.String()),
			zap.Error(firstErr),
		)
	}

	logger.Log.Info("APISIX routes deregistered for product instance",
		zap.String("instance_id", instanceID.String()),
		zap.Int("endpoint_count", len(rows)),
	)

	return nil
}

// endpointRow is a minimal projection of iam_apisix_routes used by
// DeregisterRoutes.
type endpointRow struct {
	apisixRouteID    string
	apisixUpstreamID string
}

// fetchEndpoints returns the active APISIX IDs for a product instance.
func (s *RouteRegistrationService) fetchEndpoints(ctx context.Context, instanceID uuid.UUID) ([]endpointRow, error) {
	const q = `
		SELECT
			COALESCE(apisix_route_id, '')    AS apisix_route_id,
			COALESCE(apisix_upstream_id, '') AS apisix_upstream_id
		FROM iam_apisix_routes
		WHERE instance_id = $1
		  AND status = 'active'`

	pgRows, err := s.db.Query(ctx, q, instanceID)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer pgRows.Close()

	var rows []endpointRow
	for pgRows.Next() {
		var row endpointRow
		if err := pgRows.Scan(&row.apisixRouteID, &row.apisixUpstreamID); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		rows = append(rows, row)
	}
	if err := pgRows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return rows, nil
}

// markEndpointsDeleted sets status = 'deleted' for all endpoint rows belonging
// to the given instance.
func (s *RouteRegistrationService) markEndpointsDeleted(ctx context.Context, instanceID uuid.UUID) error {
	const q = `
		UPDATE iam_apisix_routes
		   SET status     = 'deleted',
		       updated_at = now()
		 WHERE instance_id = $1
		   AND status      = 'active'`

	_, err := s.db.Exec(ctx, q, instanceID)
	if err != nil {
		return fmt.Errorf("RouteRegistrationService.markEndpointsDeleted: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Naming helpers
// ---------------------------------------------------------------------------

// buildEndpointName returns a stable, readable identifier for an endpoint within
// a product, composed of the product slug, HTTP method, and positional index.
// The index ensures uniqueness when multiple endpoints share the same path but
// differ by method, and when a product defines many endpoints.
func buildEndpointName(productSlug, method, path string, index int) string {
	// Convert the path into a component safe for use in IDs by replacing slashes
	// and other special chars with hyphens and collapsing duplicates.
	sanitised := sanitisePath(path)
	return fmt.Sprintf("%s-%s-%s-%d", productSlug, strings.ToLower(method), sanitised, index)
}

// buildUpstreamID returns the APISIX upstream ID for a specific endpoint of a
// product instance.  Including the index makes it unique per endpoint so each
// endpoint can reference a different upstream if UpstreamHost differs.
func buildUpstreamID(productSlug string, instanceID uuid.UUID, index int) string {
	return fmt.Sprintf("%s-%s-upstream-%d", productSlug, instanceID.String(), index)
}

// buildRouteID returns a deterministic APISIX route ID for an endpoint.
func buildRouteID(productSlug, endpointName string, instanceID uuid.UUID) string {
	return fmt.Sprintf("%s-%s-%s", productSlug, endpointName, instanceID.String())
}

// buildRouteURI constructs the APISIX URI pattern for an endpoint.
// When ep.Path is a concrete path (e.g. "/v1/invoices"), this produces a
// wildcard catch-all at /api/{productSlug}{path}/* so the upstream receives
// all sub-routes. When ep.Path already ends with a wildcard it is used as-is.
func buildRouteURI(productSlug, epPath string) string {
	if strings.HasSuffix(epPath, "*") {
		return epPath
	}
	base := fmt.Sprintf("/api/%s%s", productSlug, epPath)
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base + "*"
}

// defaultUpstreamHost returns a conventional Docker / Kubernetes service name
// derived from the product slug.  The slug is used directly since HexxLock
// names containers after their product slugs (e.g. "examplesuite", "hotel-pms").
func defaultUpstreamHost(productSlug string) string {
	return fmt.Sprintf("%s:8080", productSlug)
}

// sanitisePath converts a URL path into a component safe for use inside APISIX
// resource IDs by replacing non-alphanumeric characters with hyphens and
// collapsing consecutive hyphens.
func sanitisePath(path string) string {
	var b strings.Builder
	prevHyphen := false
	for _, c := range path {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
			prevHyphen = false
		} else {
			if !prevHyphen {
				b.WriteByte('-')
			}
			prevHyphen = true
		}
	}
	result := strings.ToLower(strings.Trim(b.String(), "-"))
	if result == "" {
		return "root"
	}
	return result
}

// buildPlugins constructs the APISIX plugin map for a route based on the
// EndpointSpec configuration.  A request-id plugin is always enabled for
// observability; rate limiting and auth plugins are added based on the spec.
func buildPlugins(ep models.EndpointSpec) map[string]any {
	plugins := map[string]any{
		"request-id": map[string]any{
			"header_name":         "X-Request-ID",
			"include_in_response": true,
		},
	}

	// Add rate-limiting when the spec defines a non-zero rate.
	if ep.RateLimit > 0 {
		plugins["limit-req"] = map[string]any{
			"rate":          ep.RateLimit,
			"burst":         ep.RateLimit / 2,
			"rejected_code": 429,
			"key_type":      "var",
			"key":           "remote_addr",
		}
	}

	// Add JWT validation when the endpoint requires bearer-token auth.
	if ep.AuthType == "bearer" || ep.AuthType == "jwt" {
		plugins["jwt-auth"] = map[string]any{}
	}

	// Merge any caller-supplied plugin overrides from the manifest.
	for k, v := range ep.PluginConfig {
		plugins[k] = v
	}

	return plugins
}

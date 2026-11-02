// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantprojection

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const defaultBootstrapPageSize = 200

// Bootstrap hydrates iam_tenants from the tenant-management REST API before
// the Kafka consumer joins. This closes the cold-start gap: events emitted
// before the consumer was first deployed are reconciled from the REST snapshot.
//
// RunOnce is idempotent via the updated_at guard inside ApplyTenantUpsert:
// rows that are already newer (written by the signup adapter) are silently
// skipped. It is safe to call on every restart but is most valuable on first
// boot (before any Kafka offsets are committed).
//
// Internal cluster URL (not public api.example.com):
//
//	http://platform-tenant-management.example-platform.svc.cluster.local:80
type Bootstrap struct {
	httpClient       *http.Client
	tenantServiceURL string
	repo             *Repository
	log              *zap.SugaredLogger
	pageSize         int
	trialReadyHook   func(context.Context, uuid.UUID) error
}

func (b *Bootstrap) SetTrialReadyHook(hook func(context.Context, uuid.UUID) error) {
	b.trialReadyHook = hook
}

// NewBootstrap creates a Bootstrap. httpClient should be an authenticated
// client (OAuth2 client_credentials) in production; pass nil for local dev
// (falls back to http.DefaultClient with no auth — tenant-management's
// internal endpoint is not publicly reachable so this is safe).
func NewBootstrap(httpClient *http.Client, tenantServiceURL string, repo *Repository, log *zap.SugaredLogger) *Bootstrap {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Bootstrap{
		httpClient:       httpClient,
		tenantServiceURL: tenantServiceURL,
		repo:             repo,
		log:              log,
		pageSize:         defaultBootstrapPageSize,
	}
}

// tenantListResponse mirrors the PaginatedResponse shape from
// tenant-management's handlers package.
type tenantListResponse struct {
	Data       []bootstrapTenantPayload `json:"data"`
	Total      int                      `json:"total"`
	Page       int                      `json:"page"`
	PageSize   int                      `json:"page_size"`
	TotalPages int                      `json:"total_pages"`
}

// bootstrapTenantPayload is a partial decode of the REST response — we only
// extract the fields the projection stores.
type bootstrapTenantPayload struct {
	ID             uuid.UUID       `json:"id"`
	Plan           string          `json:"plan"`
	Type           string          `json:"type"`
	Status         string          `json:"subscription_status"`
	PlatformStatus string          `json:"status"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// RunOnce performs a full paginated snapshot of tenant-management and applies
// ApplyTenantUpsert for each tenant. Returns the number of upserts attempted
// (applied + skipped; orphans are logged and not counted).
//
// If tenantServiceURL is empty, RunOnce is a no-op (local dev without
// tenant-management running).
func (b *Bootstrap) RunOnce(ctx context.Context) (int, error) {
	if b.tenantServiceURL == "" {
		if b.log != nil {
			b.log.Info("tenantprojection bootstrap: TENANT_MANAGEMENT_INTERNAL_URL empty, skipping REST snapshot")
		}
		return 0, nil
	}

	page := 1
	total := 0
	for {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}

		batch, hasMore, err := b.fetchPage(ctx, page)
		if err != nil {
			return total, fmt.Errorf("RunOnce: page %d: %w", page, err)
		}
		if len(batch) == 0 {
			break
		}

		for _, t := range batch {
			// Phase 3.2 (ADR 0029): bootstrap REST payload still carries
			// plan + type for producer-side backward compatibility, but they
			// are no longer copied into TenantEvent — iam_tenants.plan /
			// iam_tenants.type were physically dropped (the GitOps repository
			// !699).
			evt := TenantEvent{
				ID:        t.ID,
				Status:    tenantProjectionStatus(tenantPayload{Status: t.Status, PlatformStatus: t.PlatformStatus}),
				Metadata:  []byte(t.Metadata),
				EventTime: t.UpdatedAt,
			}
			result, err := b.repo.ApplyTenantUpsert(ctx, evt)
			if err != nil {
				// Log and continue — one bad row doesn't abort the snapshot.
				if b.log != nil {
					b.log.Warnw("tenantprojection bootstrap: upsert failed",
						"tenant_id", t.ID, "error", err)
				}
				continue
			}
			var metadata map[string]any
			if len(t.Metadata) > 0 {
				_ = json.Unmarshal(t.Metadata, &metadata)
			}
			if result != UpsertResultOrphan && evt.Status == "trial" && metadata["signup_trial_started"] == true && b.trialReadyHook != nil {
				if err := b.trialReadyHook(ctx, t.ID); err != nil {
					return total, fmt.Errorf("bootstrap confirmed trial product: %w", err)
				}
			}
			switch result {
			case UpsertResultApplied, UpsertResultSkipped:
				total++
			case UpsertResultOrphan:
				// Tenant exists in tenant-management but not in iam_tenants.
				// This can happen when tenant-management has data that was
				// provisioned before falcon-id's signup adapter ran. Log at
				// Info because it is expected during initial migration.
				if b.log != nil {
					b.log.Infow("tenantprojection bootstrap: orphan tenant in snapshot (not in iam_tenants)",
						"tenant_id", t.ID,
						"hint", "tenant-management knows this tenant but falcon-id signup adapter hasn't created the iam_tenants row",
					)
				}
			}
		}

		if !hasMore {
			break
		}
		page++
	}

	if b.log != nil {
		b.log.Infow("tenantprojection bootstrap: snapshot complete",
			"tenants_processed", total, "pages_fetched", page)
	}
	return total, nil
}

// fetchPage GETs one page from /api/v1/internal/tenants and returns the decoded
// payload plus a hasMore flag.
//
// URL note: pre-ADR-0029-G the poll hit /api/v1/tenants which lives under
// the legacy user-token RequireAuth chain and silently rejects every
// RS256 client_credentials token. The receiver moved the s2s read surface
// to /api/v1/internal/tenants gated by shared/service-auth.RequireScope
// (`platform:tenants:read`); the caller MUST be an OAuth-authenticated
// http.Client (see startTenantProjection wiring in cmd/background.go).
func (b *Bootstrap) fetchPage(ctx context.Context, page int) ([]bootstrapTenantPayload, bool, error) {
	url := fmt.Sprintf("%s/api/v1/internal/tenants?page=%d&page_size=%d",
		b.tenantServiceURL, page, b.pageSize)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("fetchPage: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("fetchPage: do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return nil, false, fmt.Errorf("fetchPage: status %d from %s", resp.StatusCode, url)
	}

	var body tenantListResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false, fmt.Errorf("fetchPage: decode: %w", err)
	}

	hasMore := page < body.TotalPages
	return body.Data, hasMore, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantprojection_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	pgxmock "github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/tenantprojection"
)

// ---------------------------------------------------------------------------
// Bootstrap.RunOnce — REST pagination + ApplyTenantUpsert wiring
// ---------------------------------------------------------------------------

// buildPaginatedResponse emits a single-page tenant list response in the
// shape that tenant-management returns.
func buildPaginatedResponse(tenants []map[string]interface{}, page, totalPages int) []byte {
	body := map[string]interface{}{
		"data":        tenants,
		"total":       len(tenants) * totalPages,
		"page":        page,
		"page_size":   200,
		"total_pages": totalPages,
	}
	b, _ := json.Marshal(body)
	return b
}

func TestBootstrap_RunOnce_SinglePage(t *testing.T) {
	tenantID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	// HTTP stub returns one page with one tenant.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/internal/tenants", r.URL.Path)
		assert.Equal(t, "1", r.URL.Query().Get("page"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buildPaginatedResponse([]map[string]interface{}{
			{
				"id":                  tenantID.String(),
				"plan":                "starter",
				"type":                "customer",
				"subscription_status": "active",
				"updated_at":          now.Format(time.RFC3339),
			},
		}, 1, 1))
	}))
	defer srv.Close()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)

	// Expect existence probe + UPDATE for the one tenant.
	// Phase 3.1: UPDATE binds 4 args (id, status, metadata, eventTime); plan +
	// type are no longer written.
	mock.ExpectQuery(`SELECT 1 FROM iam_tenants`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(mock.NewRows([]string{"found"}).AddRow(1))
	mock.ExpectExec(`UPDATE iam_tenants`).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	repo := tenantprojection.NewRepository(mock)
	b := tenantprojection.NewBootstrap(srv.Client(), srv.URL, repo, nil)

	n, err := b.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBootstrap_RunOnce_MultiPage(t *testing.T) {
	t1 := uuid.New()
	t2 := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		w.Header().Set("Content-Type", "application/json")
		var tenants []map[string]interface{}
		switch page {
		case 1:
			tenants = []map[string]interface{}{
				{"id": t1.String(), "plan": "pro", "type": "customer",
					"subscription_status": "active", "updated_at": now.Format(time.RFC3339)},
			}
			_, _ = w.Write(buildPaginatedResponse(tenants, 1, 2))
		case 2:
			tenants = []map[string]interface{}{
				{"id": t2.String(), "plan": "starter", "type": "trial",
					"subscription_status": "trialing", "updated_at": now.Format(time.RFC3339)},
			}
			_, _ = w.Write(buildPaginatedResponse(tenants, 2, 2))
		}
	}))
	defer srv.Close()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)

	// Two tenants → two existence probes + two UPDATEs.
	// Phase 3.1: UPDATE binds 4 args (id, status, metadata, eventTime); plan +
	// type are no longer written.
	for range []uuid.UUID{t1, t2} {
		mock.ExpectQuery(`SELECT 1 FROM iam_tenants`).
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(mock.NewRows([]string{"found"}).AddRow(1))
		mock.ExpectExec(`UPDATE iam_tenants`).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	}

	repo := tenantprojection.NewRepository(mock)
	b := tenantprojection.NewBootstrap(srv.Client(), srv.URL, repo, nil)

	n, err := b.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBootstrap_RunOnce_EmptyURL_IsNoop(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)

	repo := tenantprojection.NewRepository(mock)
	b := tenantprojection.NewBootstrap(nil, "", repo, nil)

	n, err := b.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBootstrap_RunOnce_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)

	repo := tenantprojection.NewRepository(mock)
	b := tenantprojection.NewBootstrap(srv.Client(), srv.URL, repo, nil)

	_, err = b.RunOnce(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

func TestBootstrap_RunOnce_OrphanTenantIsContinued(t *testing.T) {
	t1 := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buildPaginatedResponse([]map[string]interface{}{
			{"id": t1.String(), "plan": "free", "type": "customer",
				"subscription_status": "active", "updated_at": now.Format(time.RFC3339)},
		}, 1, 1))
	}))
	defer srv.Close()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)

	// Existence probe returns no-rows → orphan path.
	mock.ExpectQuery(`SELECT 1 FROM iam_tenants`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnError(errors.New("no rows in result set"))

	repo := tenantprojection.NewRepository(mock)
	b := tenantprojection.NewBootstrap(srv.Client(), srv.URL, repo, nil)

	// Orphan is logged and skipped — RunOnce should return 0 processed, no error.
	n, err := b.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBootstrap_RunOnce_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Should never be called — context cancelled before first page.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)

	repo := tenantprojection.NewRepository(mock)
	b := tenantprojection.NewBootstrap(srv.Client(), srv.URL, repo, nil)

	_, err = b.RunOnce(ctx)
	// Context cancellation may surface as context.Canceled or a wrapped error.
	assert.Error(t, err)
}

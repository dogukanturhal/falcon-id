// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

type tenantSeatsReader struct {
	counters *models.SeatCounters
	err      error
	tenant   uuid.UUID
	calls    int
}

func (r *tenantSeatsReader) Get(_ context.Context, tenant uuid.UUID) (*models.SeatCounters, error) {
	r.tenant = tenant
	r.calls++
	return r.counters, r.err
}

func (*tenantSeatsReader) SetSeatLimit(context.Context, uuid.UUID, int, *int64, *time.Time) (*models.SeatCounters, bool, error) {
	panic("public seats endpoint must never mutate limits")
}

func TestGetTenantSeats(t *testing.T) {
	limit := 4
	for _, tc := range []struct {
		name     string
		user     *models.CurrentUser
		counters *models.SeatCounters
		err      error
		status   int
		body     string
	}{
		{"ledger includes pending reservations", &models.CurrentUser{TenantID: uuid.New()}, &models.SeatCounters{SeatsUsed: 3, SeatsPending: 1, SeatLimit: &limit}, nil, 200, `{"seats_used":3,"seats_pending":1,"seat_limit":4}`},
		{"unconfigured limit", &models.CurrentUser{TenantID: uuid.New()}, &models.SeatCounters{SeatsUsed: 2, SeatsPending: 1}, nil, 200, `{"seats_used":2,"seats_pending":1,"seat_limit":null}`},
		{"missing ledger", &models.CurrentUser{TenantID: uuid.New()}, nil, nil, 200, `{"seats_used":0,"seats_pending":0,"seat_limit":null}`},
		{"unauthenticated", nil, nil, nil, 401, ""},
		{"missing signed tenant", &models.CurrentUser{}, nil, nil, 401, ""},
		{"infrastructure failure", &models.CurrentUser{TenantID: uuid.New()}, nil, errors.New("private database diagnostic"), 500, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &tenantSeatsReader{counters: tc.counters, err: tc.err}
			h := &SeatLimitHandler{seatCounters: repo, logger: zap.NewNop()}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/tenants/me/seats?tenant_id="+uuid.NewString(), nil)
			c.Request.Header.Set("X-Tenant-ID", uuid.NewString())
			if tc.user != nil {
				c.Set(middleware.CurrentUserKey, tc.user)
			}
			h.GetTenantSeats(c)
			require.Equal(t, "private, no-store", w.Header().Get("Cache-Control"))
			require.Equal(t, tc.status, w.Code)
			if tc.body != "" {
				require.JSONEq(t, tc.body, w.Body.String())
			}
			if tc.name == "ledger includes pending reservations" {
				golden, err := os.ReadFile("testdata/bqo-seats.json")
				require.NoError(t, err)
				require.JSONEq(t, string(golden), w.Body.String())
			}
			if tc.status == http.StatusUnauthorized {
				require.Zero(t, repo.calls)
			} else {
				require.Equal(t, tc.user.TenantID, repo.tenant)
				require.Equal(t, 1, repo.calls)
			}
			require.NotContains(t, w.Body.String(), "private database diagnostic")
			if tc.status >= 500 {
				require.Regexp(t, `"traceId":"[^"]+"`, w.Body.String())
			}
		})
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"github.com/dogukanturhal/platform-shared/quota"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// R6 WP-23 kiosk seat class, end to end against real PostgreSQL (fixture of employee_account_postgres_integration_test.go,
// plus the verbatim 0022 migration): free of the paid seat count, counted against the kiosk_users quota.

// kioskQuotaStub plays quota-service for the kiosk_users resource only: limit < 0 is unlimited.
type kioskQuotaStub struct {
	mu    sync.Mutex
	limit int64
	used  int64
	calls []string
}

func (q *kioskQuotaStub) MustCheckQuota(_ context.Context, _ uuid.UUID, rt quota.ResourceType, amount int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls = append(q.calls, "check:"+string(rt))
	if q.limit >= 0 && q.used+amount > q.limit {
		return &quota.QuotaExceededError{ResourceType: rt, CurrentUsage: q.used, Limit: q.limit, Message: "kiosk users limit reached"}
	}
	return nil
}

func (q *kioskQuotaStub) IncrementUsage(_ context.Context, _ uuid.UUID, rt quota.ResourceType, amount int64) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls = append(q.calls, "inc:"+string(rt))
	q.used += amount
	return true, nil
}

func (q *kioskQuotaStub) DecrementUsage(_ context.Context, _ uuid.UUID, rt quota.ResourceType, amount int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls = append(q.calls, "dec:"+string(rt))
	q.used -= amount
	return nil
}

// scoped runs a single-value query under the tenant's RLS scope (iam_user_memberships is FORCE RLS).
func scoped[T any](t *testing.T, f *employeeFixture, query string, args ...any) T {
	t.Helper()
	var out T
	require.NoError(t, repositories.WithTenantScope(context.Background(), f.pool, f.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), query, args...).Scan(&out)
	}))
	return out
}

func (f *employeeFixture) kioskRouter(admin uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(middleware.CurrentUserKey, &models.CurrentUser{ID: admin, TenantID: f.tenant})
		c.Next()
	})
	r.POST("/api/v1/tenants/me/kiosk-users", f.handler.ProvisionKioskUser)
	r.DELETE("/api/v1/tenants/me/kiosk-users/:id", f.handler.RevokeKioskUser)
	return r
}

func (f *employeeFixture) kioskDo(t *testing.T, r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestKioskUsersPostgres_Provision_SeatCountUnchanged_CountedAgainstKioskQuota(t *testing.T) {
	f := newEmployeeFixture(t)
	ctx := context.Background()
	stub := &kioskQuotaStub{limit: 3}
	f.userService.SetQuotaClient(stub)
	memberID := f.seedMember(t, "owner@example.test")
	r := f.kioskRouter(memberID)

	activeSeats := func() int {
		n, err := f.users.CountActiveByTenant(ctx, f.tenant)
		require.NoError(t, err)
		return n
	}
	require.Equal(t, 1, activeSeats())

	w := f.kioskDo(t, r, http.MethodPost, "/api/v1/tenants/me/kiosk-users", `{"email":"Op1@Example.test","firstName":"Op","lastName":"One"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp struct {
		UserID    uuid.UUID `json:"userId"`
		SeatClass string    `json:"seatClass"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, "kiosk", resp.SeatClass)

	// Kiosk-class membership, one role grant, only the ppscm:operator template, one audit row.
	require.Equal(t, "kiosk", scoped[string](t, f, `SELECT seat_class FROM iam_user_memberships WHERE user_id = $1`, resp.UserID))
	require.Equal(t, 1, scalar[int](t, f.pool, `SELECT count(*) FROM iam_user_roles WHERE user_id = $1`, resp.UserID))
	require.Equal(t, []string{"ppscm:operator"}, f.templ.requested)
	require.Equal(t, 1, scalar[int](t, f.pool, `SELECT count(*) FROM iam_audit_log WHERE tenant_id = $1 AND action = 'kiosk_user_provisioned'`, f.tenant))

	// Paid seat count unchanged: the billed-user count, the seat counter and the seat-free lookup all agree.
	require.Equal(t, 1, activeSeats(), "kiosk user must not count as a paid seat")
	require.Zero(t, scalar[int](t, f.pool, `SELECT COALESCE(sum(seats_used + seats_pending), 0) FROM tenant_seat_counters WHERE tenant_id = $1`, f.tenant))
	free, err := f.memberships.IsSeatFree(ctx, f.tenant, resp.UserID)
	require.NoError(t, err)
	require.True(t, free)
	n, err := f.memberships.CountActiveEmployeeSeatUsers(ctx, f.tenant)
	require.NoError(t, err)
	require.Equal(t, 1, n, "the seat-quota reconciler must subtract the kiosk user from the billable users")

	// Only the kiosk_users quota was consulted and incremented, never "users".
	require.Equal(t, []string{"check:kiosk_users", "inc:kiosk_users"}, stub.calls)
	require.EqualValues(t, 1, stub.used)
}

func TestKioskUsersPostgres_QuotaExceeded_403_NothingCreated(t *testing.T) {
	f := newEmployeeFixture(t)
	stub := &kioskQuotaStub{limit: 1}
	f.userService.SetQuotaClient(stub)
	r := f.kioskRouter(uuid.New())

	require.Equal(t, http.StatusCreated, f.kioskDo(t, r, http.MethodPost, "/api/v1/tenants/me/kiosk-users", `{"email":"op1@example.test"}`).Code)

	w := f.kioskDo(t, r, http.MethodPost, "/api/v1/tenants/me/kiosk-users", `{"email":"op2@example.test"}`)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, "Quota exceeded", body["error"])
	require.Equal(t, "quota_exceeded", body["code"])
	require.Equal(t, "kiosk_users", body["resource_type"])
	require.EqualValues(t, 1, body["limit"])

	// The refused call created no user, membership or audit row, and left the usage at 1.
	require.Zero(t, scalar[int](t, f.pool, `SELECT count(*) FROM iam_users WHERE email = 'op2@example.test'`))
	require.Equal(t, 1, scoped[int](t, f, `SELECT count(*) FROM iam_user_memberships WHERE seat_class = 'kiosk'`))
	require.EqualValues(t, 1, stub.used)
}

func TestKioskUsersPostgres_Revoke_FreesQuota_OnlyKioskRows(t *testing.T) {
	f := newEmployeeFixture(t)
	stub := &kioskQuotaStub{limit: 1}
	f.userService.SetQuotaClient(stub)
	memberID := f.seedMember(t, "member@example.test")
	r := f.kioskRouter(memberID)

	var resp struct {
		UserID uuid.UUID `json:"userId"`
	}
	w := f.kioskDo(t, r, http.MethodPost, "/api/v1/tenants/me/kiosk-users", `{"email":"op1@example.test"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// A seat-holding member is not revocable through the kiosk endpoint.
	require.Equal(t, http.StatusNotFound, f.kioskDo(t, r, http.MethodDelete, "/api/v1/tenants/me/kiosk-users/"+memberID.String(), "").Code)
	require.True(t, scalar[bool](t, f.pool, `SELECT is_active FROM iam_users WHERE id = $1`, memberID))

	require.Equal(t, http.StatusNoContent, f.kioskDo(t, r, http.MethodDelete, "/api/v1/tenants/me/kiosk-users/"+resp.UserID.String(), "").Code)
	require.False(t, scalar[bool](t, f.pool, `SELECT is_active FROM iam_users WHERE id = $1`, resp.UserID))
	require.Equal(t, "deactivated", scoped[string](t, f, `SELECT status FROM iam_user_memberships WHERE user_id = $1`, resp.UserID))
	require.Zero(t, scalar[int](t, f.pool, `SELECT count(*) FROM iam_user_roles WHERE user_id = $1`, resp.UserID))
	require.EqualValues(t, 0, stub.used)

	// Revoking again is a 404 (no double decrement); the freed slot is usable again.
	require.Equal(t, http.StatusNotFound, f.kioskDo(t, r, http.MethodDelete, "/api/v1/tenants/me/kiosk-users/"+resp.UserID.String(), "").Code)
	require.EqualValues(t, 0, stub.used)
	require.Equal(t, http.StatusCreated, f.kioskDo(t, r, http.MethodPost, "/api/v1/tenants/me/kiosk-users", `{"email":"op2@example.test"}`).Code)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestBillableSeatClassesPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	ctx := context.Background()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	schema, role := "seatfix_"+suffix, "seatfix_app_"+suffix
	sch, rol := pgx.Identifier{schema}.Sanitize(), pgx.Identifier{role}.Sanitize()
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+sch+" CASCADE")
		_, _ = admin.Exec(ctx, "DROP ROLE "+rol)
		_ = admin.Close(ctx)
	})
	for _, sql := range []string{
		"CREATE SCHEMA " + sch, "SET search_path = " + sch,
		`CREATE TABLE iam_users(id uuid PRIMARY KEY, tenant_id uuid NOT NULL, username text NOT NULL, is_active bool NOT NULL DEFAULT true, deletion_scheduled_at timestamptz)`,
		`CREATE TABLE iam_user_memberships(tenant_id uuid NOT NULL, user_id uuid NOT NULL, seat_class text NOT NULL, status text NOT NULL DEFAULT 'active', deactivated_at timestamptz, PRIMARY KEY(tenant_id,user_id))`,
		`CREATE TABLE tenant_seat_counters(tenant_id uuid PRIMARY KEY, seats_used int NOT NULL DEFAULT 0, updated_at timestamptz NOT NULL DEFAULT now())`,
		`ALTER TABLE iam_user_memberships ENABLE ROW LEVEL SECURITY`, `ALTER TABLE iam_user_memberships FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY tenant_isolation ON iam_user_memberships USING(tenant_id::text = NULLIF(current_setting('app.current_tenant_id',true),''))`,
		"CREATE ROLE " + rol + " NOLOGIN NOSUPERUSER NOBYPASSRLS", "GRANT USAGE ON SCHEMA " + sch + " TO " + rol,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA " + sch + " TO " + rol,
	} {
		_, err := admin.Exec(ctx, sql)
		require.NoError(t, err)
	}
	tenant := uuid.New()
	ids := map[string]uuid.UUID{}
	for _, class := range []string{"member", "employee", "kiosk", "service", "external", "legacy", "svc-service", "svc-legacy", "inactive", "pending"} {
		id := uuid.New()
		ids[class] = id
		_, err = admin.Exec(ctx, `INSERT INTO iam_users(id,tenant_id,username,is_active,deletion_scheduled_at) VALUES($1,$2,$3,$4,CASE WHEN $5 THEN now() END)`, id, tenant, class, class != "inactive", class == "pending")
		require.NoError(t, err)
		if !strings.Contains(class, "legacy") {
			seatClass := class
			if class == "svc-service" {
				seatClass = "service"
			}
			if class == "inactive" || class == "pending" {
				seatClass = "member"
			}
			_, err = admin.Exec(ctx, `INSERT INTO iam_user_memberships(tenant_id,user_id,seat_class) VALUES($1,$2,$3)`, tenant, id, seatClass)
			require.NoError(t, err)
		}
	}
	_, err = admin.Exec(ctx, `INSERT INTO tenant_seat_counters(tenant_id,seats_used) VALUES($1,99)`, tenant)
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error { _, err := c.Exec(ctx, "SET ROLE "+rol); return err }
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	users, memberships := repositories.NewUserRepository(pool), repositories.NewUserMembershipRepository(pool)
	n, err := users.CountActiveByTenant(ctx, tenant)
	require.NoError(t, err)
	require.Equal(t, 2, n, "member + legacy only; svc service is excluded once, not subtracted twice")
	for _, class := range []string{"employee", "kiosk", "service", "external", "svc-service", "svc-legacy"} {
		free, err := memberships.IsSeatFree(ctx, tenant, ids[class])
		require.NoError(t, err)
		require.True(t, free, class)
		free, err = memberships.IsSeatFree(ctx, uuid.New(), ids[class])
		require.NoError(t, err)
		require.False(t, free, "other tenant")
	}
	for _, class := range []string{"member", "legacy"} {
		free, err := memberships.IsSeatFree(ctx, tenant, ids[class])
		require.NoError(t, err)
		require.False(t, free, class)
	}
	var pushed []int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req seatQuotaReconcileRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.Equal(t, tenant, req.TenantID)
		pushed = append(pushed, req.ActualCount)
		_ = json.NewEncoder(w).Encode(seatQuotaReconcileEnvelope{Success: true, Data: &seatQuotaReconcileResult{ActualUsage: req.ActualCount, Corrected: true}})
	}))
	t.Cleanup(server.Close)
	reconciler := NewSeatQuotaReconciler(pool, server.URL, server.Client(), &config.Config{})
	stats, err := reconciler.Reconcile(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, stats.TenantsProcessed)
	require.Equal(t, 1, stats.TenantsCorrected)
	require.Zero(t, stats.Errors)
	var seats int
	require.NoError(t, admin.QueryRow(ctx, `SELECT seats_used FROM tenant_seat_counters WHERE tenant_id=$1`, tenant).Scan(&seats))
	require.Equal(t, 1, seats)
	for _, class := range []string{"employee", "kiosk", "service", "external"} {
		changed, err := memberships.Deactivate(ctx, tenant, ids[class])
		require.NoError(t, err)
		require.True(t, changed)
		free, err := memberships.IsSeatFree(ctx, tenant, ids[class])
		require.NoError(t, err)
		require.True(t, free, "deactivated free classes remain seat-free on restore")
		changed, err = memberships.Reactivate(ctx, tenant, ids[class])
		require.NoError(t, err)
		require.True(t, changed)
		changed, err = memberships.Delete(ctx, tenant, ids[class])
		require.NoError(t, err)
		require.True(t, changed)
		require.NoError(t, admin.QueryRow(ctx, `SELECT seats_used FROM tenant_seat_counters WHERE tenant_id=$1`, tenant).Scan(&seats))
		require.Equal(t, 1, seats, class+" lifecycle must not release or occupy a member seat")
	}
	_, err = admin.Exec(ctx, `UPDATE iam_users SET is_active=false WHERE tenant_id=$1`, tenant)
	require.NoError(t, err)
	stats, err = reconciler.Reconcile(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, stats.TenantsProcessed)
	require.Zero(t, stats.Errors)
	require.Equal(t, []int64{2, 0}, pushed, "zero-seat tenants still reconcile stale usage")
}

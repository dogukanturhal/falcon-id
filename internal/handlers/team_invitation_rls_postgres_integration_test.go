// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// rewireAsRLSApp re-points the fixture's handler at a pool that runs as a
// NOSUPERUSER NOBYPASSRLS role, the way falcon_id_app runs in production
// against the real 0013 FORCE RLS policies. f.pool stays the superuser pool
// for setup and assertions.
func (f *externalFixture) rewireAsRLSApp(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("TEST_DATABASE_URL")
	var schema string
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema))
	role := pgx.Identifier{"inv_rls_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]}.Sanitize()
	schemaIdent := pgx.Identifier{schema}.Sanitize()
	for _, stmt := range []string{
		"CREATE ROLE " + role + " NOLOGIN NOSUPERUSER NOBYPASSRLS",
		"GRANT USAGE ON SCHEMA " + schemaIdent + " TO " + role,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA " + schemaIdent + " TO " + role,
	} {
		_, err := f.pool.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(ctx, "DROP OWNED BY "+role)
		_, _ = f.pool.Exec(ctx, "DROP ROLE IF EXISTS "+role)
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+role)
		return err
	}
	app, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(app.Close)

	var n int
	require.NoError(t, app.QueryRow(ctx, `SELECT count(*) FROM tenant_seat_counters`).Scan(&n))
	require.Zero(t, n, "precondition: FORCE RLS hides rows from the unscoped app role")

	f.invRepo = repositories.NewTeamInvitationRepository(app)
	roleRepo := repositories.NewRoleRepository(app)
	f.h = handlers.NewTeamInvitationHandler(nil, repositories.NewUserRepository(app), roleRepo,
		services.NewRoleService(roleRepo, repositories.NewPermissionRepository(app), nil), f.invRepo, zaptest.NewLogger(t))
	f.h.SetEmailService(services.NewEmailService(&config.Config{}))
	f.h.SetSeatRepositories(repositories.NewUserMembershipRepository(app), repositories.NewSeatCounterRepository(app))
	f.h.SetTenantBootstrap(services.NewTenantBootstrapService(nil))
}

// LD-R3-TX-2: the guest write paths (accept from the partner tenant, the
// client's external-member list, revoke) under FORCE RLS as a NOBYPASSRLS
// role, with no request-level tenant GUC.
func TestExternalInvitationPostgres_RLSAppRole_AcceptListRevoke(t *testing.T) {
	f := newExternalFixture(t)
	f.rewireAsRLSApp(t)
	ctx := context.Background()
	token := f.invite(t, models.SeatClassExternal, f.readRole)

	w := f.serve(t, f.accountantUser(), http.MethodPost, "/invitations/accept", gin.H{"token": token})
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	var status string
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT status FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2 AND seat_class = 'external'`,
		f.client, f.accountant).Scan(&status))
	require.Equal(t, "active", status)

	w = f.serve(t, f.adminUser(), http.MethodGet, "/tenants/me/external-members", nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list struct {
		Items []models.ExternalMember `json:"items"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Len(t, list.Items, 1, "the client admin's list must see the membership under RLS")
	require.Equal(t, f.accountant, list.Items[0].ID)

	// No SpiceDB client in this fixture: PostgreSQL commits, then 503.
	w = f.serve(t, f.adminUser(), http.MethodDelete, "/team/external-members/"+f.accountant.String(), nil)
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT status FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`,
		f.client, f.accountant).Scan(&status))
	require.Equal(t, "deactivated", status)
	require.Zero(t, f.clientRoleCount(t))
}

// Member (seat-holding) invitations under RLS: decline releases the
// reservation the invite took; accept converts it into a used seat.
func TestExternalInvitationPostgres_RLSAppRole_MemberSeatCounters(t *testing.T) {
	f := newExternalFixture(t)
	ctx := context.Background()
	_, err := f.pool.Exec(ctx, `INSERT INTO tenant_seat_counters (tenant_id, seats_pending) VALUES ($1, 2)`, f.client)
	require.NoError(t, err)
	member := uuid.New()
	_, err = f.pool.Exec(ctx, `INSERT INTO iam_users (id, tenant_id, username, email) VALUES ($1, $2, 'clerk', 'smmm@partner.test')`, member, f.client)
	require.NoError(t, err)
	f.rewireAsRLSApp(t)
	memberUser := &models.CurrentUser{ID: member, TenantID: f.client, Email: "smmm@partner.test"}

	declined := f.invite(t, models.SeatClassMember, f.readRole)
	w := f.serve(t, memberUser, http.MethodPost, "/invitations/decline", gin.H{"token": declined})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var used, pending int
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT seats_used, seats_pending FROM tenant_seat_counters WHERE tenant_id = $1`, f.client).Scan(&used, &pending))
	require.Equal(t, 0, used)
	require.Equal(t, 1, pending, "decline released one reservation")

	accepted := f.invite(t, models.SeatClassMember, f.readRole)
	w = f.serve(t, memberUser, http.MethodPost, "/invitations/accept", gin.H{"token": accepted})
	require.Contains(t, []int{http.StatusOK, http.StatusAccepted}, w.Code, w.Body.String())
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT seats_used, seats_pending FROM tenant_seat_counters WHERE tenant_id = $1`, f.client).Scan(&used, &pending))
	require.Equal(t, 1, used, "accept confirmed the seat")
	require.Equal(t, 0, pending)
}

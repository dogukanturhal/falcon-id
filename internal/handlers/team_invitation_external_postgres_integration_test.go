// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// External (seat_class=external) accountant invitations, end to end against
// the real 0002/0011/0013 DDL plus a minimal role catalogue. The SpiceDB
// client is deliberately absent (NewTenantBootstrapService(nil)): accept then
// answers 202 "synchronizing" and revoke 503, and every assertion is on the
// PostgreSQL authority, which the reconciler converges SpiceDB from.

type externalFixture struct {
	pool        *pgxpool.Pool
	h           *handlers.TeamInvitationHandler
	invRepo     *repositories.TeamInvitationRepository
	client      uuid.UUID // inviting (client) tenant
	partner     uuid.UUID // accountant's home tenant
	admin       uuid.UUID // client tenant admin
	accountant  uuid.UUID // lives in partner tenant
	readRole    uuid.UUID // client role: core:reports:read only
	writeRole   uuid.UUID // client role: core:reports:read + core:journal:create
	partnerRole uuid.UUID // accountant's own partner-tenant role
}

func newExternalFixture(t *testing.T) *externalFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	pool := setupTeamInvitationHandlerSchema(t, dsn)
	ctx := context.Background()
	for _, stmt := range []string{
		`ALTER TABLE iam_users ADD COLUMN email text NOT NULL DEFAULT '', ADD COLUMN display_name text`,
		`CREATE TABLE iam_roles(
			id uuid PRIMARY KEY, tenant_id uuid NOT NULL, name text NOT NULL, display_name text NOT NULL DEFAULT '',
			description text NOT NULL DEFAULT '', is_system boolean NOT NULL DEFAULT false, is_default boolean NOT NULL DEFAULT false,
			priority int NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(), created_by uuid, updated_by uuid)`,
		`CREATE TABLE iam_permissions(id uuid PRIMARY KEY, module text NOT NULL, resource text NOT NULL, action text NOT NULL, name text NOT NULL)`,
		`CREATE TABLE iam_role_permissions(role_id uuid NOT NULL, permission_id uuid NOT NULL, PRIMARY KEY (role_id, permission_id))`,
		// 'declined' is added to this CHECK by the the GitOps repository bundle,
		// not by internal/migrations; mirror the shipped constraint.
		`ALTER TABLE iam_team_invitations DROP CONSTRAINT iam_team_invitations_status_check`,
		`ALTER TABLE iam_team_invitations ADD CONSTRAINT iam_team_invitations_status_check
			CHECK (status IN ('pending','accepted','expired','revoked','declined'))`,
		`CREATE TABLE iam_user_roles(user_id uuid NOT NULL, role_id uuid NOT NULL, assigned_by uuid, expires_at timestamptz, PRIMARY KEY (user_id, role_id))`,
	} {
		_, err := pool.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}

	f := &externalFixture{
		pool: pool, client: uuid.New(), partner: uuid.New(), admin: uuid.New(), accountant: uuid.New(),
		readRole: uuid.New(), writeRole: uuid.New(), partnerRole: uuid.New(),
	}
	mustInsertTenantAndInviter(t, pool, f.client, f.admin)
	_, err := pool.Exec(ctx, `INSERT INTO iam_tenants (id) VALUES ($1)`, f.partner)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_users (id, tenant_id, username, email) VALUES ($1, $2, 'smmm', 'smmm@partner.test')`, f.accountant, f.partner)
	require.NoError(t, err)

	read, write := uuid.New(), uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO iam_permissions (id, module, resource, action, name) VALUES
		($1, 'core', 'reports', 'read', 'core:reports:read'),
		($2, 'core', 'journal', 'create', 'core:journal:create')`, read, write)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_roles (id, tenant_id, name) VALUES
		($1, $4, 'external_readonly'), ($2, $4, 'clerk'), ($3, $5, 'partner_admin')`,
		f.readRole, f.writeRole, f.partnerRole, f.client, f.partner)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_role_permissions (role_id, permission_id) VALUES
		($1, $3), ($2, $3), ($2, $4), ($5, $4)`, f.readRole, f.writeRole, read, write, f.partnerRole)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_user_roles (user_id, role_id) VALUES ($1, $2)`, f.accountant, f.partnerRole)
	require.NoError(t, err)

	f.invRepo = repositories.NewTeamInvitationRepository(pool)
	roleRepo := repositories.NewRoleRepository(pool)
	f.h = handlers.NewTeamInvitationHandler(nil, repositories.NewUserRepository(pool), roleRepo,
		services.NewRoleService(roleRepo, repositories.NewPermissionRepository(pool), nil), f.invRepo, zaptest.NewLogger(t))
	f.h.SetEmailService(services.NewEmailService(&config.Config{}))
	f.h.SetSeatRepositories(repositories.NewUserMembershipRepository(pool), repositories.NewSeatCounterRepository(pool))
	f.h.SetTenantBootstrap(services.NewTenantBootstrapService(nil))
	return f
}

func (f *externalFixture) invite(t *testing.T, seatClass models.SeatClass, roles ...uuid.UUID) string {
	t.Helper()
	token := uuid.NewString()
	require.NoError(t, f.invRepo.Create(context.Background(), &models.TeamInvitation{
		TenantID: f.client, Email: "smmm@partner.test", RoleIDs: roles, InvitedBy: f.admin,
		Token: models.TeamInvitationTokenDigest(token), Status: models.TeamInvitationStatusPending,
		ExpiresAt: time.Now().Add(14 * 24 * time.Hour), SeatClass: seatClass,
	}))
	return token
}

func (f *externalFixture) serve(t *testing.T, user *models.CurrentUser, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(injectCurrentUser(user))
	r.POST("/invitations/accept", f.h.AcceptInvitation)
	r.POST("/invitations/decline", f.h.DeclineInvitation)
	r.GET("/tenants/me/external-members", f.h.ListExternalMembers)
	r.DELETE("/team/external-members/:id", f.h.RevokeExternalMember)
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// The accountant is signed in to their PARTNER tenant (token tenant =
// partner) and accepts a client invitation.
func (f *externalFixture) accountantUser() *models.CurrentUser {
	return &models.CurrentUser{ID: f.accountant, TenantID: f.partner, Email: "SMMM@partner.test "}
}

func (f *externalFixture) adminUser() *models.CurrentUser {
	return &models.CurrentUser{ID: f.admin, TenantID: f.client, Permissions: []string{"*"}}
}

func (f *externalFixture) clientRoleCount(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM iam_user_roles ur JOIN iam_roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.tenant_id = $2`, f.accountant, f.client).Scan(&n))
	return n
}

func (f *externalFixture) auditCount(t *testing.T, action string) int {
	t.Helper()
	var n int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM iam_audit_log
		WHERE tenant_id = $1 AND action = $2 AND details->>'seat_class' = 'external'`, f.client, action).Scan(&n))
	return n
}

func TestExternalInvitationPostgres_AcceptAcrossTenants_SeatFree(t *testing.T) {
	f := newExternalFixture(t)
	token := f.invite(t, models.SeatClassExternal, f.readRole)

	w := f.serve(t, f.accountantUser(), http.MethodPost, "/invitations/accept", gin.H{"token": token})
	// 202: PostgreSQL committed; SpiceDB sync is pending (no client wired).
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())

	var seatClass, status string
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT seat_class, status FROM iam_user_memberships
		WHERE tenant_id = $1 AND user_id = $2`, f.client, f.accountant).Scan(&seatClass, &status))
	require.Equal(t, "external", seatClass)
	require.Equal(t, "active", status)
	require.Equal(t, 1, f.clientRoleCount(t))
	require.Equal(t, 1, f.auditCount(t, "team_invitation_accept"))

	// Seat-free: the client tenant's seat counter never moved.
	var used, pending int
	err := f.pool.QueryRow(context.Background(), `SELECT COALESCE(seats_used,0), COALESCE(seats_pending,0) FROM tenant_seat_counters WHERE tenant_id = $1`, f.client).Scan(&used, &pending)
	if err == nil {
		require.Zero(t, used)
		require.Zero(t, pending)
	}

	// The accountant shows on the client's external-member list with only
	// the client-tenant role (never the partner-tenant one).
	w = f.serve(t, f.adminUser(), http.MethodGet, "/tenants/me/external-members", nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list struct {
		Items []models.ExternalMember `json:"items"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Len(t, list.Items, 1)
	require.Equal(t, f.accountant, list.Items[0].ID)
	require.Equal(t, models.SeatClassExternal, list.Items[0].SeatClass)
	require.Len(t, list.Items[0].Roles, 1)
	require.Equal(t, f.readRole, list.Items[0].Roles[0].ID)
}

func TestExternalInvitationPostgres_WriteRole_RejectedAtAccept(t *testing.T) {
	f := newExternalFixture(t)
	token := f.invite(t, models.SeatClassExternal, f.writeRole)

	w := f.serve(t, f.accountantUser(), http.MethodPost, "/invitations/accept", gin.H{"token": token})
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Zero(t, f.clientRoleCount(t), "a write-capable role must never ride in on a seat-free invitation")
	var n int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`, f.client, f.accountant).Scan(&n))
	require.Zero(t, n)
}

// LD-R3-GUEST-1: accountant-export:create/:retry are the only non-read
// actions an external accountant role may carry; reports:lock is not. (The
// accept path also needs the tenant entitled to preaccounting, which this
// fixture's role service does not model, so the read-only rule is checked on
// the repository the accept path calls.)
func TestExternalInvitationPostgres_AccountantExportActions_Allowed_ReportsLock_Rejected(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		perms    [][2]string // resource, action
		readOnly bool
	}{
		{"export create+retry", [][2]string{{"reports", "read"}, {"accountant-export", "create"}, {"accountant-export", "retry"}}, true},
		{"reports lock", [][2]string{{"reports", "read"}, {"reports", "lock"}}, false},
		{"export delete", [][2]string{{"accountant-export", "delete"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newExternalFixture(t)
			role := uuid.New()
			_, err := f.pool.Exec(ctx, `INSERT INTO iam_roles (id, tenant_id, name) VALUES ($1, $2, 'preaccounting_accountant')`, role, f.client)
			require.NoError(t, err)
			for _, rp := range tc.perms {
				p := uuid.New()
				_, err = f.pool.Exec(ctx, `INSERT INTO iam_permissions (id, module, resource, action, name) VALUES ($1, 'preaccounting', $2, $3, $4)`,
					p, rp[0], rp[1], "preaccounting:"+rp[0]+":"+rp[1])
				require.NoError(t, err)
				_, err = f.pool.Exec(ctx, `INSERT INTO iam_role_permissions (role_id, permission_id) VALUES ($1, $2)`, role, p)
				require.NoError(t, err)
			}
			got, err := repositories.NewRoleRepository(f.pool).HasOnlyReadPermissions(ctx, role)
			require.NoError(t, err)
			require.Equal(t, tc.readOnly, got)
		})
	}
	// The same actions on another module are still writes.
	f := newExternalFixture(t)
	role := uuid.New()
	p := uuid.New()
	_, err := f.pool.Exec(ctx, `INSERT INTO iam_roles (id, tenant_id, name) VALUES ($1, $2, 'other')`, role, f.client)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `INSERT INTO iam_permissions (id, module, resource, action, name) VALUES ($1, 'accounting', 'accountant-export', 'create', 'accounting:accountant-export:create')`, p)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `INSERT INTO iam_role_permissions (role_id, permission_id) VALUES ($1, $2)`, role, p)
	require.NoError(t, err)
	got, err := repositories.NewRoleRepository(f.pool).HasOnlyReadPermissions(ctx, role)
	require.NoError(t, err)
	require.False(t, got)
}

func TestExternalInvitationPostgres_WrongEmail_Forbidden(t *testing.T) {
	f := newExternalFixture(t)
	token := f.invite(t, models.SeatClassExternal, f.readRole)

	other := &models.CurrentUser{ID: f.accountant, TenantID: f.partner, Email: "someone-else@partner.test"}
	w := f.serve(t, other, http.MethodPost, "/invitations/accept", gin.H{"token": token})
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Zero(t, f.clientRoleCount(t))
}

func TestExternalInvitationPostgres_HomeMember_CannotBecomeFreeSeat(t *testing.T) {
	f := newExternalFixture(t)
	token := f.invite(t, models.SeatClassExternal, f.readRole)

	// The client tenant's own admin cannot accept an external invite into
	// their home tenant (that would convert a paid seat into a free one).
	admin := &models.CurrentUser{ID: f.admin, TenantID: f.client, Email: "smmm@partner.test"}
	w := f.serve(t, admin, http.MethodPost, "/invitations/accept", gin.H{"token": token})
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

// A member invitation is bound to the verified email, not the home tenant: the
// person (email matches) joins as an additional member, one global account.
// An address mismatch is still refused (see the member onboarding tests).
func TestExternalInvitationPostgres_MemberInvite_JoinsByVerifiedEmail(t *testing.T) {
	f := newExternalFixture(t)
	token := f.invite(t, models.SeatClassMember, f.readRole)

	w := f.serve(t, f.accountantUser(), http.MethodPost, "/invitations/accept", gin.H{"token": token})
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	require.Equal(t, 1, f.clientRoleCount(t))
}

func TestExternalInvitationPostgres_DeclineAcrossTenants(t *testing.T) {
	f := newExternalFixture(t)
	token := f.invite(t, models.SeatClassExternal, f.readRole)

	w := f.serve(t, f.accountantUser(), http.MethodPost, "/invitations/decline", gin.H{"token": token})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestExternalInvitationPostgres_Revoke_RemovesClientAccessOnly(t *testing.T) {
	f := newExternalFixture(t)
	token := f.invite(t, models.SeatClassExternal, f.readRole)
	w := f.serve(t, f.accountantUser(), http.MethodPost, "/invitations/accept", gin.H{"token": token})
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())

	w = f.serve(t, f.adminUser(), http.MethodDelete, "/team/external-members/"+f.accountant.String(), nil)
	// 503: PostgreSQL revoked; the SpiceDB delete has no client here.
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())

	var status string
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT status FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`, f.client, f.accountant).Scan(&status))
	require.Equal(t, "deactivated", status)
	require.Zero(t, f.clientRoleCount(t))
	var partnerGrants int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM iam_user_roles WHERE user_id = $1 AND role_id = $2`, f.accountant, f.partnerRole).Scan(&partnerGrants))
	require.Equal(t, 1, partnerGrants, "the accountant's own partner-tenant role must survive")
	require.Equal(t, 1, f.auditCount(t, "team_external_member_revoke"))

	// Second revoke: nothing left to revoke.
	w = f.serve(t, f.adminUser(), http.MethodDelete, "/team/external-members/"+f.accountant.String(), nil)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

func TestExternalInvitationPostgres_Revoke_NeverTouchesSeatMembers(t *testing.T) {
	f := newExternalFixture(t)
	_, err := f.pool.Exec(context.Background(), `INSERT INTO iam_user_memberships (tenant_id, user_id, seat_class, status) VALUES ($1, $2, 'member', 'active')
		ON CONFLICT (tenant_id, user_id) DO NOTHING`, f.client, f.admin)
	require.NoError(t, err)

	w := f.serve(t, f.adminUser(), http.MethodDelete, "/team/external-members/"+f.admin.String(), nil)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	var status string
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT status FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`, f.client, f.admin).Scan(&status))
	require.Equal(t, "active", status)
}

func TestExternalInvitationPostgres_Revoke_OtherTenantsExternal_NotFound(t *testing.T) {
	f := newExternalFixture(t)
	token := f.invite(t, models.SeatClassExternal, f.readRole)
	w := f.serve(t, f.accountantUser(), http.MethodPost, "/invitations/accept", gin.H{"token": token})
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())

	// An admin of a different tenant cannot revoke the client's grant.
	stranger := &models.CurrentUser{ID: uuid.New(), TenantID: f.partner, Permissions: []string{"*"}}
	w = f.serve(t, stranger, http.MethodDelete, "/team/external-members/"+f.accountant.String(), nil)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	require.Equal(t, 1, f.clientRoleCount(t))
}

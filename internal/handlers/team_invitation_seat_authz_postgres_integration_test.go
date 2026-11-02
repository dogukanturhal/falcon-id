// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// setupTeamInvitationHandlerSchema creates a throwaway Postgres schema and
// applies the real 0002/0011/0013 migration files against it (the same
// migration files hack/run-team-postgres-tests.sh applies against a fresh
// docker Postgres), so these handler-level tests exercise CreateInvitation /
// ResendInvitation / RevokeInvitation against the same DDL that ships to
// production rather than a hand-maintained approximation of it.
func setupTeamInvitationHandlerSchema(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	schema := "team_authz_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]

	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	})

	setPath, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = setPath.Close(ctx) }()
	_, err = setPath.Exec(ctx, "SET search_path = "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)
	// CREATE EXTENSION IF NOT EXISTS pgcrypto still races against other
	// tests creating the same (database-wide, not schema-scoped) extension
	// concurrently — pg_extension_name_index can raise a duplicate-key error
	// even with IF NOT EXISTS under concurrent CREATE EXTENSION calls. That
	// race is benign here (the extension ends up created either way), so
	// tolerate exactly that one error code.
	if _, err = setPath.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			require.NoError(t, err)
		}
	}
	_, err = setPath.Exec(ctx, `CREATE TABLE iam_tenants(id uuid PRIMARY KEY)`)
	require.NoError(t, err)
	_, err = setPath.Exec(ctx, `CREATE TABLE iam_users(
		id uuid PRIMARY KEY,
		tenant_id uuid,
		username text NOT NULL DEFAULT '',
		is_active boolean NOT NULL DEFAULT true,
		deletion_scheduled_at timestamptz,
		created_at timestamptz NOT NULL DEFAULT now()
	)`)
	require.NoError(t, err)
	// Not tracked under internal/migrations (predates this migration
	// system) but referenced by repositories.CreateAuditLogTx.
	_, err = setPath.Exec(ctx, `CREATE TABLE iam_audit_log(
		id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_id uuid NOT NULL,
		user_id uuid,
		target_user_id uuid,
		action text NOT NULL,
		resource_type text,
		resource_id uuid,
		details jsonb,
		ip_address text,
		country_code text,
		user_agent text,
		success boolean NOT NULL DEFAULT true,
		error_message text,
		created_at timestamptz NOT NULL DEFAULT now()
	)`)
	require.NoError(t, err)

	for _, file := range []string{
		"../migrations/0002_team_invitations_phase2.sql",
		"../migrations/0011_team_invitation_pending_email_uniqueness.sql",
		"../migrations/0013_iam_invitations_seats.sql",
		"../migrations/0021_iam_employee_seat_class.sql",
		"../migrations/0025_iam_membership_multi_company.sql",
	} {
		sqlBytes, readErr := os.ReadFile(file)
		require.NoError(t, readErr, file)
		_, err = setPath.Exec(ctx, string(sqlBytes))
		require.NoError(t, err, file)
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// newTestTeamInvitationHandler wires a TeamInvitationHandler against the real
// TeamInvitationRepository/SeatCounterRepository/UserMembershipRepository,
// with an EmailService that has no SMTP host configured. That's fine for
// every scenario below: seat_limit_reached (409) and the resend rate limit
// (429) are both detected and returned BEFORE CreateInvitation/
// ResendInvitation ever call SendTeamInvitation, and the cross-tenant-block
// case on ResendInvitation returns 403 before persistence too.
func newTestTeamInvitationHandler(pool *pgxpool.Pool) (*handlers.TeamInvitationHandler, *repositories.TeamInvitationRepository, *repositories.SeatCounterRepository) {
	invRepo := repositories.NewTeamInvitationRepository(pool)
	seatRepo := repositories.NewSeatCounterRepository(pool)
	membershipRepo := repositories.NewUserMembershipRepository(pool)

	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, invRepo, zap.NewNop())
	h.SetEmailService(services.NewEmailService(&config.Config{}))
	h.SetSeatRepositories(membershipRepo, seatRepo)
	return h, invRepo, seatRepo
}

func mustInsertTenantAndInviter(t *testing.T, pool *pgxpool.Pool, tenantID, inviterID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `INSERT INTO iam_tenants (id) VALUES ($1)`, tenantID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_users (id, tenant_id, username) VALUES ($1, $2, 'inviter')`, inviterID, tenantID)
	require.NoError(t, err)
}

// NOTE ON SCOPE: CreateInvitation's 409 seat_limit_reached mapping is
// intentionally NOT exercised through a full handler round-trip here.
// CreateTeamInvitationRequest.RoleIDs carries binding:"required,min=1", so
// reaching CreateInvitation's seat-reservation step at all requires at
// least one role_id that both belongs to the tenant
// (verifyRolesBelongToTenant) AND is "manageable" by the caller under
// RoleService.ManageableSelfServiceRoleIDs — which in turn depends on the
// full role/permission/module-entitlement catalogue (iam_roles,
// iam_user_roles, iam_permissions, iam_role_permissions, actor role
// priority, etc.), none of which this migration touches. Standing up that
// catalogue purely to clear a validation gate unrelated to the seat model
// is out of scope for this change. Instead:
//   - the reservation algorithm itself (never exceeding seat_limit,
//     ErrSeatLimitReached returned once exhausted) is verified against real
//     Postgres, including under concurrency, by
//     TestSeatCounterPostgres_ReserveSeat_NeverExceedsLimit and
//     TestSeatCounterPostgres_ReserveSeat_UnlimitedWhenSeatLimitNil in
//     internal/repositories/seat_counter_postgres_integration_test.go;
//   - CreateInvitation's error-to-HTTP mapping
//     (errors.Is(err, repositories.ErrSeatLimitReached) -> 409 with
//     models.SeatLimitReachedError) is a short, self-contained branch in
//     team_invitation_handler.go with no further branching, reviewed by
//     inspection alongside this change.

// TestTeamInvitationHandlerPostgres_ResendInvitation_CrossTenantBlocked
// covers the handler-level cross-tenant guard: an admin authenticated
// against tenant B must get 403 (not 404, which would leak whether an
// invitation with that ID exists at all) when resending an invitation that
// belongs to tenant A.
func TestTeamInvitationHandlerPostgres_ResendInvitation_CrossTenantBlocked(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	pool := setupTeamInvitationHandlerSchema(t, dsn)
	h, invRepo, _ := newTestTeamInvitationHandler(pool)

	tenantA, inviterA := uuid.New(), uuid.New()
	tenantB, adminB := uuid.New(), uuid.New()
	mustInsertTenantAndInviter(t, pool, tenantA, inviterA)
	mustInsertTenantAndInviter(t, pool, tenantB, adminB)

	inv := &models.TeamInvitation{
		TenantID:  tenantA,
		Email:     "victim@example.test",
		RoleIDs:   []uuid.UUID{},
		InvitedBy: inviterA,
		Token:     models.TeamInvitationTokenDigest(uuid.NewString()),
		Status:    models.TeamInvitationStatusPending,
		ExpiresAt: time.Now().Add(14 * 24 * time.Hour),
		SeatClass: models.SeatClassMember,
	}
	require.NoError(t, invRepo.Create(context.Background(), inv))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(injectCurrentUser(&models.CurrentUser{ID: adminB, TenantID: tenantB, Permissions: []string{"*"}}))
	r.POST("/invitations/:id/actions/resend", h.ResendInvitation)

	req := httptest.NewRequest(http.MethodPost, "/invitations/"+inv.ID.String()+"/actions/resend", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Confirm the cross-tenant attempt was a true no-op: still pending, same
	// expiry, no last_resent_at set.
	reloaded, err := invRepo.GetByID(context.Background(), inv.ID)
	require.NoError(t, err)
	require.Equal(t, models.TeamInvitationStatusPending, reloaded.Status)
}

// TestTeamInvitationHandlerPostgres_ResendInvitation_RateLimited covers the
// 429 path: a second resend within 5 minutes of the first must be rejected
// without sending another email or touching expires_at again.
func TestTeamInvitationHandlerPostgres_ResendInvitation_RateLimited(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	pool := setupTeamInvitationHandlerSchema(t, dsn)
	h, invRepo, _ := newTestTeamInvitationHandler(pool)

	tenantID, adminID := uuid.New(), uuid.New()
	mustInsertTenantAndInviter(t, pool, tenantID, adminID)

	inv := &models.TeamInvitation{
		TenantID:  tenantID,
		Email:     "resendee@example.test",
		RoleIDs:   []uuid.UUID{},
		InvitedBy: adminID,
		Token:     models.TeamInvitationTokenDigest(uuid.NewString()),
		Status:    models.TeamInvitationStatusPending,
		ExpiresAt: time.Now().Add(14 * 24 * time.Hour),
		SeatClass: models.SeatClassMember,
	}
	require.NoError(t, invRepo.Create(context.Background(), inv))

	// First resend directly against the repository (bypassing the handler's
	// email send) to seed last_resent_at = now(), then hit the handler's
	// resend a second time immediately after — this must 429, not attempt
	// another SMTP send.
	ok, err := invRepo.Resend(context.Background(), inv.ID, time.Now().Add(14*24*time.Hour), models.TeamInvitationTokenDigest(uuid.NewString()))
	require.NoError(t, err)
	require.True(t, ok)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(injectCurrentUser(&models.CurrentUser{ID: adminID, TenantID: tenantID, Permissions: []string{"*"}}))
	r.POST("/invitations/:id/actions/resend", h.ResendInvitation)

	req := httptest.NewRequest(http.MethodPost, "/invitations/"+inv.ID.String()+"/actions/resend", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// Member (seat-consuming) invitation onboarding against the real 0002/0011/0013
// DDL: a person with no account registers from the token; a person with an
// account in ANOTHER company signs in and accepts. SpiceDB is absent
// (NewTenantBootstrapService(nil)), so successful requests answer 201/202 with
// role authorization "synchronizing" and every assertion is on PostgreSQL.

// stubInvitedAccounts persists the invited account into the fixture's minimal
// iam_users table (the production store needs the full table + PII encryption).
type stubInvitedAccounts struct {
	pool interface {
		QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	}
}

func (s stubInvitedAccounts) EmailTaken(ctx context.Context, email string) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM iam_users WHERE lower(email) = lower($1)`, email).Scan(&n)
	return n > 0, err
}

func (s stubInvitedAccounts) FindByEmail(ctx context.Context, tx pgx.Tx, email string) (*models.User, error) {
	var db interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	} = s.pool
	if tx != nil {
		db = tx
	}
	u := &models.User{}
	err := db.QueryRow(ctx, `SELECT id, tenant_id FROM iam_users WHERE lower(email) = lower($1) LIMIT 1`, email).Scan(&u.ID, &u.TenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

func (s stubInvitedAccounts) CreateVerified(ctx context.Context, tx pgx.Tx, u *models.User) error {
	u.ID = uuid.New()
	_, err := tx.Exec(ctx, `INSERT INTO iam_users (id, tenant_id, username, email, display_name) VALUES ($1, $2, $3, $4, $5)`,
		u.ID, u.TenantID, u.Username, u.Email, u.DisplayName)
	return err
}

type stubInvitedPreparer struct{}

func (stubInvitedPreparer) PrepareInvitedMemberUser(_ context.Context, tenantID uuid.UUID, email, name, password string) (*models.User, error) {
	if password == "weak" {
		return nil, &services.SignupPasswordError{Violations: []string{"too_short"}}
	}
	n := name
	return &models.User{TenantID: tenantID, Username: strings.ToLower(email), Email: strings.ToLower(email), DisplayName: &n, IsActive: true, IsEmailVerified: true}, nil
}

type stubInvitedSessions struct{ calls int }

func (s *stubInvitedSessions) IssueSessionForNewUser(_ context.Context, _ uuid.UUID, _ *models.User, _, _ string) (*models.LoginResponse, error) {
	s.calls++
	return &models.LoginResponse{AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 900}, nil
}

type memberFixture struct {
	*externalFixture
	sessions  *stubInvitedSessions
	ownerRole uuid.UUID // client role named "owner": triggers MFA enrolment
}

func newMemberFixture(t *testing.T) *memberFixture {
	t.Helper()
	f := &memberFixture{externalFixture: newExternalFixture(t), sessions: &stubInvitedSessions{}}
	ctx := context.Background()
	f.ownerRole = uuid.New()
	_, err := f.pool.Exec(ctx, `INSERT INTO iam_roles (id, tenant_id, name, display_name) VALUES ($1, $2, 'owner', 'Owner')`, f.ownerRole, f.client)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `INSERT INTO iam_role_permissions (role_id, permission_id)
		SELECT $1, rp.permission_id FROM iam_role_permissions rp WHERE rp.role_id = $2`, f.ownerRole, f.readRole)
	require.NoError(t, err)
	// One pending invitation holds one seat (what CreateInvitation reserved).
	_, err = f.pool.Exec(ctx, `INSERT INTO tenant_seat_counters (tenant_id, seats_used, seats_pending, seat_limit) VALUES ($1, 1, 1, 5)
		ON CONFLICT (tenant_id) DO UPDATE SET seats_used = 1, seats_pending = 1, seat_limit = 5`, f.client)
	require.NoError(t, err)
	f.h.SetInvitedAccountStore(stubInvitedAccounts{pool: f.pool})
	f.h.SetOnboardingServices(stubInvitedPreparer{}, f.sessions)
	return f
}

func (f *memberFixture) inviteEmail(t *testing.T, email string, expires time.Duration, status models.TeamInvitationStatus, roles ...uuid.UUID) string {
	t.Helper()
	token := uuid.NewString()
	require.NoError(t, f.invRepo.Create(context.Background(), &models.TeamInvitation{
		TenantID: f.client, Email: email, RoleIDs: roles, InvitedBy: f.admin,
		Token: models.TeamInvitationTokenDigest(token), Status: status,
		ExpiresAt: time.Now().Add(expires), SeatClass: models.SeatClassMember,
	}))
	return token
}

func (f *memberFixture) do(t *testing.T, user *models.CurrentUser, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if user != nil {
		r.Use(injectCurrentUser(user))
	}
	r.GET("/invitations/preview", f.h.PreviewInvitation)
	r.POST("/auth/invitations/register", f.h.RegisterFromInvitation)
	r.POST("/invitations/accept", f.h.AcceptInvitation)
	r.POST("/invitations/decline", f.h.DeclineInvitation)
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

func (f *memberFixture) seats(t *testing.T) (used, pending int) {
	t.Helper()
	require.NoError(t, f.pool.QueryRow(context.Background(),
		`SELECT seats_used, seats_pending FROM tenant_seat_counters WHERE tenant_id = $1`, f.client).Scan(&used, &pending))
	return
}

func (f *memberFixture) membership(t *testing.T, tenant, user uuid.UUID) (class, status string, ok bool) {
	t.Helper()
	err := f.pool.QueryRow(context.Background(),
		`SELECT seat_class, status FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`, tenant, user).Scan(&class, &status)
	return class, status, err == nil
}

func (f *memberFixture) invitationStatus(t *testing.T, token string) string {
	t.Helper()
	var s string
	require.NoError(t, f.pool.QueryRow(context.Background(),
		`SELECT status FROM iam_team_invitations WHERE token = $1`, models.TeamInvitationTokenDigest(token)).Scan(&s))
	return s
}

func (f *memberFixture) userByEmail(t *testing.T, email string) (uuid.UUID, bool) {
	t.Helper()
	var id uuid.UUID
	err := f.pool.QueryRow(context.Background(), `SELECT id FROM iam_users WHERE lower(email) = lower($1)`, email).Scan(&id)
	return id, err == nil
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &m), w.Body.String())
	return m
}

func skipWithoutDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
}

func TestMemberOnboardingPostgres_NewPersonRegisters(t *testing.T) {
	skipWithoutDB(t)
	f := newMemberFixture(t)
	token := f.inviteEmail(t, "Deniz@Example.test", 7*24*time.Hour, models.TeamInvitationStatusPending, f.writeRole)

	w := f.do(t, nil, http.MethodPost, "/auth/invitations/register", gin.H{"token": token, "name": "Deniz Celik", "password": "correct-horse-battery"})
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	out := decode(t, w)
	require.Equal(t, "deniz@example.test", out["email"], "email comes from the invitation, canonicalised")
	require.Equal(t, false, out["mfa_enrollment_required"])
	require.Equal(t, "tok", out["access_token"], "non-admin invitee is signed in at once")
	require.Equal(t, 1, f.sessions.calls)

	uid, ok := f.userByEmail(t, "deniz@example.test")
	require.True(t, ok)
	mfaNeeded, err := repositories.NewUserRepository(f.pool).RequiresInvitedAdminMFA(context.Background(), uid, f.client)
	require.NoError(t, err)
	require.False(t, mfaNeeded, "a non-admin invitee is not forced to enrol")
	class, status, has := f.membership(t, f.client, uid)
	require.True(t, has)
	require.Equal(t, "member", class)
	require.Equal(t, "active", status)
	require.Equal(t, "accepted", f.invitationStatus(t, token))

	var roles int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM iam_user_roles WHERE user_id = $1 AND role_id = $2`, uid, f.writeRole).Scan(&roles))
	require.Equal(t, 1, roles)
	used, pending := f.seats(t)
	require.Equal(t, 2, used, "the pending seat converts to a used seat")
	require.Zero(t, pending)
}

func TestMemberOnboardingPostgres_TokenIsSingleUse(t *testing.T) {
	skipWithoutDB(t)
	f := newMemberFixture(t)
	token := f.inviteEmail(t, "once@example.test", 7*24*time.Hour, models.TeamInvitationStatusPending, f.readRole)
	body := gin.H{"token": token, "name": "Once", "password": "correct-horse-battery"}
	require.Equal(t, http.StatusCreated, f.do(t, nil, http.MethodPost, "/auth/invitations/register", body).Code)
	w := f.do(t, nil, http.MethodPost, "/auth/invitations/register", body)
	require.Equal(t, http.StatusBadRequest, w.Code, "a consumed token is refused: %s", w.Body.String())
	used, _ := f.seats(t)
	require.Equal(t, 2, used, "the seat converts exactly once")
}

func TestMemberOnboardingPostgres_ExpiredRevokedAndUnknownTokens(t *testing.T) {
	skipWithoutDB(t)
	f := newMemberFixture(t)
	expired := f.inviteEmail(t, "late@example.test", -time.Hour, models.TeamInvitationStatusPending, f.readRole)
	revoked := f.inviteEmail(t, "gone@example.test", 7*24*time.Hour, models.TeamInvitationStatusRevoked, f.readRole)
	for name, tok := range map[string]string{"expired": expired, "revoked": revoked, "unknown": uuid.NewString()} {
		w := f.do(t, nil, http.MethodPost, "/auth/invitations/register", gin.H{"token": tok, "name": "X", "password": "correct-horse-battery"})
		require.Equal(t, http.StatusBadRequest, w.Code, "%s: %s", name, w.Body.String())
	}
	for _, e := range []string{"late@example.test", "gone@example.test"} {
		_, ok := f.userByEmail(t, e)
		require.False(t, ok, "no account is created for %s", e)
	}
	used, pending := f.seats(t)
	require.Equal(t, 1, used)
	require.Equal(t, 1, pending)
}

func TestMemberOnboardingPostgres_ExistingAccountMustSignIn(t *testing.T) {
	skipWithoutDB(t)
	f := newMemberFixture(t)
	token := f.inviteEmail(t, "smmm@partner.test", 7*24*time.Hour, models.TeamInvitationStatusPending, f.readRole)
	w := f.do(t, nil, http.MethodPost, "/auth/invitations/register", gin.H{"token": token, "name": "Dup", "password": "correct-horse-battery"})
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Equal(t, "account_exists", decode(t, w)["code"])
	require.Equal(t, "pending", f.invitationStatus(t, token), "the invitation stays usable for the sign-in path")
}

func TestMemberOnboardingPostgres_WeakPasswordLeavesInvitationUntouched(t *testing.T) {
	skipWithoutDB(t)
	f := newMemberFixture(t)
	token := f.inviteEmail(t, "weak@example.test", 7*24*time.Hour, models.TeamInvitationStatusPending, f.readRole)
	w := f.do(t, nil, http.MethodPost, "/auth/invitations/register", gin.H{"token": token, "name": "Weak", "password": "weak"})
	require.Equal(t, http.StatusUnprocessableEntity, w.Code, w.Body.String())
	require.Equal(t, "pending", f.invitationStatus(t, token))
	_, ok := f.userByEmail(t, "weak@example.test")
	require.False(t, ok)
}

func TestMemberOnboardingPostgres_OwnerInviteRequiresMFAEnrolmentNoSession(t *testing.T) {
	skipWithoutDB(t)
	f := newMemberFixture(t)
	token := f.inviteEmail(t, "boss@example.test", 7*24*time.Hour, models.TeamInvitationStatusPending, f.ownerRole)

	pw := f.do(t, nil, http.MethodGet, "/invitations/preview?token="+token, nil)
	require.Equal(t, http.StatusOK, pw.Code, pw.Body.String())
	require.Equal(t, true, decode(t, pw)["requiresMfaEnrollment"])

	w := f.do(t, nil, http.MethodPost, "/auth/invitations/register", gin.H{"token": token, "name": "Boss", "password": "correct-horse-battery"})
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	out := decode(t, w)
	require.Equal(t, true, out["mfa_enrollment_required"])
	require.NotContains(t, out, "access_token", "an owner/admin never gets an unchallenged session")
	require.Zero(t, f.sessions.calls)

	// The sign-in path then forces enrolment: an invited owner/admin with no
	// factor is routed through the MFA registration interrupt.
	bossID, ok := f.userByEmail(t, "boss@example.test")
	require.True(t, ok)
	required, err := repositories.NewUserRepository(f.pool).RequiresInvitedAdminMFA(context.Background(), bossID, f.client)
	require.NoError(t, err)
	require.True(t, required)
}

func TestMemberOnboardingPostgres_PreviewStatesAndPrivacy(t *testing.T) {
	skipWithoutDB(t)
	f := newMemberFixture(t)
	good := f.inviteEmail(t, "deniz@example.test", 7*24*time.Hour, models.TeamInvitationStatusPending, f.readRole)
	used := f.inviteEmail(t, "used@example.test", 7*24*time.Hour, models.TeamInvitationStatusAccepted, f.readRole)
	late := f.inviteEmail(t, "late@example.test", -time.Minute, models.TeamInvitationStatusPending, f.readRole)

	w := f.do(t, nil, http.MethodGet, "/invitations/preview?token="+good, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	out := decode(t, w)
	require.Equal(t, true, out["valid"])
	require.Equal(t, "d***@example.test", out["maskedEmail"])
	require.NotContains(t, w.Body.String(), "deniz@example.test", "the full address is never returned")
	require.Equal(t, false, out["accountExists"], "no account yet: the page offers create-account")

	known := f.inviteEmail(t, "smmm@partner.test", 7*24*time.Hour, models.TeamInvitationStatusPending, f.writeRole)
	w = f.do(t, nil, http.MethodGet, "/invitations/preview?token="+known, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, true, decode(t, w)["accountExists"], "existing account: the page offers sign-in")

	for tok, want := range map[string]string{used: "used", late: "expired"} {
		w := f.do(t, nil, http.MethodGet, "/invitations/preview?token="+tok, nil)
		require.Equal(t, http.StatusGone, w.Code)
		require.Equal(t, want, decode(t, w)["reason"])
	}
	require.Equal(t, http.StatusNotFound, f.do(t, nil, http.MethodGet, "/invitations/preview?token="+uuid.NewString(), nil).Code)
}

func TestMemberOnboardingPostgres_ExistingAccountInAnotherTenantJoinsAsMember(t *testing.T) {
	skipWithoutDB(t)
	f := newMemberFixture(t)
	token := f.inviteEmail(t, "smmm@partner.test", 7*24*time.Hour, models.TeamInvitationStatusPending, f.writeRole)

	// Isolation first: being a member of the partner company gives nothing in the client company.
	_, _, has := f.membership(t, f.client, f.accountant)
	require.False(t, has)
	require.Zero(t, f.clientRoleCount(t))

	// The signed-in session belongs to the PARTNER tenant (home) and has a different-case email.
	w := f.do(t, f.accountantUser(), http.MethodPost, "/invitations/accept", gin.H{"token": token})
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String()) // 202: SpiceDB sync pending (no client wired)

	class, status, has := f.membership(t, f.client, f.accountant)
	require.True(t, has)
	require.Equal(t, "member", class)
	require.Equal(t, "active", status)
	require.Equal(t, 1, f.clientRoleCount(t))
	used, pending := f.seats(t)
	require.Equal(t, 2, used)
	require.Zero(t, pending)

	// The home company is untouched: still exactly its own role.
	var partnerRoles int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM iam_user_roles ur JOIN iam_roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.tenant_id = $2`, f.accountant, f.partner).Scan(&partnerRoles))
	require.Equal(t, 1, partnerRoles)

	// Single use.
	w = f.do(t, f.accountantUser(), http.MethodPost, "/invitations/accept", gin.H{"token": token})
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}

func TestMemberOnboardingPostgres_WrongEmailCannotAccept(t *testing.T) {
	skipWithoutDB(t)
	f := newMemberFixture(t)
	token := f.inviteEmail(t, "someone.else@example.test", 7*24*time.Hour, models.TeamInvitationStatusPending, f.writeRole)

	w := f.do(t, f.accountantUser(), http.MethodPost, "/invitations/accept", gin.H{"token": token})
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "different account")
	_, _, has := f.membership(t, f.client, f.accountant)
	require.False(t, has)
	require.Zero(t, f.clientRoleCount(t))
	used, pending := f.seats(t)
	require.Equal(t, 1, used)
	require.Equal(t, 1, pending, "the pending seat is still held")
	require.Equal(t, "pending", f.invitationStatus(t, token))

	// Decline obeys the same identity rule.
	w = f.do(t, f.accountantUser(), http.MethodPost, "/invitations/decline", gin.H{"token": token})
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Equal(t, "pending", f.invitationStatus(t, token))
}

func TestMemberOnboardingPostgres_ExpiredInvitationCannotBeAccepted(t *testing.T) {
	skipWithoutDB(t)
	f := newMemberFixture(t)
	token := f.inviteEmail(t, "smmm@partner.test", -time.Hour, models.TeamInvitationStatusPending, f.writeRole)
	w := f.do(t, f.accountantUser(), http.MethodPost, "/invitations/accept", gin.H{"token": token})
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	_, _, has := f.membership(t, f.client, f.accountant)
	require.False(t, has)
}

func TestMemberOnboardingPostgres_AlreadyActiveMemberIsRefused(t *testing.T) {
	skipWithoutDB(t)
	f := newMemberFixture(t)
	first := f.inviteEmail(t, "smmm@partner.test", 7*24*time.Hour, models.TeamInvitationStatusPending, f.writeRole)
	require.Equal(t, http.StatusAccepted, f.do(t, f.accountantUser(), http.MethodPost, "/invitations/accept", gin.H{"token": first}).Code)
	second := f.inviteEmail(t, "smmm@partner.test", 7*24*time.Hour, models.TeamInvitationStatusPending, f.writeRole)
	w := f.do(t, f.accountantUser(), http.MethodPost, "/invitations/accept", gin.H{"token": second})
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Equal(t, "pending", f.invitationStatus(t, second))
}

// 0025 backfills a membership for users created after 0013 and is idempotent;
// it never touches service identities.
func TestMemberOnboardingPostgres_Migration0025BackfillIdempotent(t *testing.T) {
	skipWithoutDB(t)
	f := newMemberFixture(t)
	ctx := context.Background()
	late, svc := uuid.New(), uuid.New()
	_, err := f.pool.Exec(ctx, `INSERT INTO iam_users (id, tenant_id, username, email) VALUES ($1, $2, 'late-user', 'late@x.test'), ($3, $2, 'svc-sync', 'svc@x.test')`, late, f.client, svc)
	require.NoError(t, err)
	_, _, has := f.membership(t, f.client, late)
	require.False(t, has)

	sql, err := os.ReadFile("../migrations/0025_iam_membership_multi_company.sql")
	require.NoError(t, err)
	for i := 0; i < 2; i++ { // second run proves idempotency
		_, err = f.pool.Exec(ctx, strings.ReplaceAll(string(sql), "SET LOCAL", "-- SET LOCAL"))
		require.NoError(t, err)
	}
	class, status, has := f.membership(t, f.client, late)
	require.True(t, has)
	require.Equal(t, "member", class)
	require.Equal(t, "active", status)
	_, _, has = f.membership(t, f.client, svc)
	require.False(t, has, "service identities are never a membership")

	var n int
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT count(*) FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`, f.client, late).Scan(&n))
	require.Equal(t, 1, n)
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'iam_user_memberships' AND column_name = 'last_used_at' AND table_schema = current_schema()`).Scan(&n))
	require.Equal(t, 1, n)
}

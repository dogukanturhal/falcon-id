// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// One global account, many companies: invitation create/expire/signed-in
// accept, against the real 0002/0011/0013/0025 DDL plus the minimal role
// catalogue of externalFixture.

// stubInviteeIdentity serves the caller-identity lookups of the signed-in flow.
type stubInviteeIdentity struct {
	email    map[uuid.UUID]string
	verified map[uuid.UUID]bool
	mfa      map[uuid.UUID]bool
}

func (s stubInviteeIdentity) VerifiedEmail(_ context.Context, id uuid.UUID) (string, bool, error) {
	return s.email[id], s.verified[id], nil
}

func (s stubInviteeIdentity) HasAnyMFAFactor(_ context.Context, id uuid.UUID) (bool, error) {
	return s.mfa[id], nil
}

type identityFixture struct {
	*externalFixture
	identity stubInviteeIdentity
}

func newIdentityFixture(t *testing.T) *identityFixture {
	t.Helper()
	f := &identityFixture{externalFixture: newExternalFixture(t)}
	f.identity = stubInviteeIdentity{
		email:    map[uuid.UUID]string{f.accountant: "smmm@partner.test"},
		verified: map[uuid.UUID]bool{f.accountant: true},
		mfa:      map[uuid.UUID]bool{},
	}
	// The inviting admin outranks the invitable roles (role priority gate).
	superRole := uuid.New()
	_, err := f.pool.Exec(context.Background(), `INSERT INTO iam_roles (id, tenant_id, name, priority) VALUES ($1, $2, 'tenant_super', 100)`, superRole, f.client)
	require.NoError(t, err)
	_, err = f.pool.Exec(context.Background(), `INSERT INTO iam_user_roles (user_id, role_id) VALUES ($1, $2)`, f.admin, superRole)
	require.NoError(t, err)
	f.h.SetInvitedAccountStore(stubInvitedAccounts{pool: f.pool})
	f.h.SetInviteeIdentityStore(f.identity)
	return f
}

func (f *identityFixture) router(user *models.CurrentUser) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(injectCurrentUser(user))
	r.POST("/invitations", f.h.CreateInvitation)
	r.GET("/invitations/mine", f.h.ListMyInvitations)
	r.POST("/invitations/mine/:id/accept", f.h.AcceptMyInvitation)
	r.POST("/invitations/mine/:id/decline", f.h.DeclineMyInvitation)
	return r
}

func (f *identityFixture) do(t *testing.T, user *models.CurrentUser, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return f.externalFixtureServe(t, f.router(user), method, path, body)
}

func (f *identityFixture) externalFixtureServe(t *testing.T, r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
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

func (f *identityFixture) seats(t *testing.T) (used, pending int) {
	t.Helper()
	err := f.pool.QueryRow(context.Background(), `SELECT seats_used, seats_pending FROM tenant_seat_counters WHERE tenant_id = $1`, f.client).Scan(&used, &pending)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0
	}
	require.NoError(t, err)
	return used, pending
}

func (f *identityFixture) createBody(email string) gin.H {
	return gin.H{"email": email, "roleIds": []uuid.UUID{f.readRole}}
}

// addMemberUser makes an account whose home is the client tenant.
func (f *identityFixture) addUser(t *testing.T, tenant uuid.UUID, email string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := f.pool.Exec(context.Background(), `INSERT INTO iam_users (id, tenant_id, username, email) VALUES ($1, $2, $3, $3)`, id, tenant, email)
	require.NoError(t, err)
	f.identity.email[id] = email
	f.identity.verified[id] = true
	return id
}

func TestCreateInvitationPostgres_ExistingGlobalAccountLooksLikeNewEmail(t *testing.T) {
	f := newIdentityFixture(t)

	fresh := f.do(t, f.adminUser(), http.MethodPost, "/invitations", f.createBody("brand-new@example.test"))
	existing := f.do(t, f.adminUser(), http.MethodPost, "/invitations", f.createBody("smmm@partner.test"))
	require.Equal(t, http.StatusCreated, fresh.Code, fresh.Body.String())
	require.Equal(t, http.StatusCreated, existing.Code, existing.Body.String())

	// Same response shape: nothing in the body reveals that an account exists.
	shape := func(w *httptest.ResponseRecorder) map[string]bool {
		var m map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &m))
		keys := map[string]bool{}
		for k := range m {
			keys[k] = true
		}
		return keys
	}
	require.Equal(t, shape(fresh), shape(existing))

	_, pending := f.seats(t)
	require.Equal(t, 2, pending, "both invitations reserve a seat")
}

func TestCreateInvitationPostgres_ActiveMemberIsRefusedWithoutReservingASeat(t *testing.T) {
	f := newIdentityFixture(t)

	// Home member of the inviting tenant.
	f.addUser(t, f.client, "colleague@example.test")
	w := f.do(t, f.adminUser(), http.MethodPost, "/invitations", f.createBody("Colleague@Example.test"))
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"code":"already_member"`)

	// Partner-tenant accountant with an active additional membership.
	_, err := f.pool.Exec(context.Background(), `INSERT INTO iam_user_memberships (tenant_id, user_id, seat_class, status) VALUES ($1, $2, 'member', 'active')`, f.client, f.accountant)
	require.NoError(t, err)
	w = f.do(t, f.adminUser(), http.MethodPost, "/invitations", f.createBody("smmm@partner.test"))
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"code":"already_member"`)

	used, pending := f.seats(t)
	require.Zero(t, used)
	require.Zero(t, pending, "a refused invite must not leave a reserved seat")
	var n int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM iam_team_invitations WHERE tenant_id = $1`, f.client).Scan(&n))
	require.Zero(t, n)
}

func TestCreateInvitationPostgres_DuplicatePendingCarriesCode(t *testing.T) {
	f := newIdentityFixture(t)
	require.Equal(t, http.StatusCreated, f.do(t, f.adminUser(), http.MethodPost, "/invitations", f.createBody("dup@example.test")).Code)
	w := f.do(t, f.adminUser(), http.MethodPost, "/invitations", f.createBody("dup@example.test"))
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"code":"invitation_pending"`)
	_, pending := f.seats(t)
	require.Equal(t, 1, pending, "the rejected duplicate reserved nothing")
}

func TestCreateInvitationPostgres_ReinviteAfterExpiryDoesNotLeakTheSeat(t *testing.T) {
	f := newIdentityFixture(t)
	require.Equal(t, http.StatusCreated, f.do(t, f.adminUser(), http.MethodPost, "/invitations", f.createBody("lapsed@example.test")).Code)
	_, pending := f.seats(t)
	require.Equal(t, 1, pending)

	// The first invitation lapses before the background sweeper sees it.
	_, err := f.pool.Exec(context.Background(), `UPDATE iam_team_invitations SET expires_at = now() - interval '1 hour' WHERE tenant_id = $1`, f.client)
	require.NoError(t, err)

	require.Equal(t, http.StatusCreated, f.do(t, f.adminUser(), http.MethodPost, "/invitations", f.createBody("lapsed@example.test")).Code)
	_, pending = f.seats(t)
	require.Equal(t, 1, pending, "the expired row's reservation is released, then one new seat reserved")

	var expired int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM iam_team_invitations WHERE tenant_id = $1 AND status = 'expired'`, f.client).Scan(&expired))
	require.Equal(t, 1, expired)
}

// pendingFor inserts a member-seat invitation for email and reserves its seat.
func (f *identityFixture) pendingFor(t *testing.T, email string, roles ...uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	_, err := f.pool.Exec(ctx, `INSERT INTO tenant_seat_counters (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING`, f.client)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE tenant_seat_counters SET seats_pending = seats_pending + 1 WHERE tenant_id = $1`, f.client)
	require.NoError(t, err)
	inv := &models.TeamInvitation{
		TenantID: f.client, Email: email, RoleIDs: roles, InvitedBy: f.admin,
		Token: models.TeamInvitationTokenDigest(uuid.NewString()), Status: models.TeamInvitationStatusPending,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), SeatClass: models.SeatClassMember,
	}
	require.NoError(t, f.invRepo.Create(ctx, inv))
	return inv.ID
}

func (f *identityFixture) memberUser() *models.CurrentUser {
	// Signed in to the partner (home) tenant; the claims email is irrelevant to
	// the by-id flow, which trusts only the verified account email.
	return &models.CurrentUser{ID: f.accountant, TenantID: f.partner, Email: "someone-else@example.test"}
}

func TestMyInvitationsPostgres_ListShowsOnlyVerifiedOwnersPendingInvites(t *testing.T) {
	f := newIdentityFixture(t)
	mine := f.pendingFor(t, "SMMM@partner.test", f.readRole)
	f.pendingFor(t, "other@example.test", f.readRole)

	w := f.do(t, f.memberUser(), http.MethodGet, "/invitations/mine", nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Len(t, list, 1)
	require.Equal(t, mine.String(), list[0]["id"])
	require.NotContains(t, list[0], "token")
	require.NotContains(t, w.Body.String(), "sha256:")

	// Unverified mailbox: sees nothing.
	f.identity.verified[f.accountant] = false
	w = f.do(t, f.memberUser(), http.MethodGet, "/invitations/mine", nil)
	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, `[]`, w.Body.String())
}

func TestMyInvitationsPostgres_AcceptCreatesMembershipAndConfirmsSeat(t *testing.T) {
	f := newIdentityFixture(t)
	id := f.pendingFor(t, "smmm@partner.test", f.readRole)

	w := f.do(t, f.memberUser(), http.MethodPost, "/invitations/mine/"+id.String()+"/accept", nil)
	// 202: PostgreSQL committed, SpiceDB sync pending (no client wired).
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), f.client.String())

	var status, seatClass string
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT status, seat_class FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`, f.client, f.accountant).Scan(&status, &seatClass))
	require.Equal(t, "active", status)
	require.Equal(t, "member", seatClass)
	used, pending := f.seats(t)
	require.Equal(t, 1, used)
	require.Zero(t, pending)
	require.Equal(t, 1, f.clientRoleCount(t))

	// Accepting again is a conflict, not a second membership or seat.
	w = f.do(t, f.memberUser(), http.MethodPost, "/invitations/mine/"+id.String()+"/accept", nil)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"code":"invitation_not_pending"`)
	used, pending = f.seats(t)
	require.Equal(t, 1, used)
	require.Zero(t, pending)
}

func TestMyInvitationsPostgres_OtherUsersInvitationAndUnverifiedAreNotFound(t *testing.T) {
	f := newIdentityFixture(t)
	someoneElse := f.pendingFor(t, "other@example.test", f.readRole)

	w := f.do(t, f.memberUser(), http.MethodPost, "/invitations/mine/"+someoneElse.String()+"/accept", nil)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = f.do(t, f.memberUser(), http.MethodPost, "/invitations/mine/"+someoneElse.String()+"/decline", nil)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = f.do(t, f.memberUser(), http.MethodPost, "/invitations/mine/"+uuid.NewString()+"/accept", nil)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	own := f.pendingFor(t, "smmm@partner.test", f.readRole)
	f.identity.verified[f.accountant] = false
	w = f.do(t, f.memberUser(), http.MethodPost, "/invitations/mine/"+own.String()+"/accept", nil)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	var status string
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT status FROM iam_team_invitations WHERE id = $1`, own).Scan(&status))
	require.Equal(t, "pending", status)
}

func TestMyInvitationsPostgres_DeclineReleasesTheReservation(t *testing.T) {
	f := newIdentityFixture(t)
	id := f.pendingFor(t, "smmm@partner.test", f.readRole)
	_, pending := f.seats(t)
	require.Equal(t, 1, pending)

	w := f.do(t, f.memberUser(), http.MethodPost, "/invitations/mine/"+id.String()+"/decline", nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	_, pending = f.seats(t)
	require.Zero(t, pending)

	w = f.do(t, f.memberUser(), http.MethodPost, "/invitations/mine/"+id.String()+"/decline", nil)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestMyInvitationsPostgres_AdminRoleRequiresAnEnrolledFactor(t *testing.T) {
	f := newIdentityFixture(t)
	adminRole := uuid.New()
	_, err := f.pool.Exec(context.Background(), `INSERT INTO iam_roles (id, tenant_id, name) VALUES ($1, $2, 'admin')`, adminRole, f.client)
	require.NoError(t, err)
	id := f.pendingFor(t, "smmm@partner.test", adminRole)

	w := f.do(t, f.memberUser(), http.MethodPost, "/invitations/mine/"+id.String()+"/accept", nil)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"code":"mfa_enrollment_required"`)
	var refused int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM iam_audit_log WHERE tenant_id = $1 AND action = 'team_invitation_accept' AND NOT success AND details->>'reason' = 'mfa_enrollment_required'`, f.client).Scan(&refused))
	require.Equal(t, 1, refused, "the refusal is audited")
	var status string
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT status FROM iam_team_invitations WHERE id = $1`, id).Scan(&status))
	require.Equal(t, "pending", status)

	f.identity.mfa[f.accountant] = true
	w = f.do(t, f.memberUser(), http.MethodPost, "/invitations/mine/"+id.String()+"/accept", nil)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
}

func TestAcceptByTokenPostgres_AdminRoleRequiresAnEnrolledFactor(t *testing.T) {
	f := newIdentityFixture(t)
	adminRole := uuid.New()
	_, err := f.pool.Exec(context.Background(), `INSERT INTO iam_roles (id, tenant_id, name) VALUES ($1, $2, 'owner')`, adminRole, f.client)
	require.NoError(t, err)
	token := f.invite(t, models.SeatClassMember, adminRole)

	w := f.serveAccept(t, f.accountantUser(), token)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"code":"mfa_enrollment_required"`)
}

func (f *identityFixture) serveAccept(t *testing.T, user *models.CurrentUser, token string) *httptest.ResponseRecorder {
	t.Helper()
	return f.serve(t, user, http.MethodPost, "/invitations/accept", gin.H{"token": token})
}

func TestHasCompletedSignupForUserPostgres(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	_, err := f.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS iam_signup_requests (
		id uuid PRIMARY KEY, email text NOT NULL, user_id uuid, verified boolean NOT NULL DEFAULT false, completed boolean NOT NULL DEFAULT false)`)
	require.NoError(t, err)
	repo := repositories.NewSignupRequestRepository(f.pool)

	insert := func(email string, user uuid.UUID, verified, completed bool) {
		_, err := f.pool.Exec(ctx, `INSERT INTO iam_signup_requests (id, email, user_id, verified, completed) VALUES ($1,$2,$3,$4,$5)`, uuid.New(), email, user, verified, completed)
		require.NoError(t, err)
	}
	owner, forced, unfinished := uuid.New(), uuid.New(), uuid.New()
	insert(" Owner@Example.test ", owner, true, true)
	insert("forced@example.test", uuid.New(), true, true) // someone else's row for that address
	insert("unfinished@example.test", unfinished, true, false)

	ok, err := repo.HasCompletedSignupForUser(ctx, owner, "owner@example.test")
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = repo.HasCompletedSignupForUser(ctx, owner, "other@example.test")
	require.NoError(t, err)
	require.False(t, ok, "email must match the signup row")
	ok, err = repo.HasCompletedSignupForUser(ctx, forced, "forced@example.test")
	require.NoError(t, err)
	require.False(t, ok, "an admin-forced account has no signup row of its own")
	ok, err = repo.HasCompletedSignupForUser(ctx, unfinished, "unfinished@example.test")
	require.NoError(t, err)
	require.False(t, ok, "signup must be completed")
}

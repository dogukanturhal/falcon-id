// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Tenant switcher for external (seat_class=external) accountants: the client
// tenant is listed and switchable only while the membership is active, and
// role names never leak across tenants.
func TestContextHandlerPostgres_ExternalMembership(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	ctx := context.Background()
	schema := "ctx_ext_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	for _, stmt := range []string{
		`CREATE TABLE iam_tenants(id uuid PRIMARY KEY, slug text NOT NULL, name text NOT NULL, status text NOT NULL DEFAULT 'active')`,
		`CREATE TABLE iam_tenant_status(tenant_id uuid PRIMARY KEY, suspended boolean NOT NULL DEFAULT false)`,
		`CREATE TABLE iam_users(id uuid PRIMARY KEY, tenant_id uuid NOT NULL, realm_id uuid, is_active boolean NOT NULL DEFAULT true)`,
		`CREATE TABLE iam_user_memberships(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, user_id uuid NOT NULL, seat_class text NOT NULL, status text NOT NULL, last_used_at timestamptz)`,
		`CREATE TABLE iam_roles(id uuid PRIMARY KEY, tenant_id uuid NOT NULL, name text NOT NULL)`,
		`CREATE TABLE iam_user_roles(user_id uuid NOT NULL, role_id uuid NOT NULL, expires_at timestamptz)`,
	} {
		_, err := pool.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}

	partner, client, other := uuid.New(), uuid.New(), uuid.New()
	accountant := uuid.New()
	partnerAdmin, clientRead := uuid.New(), uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO iam_tenants (id, slug, name) VALUES ($1,'partner','Partner SMMM'), ($2,'client','Client AS'), ($3,'other','Other AS')`, partner, client, other)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_users (id, tenant_id) VALUES ($1, $2)`, accountant, partner)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_roles (id, tenant_id, name) VALUES ($1, $3, 'Tenant Admin'), ($2, $4, 'external_readonly')`, partnerAdmin, clientRead, partner, client)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_user_roles (user_id, role_id) VALUES ($1, $2), ($1, $3)`, accountant, partnerAdmin, clientRead)
	require.NoError(t, err)

	h := &ContextHandler{db: pool}

	// Before any membership: home tenant only, client not switchable.
	contexts, err := h.getUserContextsFromDB(ctx, accountant)
	require.NoError(t, err)
	require.Len(t, contexts, 1)
	ok, _, err := h.verifyUserContextAccess(ctx, accountant, client, uuid.Nil)
	require.NoError(t, err)
	require.False(t, ok, "no membership must be a plain denial, not an error")

	_, err = pool.Exec(ctx, `INSERT INTO iam_user_memberships (tenant_id, user_id, seat_class, status) VALUES ($1, $2, 'external', 'active')`, client, accountant)
	require.NoError(t, err)

	contexts, err = h.getUserContextsFromDB(ctx, accountant)
	require.NoError(t, err)
	require.Len(t, contexts, 2)
	byTenant := map[uuid.UUID][]string{}
	kinds := map[uuid.UUID]string{}
	for _, c := range contexts {
		byTenant[c.TenantID] = c.Roles
		kinds[c.TenantID] = c.MembershipKind
	}
	require.Equal(t, "home", kinds[partner])
	require.Equal(t, "external", kinds[client], "the switcher must know which contexts need a token exchange")
	require.Equal(t, []string{"external_readonly"}, byTenant[client], "partner-tenant roles must not appear under the client")
	require.Equal(t, []string{"Tenant Admin"}, byTenant[partner])

	ok, info, err := h.verifyUserContextAccess(ctx, accountant, client, uuid.Nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, client, info.TenantID)
	require.Empty(t, switchTargetRefusal(info))
	roles, err := h.getUserRolesInContext(ctx, accountant, client, uuid.Nil)
	require.NoError(t, err)
	require.Equal(t, []string{"external_readonly"}, roles)

	// LD-R3-TX-3: a suspended or inactive client tenant is reachable but
	// refused as a switch target.
	_, err = pool.Exec(ctx, `INSERT INTO iam_tenant_status (tenant_id, suspended) VALUES ($1, true)`, client)
	require.NoError(t, err)
	ok, info, err = h.verifyUserContextAccess(ctx, accountant, client, uuid.Nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "tenant_suspended", switchTargetRefusal(info))
	_, err = pool.Exec(ctx, `UPDATE iam_tenant_status SET suspended = false WHERE tenant_id = $1`, client)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE iam_tenants SET status = 'cancelled' WHERE id = $1`, client)
	require.NoError(t, err)
	ok, info, err = h.verifyUserContextAccess(ctx, accountant, client, uuid.Nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "tenant_not_active", switchTargetRefusal(info))
	_, err = pool.Exec(ctx, `UPDATE iam_tenants SET status = 'trial' WHERE id = $1`, client)
	require.NoError(t, err)
	ok, info, err = h.verifyUserContextAccess(ctx, accountant, client, uuid.Nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.Empty(t, switchTargetRefusal(info))

	// A tenant with no membership stays closed.
	ok, _, err = h.verifyUserContextAccess(ctx, accountant, other, uuid.Nil)
	require.NoError(t, err)
	require.False(t, ok)

	// Revocation: a deactivated membership closes the switch at once.
	_, err = pool.Exec(ctx, `UPDATE iam_user_memberships SET status = 'deactivated' WHERE tenant_id = $1 AND user_id = $2`, client, accountant)
	require.NoError(t, err)
	ok, _, err = h.verifyUserContextAccess(ctx, accountant, client, uuid.Nil)
	require.NoError(t, err)
	require.False(t, ok)
	contexts, err = h.getUserContextsFromDB(ctx, accountant)
	require.NoError(t, err)
	require.Len(t, contexts, 1)

	// An active member (invited, seat-holding) row opens the company in the
	// switcher as membership_kind "member"; a deactivated one does not.
	_, err = pool.Exec(ctx, `INSERT INTO iam_user_memberships (tenant_id, user_id, seat_class, status) VALUES ($1, $2, 'member', 'active')`, other, accountant)
	require.NoError(t, err)
	ok, _, err = h.verifyUserContextAccess(ctx, accountant, other, uuid.Nil)
	require.NoError(t, err)
	require.True(t, ok)
	contexts, err = h.getUserContextsFromDB(ctx, accountant)
	require.NoError(t, err)
	memberKinds := map[string]bool{}
	for _, c := range contexts {
		memberKinds[c.MembershipKind] = true
	}
	require.True(t, memberKinds["member"])

	_, err = pool.Exec(ctx, `UPDATE iam_user_memberships SET status = 'deactivated' WHERE tenant_id = $1 AND user_id = $2`, other, accountant)
	require.NoError(t, err)
	ok, _, err = h.verifyUserContextAccess(ctx, accountant, other, uuid.Nil)
	require.NoError(t, err)
	require.False(t, ok)
}

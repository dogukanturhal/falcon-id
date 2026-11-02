// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestNotificationRecipientsPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; run hack/run-team-postgres-tests.sh")
	}
	ctx := context.Background()
	schema := "notif_recipients_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer admin.Close(ctx)
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	defer func() { _, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") }()
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(ctx, `
CREATE TABLE iam_users(id uuid primary key, tenant_id uuid not null, email text, is_active bool not null default true, deletion_scheduled_at timestamptz, activation_status text);
CREATE TABLE iam_roles(id uuid primary key, tenant_id uuid not null, name text not null);
CREATE TABLE iam_user_roles(user_id uuid not null references iam_users(id), role_id uuid not null references iam_roles(id), expires_at timestamptz, primary key(user_id,role_id));
CREATE TABLE iam_user_memberships(id uuid primary key default gen_random_uuid(), tenant_id uuid not null, user_id uuid not null, seat_class text not null, status text not null, access_expires_at timestamptz, unique(tenant_id,user_id));`)
	require.NoError(t, err)

	enc, err := crypto.NewEncryptionService("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	repo := NewNotificationRecipientRepository(pool, enc)

	tenant, otherTenant, partner := uuid.New(), uuid.New(), uuid.New()
	ownerRole, adminRole, billingRole, otherOwnerRole := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, r := range []struct {
		id     uuid.UUID
		tenant uuid.UUID
		name   string
	}{{ownerRole, tenant, "owner"}, {adminRole, tenant, "admin"}, {billingRole, tenant, "billing"}, {otherOwnerRole, otherTenant, "owner"}} {
		_, err = pool.Exec(ctx, `INSERT INTO iam_roles(id,tenant_id,name) VALUES($1,$2,$3)`, r.id, r.tenant, r.name)
		require.NoError(t, err)
	}
	type fixture struct {
		id       uuid.UUID
		home     uuid.UUID
		email    string
		active   bool
		deleting bool
		seat     string
		status   string
		expired  bool
	}
	owner, adm, billing, member, inactiveUser, pendingDel, expiredAcc, external, expiredRole, otherTenantOwner, noMembership, missing :=
		uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, f := range []fixture{
		{id: owner, home: tenant, email: "owner@example.com", active: true, seat: "member", status: "active"},
		{id: adm, home: tenant, email: "admin@example.com", active: true, seat: "member", status: "active"},
		{id: billing, home: tenant, email: "billing@example.com", active: true, seat: "member", status: "active"},
		{id: member, home: tenant, email: "member@example.com", active: true, seat: "employee", status: "active"},
		{id: inactiveUser, home: tenant, email: "off@example.com", active: false, seat: "member", status: "active"},
		{id: pendingDel, home: tenant, email: "del@example.com", active: true, deleting: true, seat: "member", status: "active"},
		{id: expiredAcc, home: tenant, email: "exp@example.com", active: true, seat: "employee", status: "active", expired: true},
		{id: external, home: partner, email: "acct@partner.example", active: true, seat: "external", status: "active"},
		{id: expiredRole, home: tenant, email: "oldadmin@example.com", active: true, seat: "member", status: "active"},
		{id: otherTenantOwner, home: otherTenant, email: "o2@example.com", active: true, seat: "member", status: "active"},
		{id: noMembership, home: tenant, email: "nomem@example.com", active: true},
	} {
		ct, err := enc.EncryptForTenant(f.home, f.email)
		require.NoError(t, err)
		var del *time.Time
		if f.deleting {
			now := time.Now()
			del = &now
		}
		_, err = pool.Exec(ctx, `INSERT INTO iam_users(id,tenant_id,email,is_active,deletion_scheduled_at) VALUES($1,$2,$3,$4,$5)`, f.id, f.home, ct, f.active, del)
		require.NoError(t, err)
		if f.seat == "" {
			continue
		}
		var exp *time.Time
		if f.expired {
			past := time.Now().Add(-time.Hour)
			exp = &past
		}
		mt := tenant
		if f.id == otherTenantOwner {
			mt = otherTenant
		}
		_, err = pool.Exec(ctx, `INSERT INTO iam_user_memberships(tenant_id,user_id,seat_class,status,access_expires_at) VALUES($1,$2,$3,$4,$5)`, mt, f.id, f.seat, f.status, exp)
		require.NoError(t, err)
	}
	grant := func(u, r uuid.UUID, exp *time.Time) {
		_, err := pool.Exec(ctx, `INSERT INTO iam_user_roles(user_id,role_id,expires_at) VALUES($1,$2,$3)`, u, r, exp)
		require.NoError(t, err)
	}
	past := time.Now().Add(-time.Hour)
	grant(owner, ownerRole, nil)
	grant(owner, adminRole, nil)
	grant(adm, adminRole, nil)
	grant(billing, billingRole, nil)
	grant(inactiveUser, adminRole, nil) // inactive role holder is not enumerated
	grant(expiredRole, adminRole, &past)
	grant(otherTenantOwner, otherOwnerRole, nil) // role of another tenant never leaks

	byID := func(rows []NotificationRecipientRow) map[uuid.UUID]NotificationRecipientRow {
		m := map[uuid.UUID]NotificationRecipientRow{}
		for _, r := range rows {
			m[r.UserID] = r
		}
		return m
	}

	// Role enumeration only.
	rows, err := repo.ListNotificationRecipients(ctx, tenant, nil, []string{"owner", "admin", "billing"})
	require.NoError(t, err)
	got := byID(rows)
	require.Len(t, got, 3)
	require.Equal(t, []string{"admin", "owner"}, got[owner].SystemRoles)
	require.Equal(t, "owner@example.com", got[owner].Email)
	require.True(t, got[owner].Active)
	require.Equal(t, []string{"admin"}, got[adm].SystemRoles)
	require.Equal(t, []string{"billing"}, got[billing].SystemRoles)
	require.Equal(t, "internal", got[billing].MembershipKind)

	// Requested ids union roles; inactive/missing requested ids come back active=false.
	rows, err = repo.ListNotificationRecipients(ctx, tenant,
		[]uuid.UUID{member, inactiveUser, pendingDel, expiredAcc, external, noMembership, missing, otherTenantOwner, owner},
		[]string{"owner"})
	require.NoError(t, err)
	got = byID(rows)
	require.Len(t, got, 9)
	require.True(t, got[member].Active)
	require.Equal(t, "internal", got[member].MembershipKind)
	require.Empty(t, got[member].SystemRoles)
	for _, id := range []uuid.UUID{inactiveUser, pendingDel, expiredAcc, noMembership, missing, otherTenantOwner} {
		require.False(t, got[id].Active, id.String())
		require.Empty(t, got[id].Email, id.String())
		require.NotNil(t, got[id].SystemRoles)
	}
	require.Equal(t, "", got[noMembership].MembershipKind)
	require.Equal(t, "", got[otherTenantOwner].MembershipKind)
	require.Equal(t, "external", got[external].MembershipKind)
	require.True(t, got[external].Active)
	require.Equal(t, "acct@partner.example", got[external].Email) // decrypted with the user's home tenant key
	require.Equal(t, []string{"owner"}, got[owner].SystemRoles)

	// Deactivated membership is inactive.
	_, err = pool.Exec(ctx, `UPDATE iam_user_memberships SET status='deactivated' WHERE tenant_id=$1 AND user_id=$2`, tenant, member)
	require.NoError(t, err)
	rows, err = repo.ListNotificationRecipients(ctx, tenant, []uuid.UUID{member}, nil)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.False(t, rows[0].Active)
}

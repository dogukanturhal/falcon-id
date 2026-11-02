// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/testsupport"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

type revokeFaultClient struct {
	*fakeSpiceDB
	mu         sync.Mutex
	fail       bool
	failWrites bool
	deletes    int
}

func (f *revokeFaultClient) DeleteUserRole(ctx context.Context, tenant, user, role uuid.UUID) (string, error) {
	f.mu.Lock()
	f.deletes++
	fail := f.fail
	f.mu.Unlock()
	if fail {
		return "", errors.New("SpiceDB unavailable")
	}
	return f.fakeSpiceDB.DeleteUserRole(ctx, tenant, user, role)
}
func (f *revokeFaultClient) WriteUserRole(ctx context.Context, tenant, user, role uuid.UUID) (string, error) {
	if f.failWrites {
		return "", errors.New("SpiceDB write unavailable")
	}
	return f.WriteUserRoleUntil(ctx, tenant, user, role, time.Time{})
}
func (f *revokeFaultClient) recover() { f.mu.Lock(); f.fail = false; f.mu.Unlock() }

// Only PII user lookup is adapted to this minimal schema. Role mutation is
// the real repository transaction, not a mock of its outbox implementation.
type revokeUserRepo struct {
	*repositories.UserRepository
	pool *pgxpool.Pool
}

func (r *revokeUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	u := &models.User{ID: id}
	err := r.pool.QueryRow(ctx, `SELECT tenant_id FROM iam_users WHERE id=$1`, id).Scan(&u.TenantID)
	return u, err
}

func revokePostgres(t *testing.T) (*pgxpool.Pool, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	schema := "revoke_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		p.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	})
	_, err = p.Exec(ctx, `CREATE TABLE iam_users(id uuid PRIMARY KEY, tenant_id uuid NOT NULL);
	 CREATE TABLE iam_roles(id uuid PRIMARY KEY, tenant_id uuid NOT NULL, name text DEFAULT 'role',
	 display_name text DEFAULT 'Role', description text, is_system boolean DEFAULT false,
	 is_default boolean DEFAULT false, priority integer DEFAULT 1, created_at timestamptz DEFAULT now(),
	 updated_at timestamptz DEFAULT now(), created_by uuid, updated_by uuid);
	 CREATE TABLE iam_user_roles(user_id uuid NOT NULL REFERENCES iam_users(id), role_id uuid NOT NULL REFERENCES iam_roles(id),
	 assigned_by uuid, expires_at timestamptz, PRIMARY KEY(user_id,role_id));
	 CREATE TABLE iam_jit_access_grants(id uuid PRIMARY KEY, user_id uuid NOT NULL, role_id uuid NOT NULL,
	 tenant_id uuid NOT NULL, justification text DEFAULT '', requested_at timestamptz DEFAULT now(),
	 approved_by uuid, approved_at timestamptz, starts_at timestamptz DEFAULT now(), expires_at timestamptz NOT NULL,
	 status text NOT NULL, created_at timestamptz DEFAULT now());`+testsupport.PermissionOutboxDDL)
	require.NoError(t, err)
	tenant, user, role := uuid.New(), uuid.New(), uuid.New()
	_, err = p.Exec(ctx, `INSERT INTO iam_users VALUES($1,$2)`, user, tenant)
	require.NoError(t, err)
	_, err = p.Exec(ctx, `INSERT INTO iam_roles(id,tenant_id) VALUES($1,$2)`, role, tenant)
	require.NoError(t, err)
	_, err = p.Exec(ctx, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2)`, user, role)
	require.NoError(t, err)
	return p, tenant, user, role
}

func revokeClientAndService(p *pgxpool.Pool, tenant, user, role uuid.UUID) (*revokeFaultClient, *RoleRevokeDrainer, *UserService) {
	f := &revokeFaultClient{fakeSpiceDB: newFakeSpiceDB(), fail: true}
	_, _ = f.WriteUserRole(context.Background(), tenant, user, role)
	d := NewRoleRevokeDrainer(p, f, zap.NewNop())
	s := &UserService{userRepo: &revokeUserRepo{UserRepository: repositories.NewUserRepository(p), pool: p}, spicedbClient: f, roleRevokes: d}
	return f, d, s
}

func assertRevokePermission(t *testing.T, f *revokeFaultClient, tenant, user, role uuid.UUID, allowed bool) {
	t.Helper()
	engine := NewAuthorizationEngine(nil, nil, nil, nil, f, &config.Config{})
	result, err := engine.CheckResourcePermission(context.Background(), ResourcePermissionRequest{
		TenantID: tenant, UserID: user, ResourceType: "role", ResourceID: role.String(), Action: "member"})
	require.NoError(t, err)
	require.Equal(t, allowed, result.Allowed)
}

func assertPendingRevoke(t *testing.T, p *pgxpool.Pool, tenant, user, role uuid.UUID) {
	t.Helper()
	var status, resource, subject, relation, op string
	var attempts int
	var next time.Time
	var lastError *string
	require.NoError(t, p.QueryRow(context.Background(), `SELECT status,resource_id,subject_id,relation,operation,retry_count,next_retry_at,error_message FROM iam_permission_outbox`).Scan(&status, &resource, &subject, &relation, &op, &attempts, &next, &lastError))
	require.Equal(t, "failed", status)
	require.Equal(t, tenant.String()+"/"+role.String(), resource)
	require.Equal(t, tenant.String()+"/"+user.String(), subject)
	require.Equal(t, "member", relation)
	require.Equal(t, "delete", op)
	require.Greater(t, attempts, 0)
	require.NotNil(t, lastError)
	require.LessOrEqual(t, time.Until(next), 60*time.Second)
}

func makeRevokeDue(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	_, err := p.Exec(context.Background(), `UPDATE iam_permission_outbox SET next_retry_at=now()-interval '1 second' WHERE status='failed'`)
	require.NoError(t, err)
}

func TestRoleRevokePostgres_OutageRecovery(t *testing.T) {
	p, tenant, user, role := revokePostgres(t)
	f, d, s := revokeClientAndService(p, tenant, user, role)
	require.NoError(t, s.SetUserRoles(context.Background(), user, nil, nil))
	var n int
	require.NoError(t, p.QueryRow(context.Background(), `SELECT count(*) FROM iam_user_roles`).Scan(&n))
	require.Zero(t, n)
	assertPendingRevoke(t, p, tenant, user, role)
	assertRevokePermission(t, f, tenant, user, role, true)
	// The generic finite-retry worker cannot steal these security rows.
	events, err := repositories.NewOutboxRepository(p).GetPendingEvents(context.Background(), 100)
	require.NoError(t, err)
	require.Empty(t, events)
	// Not-due rows are not retried on each tick.
	require.NoError(t, d.Drain(context.Background(), user))
	require.Equal(t, 1, f.deletes)
	f.recover()
	// Restarted drainer picks up the persisted row at its real next_retry_at.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); NewRoleRevokeDrainer(p, f, zap.NewNop()).Start(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	require.Eventually(t, func() bool {
		var count int
		_ = p.QueryRow(context.Background(), `SELECT count(*) FROM iam_permission_outbox WHERE status='completed' AND processed_at IS NOT NULL AND error_message IS NULL`).Scan(&count)
		return count == 1
	}, 5*time.Second, 50*time.Millisecond)
	assertRevokePermission(t, f, tenant, user, role, false)
}

func TestRoleRevokePostgres_ImmediateSuccess(t *testing.T) {
	p, tenant, user, role := revokePostgres(t)
	f, _, s := revokeClientAndService(p, tenant, user, role)
	f.recover()
	require.NoError(t, s.SetUserRoles(context.Background(), user, nil, nil))
	assertRevokePermission(t, f, tenant, user, role, false)
	var done bool
	require.NoError(t, p.QueryRow(context.Background(), `SELECT status='completed' AND processed_at IS NOT NULL AND next_retry_at IS NULL FROM iam_permission_outbox`).Scan(&done))
	require.True(t, done)
}

func TestRoleRevokePostgres_GrantStillBestEffort(t *testing.T) {
	p, tenant, user, role := revokePostgres(t)
	f, _, s := revokeClientAndService(p, tenant, user, role)
	f.failWrites = true
	added := uuid.New()
	_, err := p.Exec(context.Background(), `INSERT INTO iam_roles(id,tenant_id) VALUES($1,$2)`, added, tenant)
	require.NoError(t, err)
	r := &MockRoleRepository{}
	r.On("GetByIDAndTenant", mock.Anything, added, tenant).Return(&models.Role{ID: added, TenantID: tenant}, nil)
	r.On("GetByIDAndTenant", mock.Anything, role, tenant).Return(&models.Role{ID: role, TenantID: tenant}, nil)
	s.roleRepo = r
	require.NoError(t, s.SetUserRoles(context.Background(), user, []uuid.UUID{role, added}, nil))
	var assigned bool
	require.NoError(t, p.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM iam_user_roles WHERE role_id=$1)`, added).Scan(&assigned))
	require.True(t, assigned)
	assertRevokePermission(t, f, tenant, user, added, false)
	var n int
	require.NoError(t, p.QueryRow(context.Background(), `SELECT count(*) FROM iam_permission_outbox`).Scan(&n))
	require.Zero(t, n, "grant failures do not enter the delete outbox")
}

func TestRoleRevokePostgres_RetriesNeverExhaust(t *testing.T) {
	p, tenant, user, role := revokePostgres(t)
	f, d, s := revokeClientAndService(p, tenant, user, role)
	require.NoError(t, s.SetUserRoles(context.Background(), user, nil, nil))
	_, err := p.Exec(context.Background(), `UPDATE iam_permission_outbox SET max_retries=1`)
	require.NoError(t, err)
	for i := 0; i < 9; i++ {
		makeRevokeDue(t, p)
		require.NoError(t, d.Drain(context.Background(), user))
		assertPendingRevoke(t, p, tenant, user, role)
	}
	require.Equal(t, 10, f.deletes)
	f.recover()
	makeRevokeDue(t, p)
	require.NoError(t, d.Drain(context.Background(), user))
	assertRevokePermission(t, f, tenant, user, role, false)
}

func TestRoleRevokePostgres_AtomicRollback(t *testing.T) {
	p, _, user, _ := revokePostgres(t)
	_, err := p.Exec(context.Background(), `ALTER TABLE iam_permission_outbox ADD CONSTRAINT fail_enqueue CHECK(false) NOT VALID`)
	require.NoError(t, err)
	require.Error(t, repositories.NewUserRepository(p).AssignRoles(context.Background(), user, nil, nil))
	var n int
	require.NoError(t, p.QueryRow(context.Background(), `SELECT count(*) FROM iam_user_roles`).Scan(&n))
	require.Equal(t, 1, n)
	require.NoError(t, p.QueryRow(context.Background(), `SELECT count(*) FROM iam_permission_outbox`).Scan(&n))
	require.Zero(t, n)
}

func TestRoleRevokePostgres_GrantAndLiveJITUnchanged(t *testing.T) {
	p, tenant, user, role := revokePostgres(t)
	f, _, s := revokeClientAndService(p, tenant, user, role)
	added := uuid.New()
	_, err := p.Exec(context.Background(), `INSERT INTO iam_roles(id,tenant_id) VALUES($1,$2)`, added, tenant)
	require.NoError(t, err)
	r := &MockRoleRepository{}
	r.On("GetByIDAndTenant", mock.Anything, added, tenant).Return(&models.Role{ID: added, TenantID: tenant}, nil)
	r.On("GetByIDAndTenant", mock.Anything, role, tenant).Return(&models.Role{ID: role, TenantID: tenant}, nil)
	s.roleRepo = r
	require.NoError(t, s.SetUserRoles(context.Background(), user, []uuid.UUID{role, added}, nil))
	assertRevokePermission(t, f, tenant, user, added, true)
	var n int
	require.NoError(t, p.QueryRow(context.Background(), `SELECT count(*) FROM iam_permission_outbox`).Scan(&n))
	require.Zero(t, n)
	_, err = p.Exec(context.Background(), `UPDATE iam_user_roles SET expires_at=now()+interval '1 hour' WHERE role_id=$1`, role)
	require.NoError(t, err)
	require.NoError(t, s.SetUserRoles(context.Background(), user, []uuid.UUID{added}, nil))
	assertRevokePermission(t, f, tenant, user, role, true)
	require.NoError(t, p.QueryRow(context.Background(), `SELECT count(*) FROM iam_permission_outbox`).Scan(&n))
	require.Zero(t, n)
}

func TestRoleRevokePostgres_RegrantSupersedesOldDelete(t *testing.T) {
	p, tenant, user, role := revokePostgres(t)
	f, d, s := revokeClientAndService(p, tenant, user, role)
	require.NoError(t, s.SetUserRoles(context.Background(), user, nil, nil))
	require.NoError(t, repositories.NewUserRepository(p).AssignRoles(context.Background(), user, []uuid.UUID{role}, nil))
	f.recover()
	makeRevokeDue(t, p)
	require.NoError(t, d.Drain(context.Background(), user))
	assertRevokePermission(t, f, tenant, user, role, true)
	require.Equal(t, 1, f.deletes, "stale revoke must not delete a new grant")
}

func TestJITRevokePostgres_OutageRecovery(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		name := "revoke"
		if expiry {
			name = "expiry"
		}
		t.Run(name, func(t *testing.T) {
			p, tenant, user, role := revokePostgres(t)
			f, d, _ := revokeClientAndService(p, tenant, user, role)
			expires := time.Now().Add(time.Hour)
			if expiry {
				expires = time.Now().Add(-time.Minute)
			}
			grant := uuid.New()
			_, err := p.Exec(context.Background(), `UPDATE iam_user_roles SET expires_at=$1`, expires)
			require.NoError(t, err)
			_, err = p.Exec(context.Background(), `INSERT INTO iam_jit_access_grants(id,user_id,role_id,tenant_id,expires_at,status) VALUES($1,$2,$3,$4,$5,'active')`, grant, user, role, tenant, expires)
			require.NoError(t, err)
			s := NewJITAccessService(repositories.NewJITAccessRepository(p), nil, nil, repositories.NewUserRepository(p), f, nil, zap.NewNop())
			s.SetRoleRevokeDrainer(d)
			status := "revoked"
			if expiry {
				require.NoError(t, s.ExpireGrants(context.Background()))
				status = "expired"
			} else {
				require.NoError(t, s.RevokeGrant(context.Background(), grant, uuid.New(), tenant))
			}
			var actual string
			var n int
			require.NoError(t, p.QueryRow(context.Background(), `SELECT status FROM iam_jit_access_grants WHERE id=$1`, grant).Scan(&actual))
			require.Equal(t, status, actual)
			require.NoError(t, p.QueryRow(context.Background(), `SELECT count(*) FROM iam_user_roles`).Scan(&n))
			require.Zero(t, n)
			assertPendingRevoke(t, p, tenant, user, role)
			assertRevokePermission(t, f, tenant, user, role, true)
			f.recover()
			makeRevokeDue(t, p)
			require.NoError(t, d.Drain(context.Background(), user))
			assertRevokePermission(t, f, tenant, user, role, false)
		})
	}
}

func TestRoleRevokeRetryDelay(t *testing.T) {
	for attempt := 1; attempt < 100; attempt++ {
		delay := repositories.RoleRevokeRetryDelay(attempt)
		require.Positive(t, delay)
		require.LessOrEqual(t, delay, 60*time.Second)
	}
	require.Equal(t, 2*time.Second, repositories.RoleRevokeRetryDelay(1))
	require.Equal(t, 60*time.Second, repositories.RoleRevokeRetryDelay(2147483647))
}

type failedJITActivationRepo struct {
	*repositories.JITAccessRepository
	revokeBeforeFailure bool
}

func (r *failedJITActivationRepo) Activate(ctx context.Context, id uuid.UUID) error {
	if r.revokeBeforeFailure {
		if err := r.UpdateStatus(ctx, id, models.JITAccessStatusRevoked); err != nil {
			return err
		}
	}
	return errors.New("activation persistence failed")
}

func TestJITRevokePostgres_ActivationCompensation(t *testing.T) {
	t.Run("persistence_failure", func(t *testing.T) { testJITActivationCompensation(t, false) })
	t.Run("concurrent_revoke", func(t *testing.T) { testJITActivationCompensation(t, true) })
}

func testJITActivationCompensation(t *testing.T, revokeBeforeFailure bool) {
	t.Helper()
	p, tenant, user, role := revokePostgres(t)
	f, d, _ := revokeClientAndService(p, tenant, user, role)
	// Activation can write SpiceDB before its PostgreSQL status write fails.
	// No time-boxed projection has been written yet, but deletion must survive.
	_, err := p.Exec(context.Background(), `DELETE FROM iam_user_roles`)
	require.NoError(t, err)
	grant := uuid.New()
	_, err = p.Exec(context.Background(), `INSERT INTO iam_jit_access_grants(id,user_id,role_id,tenant_id,expires_at,status)
		VALUES($1,$2,$3,$4,now()+interval '1 hour','approved')`, grant, user, role, tenant)
	require.NoError(t, err)
	r := &failedJITActivationRepo{JITAccessRepository: repositories.NewJITAccessRepository(p), revokeBeforeFailure: revokeBeforeFailure}
	s := NewJITAccessService(r, nil, nil, repositories.NewUserRepository(p), f, nil, zap.NewNop())
	s.SetRoleRevokeDrainer(d)
	require.ErrorContains(t, s.ActivateGrant(context.Background(), grant, tenant), "activation persistence failed")
	assertPendingRevoke(t, p, tenant, user, role)
	assertRevokePermission(t, f, tenant, user, role, true)
	var status string
	require.NoError(t, p.QueryRow(context.Background(), `SELECT status FROM iam_jit_access_grants`).Scan(&status))
	expected := "approved"
	if revokeBeforeFailure {
		expected = "revoked"
	}
	require.Equal(t, expected, status)
	f.recover()
	makeRevokeDue(t, p)
	require.NoError(t, d.Drain(context.Background(), user))
	assertRevokePermission(t, f, tenant, user, role, false)
}

func TestJITRevokePostgres_AtomicRollback(t *testing.T) {
	p, tenant, user, role := revokePostgres(t)
	grant := uuid.New()
	_, err := p.Exec(context.Background(), `UPDATE iam_user_roles SET expires_at=now()+interval '1 hour'`)
	require.NoError(t, err)
	_, err = p.Exec(context.Background(), `INSERT INTO iam_jit_access_grants(id,user_id,role_id,tenant_id,expires_at,status)
		VALUES($1,$2,$3,$4,now()+interval '1 hour','active')`, grant, user, role, tenant)
	require.NoError(t, err)
	_, err = p.Exec(context.Background(), `ALTER TABLE iam_permission_outbox ADD CONSTRAINT fail_enqueue CHECK(false) NOT VALID`)
	require.NoError(t, err)
	s := NewJITAccessService(repositories.NewJITAccessRepository(p), nil, nil, repositories.NewUserRepository(p), nil, nil, zap.NewNop())
	require.Error(t, s.RevokeGrant(context.Background(), grant, uuid.New(), tenant))
	var status string
	var n int
	require.NoError(t, p.QueryRow(context.Background(), `SELECT status FROM iam_jit_access_grants`).Scan(&status))
	require.Equal(t, "active", status)
	require.NoError(t, p.QueryRow(context.Background(), `SELECT count(*) FROM iam_user_roles`).Scan(&n))
	require.Equal(t, 1, n)
	require.NoError(t, p.QueryRow(context.Background(), `SELECT count(*) FROM iam_permission_outbox`).Scan(&n))
	require.Zero(t, n)
}

func TestRoleRevokePostgres_AcknowledgementFailureReplays(t *testing.T) {
	p, tenant, user, role := revokePostgres(t)
	f, d, s := revokeClientAndService(p, tenant, user, role)
	require.NoError(t, s.SetUserRoles(context.Background(), user, nil, nil))
	f.recover()
	makeRevokeDue(t, p)
	_, err := p.Exec(context.Background(), `ALTER TABLE iam_permission_outbox ADD CONSTRAINT fail_ack CHECK(status <> 'completed') NOT VALID`)
	require.NoError(t, err)
	require.Error(t, d.Drain(context.Background(), user))
	// SpiceDB succeeded but PostgreSQL acknowledgement failed. The claim
	// rolls back, so a restarted replica can safely replay the idempotent delete.
	assertRevokePermission(t, f, tenant, user, role, false)
	var status string
	require.NoError(t, p.QueryRow(context.Background(), `SELECT status FROM iam_permission_outbox`).Scan(&status))
	require.Equal(t, "failed", status)
	_, err = p.Exec(context.Background(), `ALTER TABLE iam_permission_outbox DROP CONSTRAINT fail_ack`)
	require.NoError(t, err)
	require.NoError(t, NewRoleRevokeDrainer(p, f, zap.NewNop()).Drain(context.Background(), user))
	require.NoError(t, p.QueryRow(context.Background(), `SELECT status FROM iam_permission_outbox`).Scan(&status))
	require.Equal(t, "completed", status)
	require.Equal(t, 3, f.deletes)
}

type blockingRevokeClient struct {
	*revokeFaultClient
	entered chan struct{}
	release chan struct{}
}

func (f *blockingRevokeClient) DeleteUserRole(ctx context.Context, tenant, user, role uuid.UUID) (string, error) {
	close(f.entered)
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-f.release:
	}
	return f.revokeFaultClient.DeleteUserRole(ctx, tenant, user, role)
}

func TestRoleRevokePostgres_ReplicaClaimsExclusive(t *testing.T) {
	p, tenant, user, role := revokePostgres(t)
	f, _, s := revokeClientAndService(p, tenant, user, role)
	require.NoError(t, s.SetUserRoles(context.Background(), user, nil, nil))
	f.recover()
	makeRevokeDue(t, p)
	blocking := &blockingRevokeClient{revokeFaultClient: f, entered: make(chan struct{}), release: make(chan struct{})}
	d1 := NewRoleRevokeDrainer(p, blocking, zap.NewNop())
	d2 := NewRoleRevokeDrainer(p, f, zap.NewNop())
	done := make(chan error, 1)
	go func() { done <- d1.Drain(context.Background(), user) }()
	select {
	case <-blocking.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first replica never claimed row")
	}
	err := d2.Drain(context.Background(), user)
	close(blocking.release)
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.Equal(t, 2, f.deletes, "only one successful replica delete after the original failed attempt")
	assertRevokePermission(t, f, tenant, user, role, false)
}

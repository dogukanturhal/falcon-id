// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

// ESS employee-account S2S handlers (R-HR WP-21) end to end against real PostgreSQL: the real 0002/0011/0013 DDL plus
// the verbatim 0021 migration, run as a NOBYPASSRLS role like production. SpiceDB is an in-process gRPC fake that
// records writes; the role template repositories are fakes that record which template keys were requested.
// TEST_DATABASE_URL is a superuser DSN of a throwaway database.

// fakeSpiceDB accepts every write (recording it) and answers role lookups empty.
type fakeSpiceDB struct {
	v1.UnimplementedPermissionsServiceServer
	mu      sync.Mutex
	updates []*v1.RelationshipUpdate
}

func (f *fakeSpiceDB) WriteRelationships(_ context.Context, req *v1.WriteRelationshipsRequest) (*v1.WriteRelationshipsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates = append(f.updates, req.Updates...)
	return &v1.WriteRelationshipsResponse{WrittenAt: &v1.ZedToken{Token: "t"}}, nil
}

func (f *fakeSpiceDB) LookupResources(*v1.LookupResourcesRequest, grpc.ServerStreamingServer[v1.LookupResourcesResponse]) error {
	return nil
}

func (f *fakeSpiceDB) count(op v1.RelationshipUpdate_Operation, resourceType, relation string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, u := range f.updates {
		if u.Operation == op && u.Relationship.Resource.ObjectType == resourceType && u.Relationship.Relation == relation {
			n++
		}
	}
	return n
}

// fakeTemplateRoleRepo implements the provisioner's role repository in memory.
// The role row is also written to iam_roles so the tenant-scoped role revocation sees it, as with the real repository.
type fakeTemplateRoleRepo struct {
	pool  *pgxpool.Pool
	roles map[string]*models.Role
}

func (f *fakeTemplateRoleRepo) CreateFromTemplate(ctx context.Context, role *models.Role) error {
	if _, err := f.pool.Exec(ctx, `INSERT INTO iam_roles (id, tenant_id, name) VALUES ($1, $2, $3)`, role.ID, role.TenantID, role.Name); err != nil {
		return err
	}
	f.roles[role.TenantID.String()+"/"+*role.TemplateKey] = role
	return nil
}

func (f *fakeTemplateRoleRepo) GetByTemplateKeyForTenant(_ context.Context, tenantID uuid.UUID, key string) (*models.Role, error) {
	return f.roles[tenantID.String()+"/"+key], nil
}

func (f *fakeTemplateRoleRepo) ListRolesByTemplateKey(context.Context, string) ([]models.Role, error) {
	return nil, nil
}

func (f *fakeTemplateRoleRepo) ListTemplateDerivedRolesByModule(context.Context, uuid.UUID, string) ([]models.Role, error) {
	return nil, nil
}

func (f *fakeTemplateRoleRepo) SetTemplateVersion(context.Context, uuid.UUID, int) error { return nil }

func (f *fakeTemplateRoleRepo) AssignPermissions(context.Context, uuid.UUID, []uuid.UUID, *uuid.UUID) error {
	return nil
}
func (f *fakeTemplateRoleRepo) GrantPermissionsByName(context.Context, uuid.UUID, []string) error {
	return nil
}
func (f *fakeTemplateRoleRepo) GetRolePermissions(context.Context, uuid.UUID) ([]models.Permission, error) {
	return nil, nil
}
func (f *fakeTemplateRoleRepo) ListActiveHolderIDs(context.Context, uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}

// fakeTemplateRepo serves any key as an active, permission-less template and records the keys asked for.
type fakeTemplateRepo struct{ requested []string }

func (f *fakeTemplateRepo) GetLatestByKey(_ context.Context, key string) (*models.RoleTemplate, error) {
	f.requested = append(f.requested, key)
	return &models.RoleTemplate{ID: uuid.New(), Key: key, Version: 1, Module: "hr", Name: "Calisan", IsActive: true}, nil
}

func (f *fakeTemplateRepo) ListLatestActiveByModules(context.Context, []string) ([]models.RoleTemplate, error) {
	return nil, nil
}

// fakePermissionRepo satisfies the provisioner's permission catalog with an empty catalog.
type fakePermissionRepo struct{}

func (fakePermissionRepo) List(context.Context) ([]models.Permission, error) { return nil, nil }
func (fakePermissionRepo) ListByModules(context.Context, []string) ([]models.Permission, error) {
	return nil, nil
}
func (fakePermissionRepo) GetModules(context.Context) ([]string, error) { return nil, nil }
func (fakePermissionRepo) GetUserPermissionIDs(context.Context, uuid.UUID, uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}
func (fakePermissionRepo) GetUserPermissionNames(context.Context, uuid.UUID, uuid.UUID) ([]string, error) {
	return nil, nil
}
func (fakePermissionRepo) GetPermissionNamesByIDs(context.Context, []uuid.UUID) (map[uuid.UUID]string, error) {
	return nil, nil
}
func (fakePermissionRepo) GetByID(context.Context, uuid.UUID) (*models.Permission, error) {
	return nil, nil
}

// fakeUserRoleRepo and fakeRealmResolver are the UserService collaborators the create path needs.
type fakeUserRoleRepo struct{}

func (fakeUserRoleRepo) GetByID(context.Context, uuid.UUID) (*models.Role, error) { return nil, nil }
func (fakeUserRoleRepo) GetByIDAndTenant(context.Context, uuid.UUID, uuid.UUID) (*models.Role, error) {
	return nil, nil
}
func (fakeUserRoleRepo) GetDefaultRoles(context.Context, uuid.UUID) ([]models.Role, error) {
	return nil, nil
}
func (fakeUserRoleRepo) GetMaxPriorityForUser(context.Context, uuid.UUID, uuid.UUID) (int, error) {
	return 0, nil
}

type fakeRealmResolver struct{ id uuid.UUID }

func (f fakeRealmResolver) GetTenantRealm(context.Context, uuid.UUID) (*models.Realm, error) {
	return &models.Realm{ID: f.id}, nil
}

type fakeUserAudit struct{}

func (fakeUserAudit) LogUserAction(context.Context, uuid.UUID, *uuid.UUID, *uuid.UUID, string, bool, map[string]interface{}) {
}

type employeeFixture struct {
	admin       *pgx.Conn
	pool        *pgxpool.Pool // NOBYPASSRLS application role
	router      *gin.Engine
	handler     *handlers.TeamInvitationHandler
	userService *services.UserService
	memberships *repositories.UserMembershipRepository
	spice       *fakeSpiceDB
	templ       *fakeTemplateRepo
	users       *repositories.UserRepository
	tenant      uuid.UUID
	realmID     uuid.UUID
}

func newEmployeeFixture(t *testing.T) *employeeFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	logger.Log = zap.NewNop()
	ctx := context.Background()

	base := setupTeamInvitationHandlerSchema(t, dsn)
	var schema string
	require.NoError(t, base.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema))
	sch := pgx.Identifier{schema}.Sanitize()
	role := "empacct_app_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	rol := pgx.Identifier{role}.Sanitize()

	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = admin.Close(ctx) })
	migration, err := os.ReadFile("../migrations/0021_iam_employee_seat_class.sql")
	require.NoError(t, err)
	kioskMigration, err := os.ReadFile("../migrations/0022_iam_kiosk_seat_class.sql")
	require.NoError(t, err)
	tx, err := admin.Begin(ctx)
	require.NoError(t, err)
	for _, stmt := range []string{
		"SET LOCAL search_path = " + sch,
		// The helper's minimal iam_users, widened to every column UserRepository reads and writes.
		`ALTER TABLE iam_users
			ADD COLUMN realm_id uuid, ADD COLUMN email text NOT NULL DEFAULT '', ADD COLUMN email_hash text, ADD COLUMN password_hash text,
			ADD COLUMN first_name text, ADD COLUMN last_name text, ADD COLUMN display_name text, ADD COLUMN phone text,
			ADD COLUMN department text, ADD COLUMN title text, ADD COLUMN avatar_url text,
			ADD COLUMN federation_type text, ADD COLUMN federation_id text, ADD COLUMN federation_source text,
			ADD COLUMN is_email_verified boolean NOT NULL DEFAULT false, ADD COLUMN is_locked boolean NOT NULL DEFAULT false,
			ADD COLUMN lock_reason text, ADD COLUMN locked_at timestamptz, ADD COLUMN locked_until timestamptz,
			ADD COLUMN mfa_enabled boolean NOT NULL DEFAULT false, ADD COLUMN mfa_secret text, ADD COLUMN mfa_type text,
			ADD COLUMN mfa_totp_enabled boolean NOT NULL DEFAULT false, ADD COLUMN mfa_email_enabled boolean NOT NULL DEFAULT false,
			ADD COLUMN mfa_preferred_method text, ADD COLUMN mfa_enrollment_first_prompted_at timestamptz,
			ADD COLUMN mfa_enrollment_deadline timestamptz, ADD COLUMN mfa_enrollment_skip_count integer NOT NULL DEFAULT 0,
			ADD COLUMN password_changed_at timestamptz, ADD COLUMN must_change_password boolean NOT NULL DEFAULT false,
			ADD COLUMN failed_login_attempts integer NOT NULL DEFAULT 0, ADD COLUMN last_failed_login_at timestamptz,
			ADD COLUMN last_login_at timestamptz, ADD COLUMN last_login_ip text,
			ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now(), ADD COLUMN created_by uuid, ADD COLUMN updated_by uuid`,
		`CREATE TABLE iam_roles(id uuid PRIMARY KEY, tenant_id uuid NOT NULL, name text NOT NULL DEFAULT '', display_name text NOT NULL DEFAULT '',
			description text NOT NULL DEFAULT '', is_system boolean NOT NULL DEFAULT false, is_default boolean NOT NULL DEFAULT false,
			priority integer NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
			created_by uuid, updated_by uuid)`,
		`CREATE TABLE iam_user_roles(user_id uuid NOT NULL, role_id uuid NOT NULL, assigned_by uuid, expires_at timestamptz, PRIMARY KEY (user_id, role_id))`,
		`CREATE TABLE iam_sessions(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL, is_active boolean NOT NULL DEFAULT true,
			ended_at timestamptz, end_reason text)`,
		`CREATE TABLE iam_oauth_tokens(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid, user_id uuid, token_type text NOT NULL DEFAULT 'access_token', refresh_token text, is_revoked boolean NOT NULL DEFAULT false, revoked_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now(), idp_session_id uuid, token_family_id uuid, session_id uuid)`,
		string(migration),
		string(kioskMigration),
		"CREATE ROLE " + rol + " NOLOGIN NOSUPERUSER NOBYPASSRLS",
		"GRANT USAGE ON SCHEMA " + sch + " TO " + rol,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA " + sch + " TO " + rol,
	} {
		_, err = tx.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	require.NoError(t, tx.Commit(ctx))
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP OWNED BY "+rol)
		_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+rol)
	})

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+rol)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	spice := &fakeSpiceDB{}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	v1.RegisterPermissionsServiceServer(srv, spice)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	sc, err := spicedb.NewClient(ctx, &config.Config{SpiceDBEnabled: true, SpiceDBEndpoint: lis.Addr().String(), SpiceDBToken: "test-token", SpiceDBInsecure: true}, nil)
	require.NoError(t, err)
	bootstrap := services.NewTenantBootstrapService(sc)

	enc, err := crypto.NewEncryptionService("test-unit-encryption-key-32bytes")
	require.NoError(t, err)
	users := repositories.NewUserRepository(pool)
	users.SetEncryptionService(enc)
	memberships := repositories.NewUserMembershipRepository(pool)

	templ := &fakeTemplateRepo{}
	provisioner := services.NewTemplateRoleProvisioner(&fakeTemplateRoleRepo{pool: pool, roles: map[string]*models.Role{}}, templ, fakePermissionRepo{}, nil)
	realmID := uuid.New()
	userService := services.NewUserService(&config.Config{QuotaEnforcementEnabled: true}, users, fakeUserRoleRepo{}, nil, fakeUserAudit{})
	userService.SetRealmResolver(fakeRealmResolver{id: realmID})

	h := handlers.NewTeamInvitationHandler(nil, users, nil, nil, repositories.NewTeamInvitationRepository(pool), zap.NewNop())
	h.SetSeatRepositories(memberships, repositories.NewSeatCounterRepository(pool))
	h.SetTenantBootstrap(bootstrap)
	h.SetEmployeeAccountServices(userService, provisioner, nil, services.NewEmployeeAccessService(users, memberships, bootstrap, zap.NewNop()))

	f := &employeeFixture{admin: admin, pool: pool, router: employeeAccountRouter(h, false), handler: h, userService: userService, memberships: memberships, spice: spice, templ: templ, users: users, realmID: realmID, tenant: uuid.New()}
	_, err = base.Exec(ctx, `INSERT INTO iam_tenants (id) VALUES ($1)`, f.tenant)
	require.NoError(t, err)
	return f
}

func (f *employeeFixture) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, json.NewEncoder(&buf).Encode(body))
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f *employeeFixture) provision(t *testing.T, email string) *httptest.ResponseRecorder {
	return f.do(t, http.MethodPost, "/internal/v1/tenants/"+f.tenant.String()+"/employee-accounts", gin.H{"email": email, "firstName": "Ada", "lastName": "Lovelace"})
}

func (f *employeeFixture) expiry(t *testing.T, userID uuid.UUID, expiresAt *time.Time) *httptest.ResponseRecorder {
	return f.do(t, http.MethodPut, "/internal/v1/tenants/"+f.tenant.String()+"/employee-accounts/"+userID.String()+"/access-expiry", gin.H{"expiresAt": expiresAt})
}

// scalar runs a single-value query as the table owner (RLS does not apply), for assertions.
func scalar[T any](t *testing.T, pool *pgxpool.Pool, query string, args ...any) T {
	t.Helper()
	var out T
	require.NoError(t, pool.QueryRow(context.Background(), query, args...).Scan(&out))
	return out
}

// seedMember inserts a seat-consuming member user with its membership row directly.
func (f *employeeFixture) seedMember(t *testing.T, email string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	user := &models.User{TenantID: f.tenant, RealmID: f.realmID, Username: email, Email: email, IsActive: true}
	require.NoError(t, f.users.Create(ctx, user))
	err := repositories.WithTenantScope(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO iam_user_memberships (tenant_id, user_id, seat_class, status) VALUES ($1, $2, 'member', 'active')`, f.tenant, user.ID)
		return err
	})
	require.NoError(t, err)
	return user.ID
}

func TestEmployeeAccountsPostgres_Provision_SeatFree_OnlyEmployeeTemplate(t *testing.T) {
	f := newEmployeeFixture(t)
	ctx := context.Background()

	w := f.provision(t, "Ada@Example.test")
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp struct {
		UserID    uuid.UUID `json:"userId"`
		SeatClass string    `json:"seatClass"`
		Created   bool      `json:"created"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.True(t, resp.Created)
	require.Equal(t, "employee", resp.SeatClass)

	// Employee-class membership, one role grant, and the hr:employee template is the only template ever instantiated.
	var class, status string
	require.NoError(t, repositories.WithTenantScope(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT seat_class, status FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`, f.tenant, resp.UserID).Scan(&class, &status)
	}))
	require.Equal(t, "employee", class)
	require.Equal(t, "active", status)
	require.Equal(t, 1, scalar[int](t, f.pool, `SELECT count(*) FROM iam_user_roles WHERE user_id = $1`, resp.UserID))
	require.Equal(t, []string{"hr:employee"}, f.templ.requested)
	require.Equal(t, 1, scalar[int](t, f.pool, `SELECT count(*) FROM iam_audit_log WHERE tenant_id = $1 AND action = 'employee_account_provisioned'`, f.tenant))

	// Seat-free: the tenant's seat counter never moved (no row, or zero).
	var used, pending int
	err := repositories.WithTenantScope(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(seats_used,0), COALESCE(seats_pending,0) FROM tenant_seat_counters WHERE tenant_id = $1`, f.tenant).Scan(&used, &pending)
	})
	if err == nil {
		require.Zero(t, used)
		require.Zero(t, pending)
	}

	// SpiceDB converged: tenant#member edge and the role membership.
	require.Equal(t, 1, f.spice.count(v1.RelationshipUpdate_OPERATION_TOUCH, "tenant", "member"))
	require.Equal(t, 1, f.spice.count(v1.RelationshipUpdate_OPERATION_TOUCH, "role", "member"))

	// A repeat call for the same e-mail is idempotent: 200, not created, nothing else written.
	w = f.provision(t, "ada@example.test")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.False(t, resp.Created)
	require.Equal(t, "employee", resp.SeatClass)
	require.Equal(t, 1, scalar[int](t, f.pool, `SELECT count(*) FROM iam_user_roles`))
}

func TestEmployeeAccountsPostgres_Provision_ExistingMember_Unchanged(t *testing.T) {
	f := newEmployeeFixture(t)
	ctx := context.Background()
	memberID := f.seedMember(t, "member@example.test")

	w := f.provision(t, "member@example.test")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		UserID    uuid.UUID `json:"userId"`
		SeatClass string    `json:"seatClass"`
		Created   bool      `json:"created"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, memberID, resp.UserID)
	require.False(t, resp.Created)
	require.Equal(t, "member", resp.SeatClass, "an existing seat-holder keeps its class")

	// Nothing was converted, granted, instantiated or written to SpiceDB.
	var class string
	require.NoError(t, repositories.WithTenantScope(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT seat_class FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`, f.tenant, memberID).Scan(&class)
	}))
	require.Equal(t, "member", class)
	require.Zero(t, scalar[int](t, f.pool, `SELECT count(*) FROM iam_user_roles`))
	require.Empty(t, f.templ.requested)
	require.Zero(t, scalar[int](t, f.pool, `SELECT count(*) FROM iam_audit_log WHERE action = 'employee_account_provisioned'`))
	require.Zero(t, f.spice.count(v1.RelationshipUpdate_OPERATION_TOUCH, "tenant", "member"))
}

func TestEmployeeAccountsPostgres_Expiry_NonEmployee_409(t *testing.T) {
	f := newEmployeeFixture(t)
	ctx := context.Background()
	memberID := f.seedMember(t, "member@example.test")

	past := time.Now().Add(-time.Hour)
	w := f.expiry(t, memberID, &past)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "not_employee_seat")

	// The member seat is untouched: still active, no expiry stored, user still active.
	var status string
	var expires *time.Time
	require.NoError(t, repositories.WithTenantScope(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, access_expires_at FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`, f.tenant, memberID).Scan(&status, &expires)
	}))
	require.Equal(t, "active", status)
	require.Nil(t, expires)
	require.True(t, scalar[bool](t, f.pool, `SELECT is_active FROM iam_users WHERE id = $1`, memberID))

	// An unknown user is 404, not 409.
	w = f.expiry(t, uuid.New(), &past)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

func TestEmployeeAccountsPostgres_Expiry_Past_DeactivatesNow(t *testing.T) {
	f := newEmployeeFixture(t)
	ctx := context.Background()
	w := f.provision(t, "leaver@example.test")
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp struct {
		UserID uuid.UUID `json:"userId"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	_, err := f.pool.Exec(ctx, `INSERT INTO iam_sessions (user_id) VALUES ($1)`, resp.UserID)
	require.NoError(t, err)

	// A future expiry is only stored.
	future := time.Now().Add(24 * time.Hour)
	require.Equal(t, http.StatusNoContent, f.expiry(t, resp.UserID, &future).Code)
	require.True(t, scalar[bool](t, f.pool, `SELECT is_active FROM iam_users WHERE id = $1`, resp.UserID))

	// A past expiry deactivates immediately: user off, sessions ended, membership closed, roles gone, SpiceDB edges removed.
	past := time.Now().Add(-time.Minute)
	require.Equal(t, http.StatusNoContent, f.expiry(t, resp.UserID, &past).Code)
	require.False(t, scalar[bool](t, f.pool, `SELECT is_active FROM iam_users WHERE id = $1`, resp.UserID))
	require.Zero(t, scalar[int](t, f.pool, `SELECT count(*) FROM iam_sessions WHERE user_id = $1 AND is_active`, resp.UserID))
	var status string
	require.NoError(t, repositories.WithTenantScope(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`, f.tenant, resp.UserID).Scan(&status)
	}))
	require.Equal(t, "deactivated", status)
	require.Zero(t, scalar[int](t, f.pool, `SELECT count(*) FROM iam_user_roles WHERE user_id = $1`, resp.UserID))
	require.Equal(t, 1, scalar[int](t, f.pool, `SELECT count(*) FROM iam_audit_log WHERE action = 'employee_access_expired'`))
	require.GreaterOrEqual(t, f.spice.count(v1.RelationshipUpdate_OPERATION_DELETE, "tenant", "member"), 1)
}

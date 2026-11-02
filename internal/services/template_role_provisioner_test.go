// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// In-memory fakes for TemplateRoleProvisioner's dependencies. Mirrors
// acmeapp_role_provisioner_test.go's approach: fakes prove actual end-state
// (rows/grants that exist after a call), not just call counts.
// ---------------------------------------------------------------------------

type fakeTemplateRoleRepo struct {
	rolesByID       map[uuid.UUID]*models.Role
	rolesByTemplate map[string]map[uuid.UUID]*models.Role // templateKey -> tenantID -> role
	permsByRole     map[uuid.UUID][]uuid.UUID
	// catalog resolves permission names/IDs for GrantPermissionsByName and
	// GetRolePermissions; holders feeds ListActiveHolderIDs.
	catalog []models.Permission
	holders map[uuid.UUID][]uuid.UUID
}

func (f *fakeTemplateRoleRepo) GetRolePermissions(_ context.Context, roleID uuid.UUID) ([]models.Permission, error) {
	var out []models.Permission
	for _, id := range f.permsByRole[roleID] {
		for _, p := range f.catalog {
			if p.ID == id {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// GrantPermissionsByName is additive (ON CONFLICT DO NOTHING).
func (f *fakeTemplateRoleRepo) GrantPermissionsByName(_ context.Context, roleID uuid.UUID, names []string) error {
	for _, n := range names {
		for _, p := range f.catalog {
			if p.Name == n && !slices.Contains(f.permsByRole[roleID], p.ID) {
				f.permsByRole[roleID] = append(f.permsByRole[roleID], p.ID)
			}
		}
	}
	return nil
}

func (f *fakeTemplateRoleRepo) ListActiveHolderIDs(_ context.Context, roleID uuid.UUID) ([]uuid.UUID, error) {
	return f.holders[roleID], nil
}

func newFakeTemplateRoleRepo() *fakeTemplateRoleRepo {
	return &fakeTemplateRoleRepo{
		rolesByID:       map[uuid.UUID]*models.Role{},
		rolesByTemplate: map[string]map[uuid.UUID]*models.Role{},
		permsByRole:     map[uuid.UUID][]uuid.UUID{},
	}
}

func (f *fakeTemplateRoleRepo) CreateFromTemplate(_ context.Context, role *models.Role) error {
	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	f.rolesByID[role.ID] = role
	if role.TemplateKey != nil {
		byTenant, ok := f.rolesByTemplate[*role.TemplateKey]
		if !ok {
			byTenant = map[uuid.UUID]*models.Role{}
			f.rolesByTemplate[*role.TemplateKey] = byTenant
		}
		byTenant[role.TenantID] = role
	}
	return nil
}

func (f *fakeTemplateRoleRepo) GetByTemplateKeyForTenant(_ context.Context, tenantID uuid.UUID, templateKey string) (*models.Role, error) {
	byTenant, ok := f.rolesByTemplate[templateKey]
	if !ok {
		return nil, nil
	}
	role, ok := byTenant[tenantID]
	if !ok {
		return nil, nil
	}
	return role, nil
}

func (f *fakeTemplateRoleRepo) ListRolesByTemplateKey(_ context.Context, templateKey string) ([]models.Role, error) {
	byTenant, ok := f.rolesByTemplate[templateKey]
	if !ok {
		return nil, nil
	}
	var out []models.Role
	for _, r := range byTenant {
		out = append(out, *r)
	}
	return out, nil
}

func (f *fakeTemplateRoleRepo) ListTemplateDerivedRolesByModule(_ context.Context, tenantID uuid.UUID, module string) ([]models.Role, error) {
	var out []models.Role
	for _, r := range f.rolesByID {
		if r.TenantID == tenantID && r.Module != nil && *r.Module == module && r.TemplateKey != nil {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (f *fakeTemplateRoleRepo) SetTemplateVersion(_ context.Context, roleID uuid.UUID, version int) error {
	if r, ok := f.rolesByID[roleID]; ok {
		r.TemplateVersion = &version
	}
	return nil
}

func (f *fakeTemplateRoleRepo) AssignPermissions(_ context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, _ *uuid.UUID) error {
	// Mirrors RoleRepository.AssignPermissions: delete-then-insert, so a nil
	// or empty permissionIDs strips all grants.
	f.permsByRole[roleID] = permissionIDs
	return nil
}

type fakeTemplatePermissionRepo struct {
	catalog []models.Permission
}

func (f *fakeTemplatePermissionRepo) List(_ context.Context) ([]models.Permission, error) {
	return f.catalog, nil
}

func (f *fakeTemplatePermissionRepo) ListByModules(_ context.Context, modules []string) ([]models.Permission, error) {
	want := map[string]bool{}
	for _, m := range modules {
		want[m] = true
	}
	var out []models.Permission
	for _, p := range f.catalog {
		if want[p.Module] {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeTemplatePermissionRepo) GetModules(_ context.Context) ([]string, error) { return nil, nil }
func (f *fakeTemplatePermissionRepo) GetUserPermissionIDs(_ context.Context, _, _ uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}
func (f *fakeTemplatePermissionRepo) GetUserPermissionNames(_ context.Context, _, _ uuid.UUID) ([]string, error) {
	return nil, nil
}
func (f *fakeTemplatePermissionRepo) GetPermissionNamesByIDs(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]string, error) {
	return nil, nil
}

type fakeTemplateRepo struct {
	// latest active version per key
	latest map[string]*models.RoleTemplate
}

func newFakeTemplateRepo() *fakeTemplateRepo {
	return &fakeTemplateRepo{latest: map[string]*models.RoleTemplate{}}
}

func (f *fakeTemplateRepo) GetLatestByKey(_ context.Context, key string) (*models.RoleTemplate, error) {
	t, ok := f.latest[key]
	if !ok {
		return nil, nil
	}
	return t, nil
}

func (f *fakeTemplateRepo) ListLatestActiveByModules(_ context.Context, modules []string) ([]models.RoleTemplate, error) {
	want := map[string]bool{}
	for _, m := range modules {
		want[m] = true
	}
	var out []models.RoleTemplate
	for _, t := range f.latest {
		if t.IsActive && want[t.Module] {
			out = append(out, *t)
		}
	}
	return out, nil
}

func mkPerm(name string) models.Permission {
	idx := indexByteColon(name)
	return models.Permission{ID: uuid.New(), Module: name[:idx], Name: name}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestTemplateRoleProvisioner_InstantiateForTenant_IsIdempotent(t *testing.T) {
	roleRepo := newFakeTemplateRoleRepo()
	permRepo := &fakeTemplatePermissionRepo{catalog: []models.Permission{
		mkPerm("marketing:campaigns:send"),
		mkPerm("marketing:campaigns:read"),
	}}
	templateRepo := newFakeTemplateRepo()
	templateRepo.latest["marketing:campaign_manager"] = &models.RoleTemplate{
		Key: "marketing:campaign_manager", Version: 1, Module: "marketing",
		Name: "Campaign Manager", IsActive: true,
		Permissions: []string{"marketing:campaigns:send", "marketing:campaigns:read"},
	}

	p := NewTemplateRoleProvisioner(roleRepo, templateRepo, permRepo, nil)
	tenantID := uuid.New()

	role1, err := p.InstantiateForTenant(context.Background(), tenantID, "marketing:campaign_manager", "", nil)
	require.NoError(t, err)
	require.NotNil(t, role1)
	assert.Equal(t, 2, len(roleRepo.permsByRole[role1.ID]))

	// Second call must return the SAME role, not create a duplicate.
	role2, err := p.InstantiateForTenant(context.Background(), tenantID, "marketing:campaign_manager", "", nil)
	require.NoError(t, err)
	assert.Equal(t, role1.ID, role2.ID)
	assert.Len(t, roleRepo.rolesByID, 1)
}

func TestTemplateRoleProvisioner_ProvisionForModuleGrant_MaterializesAllModuleTemplates(t *testing.T) {
	roleRepo := newFakeTemplateRoleRepo()
	permRepo := &fakeTemplatePermissionRepo{catalog: []models.Permission{
		mkPerm("marketing:campaigns:send"),
		mkPerm("marketing:audience:read"),
	}}
	templateRepo := newFakeTemplateRepo()
	templateRepo.latest["marketing:campaign_manager"] = &models.RoleTemplate{
		Key: "marketing:campaign_manager", Version: 1, Module: "marketing",
		Name: "Campaign Manager", IsActive: true,
		Permissions: []string{"marketing:campaigns:send"},
	}
	templateRepo.latest["marketing:analyst"] = &models.RoleTemplate{
		Key: "marketing:analyst", Version: 1, Module: "marketing",
		Name: "Analyst", IsActive: true,
		Permissions: []string{"marketing:audience:read"},
	}

	p := NewTemplateRoleProvisioner(roleRepo, templateRepo, permRepo, nil)
	tenantID := uuid.New()

	count, err := p.ProvisionForModuleGrant(context.Background(), tenantID, "marketing")
	require.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Len(t, roleRepo.rolesByID, 2)
}

func TestTemplateRoleProvisioner_ReconcileVersionBump_AddsAndRemovesPermissions(t *testing.T) {
	roleRepo := newFakeTemplateRoleRepo()
	permRepo := &fakeTemplatePermissionRepo{catalog: []models.Permission{
		mkPerm("marketing:campaigns:send"),
		mkPerm("marketing:campaigns:read"),
		mkPerm("marketing:campaigns:archive"),
	}}
	templateRepo := newFakeTemplateRepo()
	templateRepo.latest["marketing:campaign_manager"] = &models.RoleTemplate{
		Key: "marketing:campaign_manager", Version: 1, Module: "marketing",
		Name: "Campaign Manager", IsActive: true,
		Permissions: []string{"marketing:campaigns:send", "marketing:campaigns:read"},
	}

	p := NewTemplateRoleProvisioner(roleRepo, templateRepo, permRepo, nil)
	tenantID := uuid.New()

	role, err := p.InstantiateForTenant(context.Background(), tenantID, "marketing:campaign_manager", "", nil)
	require.NoError(t, err)
	require.Len(t, roleRepo.permsByRole[role.ID], 2)

	// Bump to v2: drop "read", add "archive".
	templateRepo.latest["marketing:campaign_manager"] = &models.RoleTemplate{
		Key: "marketing:campaign_manager", Version: 2, Module: "marketing",
		Name: "Campaign Manager", IsActive: true,
		Permissions: []string{"marketing:campaigns:send", "marketing:campaigns:archive"},
	}

	reconciled, err := p.ReconcileVersionBump(context.Background(), "marketing:campaign_manager", 2)
	require.NoError(t, err)
	assert.Equal(t, 1, reconciled)

	grantedIDs := roleRepo.permsByRole[role.ID]
	require.Len(t, grantedIDs, 2)
	grantedNames := map[uuid.UUID]string{}
	for _, p := range permRepo.catalog {
		grantedNames[p.ID] = p.Name
	}
	var names []string
	for _, id := range grantedIDs {
		names = append(names, grantedNames[id])
	}
	assert.ElementsMatch(t, []string{"marketing:campaigns:send", "marketing:campaigns:archive"}, names)
	assert.Equal(t, 2, *roleRepo.rolesByID[role.ID].TemplateVersion)
}

func TestTemplateRoleProvisioner_ReconcileVersionBump_NeverTouchesTenantCustomRoles(t *testing.T) {
	roleRepo := newFakeTemplateRoleRepo()
	permRepo := &fakeTemplatePermissionRepo{catalog: []models.Permission{mkPerm("marketing:campaigns:send")}}
	templateRepo := newFakeTemplateRepo()
	templateRepo.latest["marketing:campaign_manager"] = &models.RoleTemplate{
		Key: "marketing:campaign_manager", Version: 1, Module: "marketing",
		Name: "Campaign Manager", IsActive: true,
		Permissions: []string{"marketing:campaigns:send"},
	}
	p := NewTemplateRoleProvisioner(roleRepo, templateRepo, permRepo, nil)
	tenantID := uuid.New()

	// A tenant-custom role: TemplateKey is nil.
	customRoleID := uuid.New()
	roleRepo.rolesByID[customRoleID] = &models.Role{ID: customRoleID, TenantID: tenantID, Name: "custom_role"}
	roleRepo.permsByRole[customRoleID] = []uuid.UUID{uuid.New()}
	customPermsBefore := len(roleRepo.permsByRole[customRoleID])

	// Bump the template version — ListRolesByTemplateKey only returns
	// template-derived roles for this key, so the custom role above must
	// never be visited.
	templateRepo.latest["marketing:campaign_manager"] = &models.RoleTemplate{
		Key: "marketing:campaign_manager", Version: 2, Module: "marketing",
		Name: "Campaign Manager", IsActive: true,
		Permissions: []string{"marketing:campaigns:send"},
	}
	_, err := p.ReconcileVersionBump(context.Background(), "marketing:campaign_manager", 2)
	require.NoError(t, err)

	assert.Equal(t, customPermsBefore, len(roleRepo.permsByRole[customRoleID]))
}

func TestTemplateRoleProvisioner_DisableForModuleRevoke_StripsGrantsButKeepsRole(t *testing.T) {
	roleRepo := newFakeTemplateRoleRepo()
	permRepo := &fakeTemplatePermissionRepo{catalog: []models.Permission{mkPerm("marketing:campaigns:send")}}
	templateRepo := newFakeTemplateRepo()
	templateRepo.latest["marketing:campaign_manager"] = &models.RoleTemplate{
		Key: "marketing:campaign_manager", Version: 1, Module: "marketing",
		Name: "Campaign Manager", IsActive: true,
		Permissions: []string{"marketing:campaigns:send"},
	}
	p := NewTemplateRoleProvisioner(roleRepo, templateRepo, permRepo, nil)
	tenantID := uuid.New()

	role, err := p.InstantiateForTenant(context.Background(), tenantID, "marketing:campaign_manager", "", nil)
	require.NoError(t, err)
	require.Len(t, roleRepo.permsByRole[role.ID], 1)

	disabled, err := p.DisableForModuleRevoke(context.Background(), tenantID, "marketing")
	require.NoError(t, err)
	assert.Equal(t, 1, disabled)

	// Role row and its template provenance survive; grants are gone.
	assert.Len(t, roleRepo.permsByRole[role.ID], 0)
	survivingRole, ok := roleRepo.rolesByID[role.ID]
	require.True(t, ok)
	require.NotNil(t, survivingRole.TemplateKey)
	assert.Equal(t, "marketing:campaign_manager", *survivingRole.TemplateKey)
}

func (f *fakeTemplatePermissionRepo) GetByID(_ context.Context, _ uuid.UUID) (*models.Permission, error) {
	return nil, nil
}

func TestTemplateRoleProvisioner_InstantiateForTenant_NamesRoleByFullKey(t *testing.T) {
	roleRepo := newFakeTemplateRoleRepo()
	permRepo := &fakeTemplatePermissionRepo{catalog: []models.Permission{
		mkPerm("crm:contacts:read"),
		mkPerm("marketing:campaigns:read"),
	}}
	templateRepo := newFakeTemplateRepo()
	templateRepo.latest["crm:admin"] = &models.RoleTemplate{
		Key: "crm:admin", Version: 1, Module: "crm", Name: "CRM Admin", IsActive: true,
		Permissions: []string{"crm:contacts:read"},
	}
	templateRepo.latest["marketing:admin"] = &models.RoleTemplate{
		Key: "marketing:admin", Version: 1, Module: "marketing", Name: "Marketing Admin", IsActive: true,
		Permissions: []string{"marketing:campaigns:read"},
	}

	p := NewTemplateRoleProvisioner(roleRepo, templateRepo, permRepo, nil)
	tenantID := uuid.New()

	crm, err := p.InstantiateForTenant(context.Background(), tenantID, "crm:admin", "", nil)
	require.NoError(t, err)
	mkt, err := p.InstantiateForTenant(context.Background(), tenantID, "marketing:admin", "", nil)
	require.NoError(t, err)

	// Same slug, different modules: names must not collide and must never be
	// the reserved tenant-administrator name "admin".
	assert.Equal(t, "crm:admin", crm.Name)
	assert.Equal(t, "marketing:admin", mkt.Name)
}

// Module-role templates also get the shared baseline, at provisioning and in
// the additive top-up. The top-up never invalidates sessions.
func TestTemplateRoleProvisioner_BaselineAtProvisionAndTopUp(t *testing.T) {
	roleRepo := newFakeTemplateRoleRepo()
	base := mkPerm("core:legal_entities:read")
	send := mkPerm("marketing:campaigns:send")
	catalog := []models.Permission{send, base}
	roleRepo.catalog = catalog
	permRepo := &fakeTemplatePermissionRepo{catalog: catalog}
	templateRepo := newFakeTemplateRepo()
	templateRepo.latest["marketing:campaign_manager"] = &models.RoleTemplate{
		Key: "marketing:campaign_manager", Version: 1, Module: "marketing",
		Name: "Campaign Manager", IsActive: true,
		Permissions: []string{"marketing:campaigns:send"},
	}
	p := NewTemplateRoleProvisioner(roleRepo, templateRepo, permRepo, nil)
	ctx := context.Background()
	tenantID := uuid.New()

	role, err := p.InstantiateForTenant(ctx, tenantID, "marketing:campaign_manager", "", nil)
	require.NoError(t, err)
	assert.ElementsMatch(t, []uuid.UUID{send.ID, base.ID}, roleRepo.permsByRole[role.ID],
		"template role must hold the baseline although its template does not list it")

	n, err := p.EnsureBaselineForModule(ctx, tenantID, "marketing")
	require.NoError(t, err)
	assert.Zero(t, n)

	roleRepo.permsByRole[role.ID] = []uuid.UUID{send.ID}
	n, err = p.EnsureBaselineForModule(ctx, tenantID, "marketing")
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Contains(t, roleRepo.permsByRole[role.ID], base.ID)

	n, err = p.EnsureBaselineForModule(ctx, tenantID, "marketing")
	require.NoError(t, err)
	assert.Zero(t, n)
}

// The baseline permission missing from the live catalog is skipped cleanly.
func TestTemplateRoleProvisioner_EnsureBaseline_AbsentFromCatalogSkips(t *testing.T) {
	roleRepo := newFakeTemplateRoleRepo()
	send := mkPerm("marketing:campaigns:send")
	roleRepo.catalog = []models.Permission{send}
	permRepo := &fakeTemplatePermissionRepo{catalog: roleRepo.catalog}
	templateRepo := newFakeTemplateRepo()
	templateRepo.latest["marketing:cm"] = &models.RoleTemplate{
		Key: "marketing:cm", Version: 1, Module: "marketing", Name: "CM", IsActive: true,
		Permissions: []string{"marketing:campaigns:send"},
	}
	p := NewTemplateRoleProvisioner(roleRepo, templateRepo, permRepo, nil)
	ctx := context.Background()
	tenantID := uuid.New()
	role, err := p.InstantiateForTenant(ctx, tenantID, "marketing:cm", "", nil)
	require.NoError(t, err)
	n, err := p.EnsureBaselineForModule(ctx, tenantID, "marketing")
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Equal(t, []uuid.UUID{send.ID}, roleRepo.permsByRole[role.ID])
}

// A failed SpiceDB write aborts before the relational grant, so the role still
// looks incomplete and the next reconcile retries; it is not counted as topped.
func TestTemplateRoleProvisioner_EnsureBaseline_SpiceDBFailureRetries(t *testing.T) {
	roleRepo := newFakeTemplateRoleRepo()
	base := mkPerm("core:legal_entities:read")
	send := mkPerm("marketing:campaigns:send")
	roleRepo.catalog = []models.Permission{send, base}
	permRepo := &fakeTemplatePermissionRepo{catalog: roleRepo.catalog}
	templateRepo := newFakeTemplateRepo()
	templateRepo.latest["marketing:cm"] = &models.RoleTemplate{
		Key: "marketing:cm", Version: 1, Module: "marketing", Name: "CM", IsActive: true,
		Permissions: []string{"marketing:campaigns:send"},
	}
	// A bootstrap service without a SpiceDB client fails every write.
	p := NewTemplateRoleProvisioner(roleRepo, templateRepo, permRepo, &TenantBootstrapService{})
	ctx := context.Background()
	tenantID := uuid.New()
	role, err := p.InstantiateForTenant(ctx, tenantID, "marketing:cm", "", nil)
	require.NoError(t, err)
	roleRepo.permsByRole[role.ID] = []uuid.UUID{send.ID}

	n, err := p.EnsureBaselineForModule(ctx, tenantID, "marketing")
	require.Error(t, err)
	assert.Zero(t, n)
	assert.NotContains(t, roleRepo.permsByRole[role.ID], base.ID, "relational grant must wait for the SpiceDB write")
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

type fakeMATemplates struct {
	modules     []string
	baselineErr error
}

func (f *fakeMATemplates) ProvisionForModuleGrant(_ context.Context, _ uuid.UUID, module string) (int, error) {
	f.modules = append(f.modules, module)
	return 1, nil
}

func (f *fakeMATemplates) EnsureBaselineForModule(_ context.Context, _ uuid.UUID, _ string) (int, error) {
	return 0, f.baselineErr
}

type fakeMARoles struct {
	byName    map[string]*models.Role
	byKey     map[string]*models.Role
	holders   map[uuid.UUID][]uuid.UUID
	holderErr error

	// granted tracks owner permission grants per role: set of "module" names
	// already held, to model ON CONFLICT DO NOTHING.
	permModules map[string]int64 // module -> catalog size
	grantedPerm map[uuid.UUID]map[string]bool
}

func (f *fakeMARoles) GetByName(_ context.Context, _ uuid.UUID, name string) (*models.Role, error) {
	return f.byName[name], nil
}
func (f *fakeMARoles) GetByTemplateKeyForTenant(_ context.Context, _ uuid.UUID, key string) (*models.Role, error) {
	return f.byKey[key], nil
}
func (f *fakeMARoles) ListActiveHolderIDs(_ context.Context, roleID uuid.UUID) ([]uuid.UUID, error) {
	return f.holders[roleID], f.holderErr
}

func (f *fakeMARoles) GrantModulePermissionsToRole(_ context.Context, roleID uuid.UUID, modules []string) (int64, error) {
	if f.grantedPerm == nil {
		f.grantedPerm = map[uuid.UUID]map[string]bool{}
	}
	if f.grantedPerm[roleID] == nil {
		f.grantedPerm[roleID] = map[string]bool{}
	}
	var n int64
	for _, m := range modules {
		if !f.grantedPerm[roleID][m] {
			f.grantedPerm[roleID][m] = true
			n += f.permModules[m]
		}
	}
	return n, nil
}

type fakeMAUsers struct {
	roles *fakeMARoles
	grant [][2]uuid.UUID
}

// GrantRoles also records the holder so a second run sees it (idempotency).
func (f *fakeMAUsers) GrantRoles(_ context.Context, userID uuid.UUID, roleIDs []uuid.UUID, _ *uuid.UUID) error {
	for _, r := range roleIDs {
		f.grant = append(f.grant, [2]uuid.UUID{userID, r})
		f.roles.holders[r] = append(f.roles.holders[r], userID)
	}
	return nil
}

type fakeMASpice struct{ calls [][2]uuid.UUID }

func (f *fakeMASpice) BootstrapUserRole(_ context.Context, _, userID, roleID uuid.UUID) (string, error) {
	f.calls = append(f.calls, [2]uuid.UUID{userID, roleID})
	return "", nil
}

type fakeMAEnts struct {
	grants []repositories.TenantModuleGrant
}

func (f *fakeMAEnts) ListGrantingTenantModules(context.Context) ([]repositories.TenantModuleGrant, error) {
	return f.grants, nil
}

type fakeMAPermLister struct{ catalog map[string][]string }

func (f fakeMAPermLister) ListByModules(_ context.Context, modules []string) ([]models.Permission, error) {
	var out []models.Permission
	for _, m := range modules {
		for _, n := range f.catalog[m] {
			out = append(out, models.Permission{Name: n, Module: m})
		}
	}
	return out, nil
}

type fakeMARolePermSpice struct{ names []string }

func (f *fakeMARolePermSpice) BootstrapRolePermissions(_ context.Context, _, _ uuid.UUID, perms []string) (*BootstrapResult, error) {
	f.names = append(f.names, perms...)
	return &BootstrapResult{}, nil
}

type fakeMASessions struct {
	incremented int
	invalidated []uuid.UUID
	published   int
}

func (f *fakeMASessions) IncrementRoleVersion(context.Context, uuid.UUID) (int64, error) {
	f.incremented++
	return int64(f.incremented), nil
}
func (f *fakeMASessions) PublishPermissionInvalidation(context.Context, interface{}) error {
	f.published++
	return nil
}
func (f *fakeMASessions) InvalidateUserSessionsByRoleVersion(_ context.Context, u uuid.UUID, _ int64) error {
	f.invalidated = append(f.invalidated, u)
	return nil
}

type maFixture struct {
	tenant    uuid.UUID
	templates *fakeMATemplates
	roles     *fakeMARoles
	users     *fakeMAUsers
	spice     *fakeMASpice
	ents      *fakeMAEnts
	owners    []uuid.UUID
	p         *ModuleAccessProvisioner
}

func newMAFixture(owners int, templateKeys ...string) *maFixture {
	f := &maFixture{
		tenant:    uuid.New(),
		templates: &fakeMATemplates{},
		roles:     &fakeMARoles{byName: map[string]*models.Role{}, byKey: map[string]*models.Role{}, holders: map[uuid.UUID][]uuid.UUID{}},
		spice:     &fakeMASpice{},
		ents:      &fakeMAEnts{},
	}
	f.users = &fakeMAUsers{roles: f.roles}
	ownerRole := &models.Role{ID: uuid.New(), Name: "owner"}
	f.roles.byName["owner"] = ownerRole
	for i := 0; i < owners; i++ {
		id := uuid.New()
		f.owners = append(f.owners, id)
		f.roles.holders[ownerRole.ID] = append(f.roles.holders[ownerRole.ID], id)
	}
	for _, k := range templateKeys {
		f.roles.byKey[k] = &models.Role{ID: uuid.New(), Name: k}
	}
	f.p = NewModuleAccessProvisioner(f.templates, f.roles, f.users, f.spice, f.ents, nil)
	return f
}

func TestModuleAccessProvisioner_MaterializesAllModulesOfCode(t *testing.T) {
	f := newMAFixture(1, "qms:quality_manager", "cmms:maintenance_manager")
	res, err := f.p.EnsureModuleAccess(context.Background(), f.tenant, "quality_maintenance")
	require.NoError(t, err)
	assert.Equal(t, []string{"qms", "cmms"}, f.templates.modules)
	assert.Equal(t, 2, res.RolesProvisioned)
	assert.Equal(t, 2, res.GrantsMade)
}

func TestModuleAccessProvisioner_GrantsOwnersAndWritesSpiceDB(t *testing.T) {
	f := newMAFixture(2, "crm:admin")
	res, err := f.p.EnsureModuleAccess(context.Background(), f.tenant, "crm")
	require.NoError(t, err)
	assert.Equal(t, 2, res.OwnersFound)
	assert.Equal(t, 2, res.GrantsMade)
	assert.Len(t, f.users.grant, 2)
	assert.Len(t, f.spice.calls, 2)
	for _, c := range f.users.grant {
		assert.Equal(t, f.roles.byKey["crm:admin"].ID, c[1])
	}
}

func TestModuleAccessProvisioner_NoGrantWhenHolderExists(t *testing.T) {
	f := newMAFixture(1, "crm:admin")
	f.roles.holders[f.roles.byKey["crm:admin"].ID] = []uuid.UUID{uuid.New()}
	res, err := f.p.EnsureModuleAccess(context.Background(), f.tenant, "crm")
	require.NoError(t, err)
	assert.Equal(t, 0, res.GrantsMade)
	assert.Equal(t, 1, res.RolesAlreadyHeld)
	assert.Empty(t, f.users.grant)
}

func TestModuleAccessProvisioner_NoOwnersIsNotAnError(t *testing.T) {
	f := newMAFixture(0, "crm:admin")
	res, err := f.p.EnsureModuleAccess(context.Background(), f.tenant, "crm")
	require.NoError(t, err)
	assert.Equal(t, 0, res.OwnersFound)
	assert.Equal(t, 0, res.GrantsMade)
	assert.Equal(t, 1, res.RolesProvisioned)
}

func TestModuleAccessProvisioner_MissingTemplateSkippedOthersProceed(t *testing.T) {
	f := newMAFixture(1, "mm:purchasing_officer") // inventory:admin missing
	res, err := f.p.EnsureModuleAccess(context.Background(), f.tenant, "inventory")
	require.NoError(t, err)
	assert.Equal(t, []string{"inventory:admin"}, res.MissingTemplates)
	assert.Equal(t, 1, res.GrantsMade)
}

func TestModuleAccessProvisioner_SecondRunIsNoop(t *testing.T) {
	f := newMAFixture(1, "crm:admin")
	_, err := f.p.EnsureModuleAccess(context.Background(), f.tenant, "crm")
	require.NoError(t, err)
	res, err := f.p.EnsureModuleAccess(context.Background(), f.tenant, "crm")
	require.NoError(t, err)
	assert.Equal(t, 0, res.GrantsMade)
	assert.Len(t, f.users.grant, 1)
}

func TestModuleAccessProvisioner_HolderLookupErrorIsReturned(t *testing.T) {
	f := newMAFixture(1, "crm:admin")
	f.roles.holderErr = errors.New("boom")
	_, err := f.p.EnsureModuleAccess(context.Background(), f.tenant, "crm")
	require.Error(t, err)
}

func TestModuleAccessProvisioner_ReconcilePermissionModuleFiltersByCode(t *testing.T) {
	f := newMAFixture(1, "crm:admin", "hr:hr_manager", "hr:settings_admin")
	other := uuid.New()
	f.ents.grants = []repositories.TenantModuleGrant{
		{TenantID: f.tenant, ModuleCode: "crm"},
		{TenantID: f.tenant, ModuleCode: "hr"},
		{TenantID: other, ModuleCode: "hr"},
	}
	sum, err := f.p.ReconcilePermissionModule(context.Background(), "hr")
	require.NoError(t, err)
	assert.Len(t, sum.Results, 2)
	assert.Equal(t, 2, sum.Tenants)
	for _, r := range sum.Results {
		assert.Equal(t, "hr", r.EntitlementCode)
	}
}

func TestModuleAccessProvisioner_UnknownCodeNoop(t *testing.T) {
	f := newMAFixture(1)
	res, err := f.p.EnsureModuleAccess(context.Background(), f.tenant, "weird")
	require.NoError(t, err)
	assert.Equal(t, 0, res.RolesProvisioned)
	assert.Empty(t, f.templates.modules)
}

func TestModuleAccessProvisioner_OwnerGetsAllPermissionsOfBothModules(t *testing.T) {
	f := newMAFixture(2, "qms:quality_manager", "cmms:maintenance_manager")
	f.roles.permModules = map[string]int64{"qms": 40, "cmms": 25}
	spice := &fakeMARolePermSpice{}
	sessions := &fakeMASessions{}
	f.p.SetOwnerPermissionSync(fakeMAPermLister{catalog: map[string][]string{
		"qms":  {"qms:a:read", "qms:a:write"},
		"cmms": {"cmms:b:read"},
	}}, spice, sessions)

	res, err := f.p.EnsureModuleAccess(context.Background(), f.tenant, "quality_maintenance")
	require.NoError(t, err)
	ownerID := f.roles.byName["owner"].ID
	assert.Equal(t, int64(65), res.OwnerPermissionsGranted)
	assert.True(t, f.roles.grantedPerm[ownerID]["qms"])
	assert.True(t, f.roles.grantedPerm[ownerID]["cmms"])
	assert.ElementsMatch(t, []string{"qms:a:read", "qms:a:write", "cmms:b:read"}, spice.names)
	assert.Equal(t, 1, sessions.incremented)
	assert.Len(t, sessions.invalidated, 2)
	assert.Equal(t, 2, sessions.published)

	// Second run: nothing new inserted, so no SpiceDB write or invalidation.
	res, err = f.p.EnsureModuleAccess(context.Background(), f.tenant, "quality_maintenance")
	require.NoError(t, err)
	assert.Equal(t, int64(0), res.OwnerPermissionsGranted)
	assert.Len(t, spice.names, 3)
	assert.Equal(t, 1, sessions.incremented)
}

func TestModuleAccessProvisioner_NoOwnerRoleSkipsPermissionGrant(t *testing.T) {
	f := newMAFixture(0, "crm:admin")
	delete(f.roles.byName, "owner")
	f.roles.permModules = map[string]int64{"crm": 10}
	res, err := f.p.EnsureModuleAccess(context.Background(), f.tenant, "crm")
	require.NoError(t, err)
	assert.Equal(t, int64(0), res.OwnerPermissionsGranted)
	assert.Empty(t, f.roles.grantedPerm)
}

// An already-entitled pre-accounting tenant (accountant role only, held by an
// external accountant) gets the manager role granted to its owners on reconcile,
// and the accountant holder is untouched.
func TestModuleAccessProvisioner_PreAccountingOwnerGetsManager(t *testing.T) {
	f := newMAFixture(1, "preaccounting:accountant", "preaccounting:manager")
	acc := f.roles.byKey["preaccounting:accountant"]
	f.roles.holders[acc.ID] = []uuid.UUID{uuid.New()}
	res, err := f.p.EnsureModuleAccess(context.Background(), f.tenant, "pre_accounting")
	require.NoError(t, err)
	assert.Equal(t, 1, res.GrantsMade)
	require.Len(t, f.users.grant, 1)
	assert.Equal(t, f.roles.byKey["preaccounting:manager"].ID, f.users.grant[0][1])
	res, err = f.p.EnsureModuleAccess(context.Background(), f.tenant, "pre_accounting")
	require.NoError(t, err)
	assert.Equal(t, 0, res.GrantsMade)
}

// A failing template-baseline top-up is recorded in res.Errors and does not
// abort the owner grant.
func TestModuleAccessProvisioner_BaselineErrorRecordedNotFatal(t *testing.T) {
	f := newMAFixture(1, "qms:quality_manager", "cmms:maintenance_manager")
	f.templates.baselineErr = errors.New("spicedb down")
	res, err := f.p.EnsureModuleAccess(context.Background(), f.tenant, "quality_maintenance")
	require.NoError(t, err)
	require.NotEmpty(t, res.Errors)
	assert.Contains(t, res.Errors[0], "template baseline")
	assert.Equal(t, 2, res.GrantsMade, "owner template grants still happen")
}

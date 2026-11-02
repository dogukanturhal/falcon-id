// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// listByModulesRepo satisfies permissionServicePermissionRepo by embedding the
// interface (nil) and overriding the one method registerRoleTemplates uses.
type listByModulesRepo struct {
	permissionServicePermissionRepo
	newRows bool // RegisterPermissionsBatch reports rows as newly inserted
}

func (r listByModulesRepo) RegisterPermissionsBatch(_ context.Context, perms []*models.Permission) (int, int, error) {
	if r.newRows {
		return len(perms), 0, nil
	}
	return 0, len(perms), nil
}

func (listByModulesRepo) ListByModules(context.Context, []string) ([]models.Permission, error) {
	return nil, nil
}

type recordingTemplateRepo struct {
	fakeTemplateLatestLookup
	created []string
}

func (r *recordingTemplateRepo) Create(_ context.Context, t *models.RoleTemplate) error {
	r.created = append(r.created, t.Key)
	r.byKey[t.Key] = t
	return nil
}

type recordingModuleReconciler struct {
	mu      sync.Mutex
	modules []string
	done    chan struct{}
}

func (r *recordingModuleReconciler) ReconcilePermissionModule(_ context.Context, m string) (*ModuleAccessReconcileSummary, error) {
	r.mu.Lock()
	r.modules = append(r.modules, m)
	r.mu.Unlock()
	r.done <- struct{}{}
	return &ModuleAccessReconcileSummary{}, nil
}

func waitReconcile(t *testing.T, rec *recordingModuleReconciler, want bool) {
	t.Helper()
	select {
	case <-rec.done:
		if !want {
			t.Fatal("reconcile fired unexpectedly")
		}
	case <-time.After(300 * time.Millisecond):
		if want {
			t.Fatal("reconcile not triggered")
		}
	}
}

func registerReq(withTemplate bool) *models.RegisterModuleRequest {
	req := &models.RegisterModuleRequest{
		Module:      "hr",
		Permissions: []models.PermissionDefinition{{Resource: "employees", Actions: []string{"read"}}},
	}
	if withTemplate {
		req.RoleTemplates = []models.RoleTemplateDefinition{def("hr:hr_manager", 2, "hr:employees:read")}
	}
	return req
}

func TestRegisterModule_NewPermissionsTriggerModuleReconcile(t *testing.T) {
	rec := &recordingModuleReconciler{done: make(chan struct{}, 4)}
	s := &PermissionService{permissionRepo: listByModulesRepo{newRows: true}}
	s.SetModuleAccessReconciler(rec)

	_, err := s.RegisterModule(context.Background(), registerReq(false))
	require.NoError(t, err)
	waitReconcile(t, rec, true)
	assert.Equal(t, []string{"hr"}, rec.modules)
}

func TestRegisterModule_NoNewRowsNoTemplatesDoesNotReconcile(t *testing.T) {
	rec := &recordingModuleReconciler{done: make(chan struct{}, 4)}
	s := &PermissionService{permissionRepo: listByModulesRepo{newRows: false}}
	s.SetModuleAccessReconciler(rec)

	_, err := s.RegisterModule(context.Background(), registerReq(false))
	require.NoError(t, err)
	waitReconcile(t, rec, false)
}

func TestRegisterModule_FirstTemplateRegistrationTriggersOnceNotOnRepeat(t *testing.T) {
	repo := &recordingTemplateRepo{fakeTemplateLatestLookup: fakeTemplateLatestLookup{byKey: map[string]*models.RoleTemplate{}}}
	rec := &recordingModuleReconciler{done: make(chan struct{}, 4)}
	s := &PermissionService{permissionRepo: listByModulesRepo{newRows: false}}
	s.SetRoleTemplateSupport(repo, NewRoleTemplateValidator(repo), nil)
	s.SetModuleAccessReconciler(rec)

	_, err := s.RegisterModule(context.Background(), registerReq(true))
	require.NoError(t, err)
	waitReconcile(t, rec, true)

	_, err = s.RegisterModule(context.Background(), registerReq(true))
	require.NoError(t, err)
	waitReconcile(t, rec, false)
}

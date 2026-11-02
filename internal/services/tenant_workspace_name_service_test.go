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

type fakeNameStore struct {
	tenants map[uuid.UUID]*models.Tenant
	slugs   map[uuid.UUID]string
	order   []uuid.UUID
}

func newFakeNameStore() *fakeNameStore {
	return &fakeNameStore{tenants: map[uuid.UUID]*models.Tenant{}, slugs: map[uuid.UUID]string{}}
}

func (f *fakeNameStore) add(displayName string) uuid.UUID {
	id := uuid.New()
	f.tenants[id] = &models.Tenant{ID: id, DisplayName: displayName}
	f.slugs[id] = "slug-" + id.String()[:4]
	f.order = append(f.order, id)
	return id
}

func (f *fakeNameStore) GetByID(_ context.Context, id uuid.UUID) (*models.Tenant, error) {
	return f.tenants[id], nil
}

func (f *fakeNameStore) RenameDisplayNameIfPlaceholder(_ context.Context, id uuid.UUID, name string) (bool, error) {
	t := f.tenants[id]
	if t == nil || !models.IsPlaceholderTenantName(t.DisplayName) {
		return false, nil
	}
	t.DisplayName = name
	return true, nil
}

func (f *fakeNameStore) ListNameStates(_ context.Context) ([]repositories.TenantNameState, error) {
	var out []repositories.TenantNameState
	for _, id := range f.order {
		out = append(out, repositories.TenantNameState{ID: id, Slug: f.slugs[id], DisplayName: f.tenants[id].DisplayName})
	}
	return out, nil
}

type fakeTM struct {
	names   map[uuid.UUID]string
	updates int
	failOn  map[uuid.UUID]bool
}

func (f *fakeTM) GetName(_ context.Context, id uuid.UUID) (string, error) { return f.names[id], nil }
func (f *fakeTM) UpdateName(_ context.Context, id uuid.UUID, name string) error {
	if f.failOn[id] {
		return errors.New("tm down")
	}
	f.updates++
	f.names[id] = name
	return nil
}

type fakeCompany map[uuid.UUID]string

func (f fakeCompany) DefaultCompanyName(_ context.Context, id uuid.UUID) (string, bool, error) {
	n, ok := f[id]
	return n, ok, nil
}

func TestRenameIfPlaceholder(t *testing.T) {
	ctx := context.Background()

	t.Run("renames a placeholder in both stores", func(t *testing.T) {
		store := newFakeNameStore()
		id := store.add(models.PlaceholderTenantName)
		tm := &fakeTM{names: map[uuid.UUID]string{id: models.PlaceholderTenantName}}
		svc := NewTenantWorkspaceNameService(store, tm, nil, nil)

		out, err := svc.RenameIfPlaceholder(ctx, id, "  Acme Yazilim  ")
		require.NoError(t, err)
		assert.Equal(t, WorkspaceRenamed, out)
		assert.Equal(t, "Acme Yazilim", store.tenants[id].DisplayName)
		assert.Equal(t, "Acme Yazilim", tm.names[id])
	})

	t.Run("never overwrites a real name", func(t *testing.T) {
		store := newFakeNameStore()
		id := store.add("Real Co")
		tm := &fakeTM{names: map[uuid.UUID]string{id: "Real Co"}}
		svc := NewTenantWorkspaceNameService(store, tm, nil, nil)

		out, err := svc.RenameIfPlaceholder(ctx, id, "Other Co")
		require.NoError(t, err)
		assert.Equal(t, WorkspaceAlreadyNamed, out)
		assert.Equal(t, "Real Co", store.tenants[id].DisplayName)
		assert.Zero(t, tm.updates)
	})

	t.Run("is idempotent", func(t *testing.T) {
		store := newFakeNameStore()
		id := store.add(models.PlaceholderTenantName)
		svc := NewTenantWorkspaceNameService(store, &fakeTM{names: map[uuid.UUID]string{}}, nil, nil)

		_, err := svc.RenameIfPlaceholder(ctx, id, "Acme")
		require.NoError(t, err)
		out, err := svc.RenameIfPlaceholder(ctx, id, "Acme")
		require.NoError(t, err)
		assert.Equal(t, WorkspaceAlreadyNamed, out)
	})

	t.Run("tenant-management failure leaves the placeholder so a retry completes it", func(t *testing.T) {
		store := newFakeNameStore()
		id := store.add(models.PlaceholderTenantName)
		tm := &fakeTM{names: map[uuid.UUID]string{}, failOn: map[uuid.UUID]bool{id: true}}
		svc := NewTenantWorkspaceNameService(store, tm, nil, nil)

		_, err := svc.RenameIfPlaceholder(ctx, id, "Acme")
		require.Error(t, err)
		assert.True(t, models.IsPlaceholderTenantName(store.tenants[id].DisplayName))

		tm.failOn[id] = false
		out, err := svc.RenameIfPlaceholder(ctx, id, "Acme")
		require.NoError(t, err)
		assert.Equal(t, WorkspaceRenamed, out)
	})

	t.Run("unknown tenant", func(t *testing.T) {
		svc := NewTenantWorkspaceNameService(newFakeNameStore(), nil, nil, nil)
		out, err := svc.RenameIfPlaceholder(ctx, uuid.New(), "Acme")
		require.NoError(t, err)
		assert.Equal(t, WorkspaceNotFound, out)
	})

	t.Run("rejects empty, short and placeholder names", func(t *testing.T) {
		store := newFakeNameStore()
		id := store.add(models.PlaceholderTenantName)
		svc := NewTenantWorkspaceNameService(store, nil, nil, nil)
		for _, bad := range []string{"", " ", "A", "my company", " My Company "} {
			_, err := svc.RenameIfPlaceholder(ctx, id, bad)
			assert.ErrorIs(t, err, ErrInvalidWorkspaceName, bad)
		}
	})
}

func TestBackfill(t *testing.T) {
	ctx := context.Background()

	setup := func() (*TenantWorkspaceNameService, *fakeNameStore, *fakeTM, map[string]uuid.UUID) {
		store := newFakeNameStore()
		ids := map[string]uuid.UUID{
			"withEntity": store.add(models.PlaceholderTenantName),
			"noEntity":   store.add(models.PlaceholderTenantName),
			"named":      store.add("Already Named"),
			"tmLagging":  store.add("Named Locally"),
		}
		tm := &fakeTM{names: map[uuid.UUID]string{
			ids["withEntity"]: models.PlaceholderTenantName,
			ids["noEntity"]:   models.PlaceholderTenantName,
			ids["named"]:      "Already Named",
			ids["tmLagging"]:  models.PlaceholderTenantName,
		}}
		company := fakeCompany{ids["withEntity"]: "Acme Yazilim A.S."}
		return NewTenantWorkspaceNameService(store, tm, company, nil), store, tm, ids
	}

	t.Run("dry run reports and writes nothing", func(t *testing.T) {
		svc, store, tm, ids := setup()
		rep, err := svc.Backfill(ctx, true)
		require.NoError(t, err)

		assert.True(t, rep.DryRun)
		assert.Equal(t, 4, rep.Scanned)
		assert.Equal(t, 1, rep.Counts[BackfillActionRename])
		assert.Equal(t, 1, rep.Counts[BackfillActionSyncTM])
		assert.Equal(t, 1, rep.Counts[BackfillActionNoEntity])
		for _, it := range rep.Items {
			assert.False(t, it.Applied)
		}
		assert.True(t, models.IsPlaceholderTenantName(store.tenants[ids["withEntity"]].DisplayName))
		assert.Zero(t, tm.updates)
	})

	t.Run("apply renames from the entity, syncs tenant-management, leaves no-entity alone", func(t *testing.T) {
		svc, store, tm, ids := setup()
		rep, err := svc.Backfill(ctx, false)
		require.NoError(t, err)

		assert.Equal(t, "Acme Yazilim A.S.", store.tenants[ids["withEntity"]].DisplayName)
		assert.Equal(t, "Acme Yazilim A.S.", tm.names[ids["withEntity"]])
		assert.Equal(t, "Named Locally", tm.names[ids["tmLagging"]])
		assert.True(t, models.IsPlaceholderTenantName(store.tenants[ids["noEntity"]].DisplayName))
		assert.Equal(t, 1, rep.Counts[BackfillActionNoEntity])
	})

	t.Run("second apply finds only the tenants that still have no entity", func(t *testing.T) {
		svc, _, _, _ := setup()
		_, err := svc.Backfill(ctx, false)
		require.NoError(t, err)

		rep, err := svc.Backfill(ctx, false)
		require.NoError(t, err)
		require.Len(t, rep.Items, 1)
		assert.Equal(t, BackfillActionNoEntity, rep.Items[0].Action)
	})

	t.Run("a failing tenant is reported and does not stop the rest", func(t *testing.T) {
		svc, store, tm, ids := setup()
		tm.failOn = map[uuid.UUID]bool{ids["withEntity"]: true}
		rep, err := svc.Backfill(ctx, false)
		require.NoError(t, err)

		assert.Equal(t, 1, rep.Counts[BackfillActionError])
		assert.True(t, models.IsPlaceholderTenantName(store.tenants[ids["withEntity"]].DisplayName))
		assert.Equal(t, "Named Locally", tm.names[ids["tmLagging"]])
	})

	t.Run("refuses without a business client", func(t *testing.T) {
		svc := NewTenantWorkspaceNameService(newFakeNameStore(), nil, nil, nil)
		_, err := svc.Backfill(ctx, true)
		assert.Error(t, err)
	})
}

func TestPushName_SkipsPlaceholderAndEmpty(t *testing.T) {
	id := uuid.New()
	tm := &fakeTM{names: map[uuid.UUID]string{}}
	svc := NewTenantWorkspaceNameService(newFakeNameStore(), tm, nil, nil)
	svc.PushName(context.Background(), id, "My Company")
	svc.PushName(context.Background(), id, "  ")
	assert.Zero(t, tm.updates)
	svc.PushName(context.Background(), id, "Acme")
	assert.Equal(t, "Acme", tm.names[id])
}

func TestIsPlaceholderTenantName(t *testing.T) {
	assert.True(t, models.IsPlaceholderTenantName("My Company"))
	assert.True(t, models.IsPlaceholderTenantName("  my company "))
	assert.False(t, models.IsPlaceholderTenantName("My Company Ltd"))
	assert.False(t, models.IsPlaceholderTenantName(""))
}

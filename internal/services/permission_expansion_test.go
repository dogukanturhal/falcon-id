// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCatalog = []string{
	"core:parties:read", "core:parties:create", "core:parties_extra:read",
	"core:items:read", "jobs:jobs:read", "jobs:jobs:run",
}

func TestExpandPermissionPatterns_Match(t *testing.T) {
	got, unmatched, _ := expandPermissionPatterns(
		[]string{"core:parties:*", "jobs:jobs:read", "jobs:jobs:*"}, testCatalog)
	assert.Empty(t, unmatched)
	assert.Equal(t, []string{"core:parties:read", "core:parties:create", "jobs:jobs:read", "jobs:jobs:run"}, got)
}

func TestExpandPermissionPatterns_OnlyResourceWildcard(t *testing.T) {
	got, unmatched, moduleLevel := expandPermissionPatterns(
		[]string{"core:*", "core:parties:re*", "cor*", "core:*:*", "core:*:read"}, testCatalog)
	assert.Empty(t, got)
	assert.Equal(t, []string{"core:*", "core:parties:re*", "cor*", "core:*:read"}, unmatched)
	assert.Equal(t, []string{"core:*:*"}, moduleLevel)
}

func TestExpandPermissionPatterns_NoMatchSkipped(t *testing.T) {
	got, unmatched, _ := expandPermissionPatterns(
		[]string{"marketing:workflows:*", "*", "core:*:read", "core:items:read"}, testCatalog)
	assert.Equal(t, []string{"core:items:read"}, got)
	assert.Equal(t, []string{"marketing:workflows:*", "*", "core:*:read"}, unmatched)
}

type fakeCatalog struct {
	names []string
	err   error
}

func (f fakeCatalog) ListConcreteNames(context.Context) ([]string, error) { return f.names, f.err }

func TestBootstrapExpandRolePermissions(t *testing.T) {
	ctx := context.Background()
	tid, rid := uuid.New(), uuid.New()

	svc := NewTenantBootstrapService(nil)
	svc.SetPermissionCatalog(fakeCatalog{names: testCatalog})
	res := &BootstrapResult{}
	got := svc.expandRolePermissions(ctx, res, tid, rid, []string{"core:items:*", "marketing:workflows:*", "jobs:jobs:read"})
	assert.Equal(t, []string{"core:items:read", "jobs:jobs:read"}, got)
	assert.Empty(t, res.Errors)

	// No wildcards: slice returned untouched, catalog never consulted.
	svc = NewTenantBootstrapService(nil)
	res = &BootstrapResult{}
	in := []string{"core:items:read"}
	assert.Equal(t, in, svc.expandRolePermissions(ctx, res, tid, rid, in))

	// No catalog wired: wildcards skipped, never passed through raw.
	res = &BootstrapResult{}
	got = svc.expandRolePermissions(ctx, res, tid, rid, []string{"core:items:*", "core:items:read"})
	assert.Equal(t, []string{"core:items:read"}, got)

	// Catalog failure: wildcards skipped and the error surfaced.
	svc.SetPermissionCatalog(fakeCatalog{err: errors.New("db down")})
	res = &BootstrapResult{}
	got = svc.expandRolePermissions(ctx, res, tid, rid, []string{"core:items:*"})
	assert.Empty(t, got)
	require.Len(t, res.Errors, 1)
}

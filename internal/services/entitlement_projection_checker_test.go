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

type fakeLegacyChecker struct {
	ok  bool
	err error
}

func (f fakeLegacyChecker) IsTenantEntitled(context.Context, uuid.UUID, string) (bool, error) {
	return f.ok, f.err
}

type fakeEnvSource struct {
	env   EntitlementEnvelope
	err   error
	calls int
}

func (f *fakeEnvSource) GetEntitlements(context.Context, uuid.UUID) (EntitlementEnvelope, error) {
	f.calls++
	return f.env, f.err
}

func TestProjectionOrLegacyChecker(t *testing.T) {
	ctx := context.Background()
	tid := uuid.New()
	granting := EntitlementEnvelope{Modules: []EntitlementModule{{Code: "pre_accounting", Status: "active"}, {Code: "crm", Status: "expired"}}}

	t.Run("legacy true wins without reading projection", func(t *testing.T) {
		src := &fakeEnvSource{env: granting}
		c := NewProjectionOrLegacyChecker(fakeLegacyChecker{ok: true}, src)
		ok, err := c.IsTenantEntitled(ctx, tid, "crm")
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, 0, src.calls)
	})

	t.Run("projection-only true", func(t *testing.T) {
		c := NewProjectionOrLegacyChecker(fakeLegacyChecker{}, &fakeEnvSource{env: granting})
		ok, err := c.IsTenantEntitled(ctx, tid, "preaccounting")
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("both false", func(t *testing.T) {
		c := NewProjectionOrLegacyChecker(fakeLegacyChecker{}, &fakeEnvSource{env: granting})
		ok, err := c.IsTenantEntitled(ctx, tid, "crm") // expired
		require.NoError(t, err)
		assert.False(t, ok)
		ok, _ = c.IsTenantEntitled(ctx, tid, "unknownmod")
		assert.False(t, ok)
	})

	t.Run("legacy error surfaced only if projection does not grant", func(t *testing.T) {
		legacyErr := errors.New("legacy down")
		c := NewProjectionOrLegacyChecker(fakeLegacyChecker{err: legacyErr}, &fakeEnvSource{env: granting})
		ok, err := c.IsTenantEntitled(ctx, tid, "preaccounting")
		require.NoError(t, err)
		assert.True(t, ok)

		ok, err = c.IsTenantEntitled(ctx, tid, "hr")
		assert.False(t, ok)
		assert.ErrorIs(t, err, legacyErr)
	})

	t.Run("projection error fails closed", func(t *testing.T) {
		c := NewProjectionOrLegacyChecker(fakeLegacyChecker{}, &fakeEnvSource{err: errors.New("db down")})
		ok, err := c.IsTenantEntitled(ctx, tid, "preaccounting")
		assert.False(t, ok)
		assert.Error(t, err)
	})

	t.Run("envelope memoized across modules", func(t *testing.T) {
		src := &fakeEnvSource{env: granting}
		c := NewProjectionOrLegacyChecker(fakeLegacyChecker{}, src)
		for _, m := range []string{"hr", "crm", "preaccounting", "mm"} {
			_, _ = c.IsTenantEntitled(ctx, tid, m)
		}
		assert.Equal(t, 1, src.calls)
	})
}

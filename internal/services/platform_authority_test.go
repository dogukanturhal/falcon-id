// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

type fakeAuthorityStore struct {
	roles    []string
	standing []string
	err      error
}

func (f fakeAuthorityStore) HasStandingRole(_ context.Context, _ uuid.UUID, key string) (bool, error) {
	for _, r := range f.standing {
		if r == key {
			return true, f.err
		}
	}
	return false, f.err
}

func (f fakeAuthorityStore) ActiveRoles(context.Context, uuid.UUID) ([]string, error) {
	return f.roles, f.err
}

func (f fakeAuthorityStore) LatestActiveElevation(context.Context, uuid.UUID) (*repositories.ActiveElevationRef, error) {
	return nil, nil
}

func TestPlatformAuthority_LegacyFollowsTenantMembership(t *testing.T) {
	internal := uuid.MustParse(models.HexxlockInternalTenantID)
	var nilAuthority *PlatformAuthority
	for name, pa := range map[string]*PlatformAuthority{
		"nil":        nilAuthority,
		"non-strict": NewPlatformAuthority(false, "", fakeAuthorityStore{}),
	} {
		if !pa.AdminClaim(context.Background(), uuid.New(), internal, "a@example.com") {
			t.Errorf("%s: internal-tenant member must keep is_platform_admin (legacy)", name)
		}
		if pa.AdminClaim(context.Background(), uuid.New(), uuid.New(), "a@example.com") {
			t.Errorf("%s: non-internal tenant must not be platform admin", name)
		}
	}
}

func TestPlatformAuthority_StrictUsesPlatformRoles(t *testing.T) {
	internal := uuid.MustParse(models.HexxlockInternalTenantID)
	ctx := context.Background()
	user := uuid.New()

	viewerOnly := NewPlatformAuthority(true, "", fakeAuthorityStore{roles: []string{"platform_viewer"}})
	if viewerOnly.AdminClaim(ctx, user, internal, "a@example.com") {
		t.Error("standing viewer must not be platform admin")
	}
	elevated := NewPlatformAuthority(true, "", fakeAuthorityStore{roles: []string{"platform_viewer", "platform_admin"}})
	if !elevated.AdminClaim(ctx, user, internal, "a@example.com") {
		t.Error("active platform_admin elevation must be platform admin")
	}
	if elevated.AdminClaim(ctx, user, uuid.New(), "a@example.com") {
		t.Error("non-internal tenant must never be platform admin")
	}
	failing := NewPlatformAuthority(true, "", fakeAuthorityStore{err: errors.New("db down")})
	if failing.AdminClaim(ctx, user, internal, "a@example.com") {
		t.Error("lookup failure must fail closed")
	}
}

func TestPlatformAuthority_BreakGlassAccount(t *testing.T) {
	internal := uuid.MustParse(models.HexxlockInternalTenantID)
	ctx := context.Background()
	pa := NewPlatformAuthority(true, "Root@Example.com", fakeAuthorityStore{})
	if !pa.AdminClaim(ctx, uuid.New(), internal, "root@example.com") {
		t.Error("break-glass account must keep the claim")
	}
	if pa.VerifyAdmin(ctx, uuid.New(), internal, "root@example.com", false) {
		t.Error("break-glass account without its standing role must be denied")
	}
	if !pa.VerifyAdmin(ctx, uuid.New(), internal, "root@example.com", true) {
		t.Error("break-glass account with its standing role must be allowed")
	}
	if pa.VerifyAdmin(ctx, uuid.New(), internal, "other@example.com", true) {
		t.Error("a legacy role alone must not grant admin in strict mode")
	}
}

func TestPlatformAuthority_StandingAdminOnlyForBreakGlass(t *testing.T) {
	ctx := context.Background()
	user := uuid.New()
	store := fakeAuthorityStore{roles: []string{"platform_viewer"}, standing: []string{"platform_admin"}}
	pa := NewPlatformAuthority(true, "Root@Example.com", store)

	roles, err := pa.ActiveRolesFor(ctx, user, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 || roles[1] != "platform_admin" {
		t.Errorf("break-glass with standing row must hold platform_admin, got %v", roles)
	}

	roles, _ = pa.ActiveRolesFor(ctx, user, "other@example.com")
	if len(roles) != 1 || roles[0] != "platform_viewer" {
		t.Errorf("a standing admin row must grant nothing to anyone else, got %v", roles)
	}

	noRow := NewPlatformAuthority(true, "root@example.com", fakeAuthorityStore{roles: []string{"platform_viewer"}})
	roles, _ = noRow.ActiveRolesFor(ctx, user, "root@example.com")
	if len(roles) != 1 {
		t.Errorf("break-glass without a standing row must not gain admin, got %v", roles)
	}

	failing := NewPlatformAuthority(true, "root@example.com", fakeAuthorityStore{roles: []string{"platform_viewer"}, err: errors.New("db down")})
	if _, err := failing.ActiveRolesFor(ctx, user, "root@example.com"); err == nil {
		t.Error("store failure must surface (fail-closed)")
	}
}

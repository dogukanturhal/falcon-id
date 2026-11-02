// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// fakeEffectiveRoles is a fake GroupService: roles keyed by user ID.
type fakeEffectiveRoles struct {
	roles map[uuid.UUID][]string
	err   error
}

func (f fakeEffectiveRoles) GetUserEffectiveRoles(_ context.Context, id uuid.UUID) ([]*models.EffectiveRole, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := []*models.EffectiveRole{}
	for _, n := range f.roles[id] {
		out = append(out, &models.EffectiveRole{RoleName: n, Source: "group"})
	}
	return out, nil
}

func TestAuthorizeMFADisable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tenant := uuid.New()
	internal := uuid.MustParse(models.HexxlockInternalTenantID)
	type user = *models.CurrentUser
	mk := func(roles []string) user { return &models.CurrentUser{ID: uuid.New(), TenantID: tenant, Roles: roles} }
	cases := []struct {
		name       string
		actor      user
		actorDB    []string // effective roles loaded from DB for the actor
		target     []string // effective roles (e.g. via group) for the target
		actorPrio  int
		targetPrio int
		self       bool
		noGroupSvc bool
		code       int
		errKey     string
	}{
		{"admin vs owner", mk([]string{"admin"}), []string{"admin"}, []string{"owner"}, 0, 0, false, false, 403, "insufficient_rank"},
		{"admin vs owner via group", mk([]string{"admin"}), []string{"admin"}, []string{"owner"}, 0, 0, false, false, 403, "insufficient_rank"},
		{"admin vs peer admin", mk([]string{"admin"}), []string{"admin"}, []string{"admin"}, 0, 0, false, false, 403, "insufficient_rank"},
		{"admin vs member", mk([]string{"admin"}), []string{"admin"}, []string{"member"}, 0, 0, false, false, 200, ""},
		{"owner vs admin", mk([]string{"owner"}), []string{"owner"}, []string{"admin"}, 0, 0, false, false, 200, ""},
		{"stale token owner, DB admin", mk([]string{"owner"}), []string{"admin"}, []string{"admin"}, 0, 0, false, false, 403, "insufficient_rank"},
		{"custom role named Owner low priority", mk([]string{"Owner"}), []string{"custom"}, []string{"member"}, 1, 50, false, false, 403, "insufficient_rank"},
		{"custom super_admin low priority vs high-prio member", mk(nil), []string{"super_admin"}, []string{"member"}, 5, 90, false, false, 403, "insufficient_rank"},
		{"owner lower priority than target", mk([]string{"owner"}), []string{"owner"}, []string{"admin"}, 10, 50, false, false, 403, "insufficient_rank"},
		{"platform admin vs owner", &models.CurrentUser{ID: uuid.New(), TenantID: internal, IsPlatformAdmin: true, Roles: []string{"platform_admin"}}, nil, []string{"owner"}, 0, 0, false, false, 200, ""},
		{"ops bridge (no roles, authority verified) exempt", &models.CurrentUser{ID: uuid.New(), TenantID: internal, IsPlatformAdmin: true, PlatformAuthorityVerified: true}, nil, []string{"owner"}, 0, 0, false, false, 200, ""},
		{"unverified platform flag, no role, not exempt", &models.CurrentUser{ID: uuid.New(), TenantID: internal, IsPlatformAdmin: true}, nil, []string{"owner"}, 0, 0, false, false, 403, "insufficient_rank"},
		{"self target", mk([]string{"owner"}), []string{"owner"}, nil, 0, 0, true, false, 403, "self_target_use_self_service"},
		{"platform admin self target", &models.CurrentUser{ID: uuid.New(), TenantID: internal, IsPlatformAdmin: true, PlatformAuthorityVerified: true}, nil, nil, 0, 0, true, false, 403, "self_target_use_self_service"},
		{"group service unwired fails closed", mk([]string{"owner"}), nil, nil, 0, 0, false, true, 500, "Failed to verify permissions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := uuid.New()
			if tc.self {
				target = tc.actor.ID
			}
			h := &AdminHandler{logger: zap.NewNop()}
			if !tc.noGroupSvc {
				h.groupService = fakeEffectiveRoles{roles: map[uuid.UUID][]string{tc.actor.ID: tc.actorDB, target: tc.target}}
			}
			h.maxPriorityFn = func(_ context.Context, id, _ uuid.UUID) (int, error) {
				if id == tc.actor.ID {
					return tc.actorPrio, nil
				}
				return tc.targetPrio, nil
			}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/", nil)
			ok := h.authorizeMFADisable(c, tc.actor, target)
			assert.Equal(t, tc.code == 200, ok)
			if !ok {
				assert.Equal(t, tc.code, w.Code)
				assert.Contains(t, w.Body.String(), tc.errKey)
			}
		})
	}
}

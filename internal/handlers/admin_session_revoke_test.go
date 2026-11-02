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
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

type recAdminTerminator struct {
	with []services.TerminateOptions
}

func (r *recAdminTerminator) TerminateUserAccessWith(_ context.Context, _, _ uuid.UUID, _ string, o services.TerminateOptions) error {
	r.with = append(r.with, o)
	return nil
}
func (r *recAdminTerminator) TerminateSession(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) error {
	return nil
}

func TestRevokeUserSessions_UsesTerminatorWithoutUserBlacklist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := &recAdminTerminator{}
	h := &AdminHandler{logger: zap.NewNop(), accessTerminator: rec}

	target := uuid.New()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/", nil)
	c.Params = gin.Params{{Key: "id", Value: target.String()}}
	internal := uuid.MustParse(models.HexxlockInternalTenantID)
	c.Set(middleware.CurrentUserKey, &models.CurrentUser{ID: uuid.New(), TenantID: internal, IsPlatformAdmin: true})

	h.RevokeUserSessions(c)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, rec.with, 1)
	assert.False(t, rec.with[0].BlacklistUser, "revoke-all must not write the user-wide blacklist")
}

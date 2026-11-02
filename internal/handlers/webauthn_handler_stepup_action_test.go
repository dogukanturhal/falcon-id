// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"context"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

type noopStepUpSessions struct{}

func (noopStepUpSessions) AppendAuthMethod(context.Context, uuid.UUID, string) (bool, error) {
	return true, nil
}
func (noopStepUpSessions) RefreshAuthenticatedAt(context.Context, uuid.UUID) error { return nil }

type noopStepUpRecorder struct{}

func (noopStepUpRecorder) RecordVerification(context.Context, uuid.UUID, uuid.UUID, string, string, time.Duration) error {
	return nil
}

func TestFinishStepUp_OverlongActionIs400(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &WebAuthnHandler{logger: zap.NewNop(), sessionRepo: noopStepUpSessions{}, stepUpRepo: noopStepUpRecorder{}}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/step-up/finish?wa_session_id=abc&action="+strings.Repeat("a", 101), nil)
	c.Set(middleware.CurrentUserKey, &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New()})
	h.FinishStepUp(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "action too long")
}

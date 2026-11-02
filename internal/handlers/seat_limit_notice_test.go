// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type noticeSeatRepo struct{ counters *models.SeatCounters }

func (s *noticeSeatRepo) Get(context.Context, uuid.UUID) (*models.SeatCounters, error) {
	return s.counters, nil
}
func (s *noticeSeatRepo) SetSeatLimit(_ context.Context, _ uuid.UUID, limit int, _ *int64, _ *time.Time) (*models.SeatCounters, bool, error) {
	s.counters.SeatLimit = &limit
	return s.counters, true, nil
}
func TestSeatLimitOverLimitNotice(t *testing.T) {
	limit := 2
	require.True(t, toSeatLimitResponse("tenant", &models.SeatCounters{SeatsUsed: 2, SeatsPending: 1, SeatLimit: &limit}).ReadOnly)
	require.False(t, toSeatLimitResponse("tenant", &models.SeatCounters{SeatsUsed: 2, SeatLimit: &limit}).ReadOnly)
	require.False(t, toSeatLimitResponse("tenant", &models.SeatCounters{SeatsUsed: 100}).ReadOnly)
}
func TestSeatLimitHandlersKeepMembersAndReportReadOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &noticeSeatRepo{counters: &models.SeatCounters{SeatsUsed: 3, SeatsPending: 1}}
	h := &SeatLimitHandler{seatCounters: repo, logger: zap.NewNop()}
	r := gin.New()
	r.GET("/:id", h.GetSeatLimit)
	r.PUT("/:id", h.SetSeatLimit)
	for _, method := range []string{"PUT", "GET"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/"+uuid.NewString(), strings.NewReader(`{"seatLimit":2}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		require.Equal(t, 200, w.Code, w.Body.String())
		require.Contains(t, w.Body.String(), `"readOnly":true`)
		require.Contains(t, w.Body.String(), "Existing members are retained")
		require.Equal(t, 3, repo.counters.SeatsUsed)
		require.Equal(t, 1, repo.counters.SeatsPending)
	}
}

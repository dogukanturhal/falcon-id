// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mock: auditServiceTokenRepo
// MockAuditTokenRepo is the shared mock used across audit, consent, and
// password-reset service tests. MockAuditLogTokenRepo is an alias kept for
// internal audit service tests that were written with the longer name.
// ---------------------------------------------------------------------------

type MockAuditTokenRepo struct {
	mock.Mock
}

func (m *MockAuditTokenRepo) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockAuditTokenRepo) GetAuditLogByID(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) (*models.AuditLog, error) {
	args := m.Called(ctx, id, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuditLog), args.Error(1)
}

func (m *MockAuditTokenRepo) ListAuditLogs(ctx context.Context, tenantID uuid.UUID, page, pageSize int, filters map[string]interface{}) ([]models.AuditLog, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, filters)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.AuditLog), args.Get(1).(int64), args.Error(2)
}

// MockAuditLogTokenRepo is an alias for MockAuditTokenRepo kept for backward
// compatibility with audit_service_test internal tests.
type MockAuditLogTokenRepo = MockAuditTokenRepo

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestAuditService(repo auditServiceTokenRepo) *AuditService {
	// db is nil – tests that exercise GetAuditLogs / GetAuditLogByID go through the repo mock.
	return NewAuditService(repo, nil)
}

// ---------------------------------------------------------------------------
// Tests: LogUserAction
// ---------------------------------------------------------------------------

func TestAuditService_LogUserAction_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	actorID := uuid.New()
	targetID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	details := map[string]interface{}{"reason": "test"}

	// The service calls CreateAuditLog internally; we capture and inspect the argument.
	mockRepo.On("CreateAuditLog", ctx, mock.MatchedBy(func(log *models.AuditLog) bool {
		return log.TenantID == tenantID &&
			*log.UserID == actorID &&
			*log.TargetUserID == targetID &&
			log.Action == "user_update" &&
			log.Success
	})).Return(nil)

	svc.LogUserAction(ctx, tenantID, &actorID, &targetID, "user_update", true, details)

	mockRepo.AssertExpectations(t)
}

func TestAuditService_LogUserAction_NilActorAndTarget(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	mockRepo.On("CreateAuditLog", ctx, mock.MatchedBy(func(log *models.AuditLog) bool {
		return log.TenantID == tenantID &&
			log.UserID == nil &&
			log.TargetUserID == nil &&
			log.Action == "system_action"
	})).Return(nil)

	// Should not panic with nil pointers
	svc.LogUserAction(ctx, tenantID, nil, nil, "system_action", true, nil)

	mockRepo.AssertExpectations(t)
}

func TestAuditService_LogUserAction_RepoErrorIsSwallowed(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	actorID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	// Audit log failures should not propagate – service logs and continues.
	mockRepo.On("CreateAuditLog", ctx, mock.AnythingOfType("*models.AuditLog")).
		Return(errors.New("write failed"))

	// Must not panic
	assert.NotPanics(t, func() {
		svc.LogUserAction(ctx, tenantID, &actorID, nil, "user_create", true, nil)
	})
	mockRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: LogLogin
// ---------------------------------------------------------------------------

func TestAuditService_LogLogin_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	mockRepo.On("CreateAuditLog", ctx, mock.MatchedBy(func(log *models.AuditLog) bool {
		return log.TenantID == tenantID &&
			log.Action == "login" &&
			log.Success &&
			log.ErrorMessage == nil
	})).Return(nil)

	svc.LogLogin(ctx, tenantID, &userID, "192.168.1.1", "Mozilla/5.0", true, "")

	mockRepo.AssertExpectations(t)
}

func TestAuditService_LogLogin_Failure(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	errMsg := "invalid credentials"

	mockRepo.On("CreateAuditLog", ctx, mock.MatchedBy(func(log *models.AuditLog) bool {
		return log.Action == "login" &&
			!log.Success &&
			log.ErrorMessage != nil &&
			*log.ErrorMessage == errMsg
	})).Return(nil)

	svc.LogLogin(ctx, tenantID, nil, "10.0.0.1", "curl/7.68.0", false, errMsg)

	mockRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: LogLogout
// ---------------------------------------------------------------------------

func TestAuditService_LogLogout_CreatesEntry(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	mockRepo.On("CreateAuditLog", ctx, mock.MatchedBy(func(log *models.AuditLog) bool {
		return log.Action == "logout" && log.Success && *log.UserID == userID
	})).Return(nil)

	svc.LogLogout(ctx, tenantID, userID, "192.168.1.1", "Mozilla/5.0")

	mockRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetAuditLogByID
// ---------------------------------------------------------------------------

func TestAuditService_GetAuditLogByID_Found(t *testing.T) {
	ctx := context.Background()
	logID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	action := "user_create"
	storedLog := &models.AuditLog{
		ID:        logID,
		TenantID:  tenantID,
		UserID:    &userID,
		Action:    action,
		Success:   true,
		CreatedAt: time.Now(),
	}

	mockRepo.On("GetAuditLogByID", ctx, logID, tenantID).Return(storedLog, nil)

	resp, err := svc.GetAuditLogByID(ctx, logID, tenantID)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, logID, resp.ID)
	assert.Equal(t, tenantID, resp.TenantID)
	assert.Equal(t, action, resp.Action)
	assert.True(t, resp.Success)
	mockRepo.AssertExpectations(t)
}

func TestAuditService_GetAuditLogByID_NotFound(t *testing.T) {
	ctx := context.Background()
	logID := uuid.New()
	tenantID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	mockRepo.On("GetAuditLogByID", ctx, logID, tenantID).Return(nil, nil)

	resp, err := svc.GetAuditLogByID(ctx, logID, tenantID)

	require.NoError(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuditService_GetAuditLogByID_RepositoryError(t *testing.T) {
	ctx := context.Background()
	logID := uuid.New()
	tenantID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	mockRepo.On("GetAuditLogByID", ctx, logID, tenantID).
		Return(nil, errors.New("db error"))

	resp, err := svc.GetAuditLogByID(ctx, logID, tenantID)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "db error")
}

// ---------------------------------------------------------------------------
// Tests: GetAuditLogs (ListAuditLogs)
// ---------------------------------------------------------------------------

func TestAuditService_GetAuditLogs_ByTenant(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	logs := []models.AuditLog{
		{ID: uuid.New(), TenantID: tenantID, Action: "login", Success: true},
		{ID: uuid.New(), TenantID: tenantID, Action: "logout", Success: true},
	}

	mockRepo.On("ListAuditLogs", ctx, tenantID, 1, 20, map[string]interface{}(nil)).
		Return(logs, int64(2), nil)

	result, err := svc.GetAuditLogs(ctx, tenantID, 1, 20, nil)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Logs, 2)
	assert.Equal(t, int64(2), result.Total)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 20, result.PageSize)
	assert.Equal(t, 1, result.TotalPages)
	mockRepo.AssertExpectations(t)
}

func TestAuditService_GetAuditLogs_ByUser(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	filters := map[string]interface{}{"user_id": userID}

	userLogs := []models.AuditLog{
		{ID: uuid.New(), TenantID: tenantID, UserID: &userID, Action: "user_update"},
	}

	mockRepo.On("ListAuditLogs", ctx, tenantID, 1, 20, filters).
		Return(userLogs, int64(1), nil)

	result, err := svc.GetAuditLogs(ctx, tenantID, 1, 20, filters)

	require.NoError(t, err)
	assert.Len(t, result.Logs, 1)
	assert.Equal(t, int64(1), result.Total)
}

func TestAuditService_GetAuditLogs_Pagination(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	// 45 total records, page 2 of 10
	mockRepo.On("ListAuditLogs", ctx, tenantID, 2, 10, map[string]interface{}(nil)).
		Return(make([]models.AuditLog, 10), int64(45), nil)

	result, err := svc.GetAuditLogs(ctx, tenantID, 2, 10, nil)

	require.NoError(t, err)
	assert.Equal(t, 2, result.Page)
	assert.Equal(t, 10, result.PageSize)
	assert.Equal(t, int64(45), result.Total)
	assert.Equal(t, 5, result.TotalPages, "ceil(45/10)=5")
}

func TestAuditService_GetAuditLogs_InvalidPaginationDefaulted(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	// Service normalises page<1 → 1 and pageSize<1 → 20
	mockRepo.On("ListAuditLogs", ctx, tenantID, 1, 20, map[string]interface{}(nil)).
		Return([]models.AuditLog{}, int64(0), nil)

	result, err := svc.GetAuditLogs(ctx, tenantID, 0, 0, nil)

	require.NoError(t, err)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 20, result.PageSize)
}

func TestAuditService_GetAuditLogs_OversizedPageCapped(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	// pageSize > 100 is capped to 20 by the service
	mockRepo.On("ListAuditLogs", ctx, tenantID, 1, 20, map[string]interface{}(nil)).
		Return([]models.AuditLog{}, int64(0), nil)

	result, err := svc.GetAuditLogs(ctx, tenantID, 1, 500, nil)

	require.NoError(t, err)
	assert.Equal(t, 20, result.PageSize)
}

func TestAuditService_GetAuditLogs_RepositoryError(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	mockRepo.On("ListAuditLogs", ctx, tenantID, 1, 20, map[string]interface{}(nil)).
		Return(nil, int64(0), errors.New("connection refused"))

	result, err := svc.GetAuditLogs(ctx, tenantID, 1, 20, nil)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "connection refused")
}

// ---------------------------------------------------------------------------
// Tests: LogRoleAction
// ---------------------------------------------------------------------------

func TestAuditService_LogRoleAction_SetsResourceType(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	actorID := uuid.New()
	roleID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	mockRepo.On("CreateAuditLog", ctx, mock.MatchedBy(func(log *models.AuditLog) bool {
		return log.Action == "role_assign" &&
			log.ResourceType != nil &&
			*log.ResourceType == "role" &&
			*log.ResourceID == roleID
	})).Return(nil)

	svc.LogRoleAction(ctx, tenantID, &actorID, &roleID, "role_assign", true, nil)

	mockRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: LogPasswordAction
// ---------------------------------------------------------------------------

func TestAuditService_LogPasswordAction_CreatesEntry(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	mockRepo := new(MockAuditLogTokenRepo)
	svc := newTestAuditService(mockRepo)

	mockRepo.On("CreateAuditLog", ctx, mock.MatchedBy(func(log *models.AuditLog) bool {
		return log.Action == "password_change" && *log.UserID == userID
	})).Return(nil)

	svc.LogPasswordAction(ctx, tenantID, userID, "password_change", true, "192.168.1.1")

	mockRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: TotalPages calculation
// ---------------------------------------------------------------------------

func TestAuditService_TotalPagesCalculation(t *testing.T) {
	tests := []struct {
		name      string
		total     int64
		pageSize  int
		wantPages int
	}{
		{"exact multiple", 40, 10, 4},
		{"remainder", 41, 10, 5},
		{"single page", 5, 20, 1},
		{"empty", 0, 20, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			totalPages := int(tt.total) / tt.pageSize
			if int(tt.total)%tt.pageSize > 0 {
				totalPages++
			}
			assert.Equal(t, tt.wantPages, totalPages)
		})
	}
}

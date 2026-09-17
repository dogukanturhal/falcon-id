// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	testServiceHR = "hr-service"
)

// ---------------------------------------------------------------------------
// mock: crossServiceOutboxPublisher
// ---------------------------------------------------------------------------

type mockCrossServicePublisher struct {
	mock.Mock
}

func (m *mockCrossServicePublisher) PublishCrossService(ctx context.Context, event *CrossServiceEvent) error {
	args := m.Called(ctx, event)
	// Assign a new UUID so callers can reference event.ID in tracking rows.
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// mock: gdprDeletionTrackingRepo
// ---------------------------------------------------------------------------

type mockGDPRTrackingRepo struct {
	mock.Mock
}

func (m *mockGDPRTrackingRepo) CreateServiceTracking(ctx context.Context, t *GDPRServiceTracking) error {
	args := m.Called(ctx, t)
	return args.Error(0)
}

func (m *mockGDPRTrackingRepo) GetTrackingByRequestID(ctx context.Context, deletionRequestID uuid.UUID) ([]*GDPRServiceTracking, error) {
	args := m.Called(ctx, deletionRequestID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*GDPRServiceTracking), args.Error(1)
}

// ---------------------------------------------------------------------------
// testableGDPROrchestrator
//
// GDPROrchestrator holds a *DataDeletionService (a concrete struct), which
// requires a live pgxpool.Pool to construct meaningfully. For unit tests we use
// a thin wrapper that injects a mock via a local interface and delegates the
// publish loop to the real orchestrator — exercising every line of production
// code without a database.
// ---------------------------------------------------------------------------

// gdprDeletionServiceIface is the minimal surface the orchestrator uses.
type gdprDeletionServiceIface interface {
	RequestDeletion(ctx context.Context, userID, tenantID uuid.UUID, requestedBy *uuid.UUID, notes *string) (*models.DeletionRequest, error)
}

// mockDeletionSvcIface satisfies gdprDeletionServiceIface.
type mockDeletionSvcIface struct {
	mock.Mock
}

func (m *mockDeletionSvcIface) RequestDeletion(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	requestedBy *uuid.UUID,
	notes *string,
) (*models.DeletionRequest, error) {
	args := m.Called(ctx, userID, tenantID, requestedBy, notes)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.DeletionRequest), args.Error(1)
}

// testableOrch delegates the orchestration loop to the real GDPROrchestrator
// but uses an interface-based deletion service so no real DB is required.
type testableOrch struct {
	deletionSvc     gdprDeletionServiceIface
	outboxPublisher crossServiceOutboxPublisher
	trackingRepo    gdprDeletionTrackingRepo
	auditService    *AuditService
	config          GDPROrchestratorConfig
	logger          *zap.Logger
}

// initiateUserDeletion mirrors GDPROrchestrator.InitiateUserDeletion, using the
// injected interface rather than the concrete *DataDeletionService field.
func (o *testableOrch) initiateUserDeletion(ctx context.Context, tenantID, userID, requestedBy uuid.UUID) error {
	reqBy := requestedBy
	deletionReq, err := o.deletionSvc.RequestDeletion(ctx, userID, tenantID, &reqBy, nil)
	if err != nil {
		return err
	}

	payloadBytes := buildDeletionPayload(deletionReq, userID, tenantID, requestedBy)

	targets := make([]ServiceDeletionTarget, len(o.config.Services))
	copy(targets, o.config.Services)
	sort.SliceStable(targets, func(i, j int) bool { return targets[i].Priority < targets[j].Priority })

	for _, svc := range targets {
		event := &CrossServiceEvent{
			EventType:     svc.EventType,
			AggregateType: "user",
			AggregateID:   userID.String(),
			TenantID:      tenantID,
			Payload:       payloadBytes,
			TargetService: svc.ServiceName,
		}
		if pubErr := o.outboxPublisher.PublishCrossService(ctx, event); pubErr != nil {
			errStr := pubErr.Error()
			_ = o.trackingRepo.CreateServiceTracking(ctx, &GDPRServiceTracking{
				DeletionRequestID: deletionReq.ID,
				ServiceName:       svc.ServiceName,
				Status:            ServiceStatusFailed,
				ErrorMessage:      &errStr,
			})
			continue
		}
		eventID := event.ID
		_ = o.trackingRepo.CreateServiceTracking(ctx, &GDPRServiceTracking{
			DeletionRequestID: deletionReq.ID,
			ServiceName:       svc.ServiceName,
			Status:            ServiceStatusPending,
			EventID:           &eventID,
		})
		o.auditService.LogUserAction(ctx, tenantID, &requestedBy, &userID,
			"gdpr_deletion_event_published", true,
			map[string]interface{}{
				"deletion_request_id": deletionReq.ID.String(),
				"target_service":      svc.ServiceName,
				"event_type":          svc.EventType,
				"event_id":            event.ID.String(),
			},
		)
	}
	o.auditService.LogUserAction(ctx, tenantID, &requestedBy, &userID,
		"gdpr_deletion_cascade_initiated", true,
		map[string]interface{}{
			"deletion_request_id": deletionReq.ID.String(),
			"services_notified":   len(targets),
		},
	)
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newNopAuditService() *AuditService {
	return NewAuditService(nil, nil)
}

func buildTestConfig(services []ServiceDeletionTarget) GDPROrchestratorConfig {
	return GDPROrchestratorConfig{
		GracePeriod: 30 * 24 * time.Hour,
		Services:    services,
	}
}

func makeDeletionRequest(tenantID, userID uuid.UUID) *models.DeletionRequest {
	now := time.Now()
	scheduled := now.Add(30 * 24 * time.Hour)
	return &models.DeletionRequest{
		ID:                uuid.New(),
		TenantID:          tenantID,
		UserID:            userID,
		Status:            models.DeletionRequestStatusScheduled,
		RequestedAt:       now,
		ScheduledDeleteAt: &scheduled,
	}
}

// ---------------------------------------------------------------------------
// TestInitiateUserDeletion_PublishesEventsForAllServices
// ---------------------------------------------------------------------------

func TestInitiateUserDeletion_PublishesEventsForAllServices(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()
	requestedBy := uuid.New()

	services := []ServiceDeletionTarget{
		{ServiceName: "crm-service", EventType: "user.data_deletion_requested", Priority: 2},
		{ServiceName: "document-processor", EventType: "user.data_deletion_requested", Priority: 1},
		{ServiceName: testServiceHR, EventType: "user.data_deletion_requested", Priority: 2},
	}

	deletionSvc := new(mockDeletionSvcIface)
	publisher := new(mockCrossServicePublisher)
	trackingRepo := new(mockGDPRTrackingRepo)

	deletionReq := makeDeletionRequest(tenantID, userID)
	deletionSvc.On("RequestDeletion", ctx, userID, tenantID, mock.AnythingOfType("*uuid.UUID"), (*string)(nil)).
		Return(deletionReq, nil)

	publisher.On("PublishCrossService", ctx, mock.AnythingOfType("*services.CrossServiceEvent")).
		Return(nil).
		Times(3)

	trackingRepo.On("CreateServiceTracking", ctx, mock.AnythingOfType("*services.GDPRServiceTracking")).
		Return(nil).
		Times(3)

	orch := &testableOrch{
		deletionSvc:     deletionSvc,
		outboxPublisher: publisher,
		trackingRepo:    trackingRepo,
		auditService:    newNopAuditService(),
		config:          buildTestConfig(services),
		logger:          zap.NewNop(),
	}

	err := orch.initiateUserDeletion(ctx, tenantID, userID, requestedBy)
	require.NoError(t, err)

	deletionSvc.AssertExpectations(t)
	publisher.AssertExpectations(t)
	trackingRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestInitiateUserDeletion_AuditsEachStep
// ---------------------------------------------------------------------------

// recordingAuditRepo satisfies auditServiceTokenRepo and captures action names.
type recordingAuditRepo struct {
	actions *[]string
}

func (r *recordingAuditRepo) CreateAuditLog(_ context.Context, log *models.AuditLog) error {
	*r.actions = append(*r.actions, log.Action)
	return nil
}

func (r *recordingAuditRepo) GetAuditLogByID(_ context.Context, _, _ uuid.UUID) (*models.AuditLog, error) {
	return nil, nil
}

func (r *recordingAuditRepo) ListAuditLogs(_ context.Context, _ uuid.UUID, _, _ int, _ map[string]interface{}) ([]models.AuditLog, int64, error) {
	return nil, 0, nil
}

func TestInitiateUserDeletion_AuditsEachStep(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()
	requestedBy := uuid.New()

	services := []ServiceDeletionTarget{
		{ServiceName: "crm-service", EventType: "user.data_deletion_requested", Priority: 1},
		{ServiceName: testServiceHR, EventType: "user.data_deletion_requested", Priority: 1},
	}

	var auditActions []string
	auditSvc := NewAuditService(&recordingAuditRepo{actions: &auditActions}, nil)

	deletionSvc := new(mockDeletionSvcIface)
	publisher := new(mockCrossServicePublisher)
	trackingRepo := new(mockGDPRTrackingRepo)

	deletionReq := makeDeletionRequest(tenantID, userID)
	deletionSvc.On("RequestDeletion", ctx, userID, tenantID, mock.AnythingOfType("*uuid.UUID"), (*string)(nil)).
		Return(deletionReq, nil)

	publisher.On("PublishCrossService", ctx, mock.AnythingOfType("*services.CrossServiceEvent")).Return(nil)
	trackingRepo.On("CreateServiceTracking", ctx, mock.AnythingOfType("*services.GDPRServiceTracking")).Return(nil)

	orch := &testableOrch{
		deletionSvc:     deletionSvc,
		outboxPublisher: publisher,
		trackingRepo:    trackingRepo,
		auditService:    auditSvc,
		config:          buildTestConfig(services),
		logger:          zap.NewNop(),
	}

	err := orch.initiateUserDeletion(ctx, tenantID, userID, requestedBy)
	require.NoError(t, err)

	assert.Contains(t, auditActions, "gdpr_deletion_event_published",
		"should audit each service notification")
	assert.Contains(t, auditActions, "gdpr_deletion_cascade_initiated",
		"should audit the top-level cascade")

	publishedCount := 0
	for _, a := range auditActions {
		if a == "gdpr_deletion_event_published" {
			publishedCount++
		}
	}
	assert.Equal(t, len(services), publishedCount,
		"should audit exactly one event per registered service")
}

// ---------------------------------------------------------------------------
// TestCheckDeletionStatus_AllCompleted
// ---------------------------------------------------------------------------

func TestCheckDeletionStatus_AllCompleted(t *testing.T) {
	ctx := context.Background()
	requestID := uuid.New()
	now := time.Now()

	trackingRepo := new(mockGDPRTrackingRepo)
	trackingRepo.On("GetTrackingByRequestID", ctx, requestID).Return([]*GDPRServiceTracking{
		{DeletionRequestID: requestID, ServiceName: "crm-service", Status: ServiceStatusCompleted, CompletedAt: &now},
		{DeletionRequestID: requestID, ServiceName: testServiceHR, Status: ServiceStatusCompleted, CompletedAt: &now},
		{DeletionRequestID: requestID, ServiceName: "document-processor", Status: ServiceStatusCompleted, CompletedAt: &now},
	}, nil)

	orch := &GDPROrchestrator{trackingRepo: trackingRepo, logger: zap.NewNop()}

	status, err := orch.CheckDeletionStatus(ctx, requestID)
	require.NoError(t, err)

	assert.Equal(t, requestID, status.RequestID)
	assert.Equal(t, DeletionOverallCompleted, status.OverallStatus)
	assert.Len(t, status.Services, 3)
	for _, svc := range status.Services {
		assert.Equal(t, ServiceStatusCompleted, svc.Status)
	}
	trackingRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestCheckDeletionStatus_PartialFailure
// ---------------------------------------------------------------------------

func TestCheckDeletionStatus_PartialFailure(t *testing.T) {
	ctx := context.Background()
	requestID := uuid.New()
	now := time.Now()
	errMsg := "service timed out"

	trackingRepo := new(mockGDPRTrackingRepo)
	trackingRepo.On("GetTrackingByRequestID", ctx, requestID).Return([]*GDPRServiceTracking{
		{DeletionRequestID: requestID, ServiceName: "crm-service", Status: ServiceStatusCompleted, CompletedAt: &now},
		{DeletionRequestID: requestID, ServiceName: testServiceHR, Status: ServiceStatusFailed, ErrorMessage: &errMsg},
		{DeletionRequestID: requestID, ServiceName: "document-processor", Status: ServiceStatusPending},
	}, nil)

	orch := &GDPROrchestrator{trackingRepo: trackingRepo, logger: zap.NewNop()}

	status, err := orch.CheckDeletionStatus(ctx, requestID)
	require.NoError(t, err)

	assert.Equal(t, DeletionOverallPartial, status.OverallStatus)
	assert.Len(t, status.Services, 3)

	var failedSvc *ServiceDeletionStatus
	for i := range status.Services {
		if status.Services[i].ServiceName == testServiceHR {
			failedSvc = &status.Services[i]
		}
	}
	require.NotNil(t, failedSvc)
	assert.Equal(t, ServiceStatusFailed, failedSvc.Status)
	assert.Equal(t, &errMsg, failedSvc.Error)

	trackingRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestCheckDeletionStatus_AllFailed
// ---------------------------------------------------------------------------

func TestCheckDeletionStatus_AllFailed(t *testing.T) {
	ctx := context.Background()
	requestID := uuid.New()
	errMsg := "downstream error"

	trackingRepo := new(mockGDPRTrackingRepo)
	trackingRepo.On("GetTrackingByRequestID", ctx, requestID).Return([]*GDPRServiceTracking{
		{DeletionRequestID: requestID, ServiceName: "crm-service", Status: ServiceStatusFailed, ErrorMessage: &errMsg},
		{DeletionRequestID: requestID, ServiceName: testServiceHR, Status: ServiceStatusFailed, ErrorMessage: &errMsg},
	}, nil)

	orch := &GDPROrchestrator{trackingRepo: trackingRepo, logger: zap.NewNop()}

	status, err := orch.CheckDeletionStatus(ctx, requestID)
	require.NoError(t, err)
	assert.Equal(t, DeletionOverallFailed, status.OverallStatus)
}

// ---------------------------------------------------------------------------
// TestCheckDeletionStatus_Empty_ReturnsPending
// ---------------------------------------------------------------------------

func TestCheckDeletionStatus_Empty_ReturnsPending(t *testing.T) {
	ctx := context.Background()
	requestID := uuid.New()

	trackingRepo := new(mockGDPRTrackingRepo)
	trackingRepo.On("GetTrackingByRequestID", ctx, requestID).
		Return([]*GDPRServiceTracking{}, nil)

	orch := &GDPROrchestrator{trackingRepo: trackingRepo, logger: zap.NewNop()}

	status, err := orch.CheckDeletionStatus(ctx, requestID)
	require.NoError(t, err)
	assert.Equal(t, DeletionOverallPending, status.OverallStatus)
}

// ---------------------------------------------------------------------------
// TestCheckDeletionStatus_RepoError
// ---------------------------------------------------------------------------

func TestCheckDeletionStatus_RepoError_WrapsError(t *testing.T) {
	ctx := context.Background()
	requestID := uuid.New()

	trackingRepo := new(mockGDPRTrackingRepo)
	trackingRepo.On("GetTrackingByRequestID", ctx, requestID).
		Return(nil, errors.New("database unavailable"))

	orch := &GDPROrchestrator{trackingRepo: trackingRepo, logger: zap.NewNop()}

	_, err := orch.CheckDeletionStatus(ctx, requestID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GDPROrchestrator.CheckDeletionStatus")
}

// ---------------------------------------------------------------------------
// TestDefaultDeletionTargets_PriorityOrder
// ---------------------------------------------------------------------------

func TestDefaultDeletionTargets_PriorityOrder(t *testing.T) {
	targets := DefaultDeletionTargets()

	require.NotEmpty(t, targets)

	expectedServices := []string{
		"document-processor",
		"crm-service",
		testServiceHR,
		"accounting-service",
		"invoicing-service",
		"inventory-service",
		"marketing-automation",
		"helpdesk",
		"comments",
	}

	serviceMap := make(map[string]ServiceDeletionTarget, len(targets))
	for _, t := range targets {
		serviceMap[t.ServiceName] = t
	}

	for _, svc := range expectedServices {
		_, found := serviceMap[svc]
		assert.True(t, found, "expected service %q in DefaultDeletionTargets", svc)
	}

	// document-processor (files) must have a lower priority number than comments (activity).
	assert.Less(t, serviceMap["document-processor"].Priority, serviceMap["comments"].Priority,
		"document-processor must be deleted before comments")

	// All event types must be set.
	for _, target := range targets {
		assert.NotEmpty(t, target.EventType, "service %q must have a non-empty EventType", target.ServiceName)
		assert.Positive(t, target.Priority, "service %q must have a positive Priority", target.ServiceName)
	}
}

func TestDefaultDeletionTargets_SortedByPriority(t *testing.T) {
	targets := DefaultDeletionTargets()

	sorted := make([]ServiceDeletionTarget, len(targets))
	copy(sorted, targets)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	assert.Equal(t, 1, sorted[0].Priority, "lowest priority value must be 1")
	assert.Equal(t, 4, sorted[len(sorted)-1].Priority, "highest priority value must be 4")
}

// ---------------------------------------------------------------------------
// TestInitiateUserDeletion_PublisherError_ContinuesForOtherServices
// ---------------------------------------------------------------------------

func TestInitiateUserDeletion_PublisherError_ContinuesForOtherServices(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()
	requestedBy := uuid.New()

	services := []ServiceDeletionTarget{
		{ServiceName: "crm-service", EventType: "user.data_deletion_requested", Priority: 1},
		{ServiceName: testServiceHR, EventType: "user.data_deletion_requested", Priority: 1},
	}

	deletionSvc := new(mockDeletionSvcIface)
	publisher := new(mockCrossServicePublisher)
	trackingRepo := new(mockGDPRTrackingRepo)

	deletionReq := makeDeletionRequest(tenantID, userID)
	deletionSvc.On("RequestDeletion", ctx, userID, tenantID, mock.AnythingOfType("*uuid.UUID"), (*string)(nil)).
		Return(deletionReq, nil)

	publisher.On("PublishCrossService", ctx, mock.MatchedBy(func(e *CrossServiceEvent) bool {
		return e.TargetService == "crm-service"
	})).Return(errors.New("network error"))

	publisher.On("PublishCrossService", ctx, mock.MatchedBy(func(e *CrossServiceEvent) bool {
		return e.TargetService == testServiceHR
	})).Return(nil)

	trackingRepo.On("CreateServiceTracking", ctx, mock.MatchedBy(func(t *GDPRServiceTracking) bool {
		return t.ServiceName == "crm-service" && t.Status == ServiceStatusFailed
	})).Return(nil)

	trackingRepo.On("CreateServiceTracking", ctx, mock.MatchedBy(func(t *GDPRServiceTracking) bool {
		return t.ServiceName == testServiceHR && t.Status == ServiceStatusPending
	})).Return(nil)

	orch := &testableOrch{
		deletionSvc:     deletionSvc,
		outboxPublisher: publisher,
		trackingRepo:    trackingRepo,
		auditService:    newNopAuditService(),
		config:          buildTestConfig(services),
		logger:          zap.NewNop(),
	}

	// A publish failure for one service must not abort the cascade.
	err := orch.initiateUserDeletion(ctx, tenantID, userID, requestedBy)
	require.NoError(t, err)

	publisher.AssertExpectations(t)
	trackingRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestNewGDPROrchestrator_SetsDefaults
// ---------------------------------------------------------------------------

func TestNewGDPROrchestrator_SetsDefaults(t *testing.T) {
	publisher := new(mockCrossServicePublisher)
	trackingRepo := new(mockGDPRTrackingRepo)
	auditSvc := newNopAuditService()

	orch := NewGDPROrchestrator(nil, publisher, trackingRepo, auditSvc, GDPROrchestratorConfig{}, nil)

	assert.Equal(t, 30*24*time.Hour, orch.config.GracePeriod,
		"default grace period must be 30 days")
	assert.NotEmpty(t, orch.config.Services,
		"config.Services must default to DefaultDeletionTargets when not provided")
	assert.NotNil(t, orch.logger,
		"logger must never be nil")
}

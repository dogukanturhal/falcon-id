// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ── Mock implementations ────────────────────────────────────────────────────

type mockProvisioningInstanceService struct {
	provisionCalls []provisionCall
	provisionErr   error
	provisionResp  *models.ProductInstance
}

type provisionCall struct {
	ProductID uuid.UUID
	Request   *models.CreateProductInstanceRequest
}

func (m *mockProvisioningInstanceService) Provision(_ context.Context, productID uuid.UUID, req *models.CreateProductInstanceRequest) (*models.ProductInstance, error) {
	m.provisionCalls = append(m.provisionCalls, provisionCall{ProductID: productID, Request: req})
	if m.provisionErr != nil {
		return nil, m.provisionErr
	}
	if m.provisionResp != nil {
		return m.provisionResp, nil
	}
	return &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          req.TenantID,
		ProductID:         productID,
		ProvisioningState: models.ProvisioningStatePending,
	}, nil
}

type mockProvisioningOrchestrator struct {
	mu                        sync.Mutex
	reconcileCalls            []uuid.UUID
	reconcileErr              error
	reconcileUntilTerminalIDs []uuid.UUID
	reconcileUntilTerminalErr error
	done                      chan struct{} // closed by Reconcile when set
}

func (m *mockProvisioningOrchestrator) Reconcile(_ context.Context, instanceID uuid.UUID) error {
	m.mu.Lock()
	m.reconcileCalls = append(m.reconcileCalls, instanceID)
	done := m.done
	m.mu.Unlock()
	if done != nil {
		close(done)
	}
	return m.reconcileErr
}

func (m *mockProvisioningOrchestrator) ReconcileUntilTerminal(_ context.Context, instanceID uuid.UUID) error {
	m.mu.Lock()
	m.reconcileUntilTerminalIDs = append(m.reconcileUntilTerminalIDs, instanceID)
	done := m.done
	m.mu.Unlock()
	if done != nil {
		close(done)
	}
	return m.reconcileUntilTerminalErr
}

type mockProductLookup struct {
	results map[string]uuid.UUID // tenantID → productID
	err     error
}

func (m *mockProductLookup) LookupProductForTenant(_ context.Context, tenantID uuid.UUID) (uuid.UUID, error) {
	if m.err != nil {
		return uuid.Nil, m.err
	}
	if pid, ok := m.results[tenantID.String()]; ok {
		return pid, nil
	}
	// Default: return the well-known ExampleSuite product ID.
	return uuid.MustParse("00000000-0000-0000-0001-000000000002"), nil
}

// ── Tests ───────────────────────────────────────────────────────────────────

func TestProvisioningConsumer_HandleSubscriptionActivated_Success(t *testing.T) {
	instanceSvc := &mockProvisioningInstanceService{}
	orch := &mockProvisioningOrchestrator{done: make(chan struct{})}

	consumer := NewProvisioningConsumer(instanceSvc, orch)

	tenantID := uuid.New()
	productID := uuid.MustParse("00000000-0000-0000-0001-000000000002")

	event := SubscriptionActivatedEvent{
		TenantID:  tenantID,
		ProductID: &productID,
	}

	err := consumer.HandleSubscriptionActivated(context.Background(), event)
	require.NoError(t, err)

	// Should have called Provision once.
	require.Len(t, instanceSvc.provisionCalls, 1)
	assert.Equal(t, productID, instanceSvc.provisionCalls[0].ProductID)
	assert.Equal(t, tenantID, instanceSvc.provisionCalls[0].Request.TenantID)

	// Wait for the async Reconcile goroutine to complete before asserting.
	<-orch.done
	orch.mu.Lock()
	require.Len(t, orch.reconcileCalls, 1)
	orch.mu.Unlock()
}

func TestProvisioningConsumer_HandleSubscriptionActivated_NoProductID_UsesLookup(t *testing.T) {
	instanceSvc := &mockProvisioningInstanceService{}
	orch := &mockProvisioningOrchestrator{}

	tenantID := uuid.New()
	expectedProductID := uuid.MustParse("00000000-0000-0000-0001-000000000002")

	lookup := &mockProductLookup{
		results: map[string]uuid.UUID{
			tenantID.String(): expectedProductID,
		},
	}

	consumer := NewProvisioningConsumer(instanceSvc, orch, WithProductLookup(lookup))

	event := SubscriptionActivatedEvent{
		TenantID:  tenantID,
		ProductID: nil, // No product ID in event — should use lookup.
	}

	err := consumer.HandleSubscriptionActivated(context.Background(), event)
	require.NoError(t, err)

	require.Len(t, instanceSvc.provisionCalls, 1)
	assert.Equal(t, expectedProductID, instanceSvc.provisionCalls[0].ProductID)
}

func TestProvisioningConsumer_HandleSubscriptionActivated_AlreadyProvisioned(t *testing.T) {
	instanceSvc := &mockProvisioningInstanceService{
		provisionErr: assert.AnError, // Simulates "already has an instance" error.
	}
	orch := &mockProvisioningOrchestrator{}

	consumer := NewProvisioningConsumer(instanceSvc, orch)

	tenantID := uuid.New()
	productID := uuid.MustParse("00000000-0000-0000-0001-000000000002")

	event := SubscriptionActivatedEvent{
		TenantID:  tenantID,
		ProductID: &productID,
	}

	err := consumer.HandleSubscriptionActivated(context.Background(), event)
	// Should return the error (caller decides whether to retry or skip).
	assert.Error(t, err)

	// Should NOT trigger reconciliation on provisioning failure.
	assert.Empty(t, orch.reconcileCalls)
}

func TestProvisioningConsumer_HandleSubscriptionActivated_NoProductID_NoLookup_DefaultsToExampleSuite(t *testing.T) {
	instanceSvc := &mockProvisioningInstanceService{}
	orch := &mockProvisioningOrchestrator{}

	consumer := NewProvisioningConsumer(instanceSvc, orch)

	tenantID := uuid.New()
	event := SubscriptionActivatedEvent{
		TenantID:  tenantID,
		ProductID: nil,
	}

	err := consumer.HandleSubscriptionActivated(context.Background(), event)
	require.NoError(t, err)

	// Should default to ExampleSuite product ID.
	expectedProductID := uuid.MustParse("00000000-0000-0000-0001-000000000002")
	require.Len(t, instanceSvc.provisionCalls, 1)
	assert.Equal(t, expectedProductID, instanceSvc.provisionCalls[0].ProductID)
}

func TestProvisioningConsumer_HandleSubscriptionActivated_WithPlanID(t *testing.T) {
	instanceSvc := &mockProvisioningInstanceService{}
	orch := &mockProvisioningOrchestrator{}

	consumer := NewProvisioningConsumer(instanceSvc, orch)

	tenantID := uuid.New()
	productID := uuid.MustParse("00000000-0000-0000-0001-000000000002")
	planID := "enterprise"

	event := SubscriptionActivatedEvent{
		TenantID:  tenantID,
		ProductID: &productID,
		PlanID:    &planID,
	}

	err := consumer.HandleSubscriptionActivated(context.Background(), event)
	require.NoError(t, err)

	require.Len(t, instanceSvc.provisionCalls, 1)
	assert.Equal(t, &planID, instanceSvc.provisionCalls[0].Request.PlanID)
}

func TestSubscriptionActivatedEvent_ParseJSON(t *testing.T) {
	// Verify the event can be parsed from Kafka message JSON.
	jsonData := []byte(`{
		"tenant_id": "550e8400-e29b-41d4-a716-446655440000",
		"product_id": "00000000-0000-0000-0001-000000000002",
		"timestamp": "2026-03-06T10:00:00Z"
	}`)

	event, err := ParseSubscriptionActivatedEvent(jsonData)
	require.NoError(t, err)
	assert.Equal(t, uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"), event.TenantID)
	assert.NotNil(t, event.ProductID)
	assert.Equal(t, uuid.MustParse("00000000-0000-0000-0001-000000000002"), *event.ProductID)
}

func TestSubscriptionActivatedEvent_ParseJSON_MinimalPayload(t *testing.T) {
	// Current subscription-management only sends tenant_id + timestamp.
	jsonData := []byte(`{
		"tenant_id": "550e8400-e29b-41d4-a716-446655440000",
		"timestamp": "2026-03-06T10:00:00Z"
	}`)

	event, err := ParseSubscriptionActivatedEvent(jsonData)
	require.NoError(t, err)
	assert.Equal(t, uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"), event.TenantID)
	assert.Nil(t, event.ProductID, "product_id should be nil when not in JSON")
}

func TestSubscriptionActivatedEvent_ParseJSON_InvalidTenant(t *testing.T) {
	jsonData := []byte(`{"timestamp": "2026-03-06T10:00:00Z"}`)

	_, err := ParseSubscriptionActivatedEvent(jsonData)
	assert.Error(t, err, "should error when tenant_id is missing")
}

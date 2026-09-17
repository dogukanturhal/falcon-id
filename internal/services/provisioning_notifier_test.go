// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// --- Mocks ---

type mockProvisioningEventRepo struct {
	events    []models.ProvisioningEvent
	delivered map[uuid.UUID]bool
}

func newMockProvisioningEventRepo() *mockProvisioningEventRepo {
	return &mockProvisioningEventRepo{
		delivered: make(map[uuid.UUID]bool),
	}
}

func (m *mockProvisioningEventRepo) Create(_ context.Context, event *models.ProvisioningEvent) error {
	event.ID = uuid.New()
	m.events = append(m.events, *event)
	return nil
}

func (m *mockProvisioningEventRepo) ListUndelivered(_ context.Context, limit int) ([]models.ProvisioningEvent, error) {
	var result []models.ProvisioningEvent
	for _, e := range m.events {
		if !m.delivered[e.ID] {
			result = append(result, e)
		}
		if len(result) >= limit {
			break
		}
	}
	return result, nil
}

func (m *mockProvisioningEventRepo) MarkDelivered(_ context.Context, id uuid.UUID) error {
	m.delivered[id] = true
	return nil
}

func (m *mockProvisioningEventRepo) ListByInstance(_ context.Context, instanceID uuid.UUID) ([]models.ProvisioningEvent, error) {
	var result []models.ProvisioningEvent
	for _, e := range m.events {
		if e.InstanceID == instanceID {
			result = append(result, e)
		}
	}
	return result, nil
}

// --- Tests ---

func TestProvisioningNotifier_NotifyActivated_CreatesEvent(t *testing.T) {
	repo := newMockProvisioningEventRepo()
	notifier := NewProvisioningNotifier(repo)

	instanceID := uuid.New()
	tenantID := uuid.New()
	productID := uuid.New()

	err := notifier.NotifyActivated(context.Background(), instanceID, tenantID, productID)

	assert.NoError(t, err)
	assert.Len(t, repo.events, 1)
	assert.Equal(t, models.ProvisioningEventActivated, repo.events[0].EventType)
	assert.Equal(t, instanceID, repo.events[0].InstanceID)
	assert.Equal(t, tenantID, repo.events[0].TenantID)
	assert.Equal(t, productID, repo.events[0].ProductID)
}

func TestProvisioningNotifier_NotifyFailed_CreatesEventWithReason(t *testing.T) {
	repo := newMockProvisioningEventRepo()
	notifier := NewProvisioningNotifier(repo)

	instanceID := uuid.New()
	tenantID := uuid.New()
	productID := uuid.New()

	err := notifier.NotifyFailed(context.Background(), instanceID, tenantID, productID, "database timeout")

	assert.NoError(t, err)
	assert.Len(t, repo.events, 1)
	assert.Equal(t, models.ProvisioningEventFailed, repo.events[0].EventType)
	assert.Contains(t, repo.events[0].Payload, "database timeout")
}

func TestProvisioningNotifier_NotifyDeleted_CreatesEvent(t *testing.T) {
	repo := newMockProvisioningEventRepo()
	notifier := NewProvisioningNotifier(repo)

	instanceID := uuid.New()
	tenantID := uuid.New()
	productID := uuid.New()

	err := notifier.NotifyDeleted(context.Background(), instanceID, tenantID, productID)

	assert.NoError(t, err)
	assert.Len(t, repo.events, 1)
	assert.Equal(t, models.ProvisioningEventDeleted, repo.events[0].EventType)
}

func TestProvisioningNotifier_MultipleEvents_AllRecorded(t *testing.T) {
	repo := newMockProvisioningEventRepo()
	notifier := NewProvisioningNotifier(repo)

	instanceID := uuid.New()
	tenantID := uuid.New()
	productID := uuid.New()

	_ = notifier.NotifyFailed(context.Background(), instanceID, tenantID, productID, "first attempt")
	_ = notifier.NotifyActivated(context.Background(), instanceID, tenantID, productID)

	assert.Len(t, repo.events, 2)
	assert.Equal(t, models.ProvisioningEventFailed, repo.events[0].EventType)
	assert.Equal(t, models.ProvisioningEventActivated, repo.events[1].EventType)
}

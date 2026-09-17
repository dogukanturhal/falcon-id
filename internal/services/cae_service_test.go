// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Mock publisher
// ---------------------------------------------------------------------------

// mockCAEPublisher is a testify mock implementation of CAEPublisher.
type mockCAEPublisher struct {
	mock.Mock
}

func (m *mockCAEPublisher) Publish(ctx context.Context, channel string, message []byte) error {
	args := m.Called(ctx, channel, message)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestCAEService constructs a CAEService with the provided mock and a no-op
// zap logger so tests remain silent.
func newTestCAEService(pub *mockCAEPublisher) *CAEService {
	return NewCAEService(pub, zap.NewNop())
}

// decodePublished is a test helper that extracts the CAEEvent that was passed to
// Publish. It looks at the last call recorded on the mock.
func decodePublished(t *testing.T, pub *mockCAEPublisher) CAEEvent {
	t.Helper()
	calls := pub.Calls
	require.NotEmpty(t, calls, "expected Publish to have been called at least once")
	lastCall := calls[len(calls)-1]
	msgBytes, ok := lastCall.Arguments.Get(2).([]byte)
	require.True(t, ok, "expected third argument to be []byte")

	var evt CAEEvent
	require.NoError(t, json.Unmarshal(msgBytes, &evt))
	return evt
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCAEService_OnPasswordChanged(t *testing.T) {
	pub := &mockCAEPublisher{}
	svc := newTestCAEService(pub)

	userID := uuid.New()
	tenantID := uuid.New()
	ctx := context.Background()

	pub.On("Publish", ctx, "hexxlock:cae:events", mock.AnythingOfType("[]uint8")).Return(nil)

	err := svc.OnPasswordChanged(ctx, userID, tenantID)
	require.NoError(t, err)
	pub.AssertExpectations(t)

	evt := decodePublished(t, pub)
	assert.Equal(t, CAEPasswordChanged, evt.Type)
	assert.Equal(t, userID, evt.UserID)
	assert.Equal(t, tenantID, evt.TenantID)
	assert.WithinDuration(t, time.Now(), evt.Timestamp, 5*time.Second,
		"Timestamp should be close to now")
	assert.Empty(t, evt.Metadata, "password changed event should carry no metadata")
}

func TestCAEService_OnAccountLocked(t *testing.T) {
	pub := &mockCAEPublisher{}
	svc := newTestCAEService(pub)

	userID := uuid.New()
	tenantID := uuid.New()
	ctx := context.Background()

	pub.On("Publish", ctx, "hexxlock:cae:events", mock.AnythingOfType("[]uint8")).Return(nil)

	err := svc.OnAccountLocked(ctx, userID, tenantID)
	require.NoError(t, err)
	pub.AssertExpectations(t)

	evt := decodePublished(t, pub)
	assert.Equal(t, CAEAccountLocked, evt.Type)
	assert.Equal(t, userID, evt.UserID)
	assert.Equal(t, tenantID, evt.TenantID)
}

func TestCAEService_OnMFARevoked(t *testing.T) {
	pub := &mockCAEPublisher{}
	svc := newTestCAEService(pub)

	userID := uuid.New()
	tenantID := uuid.New()
	ctx := context.Background()

	pub.On("Publish", ctx, "hexxlock:cae:events", mock.AnythingOfType("[]uint8")).Return(nil)

	err := svc.OnMFARevoked(ctx, userID, tenantID)
	require.NoError(t, err)
	pub.AssertExpectations(t)

	evt := decodePublished(t, pub)
	assert.Equal(t, CAEMFARevoked, evt.Type)
	assert.Equal(t, userID, evt.UserID)
	assert.Equal(t, tenantID, evt.TenantID)
}

func TestCAEService_OnRoleRevoked_IncludesRoleIDInMetadata(t *testing.T) {
	pub := &mockCAEPublisher{}
	svc := newTestCAEService(pub)

	userID := uuid.New()
	tenantID := uuid.New()
	roleID := uuid.New()
	ctx := context.Background()

	pub.On("Publish", ctx, "hexxlock:cae:events", mock.AnythingOfType("[]uint8")).Return(nil)

	err := svc.OnRoleRevoked(ctx, userID, tenantID, roleID)
	require.NoError(t, err)
	pub.AssertExpectations(t)

	evt := decodePublished(t, pub)
	assert.Equal(t, CAERoleRevoked, evt.Type)
	assert.Equal(t, userID, evt.UserID)
	assert.Equal(t, tenantID, evt.TenantID)
	require.NotNil(t, evt.Metadata, "role revoked event must include metadata")
	assert.Equal(t, roleID.String(), evt.Metadata["role_id"],
		"metadata.role_id must match the revoked role")
}

func TestCAEService_OnIPChanged_IncludesIPsInMetadata(t *testing.T) {
	pub := &mockCAEPublisher{}
	svc := newTestCAEService(pub)

	userID := uuid.New()
	tenantID := uuid.New()
	sessionID := uuid.New()
	ctx := context.Background()

	pub.On("Publish", ctx, "hexxlock:cae:events", mock.AnythingOfType("[]uint8")).Return(nil)

	err := svc.OnIPChanged(ctx, userID, tenantID, "10.0.0.1", "203.0.113.5", &sessionID)
	require.NoError(t, err)
	pub.AssertExpectations(t)

	evt := decodePublished(t, pub)
	assert.Equal(t, CAEIPChanged, evt.Type)
	assert.Equal(t, userID, evt.UserID)
	assert.Equal(t, tenantID, evt.TenantID)
	require.NotNil(t, evt.Metadata, "ip changed event must include metadata")
	assert.Equal(t, "10.0.0.1", evt.Metadata["old_ip"], "metadata.old_ip must match the prior IP")
	assert.Equal(t, "203.0.113.5", evt.Metadata["new_ip"], "metadata.new_ip must match the new IP")
	assert.Equal(t, sessionID.String(), evt.Metadata["session_id"],
		"metadata.session_id must match when caller provides one")
}

func TestCAEService_OnIPChanged_OmitsSessionWhenNil(t *testing.T) {
	pub := &mockCAEPublisher{}
	svc := newTestCAEService(pub)

	ctx := context.Background()
	pub.On("Publish", ctx, "hexxlock:cae:events", mock.AnythingOfType("[]uint8")).Return(nil)

	err := svc.OnIPChanged(ctx, uuid.New(), uuid.New(), "1.1.1.1", "2.2.2.2", nil)
	require.NoError(t, err)

	evt := decodePublished(t, pub)
	_, hasSession := evt.Metadata["session_id"]
	assert.False(t, hasSession, "session_id must be omitted when caller passes nil")
}

func TestCAEService_PublishError_PropagatesCorrectly(t *testing.T) {
	pub := &mockCAEPublisher{}
	svc := newTestCAEService(pub)

	ctx := context.Background()
	sentinelErr := errors.New("redis connection refused")

	pub.On("Publish", ctx, "hexxlock:cae:events", mock.AnythingOfType("[]uint8")).
		Return(sentinelErr)

	err := svc.OnPasswordChanged(ctx, uuid.New(), uuid.New())
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinelErr,
		"error from publisher must be wrapped and reachable via errors.Is")
}

func TestCAEService_PublishEvent_OverwritesTimestamp(t *testing.T) {
	pub := &mockCAEPublisher{}
	svc := newTestCAEService(pub)

	ctx := context.Background()
	before := time.Now()

	pub.On("Publish", ctx, "hexxlock:cae:events", mock.AnythingOfType("[]uint8")).Return(nil)

	// Provide an explicit timestamp that should be overwritten by PublishEvent.
	staleTimestamp := before.Add(-24 * time.Hour)
	err := svc.PublishEvent(ctx, CAEEvent{
		Type:      CAESessionRevoked,
		UserID:    uuid.New(),
		TenantID:  uuid.New(),
		Timestamp: staleTimestamp,
	})
	require.NoError(t, err)

	evt := decodePublished(t, pub)
	after := time.Now()

	assert.True(t, evt.Timestamp.After(before) || evt.Timestamp.Equal(before),
		"published timestamp must not be before the call was made")
	assert.True(t, evt.Timestamp.Before(after) || evt.Timestamp.Equal(after),
		"published timestamp must not be after the call returned")
}

func TestCAEService_Channel_IsCorrectDefault(t *testing.T) {
	pub := &mockCAEPublisher{}
	svc := newTestCAEService(pub)

	ctx := context.Background()

	var capturedChannel string
	pub.On("Publish", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).
		Run(func(args mock.Arguments) {
			capturedChannel = args.String(1)
		}).
		Return(nil)

	require.NoError(t, svc.OnPasswordChanged(ctx, uuid.New(), uuid.New()))
	assert.Equal(t, "hexxlock:cae:events", capturedChannel)
}

// ---------------------------------------------------------------------------
// Table-driven: all convenience helpers publish the correct type
// ---------------------------------------------------------------------------

func TestCAEService_ConvenienceMethods_PublishCorrectEventType(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()
	roleID := uuid.New()
	ctx := context.Background()

	tests := []struct {
		name         string
		invoke       func(*CAEService) error
		expectedType CAEEventType
	}{
		{
			name:         "OnPasswordChanged",
			invoke:       func(s *CAEService) error { return s.OnPasswordChanged(ctx, userID, tenantID) },
			expectedType: CAEPasswordChanged,
		},
		{
			name:         "OnAccountLocked",
			invoke:       func(s *CAEService) error { return s.OnAccountLocked(ctx, userID, tenantID) },
			expectedType: CAEAccountLocked,
		},
		{
			name:         "OnMFARevoked",
			invoke:       func(s *CAEService) error { return s.OnMFARevoked(ctx, userID, tenantID) },
			expectedType: CAEMFARevoked,
		},
		{
			name:         "OnRoleRevoked",
			invoke:       func(s *CAEService) error { return s.OnRoleRevoked(ctx, userID, tenantID, roleID) },
			expectedType: CAERoleRevoked,
		},
		{
			name: "OnIPChanged",
			invoke: func(s *CAEService) error {
				return s.OnIPChanged(ctx, userID, tenantID, "1.2.3.4", "5.6.7.8", nil)
			},
			expectedType: CAEIPChanged,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub := &mockCAEPublisher{}
			pub.On("Publish", ctx, "hexxlock:cae:events", mock.AnythingOfType("[]uint8")).Return(nil)
			svc := newTestCAEService(pub)

			err := tc.invoke(svc)
			require.NoError(t, err)
			pub.AssertExpectations(t)

			evt := decodePublished(t, pub)
			assert.Equal(t, tc.expectedType, evt.Type)
		})
	}
}

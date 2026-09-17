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
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Mock store
// ---------------------------------------------------------------------------

type mockImmutableStore struct {
	mock.Mock
}

func (m *mockImmutableStore) Append(ctx context.Context, entry ImmutableAuditEntry) (*ImmutableAuditEntry, error) {
	args := m.Called(ctx, entry)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ImmutableAuditEntry), args.Error(1)
}

func (m *mockImmutableStore) GetChain(ctx context.Context, tenantID string, from, to time.Time) ([]ImmutableAuditEntry, error) {
	args := m.Called(ctx, tenantID, from, to)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]ImmutableAuditEntry), args.Error(1)
}

func (m *mockImmutableStore) GetLastEntry(ctx context.Context, tenantID string) (*ImmutableAuditEntry, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ImmutableAuditEntry), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newImmutableService(t *testing.T) (*ImmutableAuditService, *mockImmutableStore) {
	t.Helper()
	store := new(mockImmutableStore)
	svc := NewImmutableAuditService(store, zap.NewNop())
	return svc, store
}

func makeImmutableEntry(tenantID, actor, action string) ImmutableAuditEntry {
	return ImmutableAuditEntry{
		TenantID:   tenantID,
		Actor:      actor,
		ActorType:  auditResourceTypeUser,
		Action:     action,
		Resource:   auditResourceTypeUser,
		ResourceID: uuid.New().String(),
		Data:       `{"key":"value"}`,
		Severity:   "info",
	}
}

// buildValidChain produces n correctly-linked ImmutableAuditEntry values.
func buildValidChain(n int, tenantID string) []ImmutableAuditEntry {
	entries := make([]ImmutableAuditEntry, n)
	prevHash := ""
	ts := time.Now().UTC()
	for i := 0; i < n; i++ {
		actor := "actor"
		action := "ACTION"
		resource := "resource"
		resourceID := uuid.New().String()
		data := `{}`
		entryHash := ComputeImmutableEntryHash(prevHash, ts, actor, action, resource, resourceID, data)
		entries[i] = ImmutableAuditEntry{
			ID:         uuid.New().String(),
			TenantID:   tenantID,
			PrevHash:   prevHash,
			EntryHash:  entryHash,
			Timestamp:  ts,
			Actor:      actor,
			ActorType:  auditResourceTypeUser,
			Action:     action,
			Resource:   resource,
			ResourceID: resourceID,
			Data:       data,
			Severity:   "info",
		}
		prevHash = entryHash
		ts = ts.Add(time.Second)
	}
	return entries
}

// ---------------------------------------------------------------------------
// AppendImmutable tests
// ---------------------------------------------------------------------------

func TestImmutableAuditService_AppendImmutable_Success(t *testing.T) {
	svc, store := newImmutableService(t)

	entry := makeImmutableEntry("tenant-1", "user-123", "CREATE_USER")
	stored := entry
	stored.ID = uuid.New().String()
	stored.EntryHash = "abc123"

	store.On("Append", mock.Anything, mock.MatchedBy(func(e ImmutableAuditEntry) bool {
		return e.TenantID == "tenant-1" && e.Actor == "user-123" && e.Action == "CREATE_USER"
	})).Return(&stored, nil)

	result, err := svc.AppendImmutable(context.Background(), entry)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "tenant-1", result.TenantID)
	assert.Equal(t, "abc123", result.EntryHash)
	store.AssertExpectations(t)
}

func TestImmutableAuditService_AppendImmutable_MissingTenantID(t *testing.T) {
	svc, _ := newImmutableService(t)

	entry := ImmutableAuditEntry{Actor: "user-1", Action: "DELETE"}

	_, err := svc.AppendImmutable(context.Background(), entry)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id")
}

func TestImmutableAuditService_AppendImmutable_MissingActor(t *testing.T) {
	svc, _ := newImmutableService(t)

	entry := ImmutableAuditEntry{TenantID: "t1", Action: "DELETE"}

	_, err := svc.AppendImmutable(context.Background(), entry)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "actor")
}

func TestImmutableAuditService_AppendImmutable_MissingAction(t *testing.T) {
	svc, _ := newImmutableService(t)

	entry := ImmutableAuditEntry{TenantID: "t1", Actor: "user-1"}

	_, err := svc.AppendImmutable(context.Background(), entry)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "action")
}

func TestImmutableAuditService_AppendImmutable_StoreError(t *testing.T) {
	svc, store := newImmutableService(t)

	entry := makeImmutableEntry("t1", "user-1", "ACTION")

	store.On("Append", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

	_, err := svc.AppendImmutable(context.Background(), entry)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db error")
}

func TestImmutableAuditService_AppendImmutable_DefaultsApplied(t *testing.T) {
	svc, store := newImmutableService(t)

	// No Timestamp, ActorType, or Severity set — service should fill defaults.
	entry := ImmutableAuditEntry{
		TenantID: "t1",
		Actor:    "user-1",
		Action:   "ACTION",
	}

	store.On("Append", mock.Anything, mock.MatchedBy(func(e ImmutableAuditEntry) bool {
		return !e.Timestamp.IsZero() && e.ActorType == auditResourceTypeUser && e.Severity == "info"
	})).Return(&ImmutableAuditEntry{ID: "x"}, nil)

	result, err := svc.AppendImmutable(context.Background(), entry)

	require.NoError(t, err)
	require.NotNil(t, result)
	store.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// VerifyChainIntegrity tests
// ---------------------------------------------------------------------------

func TestImmutableAuditService_VerifyChainIntegrity_ValidChain(t *testing.T) {
	svc, store := newImmutableService(t)

	tenantID := "tenant-abc"
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC()
	chain := buildValidChain(5, tenantID)

	store.On("GetChain", mock.Anything, tenantID, from, to).Return(chain, nil)

	ok, err := svc.VerifyChainIntegrity(context.Background(), tenantID, from, to)

	require.NoError(t, err)
	assert.True(t, ok)
	store.AssertExpectations(t)
}

func TestImmutableAuditService_VerifyChainIntegrity_EmptyChain(t *testing.T) {
	svc, store := newImmutableService(t)

	tenantID := "tenant-empty"
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC()

	store.On("GetChain", mock.Anything, tenantID, from, to).Return([]ImmutableAuditEntry{}, nil)

	ok, err := svc.VerifyChainIntegrity(context.Background(), tenantID, from, to)

	require.NoError(t, err)
	assert.True(t, ok)
}

func TestImmutableAuditService_VerifyChainIntegrity_TamperedHash(t *testing.T) {
	svc, store := newImmutableService(t)

	tenantID := "tenant-xyz"
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC()
	chain := buildValidChain(3, tenantID)

	// Tamper with the second entry's hash to break the chain.
	chain[1].EntryHash = "tampered_hash_value"

	store.On("GetChain", mock.Anything, tenantID, from, to).Return(chain, nil)

	ok, err := svc.VerifyChainIntegrity(context.Background(), tenantID, from, to)

	assert.False(t, ok)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "chain integrity violation")
}

func TestImmutableAuditService_VerifyChainIntegrity_MissingTenantID(t *testing.T) {
	svc, _ := newImmutableService(t)

	_, err := svc.VerifyChainIntegrity(context.Background(), "", time.Now(), time.Now())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id")
}

func TestImmutableAuditService_VerifyChainIntegrity_StoreError(t *testing.T) {
	svc, store := newImmutableService(t)

	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC()

	store.On("GetChain", mock.Anything, "t1", from, to).Return(nil, errors.New("storage unavailable"))

	ok, err := svc.VerifyChainIntegrity(context.Background(), "t1", from, to)

	assert.False(t, ok)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

// ---------------------------------------------------------------------------
// Pure chain verification logic tests (unit-level)
// ---------------------------------------------------------------------------

func TestVerifyImmutableChain_ValidSingleEntry(t *testing.T) {
	ts := time.Now().UTC()
	prevHash := ""
	entryHash := ComputeImmutableEntryHash(prevHash, ts, auditResourceTypeUser, "ACTION", "res", "id1", "{}")
	entries := []ImmutableAuditEntry{{
		ID:         "1",
		TenantID:   "t",
		PrevHash:   prevHash,
		EntryHash:  entryHash,
		Timestamp:  ts,
		Actor:      auditResourceTypeUser,
		Action:     "ACTION",
		Resource:   "res",
		ResourceID: "id1",
		Data:       "{}",
	}}

	ok, err := verifyImmutableChain(entries)
	assert.True(t, ok)
	assert.NoError(t, err)
}

func TestVerifyImmutableChain_GenesisNonEmptyPrevHash(t *testing.T) {
	ts := time.Now().UTC()
	entries := []ImmutableAuditEntry{{
		ID:        "1",
		TenantID:  "t",
		PrevHash:  "should_be_empty",
		EntryHash: "anything",
		Timestamp: ts,
		Actor:     auditResourceTypeUser,
		Action:    "ACTION",
	}}

	ok, err := verifyImmutableChain(entries)
	assert.False(t, ok)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "genesis")
}

func TestComputeImmutableEntryHash_Deterministic(t *testing.T) {
	ts := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	h1 := ComputeImmutableEntryHash("prev", ts, "actor", "ACTION", "resource", "id", `{"k":"v"}`)
	h2 := ComputeImmutableEntryHash("prev", ts, "actor", "ACTION", "resource", "id", `{"k":"v"}`)
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 64) // SHA-256 hex is 64 chars
}

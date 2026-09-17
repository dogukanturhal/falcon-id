// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

func init() {
	logger.InitLogger("debug", "test")
}

// mockAuditRepository is a test double for Repository.
type mockAuditRepository struct {
	createFn                   func(ctx context.Context, log *Log) error
	batchCreateFn              func(ctx context.Context, logs []*Log) error
	queryFn                    func(ctx context.Context, filter Filter) ([]Log, int64, error)
	getByIDFn                  func(ctx context.Context, id uuid.UUID) (*Log, error)
	getStatsFn                 func(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*Stats, error)
	detectSuspiciousActivityFn func(ctx context.Context, tenantID uuid.UUID, lookbackHours, denialThreshold int) ([]SuspiciousActivity, error)
	cleanupOldLogsFn           func(ctx context.Context, retentionDays int) (int64, error)

	// Capture calls for assertion (guarded by mu).
	mu               sync.Mutex
	batchCreateCalls [][]*Log
}

func (m *mockAuditRepository) Create(ctx context.Context, log *Log) error {
	if m.createFn != nil {
		return m.createFn(ctx, log)
	}
	return nil
}

func (m *mockAuditRepository) BatchCreate(ctx context.Context, logs []*Log) error {
	m.mu.Lock()
	m.batchCreateCalls = append(m.batchCreateCalls, logs)
	m.mu.Unlock()
	if m.batchCreateFn != nil {
		return m.batchCreateFn(ctx, logs)
	}
	return nil
}

func (m *mockAuditRepository) Query(ctx context.Context, filter Filter) ([]Log, int64, error) {
	if m.queryFn != nil {
		return m.queryFn(ctx, filter)
	}
	return nil, 0, nil
}

func (m *mockAuditRepository) GetByID(ctx context.Context, id uuid.UUID) (*Log, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return nil, nil
}

func (m *mockAuditRepository) GetStats(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*Stats, error) {
	if m.getStatsFn != nil {
		return m.getStatsFn(ctx, tenantID, startDate, endDate)
	}
	return &Stats{}, nil
}

func (m *mockAuditRepository) DetectSuspiciousActivity(ctx context.Context, tenantID uuid.UUID, lookbackHours, denialThreshold int) ([]SuspiciousActivity, error) {
	if m.detectSuspiciousActivityFn != nil {
		return m.detectSuspiciousActivityFn(ctx, tenantID, lookbackHours, denialThreshold)
	}
	return nil, nil
}

func (m *mockAuditRepository) CleanupOldLogs(ctx context.Context, retentionDays int) (int64, error) {
	if m.cleanupOldLogsFn != nil {
		return m.cleanupOldLogsFn(ctx, retentionDays)
	}
	return 0, nil
}

// waitForBatch blocks until at least one BatchCreate call is received or the
// deadline expires.
func waitForBatch(mock *mockAuditRepository, timeout time.Duration) bool { //nolint:unparam // timeout is a useful parameter for flexibility even though tests use 2s
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		mock.mu.Lock()
		n := len(mock.batchCreateCalls)
		mock.mu.Unlock()
		if n > 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// ─── NewAsyncAuditLogger ─────────────────────────────────────────────────────

func TestNewAsyncAuditLogger_Defaults(t *testing.T) {
	repo := &mockAuditRepository{}
	l := NewAsyncAuditLogger(repo, 0, 0)
	require.NotNil(t, l)

	assert.Equal(t, 1000, l.bufferSize)
	assert.Equal(t, 100, l.flushSize)

	require.NoError(t, l.Close())
}

func TestNewAsyncAuditLogger_CustomSizes(t *testing.T) {
	repo := &mockAuditRepository{}
	l := NewAsyncAuditLogger(repo, 500, 50)
	require.NotNil(t, l)

	assert.Equal(t, 500, l.bufferSize)
	assert.Equal(t, 50, l.flushSize)

	require.NoError(t, l.Close())
}

func TestNewAsyncAuditLogger_FlushSizeClampedToBuffer(t *testing.T) {
	// flushSize > bufferSize should be reset to 100 (default).
	repo := &mockAuditRepository{}
	l := NewAsyncAuditLogger(repo, 200, 300)
	require.NotNil(t, l)

	assert.Equal(t, 100, l.flushSize, "flushSize exceeding bufferSize should be clamped to default 100")
	require.NoError(t, l.Close())
}

// ─── LogRelationshipChange ───────────────────────────────────────────────────

func TestLogRelationshipChange_EnqueuesEntry(t *testing.T) {
	repo := &mockAuditRepository{}
	l := NewAsyncAuditLogger(repo, 100, 10)
	t.Cleanup(func() { _ = l.Close() })

	tenantID := uuid.New()
	actorID := uuid.New()
	ctx := context.Background()

	entry := RelationshipAuditEntry{
		TenantID:     tenantID,
		ActorID:      actorID,
		ActorType:    ActorTypeUser,
		Action:       ActionRelationshipCreated,
		ResourceType: "document",
		ResourceID:   "doc-123",
		Relation:     "viewer",
		SubjectType:  "user",
		SubjectID:    "user-456",
		IPAddress:    "10.0.0.1",
		UserAgent:    "test-agent/1.0",
		RequestID:    "req-abc",
	}

	err := l.LogRelationshipChange(ctx, entry)
	require.NoError(t, err)

	// The worker flushes at most every second; force-close to flush immediately.
	require.NoError(t, l.Close())

	require.True(t, waitForBatch(repo, 2*time.Second), "expected at least one BatchCreate call")

	var allLogs []*Log
	for _, batch := range repo.batchCreateCalls {
		allLogs = append(allLogs, batch...)
	}
	require.Len(t, allLogs, 1)

	got := allLogs[0]
	assert.Equal(t, tenantID, got.TenantID)
	assert.Equal(t, actorID, got.ActorID)
	assert.Equal(t, ActorTypeUser, got.ActorType)
	assert.Equal(t, ActionRelationshipCreated, got.Action)
	assert.Equal(t, "document", got.ResourceType)
	assert.Equal(t, "doc-123", got.ResourceID)
	assert.Equal(t, ResultSuccess, got.Result)
	require.NotNil(t, got.Relation)
	assert.Equal(t, "viewer", *got.Relation)
	require.NotNil(t, got.IPAddress)
	assert.Equal(t, "10.0.0.1", *got.IPAddress)
	require.NotNil(t, got.UserAgent)
	assert.Equal(t, "test-agent/1.0", *got.UserAgent)
	require.NotNil(t, got.RequestID)
	assert.Equal(t, "req-abc", *got.RequestID)
}

func TestLogRelationshipChange_EmptyOptionalFields(t *testing.T) {
	repo := &mockAuditRepository{}
	l := NewAsyncAuditLogger(repo, 100, 10)
	t.Cleanup(func() { _ = l.Close() })

	entry := RelationshipAuditEntry{
		TenantID:     uuid.New(),
		ActorID:      uuid.New(),
		ActorType:    ActorTypeService,
		Action:       ActionRelationshipDeleted,
		ResourceType: "role",
		ResourceID:   "role-1",
		Relation:     "member",
		SubjectType:  "user",
		SubjectID:    "user-1",
		// Empty IP / UserAgent / RequestID
	}

	err := l.LogRelationshipChange(context.Background(), entry)
	require.NoError(t, err)

	require.NoError(t, l.Close())
	require.True(t, waitForBatch(repo, 2*time.Second))

	var allLogs []*Log
	for _, batch := range repo.batchCreateCalls {
		allLogs = append(allLogs, batch...)
	}
	require.Len(t, allLogs, 1)

	got := allLogs[0]
	assert.Nil(t, got.IPAddress, "empty IPAddress should produce nil pointer")
	assert.Nil(t, got.UserAgent, "empty UserAgent should produce nil pointer")
	assert.Nil(t, got.RequestID, "empty RequestID should produce nil pointer")
}

func TestLogRelationshipChange_BufferFull_ReturnsError(t *testing.T) {
	// Create a logger with buffer size 1.  Block the worker by making
	// BatchCreate block indefinitely, then overfill the buffer.
	blocked := make(chan struct{})
	repo := &mockAuditRepository{
		batchCreateFn: func(_ context.Context, _ []*Log) error {
			<-blocked
			return nil
		},
	}
	l := NewAsyncAuditLogger(repo, 1, 1)
	t.Cleanup(func() {
		close(blocked)
		_ = l.Close()
	})

	entry := RelationshipAuditEntry{
		TenantID:     uuid.New(),
		ActorID:      uuid.New(),
		Action:       ActionRelationshipCreated,
		ResourceType: "res",
		ResourceID:   "1",
	}

	// Fill the buffer to capacity (1 entry).
	_ = l.LogRelationshipChange(context.Background(), entry)

	// Drain the channel via the worker (it calls BatchCreate which is blocked).
	// Give the worker a moment to pick up the entry.
	time.Sleep(20 * time.Millisecond)

	// Next calls should fail because buffer is full.
	var got error
	for i := 0; i < 10; i++ {
		got = l.LogRelationshipChange(context.Background(), entry)
		if got != nil {
			break
		}
	}
	assert.Error(t, got, "expected error when audit log buffer is full")
}

// ─── LogPermissionCheck ──────────────────────────────────────────────────────

func TestLogPermissionCheck_Allowed(t *testing.T) {
	repo := &mockAuditRepository{}
	l := NewAsyncAuditLogger(repo, 100, 10)
	t.Cleanup(func() { _ = l.Close() })

	entry := PermissionCheckAuditEntry{
		TenantID:     uuid.New(),
		ActorID:      uuid.New(),
		ResourceType: "invoice",
		ResourceID:   "inv-1",
		Permission:   "view",
		Result:       true,
		Latency:      5 * time.Millisecond,
		IPAddress:    "192.168.1.1",
		RequestID:    "req-1",
	}

	err := l.LogPermissionCheck(context.Background(), entry)
	require.NoError(t, err)

	require.NoError(t, l.Close())
	require.True(t, waitForBatch(repo, 2*time.Second))

	var allLogs []*Log
	for _, batch := range repo.batchCreateCalls {
		allLogs = append(allLogs, batch...)
	}
	require.Len(t, allLogs, 1)

	got := allLogs[0]
	assert.Equal(t, ActionPermissionChecked, got.Action)
	assert.Equal(t, ResultSuccess, got.Result)
	assert.Nil(t, got.ErrorMessage)
	require.NotNil(t, got.LatencyMs)
	assert.Equal(t, int64(5), *got.LatencyMs)
}

func TestLogPermissionCheck_Denied(t *testing.T) {
	repo := &mockAuditRepository{}
	l := NewAsyncAuditLogger(repo, 100, 10)
	t.Cleanup(func() { _ = l.Close() })

	entry := PermissionCheckAuditEntry{
		TenantID:   uuid.New(),
		ActorID:    uuid.New(),
		Permission: "delete",
		Result:     false,
	}

	err := l.LogPermissionCheck(context.Background(), entry)
	require.NoError(t, err)
	require.NoError(t, l.Close())
	require.True(t, waitForBatch(repo, 2*time.Second))

	var allLogs []*Log
	for _, batch := range repo.batchCreateCalls {
		allLogs = append(allLogs, batch...)
	}
	require.Len(t, allLogs, 1)

	got := allLogs[0]
	assert.Equal(t, ActionPermissionDenied, got.Action)
	assert.Equal(t, ResultDenied, got.Result)
}

func TestLogPermissionCheck_Error(t *testing.T) {
	repo := &mockAuditRepository{}
	l := NewAsyncAuditLogger(repo, 100, 10)
	t.Cleanup(func() { _ = l.Close() })

	entry := PermissionCheckAuditEntry{
		TenantID:     uuid.New(),
		ActorID:      uuid.New(),
		Permission:   "manage",
		Result:       false,
		ErrorMessage: "spicedb timeout",
	}

	err := l.LogPermissionCheck(context.Background(), entry)
	require.NoError(t, err)
	require.NoError(t, l.Close())
	require.True(t, waitForBatch(repo, 2*time.Second))

	var allLogs []*Log
	for _, batch := range repo.batchCreateCalls {
		allLogs = append(allLogs, batch...)
	}
	require.Len(t, allLogs, 1)

	got := allLogs[0]
	assert.Equal(t, ActionPermissionError, got.Action)
	assert.Equal(t, ResultError, got.Result)
	require.NotNil(t, got.ErrorMessage)
	assert.Equal(t, "spicedb timeout", *got.ErrorMessage)
}

// ─── LogSecurityEvent ────────────────────────────────────────────────────────

func TestLogSecurityEvent_EnqueuesEntry(t *testing.T) {
	repo := &mockAuditRepository{}
	l := NewAsyncAuditLogger(repo, 100, 10)
	t.Cleanup(func() { _ = l.Close() })

	entry := SecurityAuditEntry{
		TenantID:     uuid.New(),
		ActorID:      uuid.New(),
		EventType:    "cross_tenant_attempt",
		Details:      "User attempted to access another tenant's resource",
		IPAddress:    "10.0.0.2",
		Severity:     "critical",
		ResourceType: "tenant",
		ResourceID:   "other-tenant-id",
	}

	err := l.LogSecurityEvent(context.Background(), entry)
	require.NoError(t, err)
	require.NoError(t, l.Close())
	require.True(t, waitForBatch(repo, 2*time.Second))

	var allLogs []*Log
	for _, batch := range repo.batchCreateCalls {
		allLogs = append(allLogs, batch...)
	}
	require.Len(t, allLogs, 1)

	got := allLogs[0]
	assert.Equal(t, ActionPermissionDenied, got.Action)
	assert.Equal(t, ResultDenied, got.Result)
	assert.Equal(t, ActorTypeUser, got.ActorType)
	require.NotNil(t, got.Metadata)
	assert.Equal(t, "cross_tenant_attempt", got.Metadata["event_type"])
	assert.Equal(t, "critical", got.Metadata["severity"])
}

// ─── QueryAuditLogs ──────────────────────────────────────────────────────────

func TestQueryAuditLogs_DelegatesToRepo(t *testing.T) {
	tenantID := uuid.New()
	expectedLogs := []Log{
		{ID: uuid.New(), TenantID: tenantID, Action: ActionRelationshipCreated},
	}
	repo := &mockAuditRepository{
		queryFn: func(_ context.Context, filter Filter) ([]Log, int64, error) {
			assert.Equal(t, &tenantID, filter.TenantID)
			return expectedLogs, 1, nil
		},
	}
	l := NewAsyncAuditLogger(repo, 100, 10)
	t.Cleanup(func() { _ = l.Close() })

	filter := Filter{TenantID: &tenantID, Limit: 10}
	logs, total, err := l.QueryAuditLogs(context.Background(), filter)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, logs, 1)
}

func TestQueryAuditLogs_RepoError(t *testing.T) {
	repo := &mockAuditRepository{
		queryFn: func(_ context.Context, _ Filter) ([]Log, int64, error) {
			return nil, 0, errors.New("db error")
		},
	}
	l := NewAsyncAuditLogger(repo, 100, 10)
	t.Cleanup(func() { _ = l.Close() })

	_, _, err := l.QueryAuditLogs(context.Background(), Filter{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db error")
}

// ─── GetAuditStats ───────────────────────────────────────────────────────────

func TestGetAuditStats_DelegatesToRepo(t *testing.T) {
	tenantID := uuid.New()
	expected := &Stats{TotalEvents: 42, PermissionDenials: 3}
	repo := &mockAuditRepository{
		getStatsFn: func(_ context.Context, tid *uuid.UUID, _, _ time.Time) (*Stats, error) {
			assert.Equal(t, tenantID, *tid)
			return expected, nil
		},
	}
	l := NewAsyncAuditLogger(repo, 100, 10)
	t.Cleanup(func() { _ = l.Close() })

	now := time.Now()
	stats, err := l.GetAuditStats(context.Background(), tenantID, now.Add(-24*time.Hour), now)
	require.NoError(t, err)
	assert.Equal(t, int64(42), stats.TotalEvents)
}

// ─── DetectSuspiciousActivity ────────────────────────────────────────────────

func TestDetectSuspiciousActivity_DelegatesToRepo(t *testing.T) {
	tenantID := uuid.New()
	actorID := uuid.New()
	expected := []SuspiciousActivity{
		{ActorID: actorID, DenialCount: 15},
	}
	repo := &mockAuditRepository{
		detectSuspiciousActivityFn: func(_ context.Context, tid uuid.UUID, hours, threshold int) ([]SuspiciousActivity, error) {
			assert.Equal(t, tenantID, tid)
			assert.Equal(t, 24, hours)
			assert.Equal(t, 10, threshold)
			return expected, nil
		},
	}
	l := NewAsyncAuditLogger(repo, 100, 10)
	t.Cleanup(func() { _ = l.Close() })

	activities, err := l.DetectSuspiciousActivity(context.Background(), tenantID, 24, 10)
	require.NoError(t, err)
	require.Len(t, activities, 1)
	assert.Equal(t, int64(15), activities[0].DenialCount)
}

// ─── Close ───────────────────────────────────────────────────────────────────

func TestClose_IdempotentMultipleCalls(t *testing.T) {
	repo := &mockAuditRepository{}
	l := NewAsyncAuditLogger(repo, 100, 10)

	assert.NoError(t, l.Close())
	assert.NoError(t, l.Close()) // second call must not panic or block
}

func TestClose_FlushesPendingEntries(t *testing.T) {
	repo := &mockAuditRepository{}
	l := NewAsyncAuditLogger(repo, 1000, 100)

	// Queue 5 entries.
	for i := 0; i < 5; i++ {
		err := l.LogRelationshipChange(context.Background(), RelationshipAuditEntry{
			TenantID:     uuid.New(),
			ActorID:      uuid.New(),
			Action:       ActionRelationshipCreated,
			ResourceType: "res",
			ResourceID:   "1",
		})
		require.NoError(t, err)
	}

	// Close should flush everything before returning.
	require.NoError(t, l.Close())

	var total int
	for _, batch := range repo.batchCreateCalls {
		total += len(batch)
	}
	assert.Equal(t, 5, total, "all 5 queued entries should be flushed on Close")
}

// ─── BatchCreate flush trigger ───────────────────────────────────────────────

func TestBatchFlush_TriggeredByFlushSize(t *testing.T) {
	// flushSize = 3; send exactly 3 entries and expect a flush.
	repo := &mockAuditRepository{}
	l := NewAsyncAuditLogger(repo, 1000, 3)
	t.Cleanup(func() { _ = l.Close() })

	for i := 0; i < 3; i++ {
		err := l.LogRelationshipChange(context.Background(), RelationshipAuditEntry{
			TenantID:     uuid.New(),
			ActorID:      uuid.New(),
			Action:       ActionRelationshipCreated,
			ResourceType: "res",
			ResourceID:   "1",
		})
		require.NoError(t, err)
	}

	// Wait for the worker to flush.
	assert.True(t, waitForBatch(repo, 2*time.Second), "expected flush when batch size reached")
}

// ─── stringPtr ───────────────────────────────────────────────────────────────

func Test_stringPtr(t *testing.T) {
	t.Run("non-empty string", func(t *testing.T) {
		s := "hello"
		got := stringPtr(s)
		require.NotNil(t, got)
		assert.Equal(t, s, *got)
	})

	t.Run("empty string returns nil", func(t *testing.T) {
		got := stringPtr("")
		assert.Nil(t, got)
	})
}

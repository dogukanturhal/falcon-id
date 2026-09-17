// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantprojection_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/tenantprojection"
)

// ---------------------------------------------------------------------------
// Envelope parse logic — exercised via exported types
// ---------------------------------------------------------------------------

// TestEnvelopeParse_ValidCreated verifies the Envelope JSON structure used
// by tenant-management's outbox relay.
func TestEnvelopeParse_ValidCreated(t *testing.T) {
	tenantID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	raw, err := json.Marshal(map[string]interface{}{
		"type":      tenantprojection.SubjectTenantCreated,
		"timestamp": now.Format(time.RFC3339),
		"data": map[string]interface{}{
			"id":                  tenantID.String(),
			"plan":                "pro",
			"type":                "customer",
			"subscription_status": "active",
		},
	})
	require.NoError(t, err)

	var env tenantprojection.Envelope
	require.NoError(t, json.Unmarshal(raw, &env))

	assert.Equal(t, tenantprojection.SubjectTenantCreated, env.Type)
	assert.WithinDuration(t, now, env.Timestamp, time.Second)
	assert.NotEmpty(t, env.Data)
}

// TestEnvelopeParse_ValidDeleted verifies the minimal delete envelope shape
// ({"id": uuid}) used by tenant_service.go.
func TestEnvelopeParse_ValidDeleted(t *testing.T) {
	tenantID := uuid.New()
	raw, err := json.Marshal(map[string]interface{}{
		"type":      tenantprojection.SubjectTenantDeleted,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"data":      map[string]interface{}{"id": tenantID.String()},
	})
	require.NoError(t, err)

	var env tenantprojection.Envelope
	require.NoError(t, json.Unmarshal(raw, &env))
	assert.Equal(t, tenantprojection.SubjectTenantDeleted, env.Type)
}

// TestEnvelopeParse_InvalidJSON confirms that a corrupt payload fails to
// unmarshal rather than silently producing a zero-value struct.
func TestEnvelopeParse_InvalidJSON(t *testing.T) {
	var env tenantprojection.Envelope
	err := json.Unmarshal([]byte(`not valid json`), &env)
	assert.Error(t, err)
}

// TestEnvelopeParse_MissingTimestampIsZero confirms that an envelope without
// a timestamp field produces a zero Timestamp — the subscriber handles this by
// substituting time.Now().
func TestEnvelopeParse_MissingTimestampIsZero(t *testing.T) {
	raw := []byte(`{"type":"example.tenant.updated","data":{"id":"` + uuid.New().String() + `"}}`)
	var env tenantprojection.Envelope
	require.NoError(t, json.Unmarshal(raw, &env))
	assert.True(t, env.Timestamp.IsZero())
}

// ---------------------------------------------------------------------------
// Subscriber constants and topic list
// ---------------------------------------------------------------------------

func TestTenantSubjects_CorrectTopics(t *testing.T) {
	subjects := tenantprojection.TenantSubjects()
	assert.Len(t, subjects, 3)
	assert.Contains(t, subjects, tenantprojection.SubjectTenantCreated)
	assert.Contains(t, subjects, tenantprojection.SubjectTenantUpdated)
	assert.Contains(t, subjects, tenantprojection.SubjectTenantDeleted)
}

func TestConsumerGroup_DoesNotMatchQuotaServiceGroup(t *testing.T) {
	// This test exists purely as a documentation-level guard: if someone
	// changes ConsumerGroup to match the quota-service value, this test
	// breaks and forces the conversation.
	assert.NotEqual(t, "quota-service-projection", tenantprojection.ConsumerGroup,
		"falcon-id-tenant-projection consumer group MUST be unique")
	assert.Equal(t, "falcon-id-tenant-projection", tenantprojection.ConsumerGroup)
}

func TestDLQTopic_MatchesPlatformBootstrapProvisionedTopic(t *testing.T) {
	// The DLQ topic is provisioned by <gitops-bootstrap-repo>!709.
	// Changing this constant requires updating the KafkaTopic CR.
	assert.Equal(t, "example.tenant.dlq", tenantprojection.DLQTopic)
}

// ---------------------------------------------------------------------------
// NewTenantSubscriber — default group ID fallback
// ---------------------------------------------------------------------------

func TestNewTenantSubscriber_DefaultGroupID(t *testing.T) {
	repo := tenantprojection.NewRepository(nil)
	metrics := tenantprojection.NewMetrics(nil, nil) // nil reg = no-op

	// cfg.GroupID empty → ConsumerGroup default must be applied.
	// We can't inspect the private field directly but we confirm construction
	// doesn't panic and the exported constant has the correct value.
	sub := tenantprojection.NewTenantSubscriber(tenantprojection.SubscriberConfig{}, repo, metrics, nil)
	assert.NotNil(t, sub)
}

// ---------------------------------------------------------------------------
// Orphan metric increment (via no-op Metrics nil guard)
// ---------------------------------------------------------------------------

func TestMetrics_NilGuard(t *testing.T) {
	// Nil *Metrics must not panic — subscribers that fail to construct metrics
	// still function, just without instrumentation.
	var m *tenantprojection.Metrics
	assert.NotPanics(t, func() {
		m.IncOK("example.tenant.created")
		m.IncSkipped("example.tenant.updated")
		m.IncOrphan("example.tenant.deleted")
		m.IncDLQ("example.tenant.created")
		m.IncFailed("example.tenant.updated")
		m.ObserveLag("example.tenant.created", time.Now())
	})
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package entitlementsync

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// fakeEntitlementService implements the entitlementService interface used
// by the subscriber, recording every call so tests can assert exactly what
// was applied (and in what order) from a decoded snapshot.
type fakeEntitlementService struct {
	putCalls      []*models.ModuleEntitlement
	putFlagsCalls []*models.TenantEntitlementFlags
	putErr        error
	putFlagsErr   error
}

func (f *fakeEntitlementService) PutSnapshot(ctx context.Context, e *models.ModuleEntitlement) error {
	f.putCalls = append(f.putCalls, e)
	return f.putErr
}

func (f *fakeEntitlementService) PutFlagsSnapshot(ctx context.Context, fl *models.TenantEntitlementFlags) error {
	f.putFlagsCalls = append(f.putFlagsCalls, fl)
	return f.putFlagsErr
}

func newTestSubscriber(svc entitlementService) *Subscriber {
	return &Subscriber{svc: svc, metrics: nil, log: nil}
}

// ---------------------------------------------------------------------------
// applySnapshot: happy path, per-module upsert + flags upsert
// ---------------------------------------------------------------------------

func TestApplySnapshot_UpsertsEveryModuleAndFlags(t *testing.T) {
	svc := &fakeEntitlementService{}
	s := newTestSubscriber(svc)

	tenantID := uuid.New()
	payload := snapshotPayload{
		TenantID:     tenantID,
		EventVersion: 7,
		Modules: []modulePayload{
			{ModuleCode: "crm", Status: "active"},
			{ModuleCode: "marketing", Status: "expired", EverTrialed: true},
		},
		Flags: map[string]bool{"beta": true},
	}
	eventAt := time.Now().UTC()

	err := s.applySnapshot(context.Background(), payload, eventAt)
	require.NoError(t, err)

	require.Len(t, svc.putCalls, 2)
	assert.Equal(t, "crm", svc.putCalls[0].ModuleCode)
	assert.Equal(t, models.ModuleEntitlementStatusActive, svc.putCalls[0].Status)
	assert.Equal(t, int64(7), svc.putCalls[0].EventVersion)
	assert.Equal(t, "marketing", svc.putCalls[1].ModuleCode)
	assert.Equal(t, models.ModuleEntitlementStatusExpired, svc.putCalls[1].Status)
	assert.True(t, svc.putCalls[1].EverTrialed)

	require.Len(t, svc.putFlagsCalls, 1)
	assert.Equal(t, tenantID, svc.putFlagsCalls[0].TenantID)
	assert.True(t, svc.putFlagsCalls[0].Flags["beta"])
	assert.Equal(t, int64(7), svc.putFlagsCalls[0].EventVersion)
}

func TestApplySnapshot_SourceTierRoundtrip(t *testing.T) {
	var payload snapshotPayload
	require.NoError(t, json.Unmarshal([]byte(`{"tenant_id":"11111111-1111-1111-1111-111111111111","event_version":42,"modules":[{"module_code":"crm","status":"active","source":"operator-comp","tier_code":"professional"},{"module_code":"pm","status":"active"}]}`), &payload))
	svc := &fakeEntitlementService{}
	require.NoError(t, newTestSubscriber(svc).applySnapshot(context.Background(), payload, time.Now().UTC()))
	require.Len(t, svc.putCalls, 2)
	require.NotNil(t, svc.putCalls[0].Source)
	require.Equal(t, "operator-comp", *svc.putCalls[0].Source)
	require.NotNil(t, svc.putCalls[0].TierCode)
	require.Equal(t, "professional", *svc.putCalls[0].TierCode)
	require.Equal(t, models.TrialReasonComplimentary, svc.putCalls[0].TrialReason())
	require.Nil(t, svc.putCalls[1].Source, "legacy snapshot source is unknown, not paid")
	require.Nil(t, svc.putCalls[1].TierCode)
}

func TestApplySnapshot_ReadOnlyRoundtrip(t *testing.T) {
	var payload snapshotPayload
	require.NoError(t, json.Unmarshal([]byte(`{"tenant_id":"11111111-1111-1111-1111-111111111111","event_version":43,"modules":[{"module_code":"crm","status":"grace","read_only":true},{"module_code":"pm","status":"grace"}]}`), &payload))
	svc := &fakeEntitlementService{}
	require.NoError(t, newTestSubscriber(svc).applySnapshot(context.Background(), payload, time.Now().UTC()))
	require.Len(t, svc.putCalls, 2)
	require.True(t, svc.putCalls[0].ReadOnly)
	require.False(t, svc.putCalls[1].ReadOnly, "absent read_only means full access")
}

// ---------------------------------------------------------------------------
// applySnapshot: no flags present in the snapshot -> PutFlagsSnapshot must
// not be called at all (nil map, not an empty-flags upsert).
// ---------------------------------------------------------------------------

func TestApplySnapshot_NoFlags_SkipsFlagsUpsert(t *testing.T) {
	svc := &fakeEntitlementService{}
	s := newTestSubscriber(svc)

	payload := snapshotPayload{
		TenantID:     uuid.New(),
		EventVersion: 1,
		Modules:      []modulePayload{{ModuleCode: "crm", Status: "active"}},
	}

	err := s.applySnapshot(context.Background(), payload, time.Now().UTC())
	require.NoError(t, err)
	assert.Empty(t, svc.putFlagsCalls)
}

// ---------------------------------------------------------------------------
// applySnapshot: unknown/invalid status is skipped for that module only,
// the rest of the snapshot still applies (fail-closed: reject the bad
// entry, don't abort the whole batch and don't grant on ambiguity).
// ---------------------------------------------------------------------------

func TestApplySnapshot_UnknownStatus_SkipsModuleOnly(t *testing.T) {
	svc := &fakeEntitlementService{}
	s := newTestSubscriber(svc)

	payload := snapshotPayload{
		TenantID:     uuid.New(),
		EventVersion: 1,
		Modules: []modulePayload{
			{ModuleCode: "crm", Status: "active"},
			{ModuleCode: "bogus-module", Status: "cancelled"}, // invalid status
		},
	}

	err := s.applySnapshot(context.Background(), payload, time.Now().UTC())
	require.NoError(t, err, "an unknown status must not fail the whole snapshot")

	require.Len(t, svc.putCalls, 1, "only the valid module should have been upserted")
	assert.Equal(t, "crm", svc.putCalls[0].ModuleCode)
}

// ---------------------------------------------------------------------------
// applySnapshot: idempotency. The consumer calls PutSnapshot once per
// module every time regardless of whether this is a first-delivery or a
// stale redelivery -- idempotency itself is enforced by the repository's
// monotonic event_version guard (applied=false is swallowed as success by
// TenantEntitlementService.PutSnapshot, see services package tests). This
// test proves the SUBSCRIBER's contract: re-processing the identical
// snapshot (e.g. after a consumer-group rebalance redelivers an
// already-committed offset) calls PutSnapshot again with the SAME
// event_version and does not error, i.e. redelivery is safe.
// ---------------------------------------------------------------------------

func TestApplySnapshot_DuplicateRedelivery_IsSafeAndCallsPutAgain(t *testing.T) {
	svc := &fakeEntitlementService{}
	s := newTestSubscriber(svc)

	payload := snapshotPayload{
		TenantID:     uuid.New(),
		EventVersion: 3,
		Modules:      []modulePayload{{ModuleCode: "crm", Status: "active"}},
	}
	eventAt := time.Now().UTC()

	require.NoError(t, s.applySnapshot(context.Background(), payload, eventAt))
	require.NoError(t, s.applySnapshot(context.Background(), payload, eventAt))

	require.Len(t, svc.putCalls, 2, "redelivery calls PutSnapshot again; the repo's version guard (not the consumer) makes this idempotent")
	assert.Equal(t, svc.putCalls[0].EventVersion, svc.putCalls[1].EventVersion)
}

// ---------------------------------------------------------------------------
// applySnapshot: out-of-order delivery (an older event_version arriving
// after a newer one) is passed through unchanged to PutSnapshot -- the
// consumer does not attempt its own ordering/version comparison, trusting
// the repository's monotonic guard exclusively (single source of truth for
// "is this newer").
// ---------------------------------------------------------------------------

func TestApplySnapshot_OutOfOrderVersions_PassedThroughToService(t *testing.T) {
	svc := &fakeEntitlementService{}
	s := newTestSubscriber(svc)

	newer := snapshotPayload{TenantID: uuid.New(), EventVersion: 5, Modules: []modulePayload{{ModuleCode: "crm", Status: "active"}}}
	older := snapshotPayload{TenantID: newer.TenantID, EventVersion: 2, Modules: []modulePayload{{ModuleCode: "crm", Status: "active"}}}

	require.NoError(t, s.applySnapshot(context.Background(), newer, time.Now().UTC()))
	require.NoError(t, s.applySnapshot(context.Background(), older, time.Now().UTC()))

	require.Len(t, svc.putCalls, 2)
	assert.Equal(t, int64(5), svc.putCalls[0].EventVersion)
	assert.Equal(t, int64(2), svc.putCalls[1].EventVersion, "consumer does not reorder or reject -- that's the repo's job")
}

// ---------------------------------------------------------------------------
// applySnapshot: PutSnapshot failure aborts the remaining modules in this
// snapshot (returns error so handleMessage's retry loop retries the whole
// snapshot -- safe because each individual upsert is itself idempotent).
// ---------------------------------------------------------------------------

func TestApplySnapshot_PutSnapshotError_AbortsRemainingModules(t *testing.T) {
	svc := &fakeEntitlementService{putErr: errors.New("db unavailable")}
	s := newTestSubscriber(svc)

	payload := snapshotPayload{
		TenantID:     uuid.New(),
		EventVersion: 1,
		Modules: []modulePayload{
			{ModuleCode: "crm", Status: "active"},
			{ModuleCode: "marketing", Status: "active"},
		},
	}

	err := s.applySnapshot(context.Background(), payload, time.Now().UTC())
	require.Error(t, err)
	assert.Len(t, svc.putCalls, 1, "should stop at the first failing module, not silently continue")
}

func TestApplySnapshot_PutFlagsSnapshotError_Propagates(t *testing.T) {
	svc := &fakeEntitlementService{putFlagsErr: errors.New("db unavailable")}
	s := newTestSubscriber(svc)

	payload := snapshotPayload{
		TenantID:     uuid.New(),
		EventVersion: 1,
		Modules:      []modulePayload{{ModuleCode: "crm", Status: "active"}},
		Flags:        map[string]bool{"beta": true},
	}

	err := s.applySnapshot(context.Background(), payload, time.Now().UTC())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// handleMessage: one snapshot carrying every status at once. The consumer
// has no delete or SpiceDB path -- it upserts each valid-status row and
// skips unknown ones ("cancelled"/"removed" are not valid wire statuses; a
// module removed by the producer arrives as "expired"). The resulting
// entitlement set is then exactly {active, trialing, grace} granting and
// {expired} non-granting; invalid statuses never reach the service.
// ---------------------------------------------------------------------------
func TestHandleMessage_MixedStatusSnapshot_GrantingSetIsExact(t *testing.T) {
	svc := &fakeEntitlementService{}
	s := newTestSubscriber(svc)
	tenantID := uuid.New()

	data, err := json.Marshal(map[string]any{
		"tenant_id":     tenantID,
		"event_version": 9,
		"modules": []map[string]any{
			{"module_code": "crm", "status": "active"},
			{"module_code": "marketing", "status": "trialing"},
			{"module_code": "hr", "status": "grace"},
			{"module_code": "finance", "status": "expired", "ever_subscribed": true},
			{"module_code": "legacy-a", "status": "cancelled"},
			{"module_code": "legacy-b", "status": "removed"},
			{"module_code": "legacy-c", "status": ""},
		},
	})
	require.NoError(t, err)
	value, err := json.Marshal(Envelope{Type: "tenant.modules.sync", Data: data, Timestamp: time.Now().UTC()})
	require.NoError(t, err)

	s.handleMessage(context.Background(), kafka.Message{Value: value})

	got := map[string]models.ModuleEntitlementStatus{}
	for _, c := range svc.putCalls {
		assert.Equal(t, tenantID, c.TenantID)
		assert.Equal(t, int64(9), c.EventVersion)
		got[c.ModuleCode] = c.Status
	}
	assert.Equal(t, map[string]models.ModuleEntitlementStatus{
		"crm":       models.ModuleEntitlementStatusActive,
		"marketing": models.ModuleEntitlementStatusTrialing,
		"hr":        models.ModuleEntitlementStatusGrace,
		"finance":   models.ModuleEntitlementStatusExpired,
	}, got, "only valid-status modules are upserted; invalid ones are skipped")
	require.Len(t, svc.putCalls, 4, "no duplicate upserts")

	granting := map[string]bool{}
	for code, st := range got {
		if st.IsGranting() {
			granting[code] = true
		}
	}
	assert.Equal(t, map[string]bool{"crm": true, "marketing": true, "hr": true}, granting,
		"expired must not grant; unknown statuses must never be persisted")
	assert.Empty(t, svc.putFlagsCalls)
}

// ---------------------------------------------------------------------------
// applySnapshot: limits-only snapshot (migration 0020) still writes the row,
// with Flags nil so the stored flags are kept.
// ---------------------------------------------------------------------------

func TestApplySnapshot_LimitsOnly_UpsertsLimitsKeepsFlagsNil(t *testing.T) {
	svc := &fakeEntitlementService{}
	s := newTestSubscriber(svc)

	payload := snapshotPayload{
		TenantID:     uuid.New(),
		EventVersion: 3,
		Limits:       map[string]int64{"production_bom_depth": -1},
	}

	require.NoError(t, s.applySnapshot(context.Background(), payload, time.Now().UTC()))
	require.Len(t, svc.putFlagsCalls, 1)
	assert.Nil(t, svc.putFlagsCalls[0].Flags)
	assert.Equal(t, int64(-1), svc.putFlagsCalls[0].Limits["production_bom_depth"])
	assert.Equal(t, int64(3), svc.putFlagsCalls[0].EventVersion)
}

func TestValidateEntitlementLimits(t *testing.T) {
	assert.NoError(t, models.ValidateEntitlementLimits(nil))
	assert.NoError(t, models.ValidateEntitlementLimits(map[string]int64{"production_bom_depth": 3, "x": -1, "y": 0}))
	assert.Error(t, models.ValidateEntitlementLimits(map[string]int64{"production_bom_depth": -2}))
	assert.Error(t, models.ValidateEntitlementLimits(map[string]int64{" ": 1}))
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantprojection

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	pgxmock "github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestBpayTrialProjectionAcceptsObjectMetadataAndBothStatusProducers(t *testing.T) {
	var payload tenantPayload
	require.NoError(t, json.Unmarshal([]byte(`{"subscription_status":"suspended","metadata":{"trial_access_expired":true}}`), &payload))
	require.Equal(t, "suspended", tenantProjectionStatus(payload))
	require.JSONEq(t, `{"trial_access_expired":true}`, string(payload.Metadata))
	require.NoError(t, json.Unmarshal([]byte(`{"status":"active"}`), &payload))
	// Decode a fresh object: legacy status wins only when it was supplied.
	payload = tenantPayload{}
	require.NoError(t, json.Unmarshal([]byte(`{"status":"active"}`), &payload))
	require.Equal(t, "active", tenantProjectionStatus(payload))
	require.Equal(t, "trial", tenantProjectionStatus(tenantPayload{Status: "trial", PlatformStatus: "active"}))
}

func TestBpayTrialProjectionReplaysProductRepairAfterProjectionCommit(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()
	subscriber := NewTenantSubscriber(SubscriberConfig{}, NewRepository(mock), nil, nil)
	id := uuid.New()
	data, err := json.Marshal(map[string]any{"id": id, "subscription_status": "trial", "metadata": map[string]any{"signup_trial_started": true}})
	require.NoError(t, err)
	env := Envelope{Type: SubjectTenantUpdated, Timestamp: time.Now().UTC(), Data: data}
	calls := 0
	subscriber.SetTrialReadyHook(func(_ context.Context, got uuid.UUID) error {
		require.Equal(t, id, got)
		calls++
		if calls == 1 {
			return errors.New("temporary product failure")
		}
		return nil
	})
	for _, changed := range []int64{1, 0} {
		mock.ExpectQuery("SELECT 1 FROM iam_tenants").WithArgs(id).WillReturnRows(mock.NewRows([]string{"found"}).AddRow(1))
		mock.ExpectExec("UPDATE iam_tenants").WithArgs(id, "trial", pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", changed))
		err = subscriber.dispatch(context.Background(), SubjectTenantUpdated, env, 1)
		if changed == 1 {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
	require.Equal(t, 2, calls, "a skipped replay still retries the source-guarded product callback")
	require.NoError(t, mock.ExpectationsWereMet())
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type auth2StepUpWrites struct {
	calls []string
	fail  string
}

func (s *auth2StepUpWrites) AppendAuthMethod(_ context.Context, _ uuid.UUID, method string) (bool, error) {
	s.calls = append(s.calls, method)
	if s.fail == method {
		return false, errors.New("unavailable")
	}
	return true, nil
}
func (s *auth2StepUpWrites) RefreshAuthenticatedAt(context.Context, uuid.UUID) error {
	s.calls = append(s.calls, "freshness")
	if s.fail == "freshness" {
		return errors.New("unavailable")
	}
	return nil
}
func (s *auth2StepUpWrites) RecordVerification(_ context.Context, _ uuid.UUID, _ uuid.UUID, action, method string, ttl time.Duration) error {
	s.calls = append(s.calls, action+":"+method)
	if s.fail == "record" {
		return errors.New("unavailable")
	}
	return nil
}
func TestAuth2PasskeyStepUp_RecordsRealMethodAndFreshness(t *testing.T) {
	writes := &auth2StepUpWrites{}
	require.NoError(t, recordPasskeyStepUp(context.Background(), writes, writes, uuid.New(), uuid.New()))
	require.Equal(t, []string{"mfa", "hwk", "freshness", "oauth_step_up:webauthn"}, writes.calls)
}
func TestAuth2PasskeyStepUp_PersistenceFailureCannotReportSuccess(t *testing.T) {
	for _, failure := range []string{"mfa", "hwk", "freshness", "record"} {
		t.Run(failure, func(t *testing.T) {
			writes := &auth2StepUpWrites{fail: failure}
			require.Error(t, recordPasskeyStepUp(context.Background(), writes, writes, uuid.New(), uuid.New()))
		})
	}
}

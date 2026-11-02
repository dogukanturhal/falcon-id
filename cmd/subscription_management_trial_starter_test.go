// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/stretchr/testify/require"
)

type bpaySignupTrialTransport func(*http.Request) (*http.Response, error)

func (f bpaySignupTrialTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestBpaySignupTrialHTTPRecognizesConsumedAndRequiresRealTrialWindow(t *testing.T) {
	end := time.Now().Add(14 * 24 * time.Hour).Format(time.RFC3339)
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		consumed bool
		success  bool
	}{
		{"default-no-card", 200, `{"status":"active","is_trialing":true,"trial_end":"` + end + `"}`, false, true},
		{"consumed", 409, `{"code":"TRIAL_ALREADY_CONSUMED"}`, true, false},
		{"existing-paid-or-comp", 200, `{"status":"active","is_trialing":false}`, true, false},
		{"incomplete", 200, `{}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			starter := newHTTPSubscriptionManagementTrialStarter("http://trial.test.invalid", &http.Client{Transport: bpaySignupTrialTransport(func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				require.JSONEq(t, `{}`, string(body), "empty selection delegates to Commerce, never Free")
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})})
			err := starter.StartTrial(context.Background(), uuid.New(), "")
			if tc.consumed {
				require.ErrorIs(t, err, services.ErrSignupTrialAlreadyConsumed)
			} else if tc.success {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

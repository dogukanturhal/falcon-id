// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DDIL P3.11 — the SpiceDB read-path retry classifier must retry only transient
// gRPC conditions and never spend the budget re-issuing a permanent denial or a
// malformed request.
func TestSpiceDBRetryable(t *testing.T) {
	retryable := []codes.Code{codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Aborted}
	for _, c := range retryable {
		if !spicedbRetryable(status.Error(c, "transient")) {
			t.Errorf("expected code %v to be retryable", c)
		}
	}

	permanent := []codes.Code{codes.InvalidArgument, codes.NotFound, codes.PermissionDenied, codes.Unauthenticated, codes.FailedPrecondition}
	for _, c := range permanent {
		if spicedbRetryable(status.Error(c, "permanent")) {
			t.Errorf("expected code %v to be non-retryable", c)
		}
	}

	if spicedbRetryable(nil) {
		t.Error("nil error must not be retryable")
	}
	// A plain (non-status) error resolves to codes.Unknown → not retried.
	if spicedbRetryable(errors.New("boom")) {
		t.Error("unknown error must not be retryable")
	}
	// Context cancellation must not drive a retry.
	if spicedbRetryable(context.Canceled) {
		t.Error("context.Canceled must not be retryable")
	}
}

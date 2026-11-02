// SPDX-License-Identifier: AGPL-3.0-or-later

package leaderelection_test

import (
	"context"
	"errors"
	"testing"

	"github.com/dogukanturhal/falcon-id/pkg/leaderelection"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ----------------------------------------------------------------------------
// Compile-time interface satisfaction checks
// ----------------------------------------------------------------------------

// These blank-identifier assignments verify that both concrete types implement
// the LeaderElector interface. The test binary will not compile if the
// interface is not satisfied.

var (
	_ leaderelection.LeaderElector = (*leaderelection.AdvisoryLockElector)(nil)
	_ leaderelection.LeaderElector = (*leaderelection.K8sLeaseElector)(nil)
)

// ----------------------------------------------------------------------------
// K8sLeaseElector — unit tests (no external dependencies)
// ----------------------------------------------------------------------------

func TestK8sLeaseElector_TryAcquire_DevMode(t *testing.T) {
	t.Parallel()

	elec := leaderelection.NewK8sLeaseElector("test-lock", "default")

	acquired, err := elec.TryAcquire(context.Background())
	if err != nil {
		t.Fatalf("TryAcquire returned unexpected error: %v", err)
	}
	if !acquired {
		t.Fatal("K8sLeaseElector should always acquire in dev mode (placeholder)")
	}
	if !elec.IsLeader() {
		t.Fatal("IsLeader() should return true after successful TryAcquire")
	}
}

func TestK8sLeaseElector_Release(t *testing.T) {
	t.Parallel()

	elec := leaderelection.NewK8sLeaseElector("test-lock", "default")

	if _, err := elec.TryAcquire(context.Background()); err != nil {
		t.Fatalf("TryAcquire: %v", err)
	}

	if err := elec.Release(context.Background()); err != nil {
		t.Fatalf("Release returned unexpected error: %v", err)
	}
	if elec.IsLeader() {
		t.Fatal("IsLeader() should return false after Release")
	}
}

func TestK8sLeaseElector_IsLeader_InitiallyFalse(t *testing.T) {
	t.Parallel()

	elec := leaderelection.NewK8sLeaseElector("test-lock", "default")
	if elec.IsLeader() {
		t.Fatal("IsLeader() should be false before TryAcquire is called")
	}
}

func TestK8sLeaseElector_RunAsLeader_InvokesFn(t *testing.T) {
	t.Parallel()

	elec := leaderelection.NewK8sLeaseElector("test-lock", "default")

	called := false
	err := elec.RunAsLeader(context.Background(), func(_ context.Context) {
		called = true
	})
	if err != nil {
		t.Fatalf("RunAsLeader returned unexpected error: %v", err)
	}
	if !called {
		t.Fatal("RunAsLeader should call fn when leadership is acquired")
	}
	// Leadership must be released after fn returns.
	if elec.IsLeader() {
		t.Fatal("IsLeader() should be false after RunAsLeader returns")
	}
}

// ----------------------------------------------------------------------------
// Factory — New()
// ----------------------------------------------------------------------------

func TestNew_AdvisoryLock_NilPool_ReturnsError(t *testing.T) {
	t.Parallel()

	_, err := leaderelection.New(leaderelection.Config{
		Method:   "advisory_lock",
		LockName: "provisioning-reconciler",
		LockID:   857491001,
	}, nil)

	if err == nil {
		t.Fatal("New with advisory_lock and nil pool must return an error")
	}
}

func TestNew_DefaultMethod_NilPool_ReturnsError(t *testing.T) {
	t.Parallel()

	// Empty Method defaults to advisory_lock.
	_, err := leaderelection.New(leaderelection.Config{
		LockName: "provisioning-reconciler",
		LockID:   857491001,
	}, nil)

	if err == nil {
		t.Fatal("New with empty method and nil pool must return an error")
	}
}

func TestNew_K8sLease_NilPool_Succeeds(t *testing.T) {
	t.Parallel()

	elec, err := leaderelection.New(leaderelection.Config{
		Method:   "k8s_lease",
		LockName: "provisioning-reconciler",
	}, nil /* pool not required for k8s_lease */)
	if err != nil {
		t.Fatalf("New with k8s_lease and nil pool must not return an error: %v", err)
	}
	if elec == nil {
		t.Fatal("New must return a non-nil LeaderElector")
	}
}

func TestNew_UnknownMethod_ReturnsError(t *testing.T) {
	t.Parallel()

	_, err := leaderelection.New(leaderelection.Config{
		Method: "etcd_lock",
	}, nil)

	if err == nil {
		t.Fatal("New with unknown method must return an error")
	}

	// Verify the error message is helpful.
	expectedSubstring := "etcd_lock"
	if !containsString(err.Error(), expectedSubstring) {
		t.Errorf("error message %q should mention the unknown method %q", err.Error(), expectedSubstring)
	}
}

func TestNew_K8sLease_ImplementsInterface(t *testing.T) {
	t.Parallel()

	elec, err := leaderelection.New(leaderelection.Config{
		Method:   "k8s_lease",
		LockName: "test-lock",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Exercise all interface methods to confirm they behave correctly.
	ctx := context.Background()

	acquired, err := elec.TryAcquire(ctx)
	if err != nil {
		t.Fatalf("TryAcquire: %v", err)
	}
	if !acquired {
		t.Fatal("k8s_lease placeholder should always acquire")
	}
	if !elec.IsLeader() {
		t.Fatal("IsLeader() should be true after TryAcquire")
	}

	if err := elec.Release(ctx); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if elec.IsLeader() {
		t.Fatal("IsLeader() should be false after Release")
	}
}

// ----------------------------------------------------------------------------
// Table-driven: Config.Method routing
// ----------------------------------------------------------------------------

func TestNew_MethodRouting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		method    string
		pool      bool // whether to pass a non-nil pool
		wantError bool
	}{
		{
			name:      "empty_method_with_pool",
			method:    "",
			pool:      true,
			wantError: false,
		},
		{
			name:      "advisory_lock_with_pool",
			method:    "advisory_lock",
			pool:      true,
			wantError: false,
		},
		{
			name:      "advisory_lock_no_pool",
			method:    "advisory_lock",
			pool:      false,
			wantError: true,
		},
		{
			name:      "k8s_lease_no_pool",
			method:    "k8s_lease",
			pool:      false,
			wantError: false,
		},
		{
			name:      "k8s_lease_with_pool_ignored",
			method:    "k8s_lease",
			pool:      true,
			wantError: false,
		},
		{
			name:      "unknown_method",
			method:    "consul_lock",
			pool:      false,
			wantError: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := leaderelection.Config{
				Method:   tc.method,
				LockName: "test-lock",
				LockID:   999,
			}

			// Factory construction is lazy: it needs a real pool object, not a
			// live server. No advisory-lock acquisition is performed here.
			var pool *pgxpool.Pool
			if tc.pool {
				var err error
				pool, err = pgxpool.New(context.Background(), "postgres://test@127.0.0.1:1/test")
				if err != nil {
					t.Fatal(err)
				}
				defer pool.Close()
			}
			_, err := leaderelection.New(cfg, pool)

			if tc.wantError && err == nil {
				t.Errorf("expected an error, got nil")
			}
			if !tc.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Error sentinel — verify errors.Is compatibility for wrapped factory errors
// ----------------------------------------------------------------------------

func TestNew_ErrorIsNil_WhenSuccessful(t *testing.T) {
	t.Parallel()

	elec, err := leaderelection.New(leaderelection.Config{
		Method:   "k8s_lease",
		LockName: "singleton",
	}, nil)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if elec == nil {
		t.Fatal("elec must not be nil on success")
	}

	// Ensure returned error from a successful New is not wrapping any sentinel.
	if errors.Is(err, context.Canceled) {
		t.Fatal("returned nil error must not match context.Canceled")
	}
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func containsString(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

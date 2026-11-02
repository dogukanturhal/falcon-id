// SPDX-License-Identifier: AGPL-3.0-or-later

package leaderelection_test

import (
	"context"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/dogukanturhal/falcon-id/pkg/leaderelection"
)

var fastOpts = leaderelection.K8sLeaseOptions{
	LeaseDuration: 600 * time.Millisecond,
	RenewDeadline: 400 * time.Millisecond,
	RetryPeriod:   50 * time.Millisecond,
}

func newElector(c kubernetes.Interface, id string) *leaderelection.K8sLeaseElector {
	return leaderelection.NewK8sLeaseElectorWithClient(c, "lease-test", "ns1", id, fastOpts)
}

func holder(t *testing.T, c kubernetes.Interface) string {
	t.Helper()
	l, err := c.CoordinationV1().Leases("ns1").Get(context.Background(), "lease-test", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	if l.Spec.HolderIdentity == nil {
		return ""
	}
	return *l.Spec.HolderIdentity
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestK8sLease_AcquireCreatesLease(t *testing.T) {
	t.Parallel()
	c := fake.NewSimpleClientset()
	e := newElector(c, "pod-a")
	defer e.Release(context.Background()) //nolint:errcheck

	ok, err := e.TryAcquire(context.Background())
	if err != nil || !ok {
		t.Fatalf("TryAcquire = %v, %v; want true, nil", ok, err)
	}
	if !e.IsLeader() {
		t.Fatal("IsLeader should be true")
	}
	if got := holder(t, c); got != "pod-a" {
		t.Fatalf("holder = %q, want pod-a", got)
	}
}

func TestK8sLease_SecondCandidateDoesNotLead_ThenTakesOverOnRelease(t *testing.T) {
	t.Parallel()
	c := fake.NewSimpleClientset()
	a, b := newElector(c, "pod-a"), newElector(c, "pod-b")
	defer b.Release(context.Background()) //nolint:errcheck

	if ok, err := a.TryAcquire(context.Background()); err != nil || !ok {
		t.Fatalf("a.TryAcquire = %v, %v", ok, err)
	}
	if ok, err := b.TryAcquire(context.Background()); err != nil || ok {
		t.Fatalf("b.TryAcquire = %v, %v; want false, nil", ok, err)
	}
	if a.IsLeader() == b.IsLeader() {
		t.Fatalf("exactly one leader expected: a=%v b=%v", a.IsLeader(), b.IsLeader())
	}

	if err := a.Release(context.Background()); err != nil {
		t.Fatalf("a.Release: %v", err)
	}
	if a.IsLeader() {
		t.Fatal("a must not be leader after Release")
	}
	// b's loop keeps contending and takes over the released lease.
	eventually(t, "b to take over", b.IsLeader)
	if got := holder(t, c); got != "pod-b" {
		t.Fatalf("holder = %q, want pod-b", got)
	}
}

func TestK8sLease_ReleaseClearsHolder(t *testing.T) {
	t.Parallel()
	c := fake.NewSimpleClientset()
	e := newElector(c, "pod-a")
	if ok, _ := e.TryAcquire(context.Background()); !ok {
		t.Fatal("expected to acquire")
	}
	if err := e.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := holder(t, c); got != "" {
		t.Fatalf("holder after release = %q, want empty", got)
	}
	// Release when not leader is a no-op.
	if err := e.Release(context.Background()); err != nil {
		t.Fatalf("second Release: %v", err)
	}
}

func TestK8sLease_ReleaseThenReacquire(t *testing.T) {
	t.Parallel()
	c := fake.NewSimpleClientset()
	e := newElector(c, "pod-a")
	defer e.Release(context.Background()) //nolint:errcheck
	for i := 0; i < 2; i++ {
		if ok, err := e.TryAcquire(context.Background()); err != nil || !ok {
			t.Fatalf("round %d: TryAcquire = %v, %v", i, ok, err)
		}
		if err := e.Release(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestK8sLease_RunAsLeader(t *testing.T) {
	t.Parallel()
	c := fake.NewSimpleClientset()
	e := newElector(c, "pod-a")

	called := false
	err := e.RunAsLeader(context.Background(), func(ctx context.Context) {
		called = true
		if !e.IsLeader() {
			t.Error("must be leader inside fn")
		}
	})
	if err != nil || !called {
		t.Fatalf("RunAsLeader err=%v called=%v", err, called)
	}
	if e.IsLeader() {
		t.Fatal("leadership must be released after fn returns")
	}
	if got := holder(t, c); got != "" {
		t.Fatalf("holder = %q, want empty", got)
	}
}

func TestK8sLease_RunAsLeader_NotLeader_SkipsFn(t *testing.T) {
	t.Parallel()
	c := fake.NewSimpleClientset()
	a, b := newElector(c, "pod-a"), newElector(c, "pod-b")
	defer a.Release(context.Background()) //nolint:errcheck
	if ok, _ := a.TryAcquire(context.Background()); !ok {
		t.Fatal("a should lead")
	}
	called := false
	if err := b.RunAsLeader(context.Background(), func(context.Context) { called = true }); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("fn must not run on a non-leader")
	}
}

func TestK8sLease_TryAcquire_ContextCancelled(t *testing.T) {
	t.Parallel()
	c := fake.NewSimpleClientset()
	e := newElector(c, "pod-a")
	defer e.Release(context.Background()) //nolint:errcheck
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.TryAcquire(ctx); err == nil {
		// A pre-cancelled ctx may still win the race against the first
		// attempt; either outcome is fine as long as nothing hangs.
		t.Log("acquired despite cancelled ctx")
	}
}

func TestK8sLease_ConcurrentIsLeader(t *testing.T) {
	t.Parallel()
	c := fake.NewSimpleClientset()
	e := newElector(c, "pod-a")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, _ = e.TryAcquire(context.Background())
				_ = e.IsLeader()
			}
		}()
	}
	wg.Wait()
	_ = e.Release(context.Background())
}

func TestK8sLease_EmptyLeaseName_Errors(t *testing.T) {
	t.Parallel()
	e := leaderelection.NewK8sLeaseElectorWithClient(fake.NewSimpleClientset(), "", "ns1", "x", fastOpts)
	if ok, err := e.TryAcquire(context.Background()); err == nil || ok {
		t.Fatalf("want error for empty lease name, got %v, %v", ok, err)
	}
}

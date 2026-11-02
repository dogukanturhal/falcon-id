// SPDX-License-Identifier: AGPL-3.0-or-later

package leaderelection

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	k8sleader "k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const (
	defaultLeaseDuration = 15 * time.Second
	defaultRenewDeadline = 10 * time.Second
	defaultRetryPeriod   = 2 * time.Second

	namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// K8sLeaseOptions tunes the Lease timings. Zero values select the defaults
// (15s lease, 10s renew deadline, 2s retry period). client-go requires
// LeaseDuration > RenewDeadline > 1.2*RetryPeriod.
type K8sLeaseOptions struct {
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration
}

func (o K8sLeaseOptions) withDefaults() K8sLeaseOptions {
	if o.LeaseDuration <= 0 {
		o.LeaseDuration = defaultLeaseDuration
	}
	if o.RenewDeadline <= 0 {
		o.RenewDeadline = o.LeaseDuration * 2 / 3
	}
	if o.RetryPeriod <= 0 {
		o.RetryPeriod = defaultRetryPeriod
	}
	return o
}

// K8sLeaseElector performs leader election with a Kubernetes Lease object
// (coordination.k8s.io/v1) via client-go's leaderelection package.
//
// TryAcquire starts a background election loop that keeps renewing the lease
// for as long as this instance is leader. Leadership ends when Release is
// called (the lease is released so another pod can take over immediately), or
// when renewal fails past the renew deadline (the loop stops and IsLeader
// turns false; the next TryAcquire starts a fresh loop).
//
// Required RBAC: get/create/update/patch on leases in coordination.k8s.io in
// the election namespace (shipped in the Helm chart when
// leaderElection.k8s.enabled=true).
type K8sLeaseElector struct {
	leaseName string
	namespace string
	identity  string
	opts      K8sLeaseOptions

	// clientFn resolves the clientset lazily so constructing an elector does
	// not require an in-cluster environment.
	clientFn func() (kubernetes.Interface, error)

	isLeader atomic.Bool

	mu  sync.Mutex
	cur *k8sRun // non-nil while an election loop is running
}

// k8sRun is one election loop.
type k8sRun struct {
	cancel  context.CancelFunc
	done    chan struct{} // closed when the loop has fully exited
	decided chan struct{} // closed on first outcome (became leader or saw another)
	once    sync.Once
	lost    chan struct{} // closed when leadership ends
}

func (r *k8sRun) decide() { r.once.Do(func() { close(r.decided) }) }

// Ensure K8sLeaseElector satisfies the LeaderElector interface at compile time.
var _ LeaderElector = (*K8sLeaseElector)(nil)

// NewK8sLeaseElector creates a K8sLeaseElector using the in-cluster config.
// If namespace is empty it is resolved from POD_NAMESPACE, then the
// service-account namespace file, then "default". The identity is POD_NAME,
// falling back to the hostname.
func NewK8sLeaseElector(leaseName, namespace string) *K8sLeaseElector {
	return &K8sLeaseElector{
		leaseName: leaseName,
		namespace: resolveNamespace(namespace),
		identity:  resolveIdentity(""),
		opts:      K8sLeaseOptions{}.withDefaults(),
		clientFn: func() (kubernetes.Interface, error) {
			cfg, err := rest.InClusterConfig()
			if err != nil {
				return nil, fmt.Errorf("leaderelection: in-cluster config: %w", err)
			}
			return kubernetes.NewForConfig(cfg)
		},
	}
}

// NewK8sLeaseElectorWithClient creates a K8sLeaseElector backed by the given
// clientset (used by tests and callers that already hold a client).
func NewK8sLeaseElectorWithClient(client kubernetes.Interface, leaseName, namespace, identity string, opts K8sLeaseOptions) *K8sLeaseElector {
	return &K8sLeaseElector{
		leaseName: leaseName,
		namespace: resolveNamespace(namespace),
		identity:  resolveIdentity(identity),
		opts:      opts.withDefaults(),
		clientFn:  func() (kubernetes.Interface, error) { return client, nil },
	}
}

// WithOptions overrides the lease timings. Call before TryAcquire.
func (k *K8sLeaseElector) WithOptions(opts K8sLeaseOptions) *K8sLeaseElector {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.opts = opts.withDefaults()
	return k
}

func resolveNamespace(ns string) string {
	if ns != "" {
		return ns
	}
	if v := os.Getenv("POD_NAMESPACE"); v != "" {
		return v
	}
	if b, err := os.ReadFile(namespaceFile); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v
		}
	}
	return "default"
}

func resolveIdentity(id string) string {
	if id != "" {
		return id
	}
	if v := os.Getenv("POD_NAME"); v != "" {
		return v
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "falcon-id-unknown"
}

// start launches an election loop unless one is already running.
// Caller must hold k.mu.
func (k *K8sLeaseElector) start() (*k8sRun, error) {
	if k.cur != nil {
		return k.cur, nil
	}
	if k.leaseName == "" {
		return nil, fmt.Errorf("leaderelection: k8s_lease requires a non-empty lease name")
	}
	client, err := k.clientFn()
	if err != nil {
		return nil, err
	}

	run := &k8sRun{
		done:    make(chan struct{}),
		decided: make(chan struct{}),
		lost:    make(chan struct{}),
	}
	// The loop outlives the TryAcquire caller's ctx: leadership is held until
	// Release (or loss), not until the acquiring call returns.
	loopCtx, cancel := context.WithCancel(context.Background())
	run.cancel = cancel

	le, err := k8sleader.NewLeaderElector(k8sleader.LeaderElectionConfig{
		Lock: &resourcelock.LeaseLock{
			LeaseMeta:  metav1.ObjectMeta{Name: k.leaseName, Namespace: k.namespace},
			Client:     client.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{Identity: k.identity},
		},
		LeaseDuration:   k.opts.LeaseDuration,
		RenewDeadline:   k.opts.RenewDeadline,
		RetryPeriod:     k.opts.RetryPeriod,
		ReleaseOnCancel: true,
		Name:            k.leaseName,
		Callbacks: k8sleader.LeaderCallbacks{
			OnStartedLeading: func(context.Context) {
				k.isLeader.Store(true)
				run.decide()
			},
			OnStoppedLeading: func() {
				k.isLeader.Store(false)
				close(run.lost)
			},
			OnNewLeader: func(id string) {
				if id != k.identity {
					run.decide()
				}
			},
		},
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("leaderelection: build k8s leader elector: %w", err)
	}

	k.cur = run
	go func() {
		defer close(run.done)
		defer func() {
			k.isLeader.Store(false)
			run.decide()
			k.mu.Lock()
			if k.cur == run {
				k.cur = nil
			}
			k.mu.Unlock()
		}()
		le.Run(loopCtx) // blocks; returns on cancel or lost lease
	}()
	return run, nil
}

// TryAcquire starts (or joins) the election loop and waits for its first
// outcome, bounded by the retry period and ctx. It returns true if this
// instance holds the lease. While leader, the lease is renewed in the
// background; call Release to hand it over.
func (k *K8sLeaseElector) TryAcquire(ctx context.Context) (bool, error) {
	k.mu.Lock()
	run, err := k.start()
	wait := k.opts.RetryPeriod * 2
	k.mu.Unlock()
	if err != nil {
		return false, err
	}

	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-run.decided:
	case <-t.C:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	return k.isLeader.Load(), nil
}

// Release stops the election loop and releases the lease (so another pod can
// acquire it immediately). It is a no-op when no loop is running.
func (k *K8sLeaseElector) Release(ctx context.Context) error {
	k.mu.Lock()
	run := k.cur
	k.mu.Unlock()
	if run == nil {
		k.isLeader.Store(false)
		return nil
	}
	run.cancel()
	select {
	case <-run.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// IsLeader reports whether this instance currently holds the Lease, as seen by
// the background renewal loop. It does not make an API call.
func (k *K8sLeaseElector) IsLeader() bool {
	return k.isLeader.Load()
}

// RunAsLeader attempts to acquire the lease and, if successful, calls fn with
// a context that is cancelled when ctx ends or leadership is lost. The lease is
// released after fn returns.
//
// If leadership cannot be acquired, fn is not invoked and nil is returned.
func (k *K8sLeaseElector) RunAsLeader(ctx context.Context, fn func(ctx context.Context)) error {
	acquired, err := k.TryAcquire(ctx)
	if err != nil {
		return err
	}
	if !acquired {
		// Another pod leads; stop our candidate loop so we don't contend.
		_ = k.Release(ctx)
		return nil
	}
	k.mu.Lock()
	run := k.cur
	k.mu.Unlock()

	fnCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if run != nil {
		go func() {
			select {
			case <-run.lost:
				cancel()
			case <-fnCtx.Done():
			}
		}()
	}
	defer func() {
		relCtx, relCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer relCancel()
		_ = k.Release(relCtx) //nolint:errcheck // best-effort release on return
	}()

	fn(fnCtx)
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package leaderelection

import (
	"context"
	"sync/atomic"
)

// K8sLeaseElector uses Kubernetes Lease objects (coordination.k8s.io/v1) for
// leader election. This approach enables cross-cluster coordination without
// requiring database connectivity, making it well-suited for cloud-native
// deployments where PostgreSQL is not available as a coordination backend.
//
// # Current status
//
// This is a structured placeholder. The Kubernetes Lease REST API calls are
// not yet implemented. In its current form the electo always reports success
// (single-node / development mode), which is safe because:
//
//   - The service is typically run as a single replica in development.
//   - In production K8s deployments, operators can switch to this backend
//     once the REST API implementation is complete.
//
// # Future implementation plan
//
// Replace TryAcquire with a Kubernetes API call equivalent to:
//
//	kubectl create -f - <<EOF
//	apiVersion: coordination.k8s.io/v1
//	kind: Lease
//	metadata:
//	  name: <leaseName>
//	  namespace: <namespace>
//	spec:
//	  holderIdentity: <podName>
//	  leaseDurationSeconds: <leaseDuration>
//	  renewTime: <now>
//	EOF
//
// Use net/http with an in-cluster service-account token (mounted at
// /var/run/secrets/kubernetes.io/serviceaccount/token) so that client-go
// is not required as a dependency. The K8s REST endpoint is:
//
//	PUT /apis/coordination.k8s.io/v1/namespaces/<ns>/leases/<name>
//
// See: https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/lease-v1/
type K8sLeaseElector struct {
	leaseName string
	namespace string
	isLeader  atomic.Bool
}

// Ensure K8sLeaseElector satisfies the LeaderElector interface at compile time.
var _ LeaderElector = (*K8sLeaseElector)(nil)

// NewK8sLeaseElector creates a K8sLeaseElector for the given lease name and
// namespace. The namespace is typically the namespace the pod runs in, which
// can be read from /var/run/secrets/kubernetes.io/serviceaccount/namespace.
func NewK8sLeaseElector(leaseName, namespace string) *K8sLeaseElector {
	return &K8sLeaseElector{
		leaseName: leaseName,
		namespace: namespace,
	}
}

// TryAcquire attempts to acquire the Kubernetes Lease.
//
// TODO: Implement via the K8s coordination REST API (no client-go dependency).
// Current behaviour: always acquires (single-node / development mode).
func (k *K8sLeaseElector) TryAcquire(_ context.Context) (bool, error) {
	// TODO: POST/PUT to /apis/coordination.k8s.io/v1/namespaces/<namespace>/leases/<leaseName>
	// using the in-cluster service-account token.
	k.isLeader.Store(true)
	return true, nil
}

// Release relinquishes the Kubernetes Lease.
//
// TODO: Implement via the K8s coordination REST API.
// Current behaviour: marks this instance as non-leader in memory only.
func (k *K8sLeaseElector) Release(_ context.Context) error {
	// TODO: DELETE or clear holderIdentity on the Lease object via REST API.
	k.isLeader.Store(false)
	return nil
}

// IsLeader reports whether this instance currently holds the Kubernetes Lease.
func (k *K8sLeaseElector) IsLeader() bool {
	return k.isLeader.Load()
}

// RunAsLeader attempts to acquire the lease and, if successful, calls fn.
// Leadership is released via defer after fn returns.
//
// If leadership cannot be acquired, fn is not invoked and nil is returned.
func (k *K8sLeaseElector) RunAsLeader(ctx context.Context, fn func(ctx context.Context)) error {
	acquired, err := k.TryAcquire(ctx)
	if err != nil {
		return err
	}
	if !acquired {
		return nil
	}
	defer k.Release(ctx) //nolint:errcheck // best-effort release on return

	fn(ctx)
	return nil
}

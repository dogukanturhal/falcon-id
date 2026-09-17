// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ClusterProvisioningState represents the lifecycle state of a Kubernetes cluster instance.
type ClusterProvisioningState string

const (
	// ClusterProvisioningStatePending is an exported identifier.
	ClusterProvisioningStatePending ClusterProvisioningState = "pending"
	// ClusterProvisioningStateCreating is an exported identifier.
	ClusterProvisioningStateCreating ClusterProvisioningState = "creating"
	// ClusterProvisioningStateConfiguring is an exported identifier.
	ClusterProvisioningStateConfiguring ClusterProvisioningState = "configuring"
	// ClusterProvisioningStateRegisteringRoutes is an exported identifier.
	ClusterProvisioningStateRegisteringRoutes ClusterProvisioningState = "registering_routes"
	// ClusterProvisioningStateActive is an exported identifier.
	ClusterProvisioningStateActive ClusterProvisioningState = "active"

	// ClusterProvisioningStateFailed is an exported identifier.
	ClusterProvisioningStateFailed ClusterProvisioningState = "failed"
	// ClusterProvisioningStateDeleting is an exported identifier.
	ClusterProvisioningStateDeleting ClusterProvisioningState = "deleting"
	// ClusterProvisioningStateDeleted is an exported identifier.
	ClusterProvisioningStateDeleted ClusterProvisioningState = "deleted"
)

// ClusterProvisioningSteps defines the ordered set of forward-progress states.
// The reconciler uses this list to determine the next step from the current one.
var ClusterProvisioningSteps = []ClusterProvisioningState{
	ClusterProvisioningStatePending,
	ClusterProvisioningStateCreating,
	ClusterProvisioningStateConfiguring,
	ClusterProvisioningStateRegisteringRoutes,
	ClusterProvisioningStateActive,
}

// ClusterIsolationTier enumerates the supported Kubernetes isolation strategies.
// Values must match the DB CHECK constraint on isolation_tier.
const (
	ClusterIsolationNamespace = "namespace"
	ClusterIsolationVCluster  = "vcluster"
	ClusterIsolationDedicated = "dedicated"
	ClusterIsolationBareMetal = "bare-metal"
)

// ClusterNodeSize enumerates the supported worker node sizes.
// Values must match the DB CHECK constraint on node_size.
const (
	ClusterNodeSizeSmall  = "small"
	ClusterNodeSizeMedium = "medium"
	ClusterNodeSizeLarge  = "large"
	ClusterNodeSizeXLarge = "xlarge"
)

// ClusterProvider enumerates the provisioning back-ends.
const (
	ClusterProviderCrossplane = "crossplane"
	ClusterProviderCAPI       = "capi"
	ClusterProviderManual     = "manual"
)

// ClusterInstance represents a Kubernetes cluster provisioned for a specific
// tenant/product pair.  Each row in iam_cluster_instances tracks the full
// provisioning lifecycle from pending through active (or failed/deleted).
//
// The model is intentionally analogous to ProductInstance: it reuses the same
// retry/backoff columns so the ProvisioningOrchestrator can manage both table
// types with the same reconcile loop.
type ClusterInstance struct {
	ID          uuid.UUID `json:"id"          db:"id"`
	TenantID    uuid.UUID `json:"tenant_id"   db:"tenant_id"`
	ProductID   uuid.UUID `json:"product_id"  db:"product_id"`
	ProductSlug string    `json:"product_slug" db:"product_slug"`
	ClusterName string    `json:"cluster_name" db:"cluster_name"`

	// IsolationTier determines the Kubernetes isolation model applied.
	// Allowed values: namespace, vcluster, dedicated, bare-metal.
	IsolationTier string `json:"isolation_tier" db:"isolation_tier"`

	// DataCenter is the target availability zone for this cluster.
	// Allowed values: istanbul, ankara.
	DataCenter string `json:"data_center" db:"data_center"`

	KubernetesVersion string `json:"kubernetes_version" db:"kubernetes_version"`
	NodeCount         int    `json:"node_count"         db:"node_count"`

	// NodeSize maps to resource profile definitions in the control plane.
	// Allowed values: small, medium, large, xlarge.
	NodeSize string `json:"node_size" db:"node_size"`

	// ClusterEndpoint is the Kubernetes API server URL, set once the cluster is active.
	ClusterEndpoint *string `json:"cluster_endpoint,omitempty" db:"cluster_endpoint"`

	// KubeConfigSecretRef is a Vault path or Kubernetes Secret reference that
	// holds the cluster's kubeconfig.  Never returned over the public API.
	KubeConfigSecretRef *string `json:"-" db:"kubeconfig_secret_ref"`

	// CACertificate is the PEM-encoded CA bundle for the cluster's API server.
	CACertificate *string `json:"-" db:"ca_certificate"`

	// ProvisioningState is the current lifecycle state.
	ProvisioningState ClusterProvisioningState `json:"provisioning_state" db:"provisioning_state"`

	// CurrentStep is the in-flight step name, cleared when a step completes.
	CurrentStep string `json:"current_step" db:"current_step"`

	// CompletedSteps is an ordered list of steps that have successfully finished.
	// Stored as TEXT[] in PostgreSQL; pgx scans it natively into []string.
	CompletedSteps []string `json:"completed_steps" db:"completed_steps"`

	FailureReason *string `json:"failure_reason,omitempty" db:"failure_reason"`

	// Retry / backoff columns — mirrored from ProductInstance so the same
	// exponential-backoff reconciler logic applies unchanged.
	RetryCount          int        `json:"retry_count"           db:"retry_count"`
	MaxRetriesExhausted bool       `json:"max_retries_exhausted" db:"max_retries_exhausted"`
	NextRetryAt         *time.Time `json:"next_retry_at,omitempty" db:"next_retry_at"`

	// Provider identifies which back-end created this cluster.
	// Allowed values: crossplane, capi, manual.
	Provider string `json:"provider" db:"provider"`

	// CrossplaneClaimRef is the namespaced name of the Crossplane ClusterClaim XR
	// (e.g. "clusters/my-cluster").  Nil when provider != crossplane.
	CrossplaneClaimRef *string `json:"crossplane_claim_ref,omitempty" db:"crossplane_claim_ref"`

	// ArgocdClusterName is the name under which this cluster is registered in
	// the ArgoCD cluster store.  Set during the registering_routes step.
	ArgocdClusterName *string `json:"argocd_cluster_name,omitempty" db:"argocd_cluster_name"`

	// VclusterName and VclusterNamespace are only set when IsolationTier == "vcluster".
	VclusterName      *string `json:"vcluster_name,omitempty"      db:"vcluster_name"`
	VclusterNamespace *string `json:"vcluster_namespace,omitempty" db:"vcluster_namespace"`

	ProvisionedAt *time.Time `json:"provisioned_at,omitempty" db:"provisioned_at"`
	CreatedAt     time.Time  `json:"created_at"               db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"               db:"updated_at"`
}

// IsTerminal returns true when the state can no longer transition forward.
// A terminal instance is never picked up by the reconcile loop.
func (ci *ClusterInstance) IsTerminal() bool {
	s := ci.ProvisioningState
	return s == ClusterProvisioningStateActive ||
		s == ClusterProvisioningStateFailed ||
		s == ClusterProvisioningStateDeleted
}

// CanRetry returns true when a failed instance is eligible for automatic retry:
// retries have not been exhausted and the backoff window has elapsed.
func (ci *ClusterInstance) CanRetry() bool {
	if ci.ProvisioningState != ClusterProvisioningStateFailed {
		return false
	}
	if ci.MaxRetriesExhausted {
		return false
	}
	if ci.NextRetryAt == nil {
		return false
	}
	return !time.Now().Before(*ci.NextRetryAt)
}

// SetFailed transitions the instance to the failed state and records the
// reason.  The caller is responsible for persisting the change.
func (ci *ClusterInstance) SetFailed(reason string) {
	ci.ProvisioningState = ClusterProvisioningStateFailed
	ci.FailureReason = &reason
	ci.UpdatedAt = time.Now().UTC()
}

// SetActive transitions the instance to the active state, records the
// provisioned-at timestamp, and clears transient error fields.
// The caller is responsible for persisting the change.
func (ci *ClusterInstance) SetActive() {
	now := time.Now().UTC()
	ci.ProvisioningState = ClusterProvisioningStateActive
	ci.ProvisionedAt = &now
	ci.FailureReason = nil
	ci.CurrentStep = ""
	ci.UpdatedAt = now
}

// ResetForRetry transitions a failed instance back to pending for automatic
// retry.  The retry_count is preserved so exponential backoff continues to
// increase on subsequent failures.
func (ci *ClusterInstance) ResetForRetry() {
	ci.ProvisioningState = ClusterProvisioningStatePending
	ci.FailureReason = nil
	ci.NextRetryAt = nil
	ci.UpdatedAt = time.Now().UTC()
}

// ResetForManualRetry transitions a failed instance back to pending for an
// operator-initiated retry.  Unlike ResetForRetry it also clears retry_count
// and max_retries_exhausted so the backoff sequence restarts from scratch.
func (ci *ClusterInstance) ResetForManualRetry() {
	ci.ProvisioningState = ClusterProvisioningStatePending
	ci.FailureReason = nil
	ci.RetryCount = 0
	ci.MaxRetriesExhausted = false
	ci.NextRetryAt = nil
	ci.CompletedSteps = []string{}
	ci.CurrentStep = ""
	ci.UpdatedAt = time.Now().UTC()
}

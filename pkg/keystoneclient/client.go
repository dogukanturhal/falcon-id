// SPDX-License-Identifier: AGPL-3.0-or-later

// Package keystoneclient builds a controller-runtime client.Client wired
// to the Keystone CRDs (LogicalDatabase, DatabaseSchema, etc.) for the
// realm provisioner's runtime enrollment calls.
//
// Authority: this package wraps the in-cluster k8s API for falcon-id.
// The client gets created once at process startup and shared across
// realm_db_provisioner + realm_db_migrator. It MUST NOT leak through
// the rest of the codebase — anything that needs the Keystone API
// goes through realm_db_provisioner / realm_db_migrator.
//
// In-cluster config:
//   - rest.InClusterConfig() reads /var/run/secrets/kubernetes.io/
//     serviceaccount/{token,ca.crt} which the Pod must have mounted.
//     The falcon-id helm chart's pod template MUST set
//     automountServiceAccountToken: true (defaults are mixed across
//     templates; Phase-2b MR4 flips it to true).
//
// RBAC:
//   - The pod's ServiceAccount (falcon-id-falcon-id by default) must
//     be bound to ClusterRole/keystone-tenant-enroller via the
//     falcon-id/RoleBinding shipped in the GitOps repository
//     `platform/keystone/resources/falcon-id/rolebinding-tenant-enroller.yaml`.
//     The ClusterRole grants get/list/watch/create/update/patch/delete
//     on logicaldatabases + databaseschemas only — narrow surface.
package keystoneclient

import (
	"fmt"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

// New constructs a controller-runtime client.Client configured against the
// Kubernetes API and registered with the Keystone v1alpha1 scheme. The caller
// passes ownership in to one consumer (typically the realm provisioner
// constructor) and never holds a second reference.
//
// Config loading uses controller-runtime's standard resolver
// (config.GetConfig): in-cluster service-account first (the production pod
// path), then KUBECONFIG / ~/.kube/config / --kubeconfig out-of-cluster. The
// latter lets a host-run falcon-id (local dev against k3d) reach the cluster
// Keystone instead of disabling realm provisioning entirely.
//
// Returns an error when:
//   - no usable config is found (no in-cluster SA token AND no kubeconfig);
//   - the API server certificate cannot be verified;
//   - the keystone scheme cannot be registered (programmer error — never seen at runtime).
func New() (client.Client, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("keystoneclient: load kube config (in-cluster or KUBECONFIG): %w", err)
	}
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(keystonev1alpha1.AddToScheme(scheme))
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("keystoneclient: build controller-runtime client: %w", err)
	}
	return c, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package provisioners provides pluggable resource provisioners for non-database
// resources: Storage (S3/MinIO-compatible), Messaging (Kafka), DNS/Routes (APISIX),
// Identity (SpiceDB/OAuth), DNS entries, and TLS certificates via Vault PKI.
//
// Each provisioner implements the ResourceProvisioner interface, which provides
// a uniform lifecycle (Provision / Deprovision / HealthCheck) regardless of the
// backing technology.
//
// # Dev-mode safety
//
// Every provisioner is fail-safe in dev mode: when the external service is
// unavailable or credentials are not configured, Provision returns a simulated
// result with Status "active_simulated" rather than failing the entire
// provisioning saga.  Use devModeResult to build consistent simulated payloads.
package provisioners

import (
	"context"
	"fmt"
)

// ResourceProvisionRequest carries all parameters needed to provision a
// single resource during product instance setup.
type ResourceProvisionRequest struct {
	// TenantID is the UUID string of the tenant that owns the instance.
	TenantID string
	// TenantSlug is the human-readable tenant identifier (e.g. "acme-corp").
	// Provisioners use it to build bucket names, topic names, and hostnames.
	TenantSlug string
	// InstanceID is the UUID string of the ProductInstance being provisioned.
	InstanceID string
	// ProductSlug is the short product identifier (e.g. "examplesuite").
	ProductSlug string
	// ResourceName is the logical name of the resource from the product manifest
	// (e.g. "uploads", "events", "tenant-dns").
	ResourceName string
	// Config holds resource-type-specific parameters sourced from the product
	// manifest (e.g. strategy, partitions, retention_hours, domain_pattern).
	Config map[string]interface{}
}

// ResourceProvisionResult describes the outcome of a successful Provision call.
type ResourceProvisionResult struct {
	// Status indicates the final resource state.
	// Values: "active", "active_simulated".
	Status string
	// ProvisionedConfig is a map of output values that should be stored and
	// returned to callers (e.g. bucket_name, topic_name, fqdn).
	// Secret values (e.g. OAuth client_secret) MUST NOT appear here.
	ProvisionedConfig map[string]interface{}
}

// ResourceDeprovisionRequest carries parameters for tearing down a resource.
type ResourceDeprovisionRequest struct {
	// TenantID is the UUID string of the owning tenant.
	TenantID string
	// TenantSlug is the human-readable tenant identifier.
	TenantSlug string
	// InstanceID is the ProductInstance UUID string.
	InstanceID string
	// ResourceName is the logical resource name from the product manifest.
	ResourceName string
	// ProvisionedConfig is the config that was returned by Provision; it
	// provides identifiers needed to locate and delete the resource.
	ProvisionedConfig map[string]interface{}
}

// ResourceHealthCheckRequest carries parameters for checking whether a
// previously provisioned resource is healthy and accessible.
type ResourceHealthCheckRequest struct {
	// TenantID is the UUID string of the owning tenant.
	TenantID string
	// ResourceName is the logical resource name.
	ResourceName string
	// ProvisionedConfig is the config returned by Provision.
	ProvisionedConfig map[string]interface{}
}

// ResourceHealthResult describes the outcome of a HealthCheck call.
type ResourceHealthResult struct {
	// Healthy is true when the resource is accessible and operational.
	Healthy bool
	// Message provides additional context (error description or OK note).
	Message string
}

// ResourceProvisioner is the uniform interface every pluggable provisioner must
// satisfy.  Implementations handle a single resource type (e.g. "storage_bucket",
// "kafka_topic") and are registered with the ProvisioningOrchestrator via a
// ResourceProvisionerRegistry.
type ResourceProvisioner interface {
	// ResourceType returns the stable string identifier for the resource type
	// this provisioner handles (e.g. "storage_bucket", "kafka_topic").
	ResourceType() string

	// Provision allocates the resource described by req and returns configuration
	// details that should be persisted for future operations.
	// Implementations MUST be idempotent: calling Provision twice for the same
	// resource must not result in duplicate infrastructure.
	Provision(ctx context.Context, req ResourceProvisionRequest) (*ResourceProvisionResult, error)

	// Deprovision tears down the resource.  It should be best-effort and must
	// not return an error if the resource has already been removed.
	Deprovision(ctx context.Context, req ResourceDeprovisionRequest) error

	// HealthCheck verifies that the resource exists and is accessible.
	HealthCheck(ctx context.Context, req ResourceHealthCheckRequest) (*ResourceHealthResult, error)
}

// ResourceProvisionerRegistry maps resource type strings to their provisioner
// implementations.  It is the single place where provisioners are registered
// and looked up by the orchestrator.
type ResourceProvisionerRegistry struct {
	provisioners map[string]ResourceProvisioner
}

// NewResourceProvisionerRegistry creates an empty registry.
func NewResourceProvisionerRegistry() *ResourceProvisionerRegistry {
	return &ResourceProvisionerRegistry{
		provisioners: make(map[string]ResourceProvisioner),
	}
}

// Register adds a provisioner to the registry.  Panics on duplicate registration
// so misconfiguration is caught at startup rather than silently at runtime.
func (r *ResourceProvisionerRegistry) Register(p ResourceProvisioner) {
	if _, exists := r.provisioners[p.ResourceType()]; exists {
		panic(fmt.Sprintf("provisioner already registered for resource type %q", p.ResourceType()))
	}
	r.provisioners[p.ResourceType()] = p
}

// Get retrieves the provisioner for the given resource type.
// Returns (nil, false) when no provisioner is registered.
func (r *ResourceProvisionerRegistry) Get(resourceType string) (ResourceProvisioner, bool) {
	p, ok := r.provisioners[resourceType]
	return p, ok
}

// All returns a snapshot of all registered provisioners keyed by resource type.
func (r *ResourceProvisionerRegistry) All() map[string]ResourceProvisioner {
	out := make(map[string]ResourceProvisioner, len(r.provisioners))
	for k, v := range r.provisioners {
		out[k] = v
	}
	return out
}

// devModeResult builds a standardised "simulated" ResourceProvisionResult for
// use when an external service is unavailable in local development.
// The ProvisionedConfig always contains simulated=true, resource_type, and
// resource_name so callers can detect simulated resources programmatically.
func devModeResult(resourceType, resourceName string, extra map[string]interface{}) *ResourceProvisionResult {
	cfg := map[string]interface{}{
		"simulated":     true,
		"resource_type": resourceType,
		"resource_name": resourceName,
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return &ResourceProvisionResult{
		Status:            "active_simulated",
		ProvisionedConfig: cfg,
	}
}

// stringFromConfig is a convenience helper that extracts a string value from a
// config map, returning the provided default when the key is absent or the
// value is not a string.
func stringFromConfig(cfg map[string]interface{}, key, defaultVal string) string {
	if cfg == nil {
		return defaultVal
	}
	v, ok := cfg[key]
	if !ok {
		return defaultVal
	}
	s, ok := v.(string)
	if !ok {
		return defaultVal
	}
	return s
}

// intFromConfig extracts an int from a config map, accepting both int and
// float64 (JSON numbers unmarshal as float64).
func intFromConfig(cfg map[string]interface{}, key string, defaultVal int) int {
	if cfg == nil {
		return defaultVal
	}
	v, ok := cfg[key]
	if !ok {
		return defaultVal
	}
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case int64:
		return int(n)
	}
	return defaultVal
}

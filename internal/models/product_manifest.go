// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"fmt"
)

// ProductManifest describes a product's infrastructure requirements, API surface,
// permissions, events, quotas, and inter-product dependencies.  It is stored as
// JSONB in the CapabilityManifest column of iam_products (migration 086).
type ProductManifest struct {
	Database     *DatabaseSpec    `json:"database,omitempty"`
	Compute      *ComputeSpec     `json:"compute,omitempty"`
	Storage      *StorageSpec     `json:"storage,omitempty"`
	Network      *NetworkSpec     `json:"network,omitempty"`
	Endpoints    []EndpointSpec   `json:"endpoints,omitempty"`
	Permissions  []PermissionSpec `json:"permissions,omitempty"`
	Events       []EventSpec      `json:"events,omitempty"`
	Quotas       []QuotaSpec      `json:"quotas,omitempty"`
	Dependencies []string         `json:"dependencies,omitempty"`
	Lifecycle    *LifecycleSpec   `json:"lifecycle,omitempty"`
}

// LifecycleSpec defines webhook callbacks that are invoked during
// provisioning lifecycle events. The product service registers these
// URLs so Falcon-ID can notify it when instances change state.
//
// Security: All callback URLs must be internal service URLs (validated
// against an allowlist). HMAC signing prevents tampering.
type LifecycleSpec struct {
	// OnActivated is called when provisioning completes successfully.
	OnActivated string `json:"on_activated,omitempty"`
	// OnFailed is called when provisioning permanently fails.
	OnFailed string `json:"on_failed,omitempty"`
	// OnDeleted is called when an instance is deprovisioned.
	OnDeleted string `json:"on_deleted,omitempty"`
	// OnSuspended is called when an instance is suspended (e.g. billing issue).
	OnSuspended string `json:"on_suspended,omitempty"`
	// SigningSecret is the HMAC-SHA256 key used to sign callback payloads.
	// When empty, callbacks are sent unsigned (not recommended for production).
	SigningSecret string `json:"signing_secret,omitempty"`
}

// LifecycleCallbackPayload is the JSON body sent to product lifecycle webhooks.
type LifecycleCallbackPayload struct {
	EventType  string `json:"event_type"`
	InstanceID string `json:"instance_id"`
	TenantID   string `json:"tenant_id"`
	ProductID  string `json:"product_id"`
	Reason     string `json:"reason,omitempty"`
	Timestamp  string `json:"timestamp"`
}

// DatabaseSpec describes the database requirements for a product.
type DatabaseSpec struct {
	// Type is the database engine (currently only "postgresql").
	Type string `json:"type" binding:"required"`
	// IsolationDefault is the default tenant isolation strategy:
	//   "pool"   — shared database with RLS (free/starter tiers)
	//   "bridge" — schema-per-tenant in a shared database (professional)
	//   "silo"   — database-per-tenant (enterprise)
	IsolationDefault string `json:"isolation_default" binding:"required"`
	// MigrationSource is the path or registry URL for SQL migration files.
	MigrationSource string `json:"migration_source"`
	// RequiredExtensions lists PostgreSQL extensions that must be enabled.
	RequiredExtensions []string `json:"required_extensions,omitempty"`
	// SchemaPrefix is used to namespace tables within a shared database.
	SchemaPrefix string `json:"schema_prefix,omitempty"`
}

// EndpointSpec describes a single API endpoint exposed by the product.
type EndpointSpec struct {
	Path        string `json:"path" binding:"required"`
	Method      string `json:"method" binding:"required"`
	AuthType    string `json:"auth_type,omitempty"`
	Description string `json:"description,omitempty"`
	RateLimit   int    `json:"rate_limit,omitempty"`
	// UpstreamHost overrides the default upstream address for this endpoint.
	// Format: "host:port" (e.g. "crm-service:8080").
	// When empty, a conventional address derived from the product slug is used.
	UpstreamHost string `json:"upstream_host,omitempty"`
	// RoutePrefix is the full APISIX URI pattern for this endpoint
	// (e.g. "/api/crm/*"). When empty it is generated from the product slug
	// and endpoint path.
	RoutePrefix string `json:"route_prefix,omitempty"`
	// StripPrefix instructs APISIX to strip the route prefix from the request
	// URI before forwarding to the upstream.
	StripPrefix bool `json:"strip_prefix,omitempty"`
	// PluginConfig contains additional or overriding APISIX plugin configuration
	// that is merged on top of the default plugin set for this endpoint.
	PluginConfig map[string]any `json:"plugin_config,omitempty"`
}

// ComputeSpec describes the compute resource constraints for a product.
type ComputeSpec struct {
	// AllowedRuntimes lists the permitted execution runtimes (e.g. "go", "node").
	AllowedRuntimes []string `json:"allowed_runtimes,omitempty"`
	// MaxWorkloads is the maximum number of concurrent workload deployments.
	MaxWorkloads int `json:"max_workloads,omitempty"`
	// MaxFunctions is the maximum number of serverless functions the product may register.
	MaxFunctions int `json:"max_functions,omitempty"`
	// MaxCPUMilli is the total CPU budget in millicores (e.g. 2000 = 2 vCPU).
	MaxCPUMilli int `json:"max_cpu_milli,omitempty"`
	// MaxMemoryMB is the total memory budget in mebibytes.
	MaxMemoryMB int `json:"max_memory_mb,omitempty"`
	// MaxReplicas is the maximum number of pod replicas per workload.
	MaxReplicas int `json:"max_replicas,omitempty"`
}

// StorageSpec describes the object-storage constraints for a product.
type StorageSpec struct {
	// MaxBuckets is the maximum number of storage buckets the product may create.
	MaxBuckets int `json:"max_buckets,omitempty"`
	// MaxTotalBytes is the aggregate storage quota across all buckets (bytes).
	MaxTotalBytes int64 `json:"max_total_bytes,omitempty"`
	// MaxObjectBytes is the maximum size of a single object (bytes).
	MaxObjectBytes int64 `json:"max_object_bytes,omitempty"`
	// AllowedStorageClasses lists the permitted storage classes (e.g. "standard", "infrequent").
	AllowedStorageClasses []string `json:"allowed_storage_classes,omitempty"`
	// VersioningAllowed indicates whether object versioning may be enabled on buckets.
	VersioningAllowed bool `json:"versioning_allowed,omitempty"`
}

// NetworkSpec describes the networking resource constraints for a product.
type NetworkSpec struct {
	// MaxVirtualNetworks is the maximum number of virtual networks the product may create.
	MaxVirtualNetworks int `json:"max_virtual_networks,omitempty"`
	// MaxSecurityGroups is the maximum number of security groups.
	MaxSecurityGroups int `json:"max_security_groups,omitempty"`
	// MaxRulesPerGroup is the maximum number of inbound/outbound rules per security group.
	MaxRulesPerGroup int `json:"max_rules_per_group,omitempty"`
	// MaxLoadBalancers is the maximum number of load balancer resources.
	MaxLoadBalancers int `json:"max_load_balancers,omitempty"`
	// MaxDNSRecords is the maximum number of DNS records across all managed zones.
	MaxDNSRecords int `json:"max_dns_records,omitempty"`
	// CustomDomainsAllowed indicates whether the product may bind custom domains.
	CustomDomainsAllowed bool `json:"custom_domains_allowed,omitempty"`
}

// PermissionSpec describes a permission scope for a product resource.
type PermissionSpec struct {
	Resource string   `json:"resource" binding:"required"`
	Actions  []string `json:"actions" binding:"required"`
}

// EventSpec describes an event that the product emits.
type EventSpec struct {
	Type          string `json:"type" binding:"required"`
	SchemaVersion string `json:"schema_version,omitempty"`
	Description   string `json:"description,omitempty"`
}

// QuotaSpec describes a metered quota for the product.
type QuotaSpec struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description,omitempty"`
	Unit        string `json:"unit,omitempty"`
	DefaultMax  int64  `json:"default_max,omitempty"`
}

// Isolation mode constants.
const (
	IsolationPool   = "pool"
	IsolationBridge = "bridge"
	IsolationSilo   = "silo"
)

// ValidIsolationModes is the set of accepted isolation modes.
var ValidIsolationModes = map[string]bool{
	IsolationPool:   true,
	IsolationBridge: true,
	IsolationSilo:   true,
}

// ValidDatabaseTypes is the set of supported database engines.
var ValidDatabaseTypes = map[string]bool{
	"postgresql": true,
}

// ValidHTTPMethods is the set of accepted HTTP methods for endpoint specs.
var ValidHTTPMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true,
}

// ParseManifest deserialises the CapabilityManifest JSONB into a typed
// ProductManifest.  Returns nil without error when the raw JSON is nil or empty.
func (p *Product) ParseManifest() (*ProductManifest, error) {
	if len(p.CapabilityManifest) == 0 {
		return nil, nil
	}
	var m ProductManifest
	if err := json.Unmarshal(p.CapabilityManifest, &m); err != nil {
		return nil, fmt.Errorf("parse product manifest: %w", err)
	}
	return &m, nil
}

// SetManifest serialises a ProductManifest into the CapabilityManifest column.
func (p *Product) SetManifest(m *ProductManifest) error {
	if m == nil {
		p.CapabilityManifest = nil
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal product manifest: %w", err)
	}
	p.CapabilityManifest = b
	return nil
}

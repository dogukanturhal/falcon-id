// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ManifestValidator validates ProductManifest payloads.
type ManifestValidator struct{}

// NewManifestValidator creates a new ManifestValidator.
func NewManifestValidator() *ManifestValidator {
	return &ManifestValidator{}
}

// Validate checks a raw JSON manifest for structural correctness.
// Returns nil when raw is nil or an empty JSON object.
func (v *ManifestValidator) Validate(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}

	var m models.ProductManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("invalid manifest JSON: %w", err)
	}

	return v.ValidateManifest(&m)
}

// ValidateManifest checks a typed manifest for semantic correctness.
func (v *ManifestValidator) ValidateManifest(m *models.ProductManifest) error {
	if m == nil {
		return nil
	}

	if err := v.validateDatabase(m.Database); err != nil {
		return err
	}
	if err := v.validateEndpoints(m.Endpoints); err != nil {
		return err
	}
	if err := v.validatePermissions(m.Permissions); err != nil {
		return err
	}
	if err := v.validateEvents(m.Events); err != nil {
		return err
	}
	if err := v.validateQuotas(m.Quotas); err != nil {
		return err
	}
	if err := v.validateDependencies(m.Dependencies); err != nil {
		return err
	}
	if err := v.validateCompute(m.Compute); err != nil {
		return err
	}
	if err := v.validateStorage(m.Storage); err != nil {
		return err
	}
	if err := v.validateNetwork(m.Network); err != nil {
		return err
	}
	return nil
}

func (v *ManifestValidator) validateDatabase(db *models.DatabaseSpec) error {
	if db == nil {
		return nil
	}

	if db.Type == "" {
		return fmt.Errorf("manifest: database.type is required")
	}
	if !models.ValidDatabaseTypes[db.Type] {
		return fmt.Errorf("manifest: unsupported database type %q", db.Type)
	}

	if db.IsolationDefault == "" {
		return fmt.Errorf("manifest: database.isolation_default is required")
	}
	if !models.ValidIsolationModes[db.IsolationDefault] {
		return fmt.Errorf("manifest: invalid isolation_default %q; must be one of pool, bridge, silo", db.IsolationDefault)
	}

	if db.SchemaPrefix != "" {
		if len(db.SchemaPrefix) > 20 {
			return fmt.Errorf("manifest: schema_prefix must be <= 20 characters")
		}
		for _, c := range db.SchemaPrefix {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
				return fmt.Errorf("manifest: schema_prefix must contain only lowercase alphanumeric characters and underscores")
			}
		}
	}

	return nil
}

func (v *ManifestValidator) validateEndpoints(endpoints []models.EndpointSpec) error {
	seen := make(map[string]bool)
	for i, ep := range endpoints {
		if ep.Path == "" {
			return fmt.Errorf("manifest: endpoints[%d].path is required", i)
		}
		if !strings.HasPrefix(ep.Path, "/") {
			return fmt.Errorf("manifest: endpoints[%d].path must start with /", i)
		}
		method := strings.ToUpper(ep.Method)
		if method == "" {
			return fmt.Errorf("manifest: endpoints[%d].method is required", i)
		}
		if !models.ValidHTTPMethods[method] {
			return fmt.Errorf("manifest: endpoints[%d] invalid method %q", i, ep.Method)
		}
		key := method + " " + ep.Path
		if seen[key] {
			return fmt.Errorf("manifest: duplicate endpoint %s", key)
		}
		seen[key] = true
	}
	return nil
}

func (v *ManifestValidator) validatePermissions(perms []models.PermissionSpec) error {
	seen := make(map[string]bool)
	for i, p := range perms {
		if p.Resource == "" {
			return fmt.Errorf("manifest: permissions[%d].resource is required", i)
		}
		if len(p.Actions) == 0 {
			return fmt.Errorf("manifest: permissions[%d].actions must not be empty", i)
		}
		actionSeen := make(map[string]bool)
		for _, a := range p.Actions {
			if a == "" {
				return fmt.Errorf("manifest: permissions[%d] contains empty action", i)
			}
			key := p.Resource + ":" + a
			if seen[key] {
				return fmt.Errorf("manifest: duplicate permission %s", key)
			}
			seen[key] = true
			if actionSeen[a] {
				return fmt.Errorf("manifest: permissions[%d] duplicate action %q", i, a)
			}
			actionSeen[a] = true
		}
	}
	return nil
}

func (v *ManifestValidator) validateEvents(events []models.EventSpec) error {
	seen := make(map[string]bool)
	for i, e := range events {
		if e.Type == "" {
			return fmt.Errorf("manifest: events[%d].type is required", i)
		}
		if seen[e.Type] {
			return fmt.Errorf("manifest: duplicate event type %q", e.Type)
		}
		seen[e.Type] = true
	}
	return nil
}

func (v *ManifestValidator) validateQuotas(quotas []models.QuotaSpec) error {
	seen := make(map[string]bool)
	for i, q := range quotas {
		if q.Name == "" {
			return fmt.Errorf("manifest: quotas[%d].name is required", i)
		}
		if seen[q.Name] {
			return fmt.Errorf("manifest: duplicate quota name %q", q.Name)
		}
		seen[q.Name] = true
		if q.DefaultMax < 0 {
			return fmt.Errorf("manifest: quotas[%d].default_max must be >= 0", i)
		}
	}
	return nil
}

func (v *ManifestValidator) validateDependencies(deps []string) error {
	seen := make(map[string]bool)
	for i, d := range deps {
		if d == "" {
			return fmt.Errorf("manifest: dependencies[%d] must not be empty", i)
		}
		if seen[d] {
			return fmt.Errorf("manifest: duplicate dependency %q", d)
		}
		seen[d] = true
	}
	return nil
}

// validComputeRuntimes is the set of accepted runtime identifiers for ComputeSpec.
var validComputeRuntimes = map[string]bool{
	"node20":  true,
	"python3": true,
	"go121":   true,
	"java21":  true,
}

// validateCompute checks a ComputeSpec for semantic correctness.
// A nil spec is valid — compute resources are optional for all products.
func (v *ManifestValidator) validateCompute(spec *models.ComputeSpec) error {
	if spec == nil {
		return nil
	}
	for i, rt := range spec.AllowedRuntimes {
		if !validComputeRuntimes[rt] {
			return fmt.Errorf("manifest: compute.allowed_runtimes[%d] invalid runtime %q", i, rt)
		}
	}
	if spec.MaxWorkloads < 0 {
		return fmt.Errorf("manifest: compute.max_workloads must be >= 0")
	}
	if spec.MaxFunctions < 0 {
		return fmt.Errorf("manifest: compute.max_functions must be >= 0")
	}
	if spec.MaxCPUMilli < 0 {
		return fmt.Errorf("manifest: compute.max_cpu_milli must be >= 0")
	}
	if spec.MaxMemoryMB < 0 {
		return fmt.Errorf("manifest: compute.max_memory_mb must be >= 0")
	}
	if spec.MaxReplicas < 0 {
		return fmt.Errorf("manifest: compute.max_replicas must be >= 0")
	}
	return nil
}

// validStorageClasses is the set of accepted storage class identifiers for StorageSpec.
var validStorageClasses = map[string]bool{
	"standard":   true,
	"infrequent": true,
	"archive":    true,
	"cold":       true,
}

// validateStorage checks a StorageSpec for semantic correctness.
// A nil spec is valid — object storage is optional for all products.
func (v *ManifestValidator) validateStorage(spec *models.StorageSpec) error {
	if spec == nil {
		return nil
	}
	if spec.MaxBuckets < 0 {
		return fmt.Errorf("manifest: storage.max_buckets must be >= 0")
	}
	if spec.MaxTotalBytes < 0 {
		return fmt.Errorf("manifest: storage.max_total_bytes must be >= 0")
	}
	if spec.MaxObjectBytes < 0 {
		return fmt.Errorf("manifest: storage.max_object_bytes must be >= 0")
	}
	for i, sc := range spec.AllowedStorageClasses {
		if !validStorageClasses[sc] {
			return fmt.Errorf("manifest: storage.allowed_storage_classes[%d] invalid class %q", i, sc)
		}
	}
	return nil
}

// validateNetwork checks a NetworkSpec for semantic correctness.
// A nil spec is valid — networking resources are optional for all products.
func (v *ManifestValidator) validateNetwork(spec *models.NetworkSpec) error {
	if spec == nil {
		return nil
	}
	if spec.MaxVirtualNetworks < 0 {
		return fmt.Errorf("manifest: network.max_virtual_networks must be >= 0")
	}
	if spec.MaxSecurityGroups < 0 {
		return fmt.Errorf("manifest: network.max_security_groups must be >= 0")
	}
	if spec.MaxRulesPerGroup < 0 {
		return fmt.Errorf("manifest: network.max_rules_per_group must be >= 0")
	}
	if spec.MaxLoadBalancers < 0 {
		return fmt.Errorf("manifest: network.max_load_balancers must be >= 0")
	}
	if spec.MaxDNSRecords < 0 {
		return fmt.Errorf("manifest: network.max_dns_records must be >= 0")
	}
	return nil
}

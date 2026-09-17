// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ResourceProvisionRequest carries all information a provisioner needs to create a resource.
type ResourceProvisionRequest struct {
	TenantID     uuid.UUID
	ProductID    uuid.UUID
	InstanceID   uuid.UUID
	ManifestID   uuid.UUID
	ResourceName string
	Config       map[string]interface{} // decoded from manifest JSONB
	Region       string
	Tier         string // pool | bridge | silo — matches isolation mode
}

// ResourceProvisionResult contains the outcome of a successful Provision call.
type ResourceProvisionResult struct {
	// Status is the terminal status to record (typically "active").
	Status string `json:"status"`
	// ProvisionedConfig holds resource-specific details the operator needs to use
	// the resource (e.g. host, bucket name, topic ARN, client_id).
	ProvisionedConfig map[string]interface{} `json:"provisioned_config"`
}

// ResourceDeprovisionRequest carries what is needed to destroy a resource.
type ResourceDeprovisionRequest struct {
	TenantID          uuid.UUID
	ResourceName      string
	ProvisionedConfig map[string]interface{}
}

// ResourceHealthCheckRequest carries what is needed to health-check a resource.
type ResourceHealthCheckRequest struct {
	TenantID          uuid.UUID
	ResourceName      string
	ProvisionedConfig map[string]interface{}
}

// ResourceHealthResult is the outcome of a HealthCheck call.
type ResourceHealthResult struct {
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
	Healthy      bool   `json:"healthy"`
	Message      string `json:"message"`
}

// ResourceProvisioner is the interface every resource-type provisioner must implement.
// New resource types (storage, Kafka, DNS, …) are added by implementing this interface
// and registering the implementation with ResourceProvisionerRegistry.
type ResourceProvisioner interface {
	// ResourceType returns the type string this provisioner handles ("database",
	// "storage_bucket", "kafka_topic", …).  Must be stable and lowercase.
	ResourceType() string

	// Provision creates the resource for a tenant.  The call must be idempotent —
	// calling Provision twice for the same tenant+resource must not fail or create
	// duplicate resources.
	Provision(ctx context.Context, req ResourceProvisionRequest) (*ResourceProvisionResult, error)

	// Deprovision destroys the resource.  Best-effort: return the first error
	// encountered but do not abort partial cleanup — callers log and continue.
	Deprovision(ctx context.Context, req ResourceDeprovisionRequest) error

	// HealthCheck verifies the resource is reachable and operational.
	// Returns a non-nil result even on error so callers can always record state.
	HealthCheck(ctx context.Context, req ResourceHealthCheckRequest) (*ResourceHealthResult, error)
}

// ResourceProvisionerRegistry is a thread-safe registry that maps resource type
// strings to their provisioner implementations.  Register all provisioners before
// the application starts serving requests; the registry is read-only after that.
type ResourceProvisionerRegistry struct {
	provisioners map[string]ResourceProvisioner
	log          *zap.SugaredLogger
}

// NewResourceProvisionerRegistry creates an empty registry.
func NewResourceProvisionerRegistry(log *zap.SugaredLogger) *ResourceProvisionerRegistry {
	return &ResourceProvisionerRegistry{
		provisioners: make(map[string]ResourceProvisioner),
		log:          log,
	}
}

// Register adds a provisioner to the registry.  Panics if a provisioner for the
// same resource type has already been registered to surface wiring bugs early.
func (r *ResourceProvisionerRegistry) Register(p ResourceProvisioner) {
	t := p.ResourceType()
	if _, exists := r.provisioners[t]; exists {
		panic(fmt.Sprintf("ResourceProvisionerRegistry: duplicate registration for type %q", t))
	}
	r.provisioners[t] = p
	r.log.Infow("Resource provisioner registered", "resource_type", t)
}

// Get returns the provisioner for the given type, or false when none is registered.
func (r *ResourceProvisionerRegistry) Get(resourceType string) (ResourceProvisioner, bool) {
	p, ok := r.provisioners[resourceType]
	return p, ok
}

// ListTypes returns all registered resource type strings.
func (r *ResourceProvisionerRegistry) ListTypes() []string {
	types := make([]string, 0, len(r.provisioners))
	for t := range r.provisioners {
		types = append(types, t)
	}
	return types
}

// NoopResourceProvisioner is a stub provisioner that succeeds without doing any
// real work.  Used for resource types that are not yet implemented (storage_bucket,
// kafka_topic, …) so provisioning can proceed end-to-end in dev environments.
type NoopResourceProvisioner struct {
	resourceType string
	log          *zap.SugaredLogger
}

// NewNoopResourceProvisioner creates a no-op provisioner for the given type.
func NewNoopResourceProvisioner(resourceType string, log *zap.SugaredLogger) *NoopResourceProvisioner {
	return &NoopResourceProvisioner{resourceType: resourceType, log: log}
}

// ResourceType is an exported function.
func (n *NoopResourceProvisioner) ResourceType() string { return n.resourceType }

// Provision is an exported function.
func (n *NoopResourceProvisioner) Provision(_ context.Context, req ResourceProvisionRequest) (*ResourceProvisionResult, error) {
	n.log.Infow("NoopResourceProvisioner.Provision called (no real resource created)",
		"resource_type", n.resourceType,
		"resource_name", req.ResourceName,
		"tenant_id", req.TenantID,
	)
	return &ResourceProvisionResult{
		Status:            "active",
		ProvisionedConfig: map[string]interface{}{"noop": true},
	}, nil
}

// Deprovision is an exported function.
func (n *NoopResourceProvisioner) Deprovision(_ context.Context, req ResourceDeprovisionRequest) error {
	n.log.Infow("NoopResourceProvisioner.Deprovision called",
		"resource_type", n.resourceType,
		"resource_name", req.ResourceName,
	)
	return nil
}

// HealthCheck is an exported function.
func (n *NoopResourceProvisioner) HealthCheck(_ context.Context, req ResourceHealthCheckRequest) (*ResourceHealthResult, error) {
	return &ResourceHealthResult{
		ResourceType: n.resourceType,
		ResourceName: req.ResourceName,
		Healthy:      true,
		Message:      "noop provisioner always healthy",
	}, nil
}

// DatabaseResourceProvisioner wraps the existing ProductDBProvisioner behind the
// ResourceProvisioner interface so database resources participate in the universal
// manifest framework without duplicating any provisioning logic.
type DatabaseResourceProvisioner struct {
	dbProvisioner *ProductDBProvisioner
	log           *zap.SugaredLogger
}

// NewDatabaseResourceProvisioner creates a provisioner backed by the existing DB provisioner.
func NewDatabaseResourceProvisioner(dbp *ProductDBProvisioner, log *zap.SugaredLogger) *DatabaseResourceProvisioner {
	return &DatabaseResourceProvisioner{dbProvisioner: dbp, log: log}
}

// ResourceType is an exported function.
func (p *DatabaseResourceProvisioner) ResourceType() string { return "database" }

// Provision delegates to ProductDBProvisioner.ProvisionProductDatabase using the
// resource name as the product slug (which equals the database name convention).
// The isolation tier is read from req.Tier (pool/bridge/silo).
func (p *DatabaseResourceProvisioner) Provision(ctx context.Context, req ResourceProvisionRequest) (*ResourceProvisionResult, error) {
	if p.dbProvisioner == nil {
		return nil, fmt.Errorf("database provisioner not configured")
	}

	result, err := p.dbProvisioner.ProvisionProductDatabase(
		ctx,
		req.TenantID,
		req.ResourceName,
		nil, // manifest — not needed; isolation comes from req.Tier
		req.Tier,
	)
	if err != nil {
		return nil, fmt.Errorf("provision database %s: %w", req.ResourceName, err)
	}

	cfg := map[string]interface{}{
		"host":          result.Host,
		"database_name": result.DatabaseName,
		"schema":        result.Schema,
		"username":      result.Username,
	}

	p.log.Infow("Database resource provisioned",
		"resource_name", req.ResourceName,
		"tenant_id", req.TenantID,
		"host", result.Host,
		"database", result.DatabaseName,
		"schema", result.Schema,
		"tier", req.Tier,
	)

	return &ResourceProvisionResult{
		Status:            "active",
		ProvisionedConfig: cfg,
	}, nil
}

// Deprovision is an exported function.
func (p *DatabaseResourceProvisioner) Deprovision(_ context.Context, req ResourceDeprovisionRequest) error {
	// Database deprovisioning for individual resource instances is handled by
	// the ProductDBProvisioner during the full instance deletion saga.
	// For targeted resource-level deprovisioning we log and succeed gracefully.
	p.log.Infow("DatabaseResourceProvisioner.Deprovision called (handled by saga)",
		"resource_name", req.ResourceName,
		"tenant_id", req.TenantID,
	)
	return nil
}

// HealthCheck is an exported function.
func (p *DatabaseResourceProvisioner) HealthCheck(ctx context.Context, req ResourceHealthCheckRequest) (*ResourceHealthResult, error) {
	// A lightweight health check: verify the master pool is reachable.
	if p.dbProvisioner == nil {
		return &ResourceHealthResult{
			ResourceType: "database",
			ResourceName: req.ResourceName,
			Healthy:      false,
			Message:      "database provisioner not configured",
		}, nil
	}
	if err := p.dbProvisioner.masterPool.Ping(ctx); err != nil {
		return &ResourceHealthResult{
			ResourceType: "database",
			ResourceName: req.ResourceName,
			Healthy:      false,
			Message:      fmt.Sprintf("master pool ping failed: %v", err),
		}, nil
	}
	return &ResourceHealthResult{
		ResourceType: "database",
		ResourceName: req.ResourceName,
		Healthy:      true,
		Message:      "master pool reachable",
	}, nil
}

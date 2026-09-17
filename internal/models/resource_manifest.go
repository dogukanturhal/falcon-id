// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ProductResourceManifest declares a resource a product requires per tenant.
// Resources are declared at product registration time; the provisioner framework
// reads these at activation time to know what to create.
type ProductResourceManifest struct {
	ID           uuid.UUID       `json:"id" db:"id"`
	ProductID    uuid.UUID       `json:"product_id" db:"product_id"`
	ResourceType string          `json:"resource_type" db:"resource_type"`
	ResourceName string          `json:"resource_name" db:"resource_name"`
	DisplayName  string          `json:"display_name" db:"display_name"`
	Config       json.RawMessage `json:"config" db:"config"`
	Priority     int             `json:"priority" db:"priority"`
	IsRequired   bool            `json:"is_required" db:"is_required"`
	CreatedAt    time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at" db:"updated_at"`
}

// ConfigMap decodes the manifest's JSONB config field into a plain map.
// Returns an empty map on decode error so callers can always range safely.
func (m *ProductResourceManifest) ConfigMap() map[string]interface{} {
	out := make(map[string]interface{})
	if len(m.Config) == 0 {
		return out
	}
	_ = json.Unmarshal(m.Config, &out)
	return out
}

// TenantResourceInstance tracks a single provisioned resource for a tenant.
// One instance row is created per manifest entry when a product is activated.
type TenantResourceInstance struct {
	ID                uuid.UUID       `json:"id" db:"id"`
	TenantID          uuid.UUID       `json:"tenant_id" db:"tenant_id"`
	ProductID         uuid.UUID       `json:"product_id" db:"product_id"`
	InstanceID        uuid.UUID       `json:"instance_id" db:"instance_id"`
	ManifestID        uuid.UUID       `json:"manifest_id" db:"manifest_id"`
	ResourceType      string          `json:"resource_type" db:"resource_type"`
	ResourceName      string          `json:"resource_name" db:"resource_name"`
	Status            string          `json:"status" db:"status"`
	ProvisionedConfig json.RawMessage `json:"provisioned_config" db:"provisioned_config"`
	ErrorMessage      *string         `json:"error_message,omitempty" db:"error_message"`
	RetryCount        int             `json:"retry_count" db:"retry_count"`
	ProvisionedAt     *time.Time      `json:"provisioned_at,omitempty" db:"provisioned_at"`
	CreatedAt         time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at" db:"updated_at"`
}

// ProvisionedConfigMap decodes the provisioned_config JSONB field into a plain map.
func (t *TenantResourceInstance) ProvisionedConfigMap() map[string]interface{} {
	out := make(map[string]interface{})
	if len(t.ProvisionedConfig) == 0 {
		return out
	}
	_ = json.Unmarshal(t.ProvisionedConfig, &out)
	return out
}

// Resource status constants — mirrors the DB CHECK constraint values.
const (
	ResourceStatusPending  = "pending"
	ResourceStatusCreating = "creating"
	ResourceStatusActive   = "active"
	ResourceStatusFailed   = "failed"
	ResourceStatusDeleting = "deleting"
	ResourceStatusDeleted  = "deleted"
)

// Known resource types — the pluggable provisioner registry uses these strings.
const (
	ResourceTypeDatabase         = "database"
	ResourceTypeStorageBucket    = "storage_bucket"
	ResourceTypeKafkaTopic       = "kafka_topic"
	ResourceTypeApisixRoute      = "apisix_route"
	ResourceTypeSpiceDBNamespace = "spicedb_namespace"
	ResourceTypeDNSEntry         = "dns_entry"
	ResourceTypeTLSCertificate   = "tls_certificate"
	ResourceTypeOAuthClient      = "oauth_client"
)

// CreateResourceManifestRequest is the API payload to add an entry to a product manifest.
type CreateResourceManifestRequest struct {
	ResourceType string                 `json:"resource_type" binding:"required"`
	ResourceName string                 `json:"resource_name" binding:"required"`
	DisplayName  string                 `json:"display_name" binding:"required"`
	Config       map[string]interface{} `json:"config"`
	Priority     int                    `json:"priority"`
	IsRequired   *bool                  `json:"is_required"`
}

// RegisterManifestRequest is the payload sent by a service on startup to
// declare all of its resources to Falcon-ID. The service_slug identifies the
// calling service; product_id scopes resources to the correct product.
type RegisterManifestRequest struct {
	ServiceSlug string                   `json:"service_slug" binding:"required"`
	ProductID   string                   `json:"product_id"   binding:"required"`
	Resources   []ResourceDeclarationDTO `json:"resources"    binding:"required,min=1"`
}

// ResourceDeclarationDTO is a single resource entry inside RegisterManifestRequest.
type ResourceDeclarationDTO struct {
	ResourceType string                 `json:"resource_type" binding:"required"`
	ResourceName string                 `json:"resource_name" binding:"required"`
	DisplayName  string                 `json:"display_name"  binding:"required"`
	Config       map[string]interface{} `json:"config"`
	Priority     int                    `json:"priority"`
	IsRequired   bool                   `json:"is_required"`
}

// RegisterManifestResponse is returned after a successful self-registration call.
type RegisterManifestResponse struct {
	ServiceSlug    string `json:"service_slug"`
	ProductID      string `json:"product_id"`
	Registered     int    `json:"registered"`
	Updated        int    `json:"updated"`
	TotalManifests int    `json:"total_manifests"`
}

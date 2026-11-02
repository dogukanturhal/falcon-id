// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// RoleTemplateSpiceDBRelation is a SpiceDB relation hint a module attaches to
// a role template, consumed by TemplateRoleProvisioner when bootstrapping
// SpiceDB tuples for a template-derived role. Relation is the SpiceDB
// relation name (e.g. "admin", "member"); Permission, when set, scopes the
// relation to a single permission grant rather than the whole template.
type RoleTemplateSpiceDBRelation struct {
	Relation   string `json:"relation" binding:"required"`
	Permission string `json:"permission,omitempty"`
}

// RoleTemplateDefinition is the manifest shape a module submits inside
// RegisterModuleRequest.RoleTemplates to publish/version one starter role
// template. See RegisterModuleRequest for the ownership/validation rules
// applied at registration time.
type RoleTemplateDefinition struct {
	// Key is the template's stable identity, e.g. "marketing:campaign_manager".
	// Must be prefixed with the registering module's name (validated).
	Key string `json:"key" binding:"required"`
	// Version is monotonic per Key: it must be greater than the highest
	// version already stored for this Key, or exactly 1 for a brand-new
	// Key. Re-submitting the SAME version with byte-identical content is
	// treated as an idempotent no-op (safe for repeated service-startup
	// registration calls); re-submitting the same version with DIFFERENT
	// content is rejected — bump the version instead.
	Version         int               `json:"version" binding:"required,min=1"`
	Name            string            `json:"name" binding:"required"`
	NameI18n        map[string]string `json:"name_i18n,omitempty"`
	Description     string            `json:"description,omitempty"`
	DescriptionI18n map[string]string `json:"description_i18n,omitempty"`
	// Permissions are permission names ("module:resource:action"). Every
	// name must belong to the registering module, to a permission also
	// present in this same RegisterModuleRequest.Permissions payload, or to
	// a module listed in RegisterModuleRequest.Dependencies.
	Permissions      []string                      `json:"permissions" binding:"required,min=1"`
	SpiceDBRelations []RoleTemplateSpiceDBRelation `json:"spicedb_relations,omitempty"`
}

// RoleTemplate is the persisted row (one per key+version — see
// iam_role_templates in 0012_iam_role_templates.sql).
type RoleTemplate struct {
	ID               uuid.UUID                     `json:"id" db:"id"`
	Key              string                        `json:"key" db:"key"`
	Version          int                           `json:"version" db:"version"`
	Module           string                        `json:"module" db:"module"`
	Name             string                        `json:"name" db:"name"`
	NameI18n         map[string]string             `json:"name_i18n" db:"name_i18n"`
	Description      *string                       `json:"description,omitempty" db:"description"`
	DescriptionI18n  map[string]string             `json:"description_i18n" db:"description_i18n"`
	Permissions      []string                      `json:"permissions" db:"permissions"`
	SpiceDBRelations []RoleTemplateSpiceDBRelation `json:"spicedb_relations" db:"spicedb_relations"`
	IsActive         bool                          `json:"is_active" db:"is_active"`
	CreatedAt        time.Time                     `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time                     `json:"updated_at" db:"updated_at"`
}

// RoleTemplateResponse is the API-facing projection of RoleTemplate.
type RoleTemplateResponse struct {
	Key              string                        `json:"key"`
	Version          int                           `json:"version"`
	Module           string                        `json:"module"`
	Name             string                        `json:"name"`
	NameI18n         map[string]string             `json:"name_i18n,omitempty"`
	Description      *string                       `json:"description,omitempty"`
	DescriptionI18n  map[string]string             `json:"description_i18n,omitempty"`
	Permissions      []string                      `json:"permissions"`
	SpiceDBRelations []RoleTemplateSpiceDBRelation `json:"spicedb_relations,omitempty"`
}

// ToResponse projects a RoleTemplate into its API response shape.
func (t *RoleTemplate) ToResponse() *RoleTemplateResponse {
	return &RoleTemplateResponse{
		Key:              t.Key,
		Version:          t.Version,
		Module:           t.Module,
		Name:             t.Name,
		NameI18n:         t.NameI18n,
		Description:      t.Description,
		DescriptionI18n:  t.DescriptionI18n,
		Permissions:      t.Permissions,
		SpiceDBRelations: t.SpiceDBRelations,
	}
}

// RoleTemplateListResponse is the response for GET /api/v1/role-templates.
type RoleTemplateListResponse struct {
	RoleTemplates []RoleTemplateResponse `json:"role_templates"`
	Total         int                    `json:"total"`
}

// InstantiateRoleTemplateRequest is the request body for
// POST /api/v1/role-templates/{key}/instantiate. Tenant is always taken from
// the validated JWT (middleware.GetTenantID), never from the body.
type InstantiateRoleTemplateRequest struct {
	// Name overrides the tenant role's display name; defaults to the
	// template's Name when empty. The tenant may want e.g. "Campaign Lead"
	// instead of the template's generic "Campaign Manager".
	Name *string `json:"name,omitempty"`
}

// InstantiateRoleTemplateResponse wraps the created tenant role alongside
// the template it was instantiated from.
type InstantiateRoleTemplateResponse struct {
	Role        RoleResponse `json:"role"`
	TemplateKey string       `json:"template_key"`
	TemplateVer int          `json:"template_version"`
}

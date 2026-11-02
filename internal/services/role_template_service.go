// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/productslug"
)

// roleTemplateEntitledModules resolves which modules a tenant is entitled
// to, for GET /api/v1/role-templates. Satisfied by *PermissionService.
//
// ListModulesForTenant returns nil (not an empty slice) to mean "no
// entitlement filtering configured on this deployment" — the same
// unrestricted-access sentinel PermissionService.ListForTenant/
// ListGroupedByModuleForTenant use (see getEntitledModules). RoleTemplateService
// must treat nil the same way (fall back to ListModules, i.e. every
// registered module), not as "entitled to nothing".
type roleTemplateEntitledModules interface {
	ListModulesForTenant(ctx context.Context, tenantID uuid.UUID) ([]string, error)
	ListModules(ctx context.Context) ([]string, error)
}

// RoleTemplateService is the application-layer entry point for the
// role-templates HTTP surface (GET /api/v1/role-templates,
// POST /api/v1/role-templates/{key}/instantiate). It composes
// RoleTemplateRepository (catalog reads) with TemplateRoleProvisioner
// (tenant-role materialization) and the tenant's module entitlements.
type RoleTemplateService struct {
	templateRepo    templateRepoForProvisioner
	entitledModules roleTemplateEntitledModules
	provisioner     *TemplateRoleProvisioner
}

// NewRoleTemplateService constructs a RoleTemplateService.
func NewRoleTemplateService(templateRepo templateRepoForProvisioner, entitledModules roleTemplateEntitledModules, provisioner *TemplateRoleProvisioner) *RoleTemplateService {
	return &RoleTemplateService{
		templateRepo:    templateRepo,
		entitledModules: entitledModules,
		provisioner:     provisioner,
	}
}

// ListForTenant returns the latest active version of every role template
// belonging to a module tenantID is entitled to.
func (s *RoleTemplateService) ListForTenant(ctx context.Context, tenantID uuid.UUID) (*models.RoleTemplateListResponse, error) {
	modules, err := s.resolveModules(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListForTenant: %w", err)
	}
	if len(modules) == 0 {
		return &models.RoleTemplateListResponse{RoleTemplates: []models.RoleTemplateResponse{}}, nil
	}

	templates, err := s.templateRepo.ListLatestActiveByModules(ctx, modules)
	if err != nil {
		return nil, fmt.Errorf("ListForTenant: %w", err)
	}

	resp := make([]models.RoleTemplateResponse, 0, len(templates))
	for i := range templates {
		resp = append(resp, *templates[i].ToResponse())
	}
	return &models.RoleTemplateListResponse{RoleTemplates: resp, Total: len(resp)}, nil
}

// Instantiate creates (or idempotently returns) tenantID's role for
// templateKey, after confirming tenantID is entitled to the template's
// owning module — a tenant must not be able to instantiate a template for a
// module it never subscribed to, even if it somehow learns the key.
func (s *RoleTemplateService) Instantiate(ctx context.Context, tenantID uuid.UUID, templateKey string, req *models.InstantiateRoleTemplateRequest, createdBy *uuid.UUID) (*models.InstantiateRoleTemplateResponse, error) {
	tmpl, err := s.templateRepo.GetLatestByKey(ctx, templateKey)
	if err != nil {
		return nil, fmt.Errorf("Instantiate: %w", err)
	}
	if tmpl == nil || !tmpl.IsActive {
		return nil, fmt.Errorf("role template %q not found", templateKey)
	}

	modules, err := s.resolveModules(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("Instantiate: %w", err)
	}
	if !productslug.Contains(modules, tmpl.Module) {
		return nil, fmt.Errorf("tenant is not entitled to module %q", tmpl.Module)
	}

	displayName := ""
	if req != nil && req.Name != nil {
		displayName = *req.Name
	}

	role, err := s.provisioner.InstantiateForTenant(ctx, tenantID, templateKey, displayName, createdBy)
	if err != nil {
		return nil, fmt.Errorf("Instantiate: %w", err)
	}

	return &models.InstantiateRoleTemplateResponse{
		Role:        *role.ToResponse(),
		TemplateKey: tmpl.Key,
		TemplateVer: tmpl.Version,
	}, nil
}

// resolveModules resolves tenantID's entitled modules, translating the
// ListModulesForTenant nil sentinel ("no entitlement filtering configured")
// into the full module list, per roleTemplateEntitledModules' doc comment.
func (s *RoleTemplateService) resolveModules(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	modules, err := s.entitledModules.ListModulesForTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve entitled modules: %w", err)
	}
	if modules == nil {
		modules, err = s.entitledModules.ListModules(ctx)
		if err != nil {
			return nil, fmt.Errorf("list all modules: %w", err)
		}
	}
	return modules, nil
}

// RevokeModule disables every template-derived role for tenantID under
// module (see TemplateRoleProvisioner.DisableForModuleRevoke). It is the
// module-revoke counterpart to the ProvisionForModuleGrant hook wired into
// ProvisioningConsumer — falcon-id has no existing "module revoked/deactivated"
// Kafka event to run this off of (only example.tenant.subscription.activated
// exists), so it is exposed as an internal endpoint instead: see
// POST /internal/v1/role-templates/revoke in cmd/routes_admin.go. Whatever
// process eventually emits a subscription-deactivated/cancelled event should
// call this same path rather than duplicating the disable logic.
func (s *RoleTemplateService) RevokeModule(ctx context.Context, tenantID uuid.UUID, module string) (int, error) {
	disabled, err := s.provisioner.DisableForModuleRevoke(ctx, tenantID, module)
	if err != nil {
		return 0, fmt.Errorf("RevokeModule: %w", err)
	}
	return disabled, nil
}

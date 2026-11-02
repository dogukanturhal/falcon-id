// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// roleTemplateLatestLookup is the subset of RoleTemplateRepository needed to
// validate a manifest's role templates (monotonic version check).
type roleTemplateLatestLookup interface {
	GetLatestByKey(ctx context.Context, key string) (*models.RoleTemplate, error)
}

// validTemplateKey mirrors validSegment's shape but for the full
// "module:template_slug" key: lowercase alphanumeric segments joined by ':'.
var validTemplateKeySlug = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,49}$`)

// RoleTemplateValidator validates the RoleTemplates section of a
// RegisterModuleRequest (the product roadmap §4.1). It is deliberately separate
// from ManifestValidator (which validates the unrelated ProductManifest used
// by iam_products) — this validator's scope is exactly
// models.RoleTemplateDefinition.
type RoleTemplateValidator struct {
	templateRepo roleTemplateLatestLookup
}

// NewRoleTemplateValidator constructs a RoleTemplateValidator.
func NewRoleTemplateValidator(templateRepo roleTemplateLatestLookup) *RoleTemplateValidator {
	return &RoleTemplateValidator{templateRepo: templateRepo}
}

// ValidateManifest checks req.RoleTemplates for structural and ownership
// correctness. permissionNamesInRequest is the set of "module:resource:action"
// names being registered in this SAME call (req.Permissions, already
// expanded); existingModulePermissions is the set of permission names already
// in the catalog for req.Module and for each of req.Dependencies (the caller
// resolves these — this function does no I/O of its own beyond the
// monotonic-version lookup, so it stays trivially unit-testable).
//
// Rules enforced (spec: "permissions referenced must belong to the
// registering module or declared dependencies; version monotonic"):
//  1. Key must be non-empty, lowercase-segment shaped, and prefixed with
//     "<module>:" — a module may only publish templates under its own
//     namespace.
//  2. Version >= 1.
//  3. Every permission referenced must be in permissionNamesInRequest,
//     existingModulePermissions, OR start with "<module>:" (i.e. belong to
//     the registering module itself, even if not in this particular call —
//     covers a template referencing a permission this module registered in
//     an earlier call).
//  4. Version must be monotonic: strictly greater than the highest version
//     already stored for Key; when Key has never been registered any
//     version >= 1 is accepted (the owning service may already be past v1
//     when its templates first reach this deployment). Re-submitting the CURRENT latest version with identical
//     content is accepted as an idempotent no-op; re-submitting it with
//     different content is rejected.
func (v *RoleTemplateValidator) ValidateManifest(
	ctx context.Context,
	module string,
	dependencies []string,
	permissionNamesInRequest map[string]bool,
	existingModulePermissions map[string]bool,
	templates []models.RoleTemplateDefinition,
) error {
	depSet := make(map[string]bool, len(dependencies))
	for _, d := range dependencies {
		depSet[d] = true
	}

	seenKeys := make(map[string]bool, len(templates))
	for _, t := range templates {
		if err := v.validateOne(ctx, module, depSet, permissionNamesInRequest, existingModulePermissions, t); err != nil {
			return err
		}
		if seenKeys[t.Key] {
			return fmt.Errorf("role_templates: duplicate key %q within a single registration call", t.Key)
		}
		seenKeys[t.Key] = true
	}
	return nil
}

func (v *RoleTemplateValidator) validateOne(
	ctx context.Context,
	module string,
	dependencies map[string]bool,
	permissionNamesInRequest map[string]bool,
	existingModulePermissions map[string]bool,
	t models.RoleTemplateDefinition,
) error {
	if strings.TrimSpace(t.Key) == "" {
		return fmt.Errorf("role_templates: key is required")
	}
	prefix := module + ":"
	if !strings.HasPrefix(t.Key, prefix) {
		return fmt.Errorf("role_templates: key %q must be prefixed with the registering module %q (e.g. %q)", t.Key, module, prefix+"example")
	}
	slug := strings.TrimPrefix(t.Key, prefix)
	if !validTemplateKeySlug.MatchString(slug) {
		return fmt.Errorf("role_templates: key %q's slug %q must be lowercase alphanumeric with hyphens/underscores", t.Key, slug)
	}
	if t.Version < 1 {
		return fmt.Errorf("role_templates: key %q version must be >= 1", t.Key)
	}
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("role_templates: key %q: name is required", t.Key)
	}
	if len(t.Permissions) == 0 {
		return fmt.Errorf("role_templates: key %q: at least one permission is required", t.Key)
	}

	for _, permName := range t.Permissions {
		if err := validatePermissionOwnership(module, dependencies, permissionNamesInRequest, existingModulePermissions, permName); err != nil {
			return fmt.Errorf("role_templates: key %q: %w", t.Key, err)
		}
	}

	for _, rel := range t.SpiceDBRelations {
		if strings.TrimSpace(rel.Relation) == "" {
			return fmt.Errorf("role_templates: key %q: spicedb_relations entries require a relation name", t.Key)
		}
		if rel.Permission != "" {
			if err := validatePermissionOwnership(module, dependencies, permissionNamesInRequest, existingModulePermissions, rel.Permission); err != nil {
				return fmt.Errorf("role_templates: key %q: spicedb_relations: %w", t.Key, err)
			}
		}
	}

	if v.templateRepo == nil {
		return nil
	}
	latest, err := v.templateRepo.GetLatestByKey(ctx, t.Key)
	if err != nil {
		return fmt.Errorf("role_templates: key %q: look up latest version: %w", t.Key, err)
	}
	if latest == nil {
		// First time falcon-id sees this key: any version >= 1 (checked
		// above) is accepted, since the owning service may already be at
		// version N from before its templates reached this deployment.
		return nil
	}
	switch {
	case t.Version > latest.Version:
		return nil
	case t.Version == latest.Version:
		if !sameTemplateContent(latest, t) {
			return fmt.Errorf("role_templates: key %q: version %d already exists with different content; bump the version to change it", t.Key, t.Version)
		}
		return nil
	default:
		return fmt.Errorf("role_templates: key %q: version %d is not monotonic (latest registered version is %d)", t.Key, t.Version, latest.Version)
	}
}

// validatePermissionOwnership checks that permName belongs to module, one of
// dependencies, is present in permissionNamesInRequest (this same manifest
// call), or is already in the catalog under module (existingModulePermissions).
func validatePermissionOwnership(
	module string,
	dependencies map[string]bool,
	permissionNamesInRequest map[string]bool,
	existingModulePermissions map[string]bool,
	permName string,
) error {
	if permissionNamesInRequest[permName] || existingModulePermissions[permName] {
		return nil
	}
	idx := strings.IndexByte(permName, ':')
	if idx <= 0 {
		return fmt.Errorf("permission %q is not a valid module:resource:action name", permName)
	}
	permModule := permName[:idx]
	if permModule == module {
		return nil
	}
	if dependencies[permModule] {
		return nil
	}
	return fmt.Errorf("permission %q belongs to module %q, which is neither %q itself nor a declared dependency", permName, permModule, module)
}

// sameTemplateContent compares stored vs incoming content for the
// "re-submitting the same version is an idempotent no-op" rule. Compares
// name/description/permissions/relations only (not module — module is
// implied by the key's owning namespace and cannot legitimately differ).
func sameTemplateContent(stored *models.RoleTemplate, incoming models.RoleTemplateDefinition) bool {
	if stored.Name != incoming.Name {
		return false
	}
	storedDesc := ""
	if stored.Description != nil {
		storedDesc = *stored.Description
	}
	if storedDesc != incoming.Description {
		return false
	}
	if !stringSlicesEqualUnordered(stored.Permissions, incoming.Permissions) {
		return false
	}
	if len(stored.SpiceDBRelations) != len(incoming.SpiceDBRelations) {
		return false
	}
	for i := range stored.SpiceDBRelations {
		if stored.SpiceDBRelations[i] != incoming.SpiceDBRelations[i] {
			return false
		}
	}
	return true
}

func stringSlicesEqualUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]int, len(a))
	for _, s := range a {
		set[s]++
	}
	for _, s := range b {
		set[s]--
	}
	for _, v := range set {
		if v != 0 {
			return false
		}
	}
	return true
}

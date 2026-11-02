// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// fakeTemplateLatestLookup is a minimal roleTemplateLatestLookup fake for
// exercising RoleTemplateValidator's monotonic-version rule without a DB.
type fakeTemplateLatestLookup struct {
	byKey map[string]*models.RoleTemplate
}

func (f *fakeTemplateLatestLookup) GetLatestByKey(_ context.Context, key string) (*models.RoleTemplate, error) {
	return f.byKey[key], nil
}

func def(key string, version int, perms ...string) models.RoleTemplateDefinition {
	return models.RoleTemplateDefinition{
		Key: key, Version: version, Name: "Some Role", Permissions: perms,
	}
}

func TestRoleTemplateValidator_AcceptsOwnModulePermissions(t *testing.T) {
	v := NewRoleTemplateValidator(&fakeTemplateLatestLookup{byKey: map[string]*models.RoleTemplate{}})
	err := v.ValidateManifest(
		context.Background(),
		"marketing",
		nil,
		map[string]bool{"marketing:campaigns:send": true},
		nil,
		[]models.RoleTemplateDefinition{def("marketing:campaign_manager", 1, "marketing:campaigns:send")},
	)
	assert.NoError(t, err)
}

func TestRoleTemplateValidator_RejectsPermissionOutsideModuleAndDependencies(t *testing.T) {
	v := NewRoleTemplateValidator(&fakeTemplateLatestLookup{byKey: map[string]*models.RoleTemplate{}})
	err := v.ValidateManifest(
		context.Background(),
		"marketing",
		nil, // no declared dependencies
		map[string]bool{},
		nil,
		[]models.RoleTemplateDefinition{def("marketing:campaign_manager", 1, "billing:invoices:read")},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "neither")
}

func TestRoleTemplateValidator_AcceptsDeclaredDependencyPermission(t *testing.T) {
	v := NewRoleTemplateValidator(&fakeTemplateLatestLookup{byKey: map[string]*models.RoleTemplate{}})
	err := v.ValidateManifest(
		context.Background(),
		"marketing",
		[]string{"billing"},
		map[string]bool{},
		map[string]bool{"billing:invoices:read": true},
		[]models.RoleTemplateDefinition{def("marketing:campaign_manager", 1, "billing:invoices:read")},
	)
	assert.NoError(t, err)
}

func TestRoleTemplateValidator_RejectsKeyNotPrefixedWithModule(t *testing.T) {
	v := NewRoleTemplateValidator(&fakeTemplateLatestLookup{byKey: map[string]*models.RoleTemplate{}})
	err := v.ValidateManifest(
		context.Background(),
		"marketing",
		nil,
		map[string]bool{"marketing:campaigns:send": true},
		nil,
		[]models.RoleTemplateDefinition{def("billing:campaign_manager", 1, "marketing:campaigns:send")},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be prefixed with")
}

func TestRoleTemplateValidator_FirstRegistrationMayStartAboveVersion1(t *testing.T) {
	v := NewRoleTemplateValidator(&fakeTemplateLatestLookup{byKey: map[string]*models.RoleTemplate{}})
	err := v.ValidateManifest(
		context.Background(),
		"marketing",
		nil,
		map[string]bool{"marketing:campaigns:send": true},
		nil,
		[]models.RoleTemplateDefinition{def("marketing:campaign_manager", 3, "marketing:campaigns:send")},
	)
	assert.NoError(t, err)
}

func TestRoleTemplateValidator_RejectsNonMonotonicVersion(t *testing.T) {
	lookup := &fakeTemplateLatestLookup{byKey: map[string]*models.RoleTemplate{
		"marketing:campaign_manager": {Key: "marketing:campaign_manager", Version: 2, Name: "Some Role", Permissions: []string{"marketing:campaigns:send"}},
	}}
	v := NewRoleTemplateValidator(lookup)
	err := v.ValidateManifest(
		context.Background(),
		"marketing",
		nil,
		map[string]bool{"marketing:campaigns:send": true},
		nil,
		[]models.RoleTemplateDefinition{def("marketing:campaign_manager", 2, "marketing:campaigns:send")},
	)
	// Same version + identical content = idempotent no-op, must be accepted.
	assert.NoError(t, err)

	err = v.ValidateManifest(
		context.Background(),
		"marketing",
		nil,
		map[string]bool{"marketing:campaigns:send": true},
		nil,
		[]models.RoleTemplateDefinition{def("marketing:campaign_manager", 1, "marketing:campaigns:send")},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not monotonic")
}

func TestRoleTemplateValidator_RejectsSameVersionDifferentContent(t *testing.T) {
	lookup := &fakeTemplateLatestLookup{byKey: map[string]*models.RoleTemplate{
		"marketing:campaign_manager": {Key: "marketing:campaign_manager", Version: 2, Name: "Some Role", Permissions: []string{"marketing:campaigns:send"}},
	}}
	v := NewRoleTemplateValidator(lookup)
	err := v.ValidateManifest(
		context.Background(),
		"marketing",
		nil,
		map[string]bool{"marketing:campaigns:send": true, "marketing:campaigns:read": true},
		nil,
		[]models.RoleTemplateDefinition{def("marketing:campaign_manager", 2, "marketing:campaigns:send", "marketing:campaigns:read")},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists with different content")
}

func TestRoleTemplateValidator_AcceptsVersionBump(t *testing.T) {
	lookup := &fakeTemplateLatestLookup{byKey: map[string]*models.RoleTemplate{
		"marketing:campaign_manager": {Key: "marketing:campaign_manager", Version: 2, Name: "Some Role", Permissions: []string{"marketing:campaigns:send"}},
	}}
	v := NewRoleTemplateValidator(lookup)
	err := v.ValidateManifest(
		context.Background(),
		"marketing",
		nil,
		map[string]bool{"marketing:campaigns:send": true, "marketing:campaigns:archive": true},
		nil,
		[]models.RoleTemplateDefinition{def("marketing:campaign_manager", 3, "marketing:campaigns:send", "marketing:campaigns:archive")},
	)
	assert.NoError(t, err)
}

func TestRoleTemplateValidator_RejectsDuplicateKeyWithinSameCall(t *testing.T) {
	v := NewRoleTemplateValidator(&fakeTemplateLatestLookup{byKey: map[string]*models.RoleTemplate{}})
	err := v.ValidateManifest(
		context.Background(),
		"marketing",
		nil,
		map[string]bool{"marketing:campaigns:send": true},
		nil,
		[]models.RoleTemplateDefinition{
			def("marketing:campaign_manager", 1, "marketing:campaigns:send"),
			def("marketing:campaign_manager", 1, "marketing:campaigns:send"),
		},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate key")
}

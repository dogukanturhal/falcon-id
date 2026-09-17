// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

// module_registry_test.go verifies the dynamic module registry introduced
// for GAP 6.  The hardcoded module map in isModuleName is replaced by a
// package-level registry that can be extended at runtime via RegisterModules.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ─── RegisterModules / SetModuleRegistry ──────────────────────────────────────

// TestRegisterModules_AddsNewModules verifies that a module registered via
// RegisterModules is subsequently recognized by isModuleName.
func TestRegisterModules_AddsNewModules(t *testing.T) {
	// Reset registry after test to avoid polluting other tests in the suite.
	original := cloneModuleRegistry()
	t.Cleanup(func() { setModuleRegistry(original) })

	// Before registration the fictional module must NOT be known.
	assert.False(t, isModuleName("myapp_custom"), "should not be known before registration")

	RegisterModules([]string{"myapp_custom"})

	assert.True(t, isModuleName("myapp_custom"), "should be known after RegisterModules")
}

// TestRegisterModules_IdempotentOnExistingModule verifies that registering a
// module that is already in the built-in list does not cause any error and the
// module remains recognized.
func TestRegisterModules_IdempotentOnExistingModule(t *testing.T) {
	original := cloneModuleRegistry()
	t.Cleanup(func() { setModuleRegistry(original) })

	// "crm" is in the built-in list — re-registering must not break anything.
	RegisterModules([]string{"crm"})
	assert.True(t, isModuleName("crm"))
}

// TestRegisterModules_CaseInsensitive verifies that module names registered
// in mixed case are still recognized by isModuleName (which lowercases input).
func TestRegisterModules_CaseInsensitive(t *testing.T) {
	original := cloneModuleRegistry()
	t.Cleanup(func() { setModuleRegistry(original) })

	RegisterModules([]string{"MyNewModule"})
	assert.True(t, isModuleName("mynewmodule"), "lowercase lookup should find a mixed-case registration")
	assert.True(t, isModuleName("MYNEWMODULE"), "uppercase lookup should find a mixed-case registration")
}

// TestSetModuleRegistry_ReplacesRegistry verifies that SetModuleRegistry
// completely replaces the active registry, and that modules from the previous
// state are no longer recognized (unless re-added).
func TestSetModuleRegistry_ReplacesRegistry(t *testing.T) {
	original := cloneModuleRegistry()
	t.Cleanup(func() { setModuleRegistry(original) })

	// A module only in the custom registry.
	setModuleRegistry(map[string]bool{"only_this": true})

	assert.True(t, isModuleName("only_this"), "module in new registry should be recognized")
	assert.False(t, isModuleName("crm"), "built-in modules removed when registry replaced")
}

// TestIsModuleName_BuiltinsPresent verifies that all originally hard-coded
// modules are still recognized after the refactor to a dynamic registry.
func TestIsModuleName_BuiltinsPresent(t *testing.T) {
	builtins := []string{
		"crm", "hr", "accounting", "inventory", "invoicing", "pm",
		"marketing", "ppscm", "sd", "fico", "mm", "qms", "plm", "cmms",
		"cms", "helpdesk", "documents", "workflow", "custom_objects",
		"reporting", "ecommerce", "settings", "admin",
	}
	for _, m := range builtins {
		assert.True(t, isModuleName(m), "built-in module %q should be recognized", m)
	}
}

// TestIsModuleName_UnknownModuleReturnsFalse verifies that an arbitrary name
// that was never registered returns false.
func TestIsModuleName_UnknownModuleReturnsFalse(t *testing.T) {
	original := cloneModuleRegistry()
	t.Cleanup(func() { setModuleRegistry(original) })

	assert.False(t, isModuleName("notamodule_xyz_never_registered"))
}

// TestParsePermission_NewlyRegisteredModuleUsesModuleObjectType tests the full
// integration path: registering a new module and then parsing a permission
// string in the "module.action" format should resolve to "newmod_module" as the
// SpiceDB object type.
func TestParsePermission_NewlyRegisteredModuleUsesModuleObjectType(t *testing.T) {
	original := cloneModuleRegistry()
	t.Cleanup(func() { setModuleRegistry(original) })

	RegisterModules([]string{"newmod"})

	objectType, objectID, action := parsePermission("newmod.read")
	assert.Equal(t, "newmod_module", objectType)
	assert.Equal(t, "default", objectID)
	assert.Equal(t, "read", action)
}

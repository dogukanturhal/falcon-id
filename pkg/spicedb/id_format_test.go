// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

// spiceDBObjectIDRegex is the ObjectId validation regex from SpiceDB.
var spiceDBObjectIDRegex = regexp.MustCompile(`^(([a-zA-Z0-9/_|\-=+]{1,})|\*)$`)

func TestPermissionToSpiceDBID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"crm:contacts:read", "crm__contacts__read"},
		{"iam:users:manage", "iam__users__manage"},
		{"invoicing:invoices:create", "invoicing__invoices__create"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, PermissionToSpiceDBID(tt.input))
		})
	}
}

func TestSpiceDBIDToPermission(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"crm__contacts__read", "crm:contacts:read"},
		{"iam__users__manage", "iam:users:manage"},
		{"invoicing__invoices__create", "invoicing:invoices:create"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, IDToPermission(tt.input))
		})
	}
}

func TestPermissionToSpiceDBID_NoColons(t *testing.T) {
	// Passthrough: no colons means no transformation
	assert.Equal(t, "billing", PermissionToSpiceDBID("billing"))
	assert.Equal(t, "reset_password", PermissionToSpiceDBID("reset_password"))
	assert.Equal(t, "view", PermissionToSpiceDBID("view"))
}

func TestRoundTrip(t *testing.T) {
	permissions := []string{
		"crm:contacts:read",
		"iam:users:manage",
		"invoicing:invoices:create",
		"billing",
		"hr:employees:bulk_operations",
	}
	for _, perm := range permissions {
		t.Run(perm, func(t *testing.T) {
			translated := PermissionToSpiceDBID(perm)
			reversed := IDToPermission(translated)
			assert.Equal(t, perm, reversed)
		})
	}
}

func TestOutputMatchesSpiceDBRegex(t *testing.T) {
	permissions := []string{
		"crm:contacts:read",
		"iam:users:manage",
		"invoicing:invoices:create",
		"billing",
		"hr:employees:bulk_operations",
		"pm:tasks:create",
	}
	for _, perm := range permissions {
		t.Run(perm, func(t *testing.T) {
			translated := PermissionToSpiceDBID(perm)
			assert.True(t, spiceDBObjectIDRegex.MatchString(translated),
				"translated %q does not match SpiceDB ObjectId regex", translated)
		})
	}
}

func TestPermissionToSpiceDBIDChecked(t *testing.T) {
	id, err := PermissionToSpiceDBIDChecked("core:parties:read")
	assert.NoError(t, err)
	assert.Equal(t, "core__parties__read", id)
	assert.True(t, spiceDBObjectIDRegex.MatchString(id))

	for _, bad := range []string{"core:parties:*", "*", "", "core:parties:read write", "core:par*ties:read"} {
		_, err := PermissionToSpiceDBIDChecked(bad)
		assert.Error(t, err, bad)
	}
}

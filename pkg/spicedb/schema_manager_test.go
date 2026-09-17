// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ============================================================================
// Test helpers
// ============================================================================

func init() {
	// Ensure the logger is initialised before any test in this package runs.
	// permission_resolver_test.go does the same; calling InitLogger twice is safe.
	logger.InitLogger("debug", "test")
}

// newTestLogger returns a no-op zap logger suitable for unit tests.
func newTestLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

// ============================================================================
// Mock: SchemaWriter
// ============================================================================

// mockSchemaWriter is a testify mock that satisfies the SchemaWriter interface.
type mockSchemaWriter struct {
	mock.Mock
}

func (m *mockSchemaWriter) WriteSchema(ctx context.Context, schema string) error {
	args := m.Called(ctx, schema)
	return args.Error(0)
}

func (m *mockSchemaWriter) ReadSchema(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

// ============================================================================
// TestRegisterResourceType_GeneratesValidDefinition
// ============================================================================

func TestRegisterResourceType_GeneratesValidDefinition(t *testing.T) {
	writer := new(mockSchemaWriter)
	mgr := NewSchemaManager(writer, newTestLogger())

	def := &ResourceTypeDefinition{
		Name:        "crm_contact",
		ProductSlug: "examplesuite",
		Relations:   []string{"owner", "viewer", "editor"},
		Permissions: []string{"view", "edit", "delete"},
	}

	// ReadSchema returns empty — definition not yet present.
	writer.On("ReadSchema", mock.Anything).Return("", nil).Once()
	// WriteSchema must be called with a schema containing the new definition.
	writer.On("WriteSchema", mock.Anything, mock.MatchedBy(func(s string) bool {
		return strings.Contains(s, "definition crm_contact")
	})).Return(nil).Once()

	err := mgr.RegisterResourceType(context.Background(), def)
	require.NoError(t, err)

	writer.AssertExpectations(t)

	// Verify the in-memory registry contains the type.
	types := mgr.GetRegisteredTypes()
	require.Len(t, types, 1)
	assert.Equal(t, "crm_contact", types[0].Name)
}

// ============================================================================
// TestRegisterResourceType_AdditiveOnly_DoesNotRemoveExisting
// ============================================================================

func TestRegisterResourceType_AdditiveOnly_DoesNotRemoveExisting(t *testing.T) {
	writer := new(mockSchemaWriter)
	mgr := NewSchemaManager(writer, newTestLogger())

	existingSchema := `definition tenant {
    relation admin: user
    permission admin_access = admin
}`

	// Register a new type on top of an already-populated schema.
	def := &ResourceTypeDefinition{
		Name:        "hr_employee",
		ProductSlug: "examplesuite",
		Relations:   []string{"owner", "viewer"},
		Permissions: []string{"view", "delete"},
	}

	writer.On("ReadSchema", mock.Anything).Return(existingSchema, nil).Once()
	writer.On("WriteSchema", mock.Anything, mock.MatchedBy(func(s string) bool {
		// The pre-existing tenant definition must still be present.
		return strings.Contains(s, "definition tenant") &&
			strings.Contains(s, "definition hr_employee")
	})).Return(nil).Once()

	err := mgr.RegisterResourceType(context.Background(), def)
	require.NoError(t, err)

	writer.AssertExpectations(t)
}

// ============================================================================
// TestRegisterResourceType_AlreadyPresent_SkipsWrite
// ============================================================================

func TestRegisterResourceType_AlreadyPresent_SkipsWrite(t *testing.T) {
	writer := new(mockSchemaWriter)
	mgr := NewSchemaManager(writer, newTestLogger())

	// Pre-populate the manager's in-memory registry.
	mgr.registered["crm_contact"] = &ResourceTypeDefinition{
		Name:        "crm_contact",
		ProductSlug: "examplesuite",
		Relations:   []string{"owner"},
		Permissions: []string{"view"},
	}

	// The remote schema already contains "definition crm_contact".
	existingSchema := `definition crm_contact {
    relation tenant: tenant
    relation owner: user
    permission view = owner + tenant->admin
}`

	def := &ResourceTypeDefinition{
		Name:        "crm_contact",
		ProductSlug: "examplesuite",
		Relations:   []string{"owner"},
		Permissions: []string{"view"},
	}

	writer.On("ReadSchema", mock.Anything).Return(existingSchema, nil).Once()
	// WriteSchema must NOT be called when all definitions are already present.

	err := mgr.RegisterResourceType(context.Background(), def)
	require.NoError(t, err)

	// WriteSchema should never have been called.
	writer.AssertNotCalled(t, "WriteSchema")
}

// ============================================================================
// TestGenerateDefinition_StandardRelations
// ============================================================================

func TestGenerateDefinition_StandardRelations(t *testing.T) {
	mgr := NewSchemaManager(nil, newTestLogger())

	def := &ResourceTypeDefinition{
		Name:        "crm_contact",
		ProductSlug: "examplesuite",
		Relations:   []string{"owner", "viewer", "editor"},
		Permissions: []string{"view", "edit", "delete"},
	}

	got := mgr.GenerateDefinition(def)

	// Check structural markers.
	assert.True(t, strings.HasPrefix(got, "definition crm_contact {"),
		"definition block must start with correct header")
	assert.True(t, strings.HasSuffix(got, "}"),
		"definition block must end with closing brace")

	// Tenant relation always injected.
	assert.Contains(t, got, "relation tenant: tenant")

	// Standard relations with expected subject types.
	assert.Contains(t, got, "relation owner: user")
	assert.Contains(t, got, "relation viewer: user | group#member")
	assert.Contains(t, got, "relation editor: user | group#member")

	// Standard permissions with expected expressions.
	assert.Contains(t, got, "permission view = viewer + editor + owner + tenant->admin")
	assert.Contains(t, got, "permission edit = editor + owner + tenant->admin")
	assert.Contains(t, got, "permission delete = owner + tenant->admin")
}

// ============================================================================
// TestGenerateDefinition_CustomRelations
// ============================================================================

func TestGenerateDefinition_CustomRelations(t *testing.T) {
	mgr := NewSchemaManager(nil, newTestLogger())

	def := &ResourceTypeDefinition{
		Name:        "hotel_booking",
		ProductSlug: "hexxlock-hotel-pms",
		Relations:   []string{"agent", "guest"},
		Permissions: []string{"confirm", "cancel"},
	}

	got := mgr.GenerateDefinition(def)

	assert.Contains(t, got, "definition hotel_booking {")
	// Tenant relation always present.
	assert.Contains(t, got, "relation tenant: tenant")
	// Custom relations.
	assert.Contains(t, got, "relation agent: user | group#member")
	assert.Contains(t, got, "relation guest: user | group#member")
	// Generic permissions include all custom relations plus tenant->admin.
	assert.Contains(t, got, "permission confirm =")
	assert.Contains(t, got, "permission cancel =")
	assert.Contains(t, got, "tenant->admin")
}

// ============================================================================
// TestGenerateDefinition_NilReturnsEmptyString
// ============================================================================

func TestGenerateDefinition_NilReturnsEmptyString(t *testing.T) {
	mgr := NewSchemaManager(nil, newTestLogger())
	assert.Equal(t, "", mgr.GenerateDefinition(nil))
}

// ============================================================================
// TestGetRegisteredTypes_ReturnsAll
// ============================================================================

func TestGetRegisteredTypes_ReturnsAll(t *testing.T) {
	writer := new(mockSchemaWriter)
	mgr := NewSchemaManager(writer, newTestLogger())

	defs := []*ResourceTypeDefinition{
		{Name: "crm_contact", ProductSlug: "examplesuite", Relations: []string{"owner"}, Permissions: []string{"view"}},
		{Name: "hr_employee", ProductSlug: "examplesuite", Relations: []string{"owner"}, Permissions: []string{"view"}},
		{Name: "hotel_room", ProductSlug: "hexxlock-hotel-pms", Relations: []string{"owner"}, Permissions: []string{"view"}},
	}

	for _, def := range defs {
		writer.On("ReadSchema", mock.Anything).Return("", nil).Once()
		writer.On("WriteSchema", mock.Anything, mock.Anything).Return(nil).Once()
		require.NoError(t, mgr.RegisterResourceType(context.Background(), def))
	}

	types := mgr.GetRegisteredTypes()
	require.Len(t, types, 3)

	// Results must be sorted by Name.
	names := make([]string, len(types))
	for i, tp := range types {
		names[i] = tp.Name
	}
	assert.Equal(t, []string{"crm_contact", "hotel_room", "hr_employee"}, names)
}

// ============================================================================
// TestApplySchema_WritesUpdatedSchema
// ============================================================================

func TestApplySchema_WritesUpdatedSchema(t *testing.T) {
	writer := new(mockSchemaWriter)
	mgr := NewSchemaManager(writer, newTestLogger())

	// Pre-populate the in-memory registry without hitting SpiceDB (bypass
	// RegisterResourceType to test ApplySchema in isolation).
	mgr.registered["inventory_item"] = &ResourceTypeDefinition{
		Name:        "inventory_item",
		ProductSlug: "examplesuite",
		Relations:   []string{"owner", "editor"},
		Permissions: []string{"view", "edit"},
	}

	existingSchema := "definition tenant {\n    relation admin: user\n}"

	writer.On("ReadSchema", mock.Anything).Return(existingSchema, nil).Once()
	writer.On("WriteSchema", mock.Anything, mock.MatchedBy(func(s string) bool {
		return strings.Contains(s, "definition tenant") &&
			strings.Contains(s, "definition inventory_item")
	})).Return(nil).Once()

	err := mgr.ApplySchema(context.Background())
	require.NoError(t, err)

	writer.AssertExpectations(t)
}

// ============================================================================
// TestApplySchema_ReadSchemaError_PropagatesError
// ============================================================================

func TestApplySchema_ReadSchemaError_PropagatesError(t *testing.T) {
	writer := new(mockSchemaWriter)
	mgr := NewSchemaManager(writer, newTestLogger())

	mgr.registered["crm_contact"] = &ResourceTypeDefinition{
		Name:        "crm_contact",
		ProductSlug: "examplesuite",
		Relations:   []string{"owner"},
		Permissions: []string{"view"},
	}

	readErr := errors.New("spicedb connection refused")
	writer.On("ReadSchema", mock.Anything).Return("", readErr).Once()

	err := mgr.ApplySchema(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, readErr)
	assert.Contains(t, err.Error(), "applySchema")
}

// ============================================================================
// TestApplySchema_WriteSchemaError_PropagatesError
// ============================================================================

func TestApplySchema_WriteSchemaError_PropagatesError(t *testing.T) {
	writer := new(mockSchemaWriter)
	mgr := NewSchemaManager(writer, newTestLogger())

	mgr.registered["crm_contact"] = &ResourceTypeDefinition{
		Name:        "crm_contact",
		ProductSlug: "examplesuite",
		Relations:   []string{"owner"},
		Permissions: []string{"view"},
	}

	writer.On("ReadSchema", mock.Anything).Return("", nil).Once()
	writeErr := errors.New("schema write rejected")
	writer.On("WriteSchema", mock.Anything, mock.Anything).Return(writeErr).Once()

	err := mgr.ApplySchema(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, writeErr)
	assert.Contains(t, err.Error(), "applySchema")
}

// ============================================================================
// TestRegisterResourceType_WriteError_RollsBackRegistration
// ============================================================================

func TestRegisterResourceType_WriteError_RollsBackRegistration(t *testing.T) {
	writer := new(mockSchemaWriter)
	mgr := NewSchemaManager(writer, newTestLogger())

	def := &ResourceTypeDefinition{
		Name:        "crm_contact",
		ProductSlug: "examplesuite",
		Relations:   []string{"owner"},
		Permissions: []string{"view"},
	}

	writer.On("ReadSchema", mock.Anything).Return("", nil).Once()
	writer.On("WriteSchema", mock.Anything, mock.Anything).Return(errors.New("spicedb write failed")).Once()

	err := mgr.RegisterResourceType(context.Background(), def)
	require.Error(t, err)

	// The in-memory registry must have been rolled back.
	assert.Empty(t, mgr.GetRegisteredTypes(), "registration must be rolled back on write failure")
}

// ============================================================================
// TestRegisterResourceType_Validation
// ============================================================================

func TestRegisterResourceType_Validation(t *testing.T) {
	mgr := NewSchemaManager(nil, newTestLogger())

	tests := []struct {
		name    string
		def     *ResourceTypeDefinition
		wantErr string
	}{
		{
			name:    "nil definition",
			def:     nil,
			wantErr: "definition must not be nil",
		},
		{
			name:    "empty name",
			def:     &ResourceTypeDefinition{Name: "", ProductSlug: "erp"},
			wantErr: "Name must not be empty",
		},
		{
			name:    "empty product slug",
			def:     &ResourceTypeDefinition{Name: "crm_contact", ProductSlug: ""},
			wantErr: "ProductSlug must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.RegisterResourceType(context.Background(), tt.def)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// ============================================================================
// TestGetRegisteredTypes_ReturnsCopy
// ============================================================================

// TestGetRegisteredTypes_ReturnsCopy verifies that mutating the returned slice
// does not corrupt the manager's internal state.
func TestGetRegisteredTypes_ReturnsCopy(t *testing.T) {
	writer := new(mockSchemaWriter)
	mgr := NewSchemaManager(writer, newTestLogger())

	def := &ResourceTypeDefinition{
		Name:        "crm_contact",
		ProductSlug: "examplesuite",
		Relations:   []string{"owner"},
		Permissions: []string{"view"},
	}
	writer.On("ReadSchema", mock.Anything).Return("", nil).Once()
	writer.On("WriteSchema", mock.Anything, mock.Anything).Return(nil).Once()
	require.NoError(t, mgr.RegisterResourceType(context.Background(), def))

	types := mgr.GetRegisteredTypes()
	require.Len(t, types, 1)

	// Mutate the returned value.
	types[0].Name = "tampered"

	// Internal state must be unchanged.
	types2 := mgr.GetRegisteredTypes()
	require.Len(t, types2, 1)
	assert.Equal(t, "crm_contact", types2[0].Name)
}

// ============================================================================
// TestGenerateDefinition_TenantRelationNotDuplicated
// ============================================================================

// TestGenerateDefinition_TenantRelationNotDuplicated verifies that passing
// "tenant" in the Relations slice does not result in two "relation tenant:"
// lines in the output.
func TestGenerateDefinition_TenantRelationNotDuplicated(t *testing.T) {
	mgr := NewSchemaManager(nil, newTestLogger())

	def := &ResourceTypeDefinition{
		Name:        "my_resource",
		ProductSlug: "my-product",
		// Caller explicitly includes "tenant" in Relations — must be deduplicated.
		Relations:   []string{"tenant", "owner"},
		Permissions: []string{"view"},
	}

	got := mgr.GenerateDefinition(def)

	count := strings.Count(got, "relation tenant:")
	assert.Equal(t, 1, count, "tenant relation should appear exactly once")
}

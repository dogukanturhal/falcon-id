// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test doubles
// ============================================================================

// mockDenyGrantChecker implements DenyGrantChecker for CheckDenyGrant tests.
// Only CheckPermission is required by the DenyGrantChecker interface, which keeps
// this mock minimal and focused.
type mockDenyGrantChecker struct {
	mock.Mock
}

func (m *mockDenyGrantChecker) CheckPermission(
	ctx context.Context,
	tenantID, userID uuid.UUID,
	objectType, objectID, permission string,
) (bool, error) {
	args := m.Called(ctx, tenantID, userID, objectType, objectID, permission)
	return args.Bool(0), args.Error(1)
}

// mockDenyGrantWriter implements DenyGrantWriter for WriteDenyGrant / DeleteDenyGrant tests.
type mockDenyGrantWriter struct {
	mock.Mock
}

func (m *mockDenyGrantWriter) WriteRelationship(
	ctx context.Context,
	objectType, objectID, relation, subjectType, subjectID string,
) (string, error) {
	args := m.Called(ctx, objectType, objectID, relation, subjectType, subjectID)
	return args.String(0), args.Error(1)
}

func (m *mockDenyGrantWriter) DeleteRelationship(
	ctx context.Context,
	objectType, objectID, relation, subjectType, subjectID string,
) error {
	args := m.Called(ctx, objectType, objectID, relation, subjectType, subjectID)
	return args.Error(0)
}

// ============================================================================
// denyGrantObjectID — unit tests for ID formatting
// ============================================================================

func TestDenyGrantIDFormat(t *testing.T) {
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	tests := []struct {
		name      string
		tenantID  uuid.UUID
		action    string
		wantObjID string
	}{
		{
			name:      "simple action without colons",
			tenantID:  tenantID,
			action:    "delete",
			wantObjID: "00000000-0000-0000-0000-000000000001_delete",
		},
		{
			name:      "module:resource:action format translates colons to double underscores",
			tenantID:  tenantID,
			action:    "crm:contacts:read",
			wantObjID: "00000000-0000-0000-0000-000000000001_crm__contacts__read",
		},
		{
			name:      "action with underscore passthrough",
			tenantID:  tenantID,
			action:    "reset_password",
			wantObjID: "00000000-0000-0000-0000-000000000001_reset_password",
		},
		{
			name:      "invoicing module action",
			tenantID:  tenantID,
			action:    "invoicing:invoices:create",
			wantObjID: "00000000-0000-0000-0000-000000000001_invoicing__invoices__create",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotObjID := denyGrantObjectID(tt.tenantID, tt.action)
			assert.Equal(t, tt.wantObjID, gotObjID)
		})
	}
}

func TestDenyGrantSubjectIDFormat(t *testing.T) {
	tenantID := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	userID := uuid.MustParse("bbbbbbbb-0000-0000-0000-000000000002")

	got := denyGrantSubjectID(tenantID, userID)
	want := fmt.Sprintf("%s_%s", tenantID.String(), userID.String())

	assert.Equal(t, want, got)
}

// ============================================================================
// CheckDenyGrant
// ============================================================================

func TestCheckDenyGrant_Denied(t *testing.T) {
	checker := new(mockDenyGrantChecker)

	tenantID := testUUID(t)
	userID := testUUID(t)
	action := "crm:contacts:delete"
	expectedObjectID := denyGrantObjectID(tenantID, action)

	// SpiceDB returns true — a deny_grant relationship exists for this user+action.
	checker.On("CheckPermission",
		mock.Anything,
		tenantID, userID,
		"deny_grant", expectedObjectID, "check",
	).Return(true, nil)

	denied, err := CheckDenyGrant(testCtx(t), checker, tenantID, userID, action)

	require.NoError(t, err)
	assert.True(t, denied, "expected denied=true when deny_grant relationship exists")
	checker.AssertExpectations(t)
}

func TestCheckDenyGrant_NotDenied(t *testing.T) {
	checker := new(mockDenyGrantChecker)

	tenantID := testUUID(t)
	userID := testUUID(t)
	action := "invoicing:invoices:view"
	expectedObjectID := denyGrantObjectID(tenantID, action)

	// SpiceDB returns false — no deny_grant relationship; normal allow checks proceed.
	checker.On("CheckPermission",
		mock.Anything,
		tenantID, userID,
		"deny_grant", expectedObjectID, "check",
	).Return(false, nil)

	denied, err := CheckDenyGrant(testCtx(t), checker, tenantID, userID, action)

	require.NoError(t, err)
	assert.False(t, denied, "expected denied=false when no deny_grant relationship exists")
	checker.AssertExpectations(t)
}

func TestCheckDenyGrant_Error(t *testing.T) {
	checker := new(mockDenyGrantChecker)

	tenantID := testUUID(t)
	userID := testUUID(t)
	action := "hr:employees:manage"
	expectedObjectID := denyGrantObjectID(tenantID, action)

	spicedbErr := errors.New("connection refused")
	checker.On("CheckPermission",
		mock.Anything,
		tenantID, userID,
		"deny_grant", expectedObjectID, "check",
	).Return(false, spicedbErr)

	denied, err := CheckDenyGrant(testCtx(t), checker, tenantID, userID, action)

	require.Error(t, err, "expected error when SpiceDB check fails")
	assert.False(t, denied)
	assert.ErrorIs(t, err, spicedbErr)
	assert.Contains(t, err.Error(), "CheckDenyGrant")
	checker.AssertExpectations(t)
}

func TestCheckDenyGrant_NilTenantID(t *testing.T) {
	checker := new(mockDenyGrantChecker)

	denied, err := CheckDenyGrant(testCtx(t), checker, uuid.Nil, testUUID(t), "some:action:read")

	require.Error(t, err)
	assert.False(t, denied)
	assert.Contains(t, err.Error(), "tenant ID must not be nil")
	checker.AssertNotCalled(t, "CheckPermission")
}

func TestCheckDenyGrant_NilUserID(t *testing.T) {
	checker := new(mockDenyGrantChecker)

	denied, err := CheckDenyGrant(testCtx(t), checker, testUUID(t), uuid.Nil, "some:action:read")

	require.Error(t, err)
	assert.False(t, denied)
	assert.Contains(t, err.Error(), "user ID must not be nil")
	checker.AssertNotCalled(t, "CheckPermission")
}

func TestCheckDenyGrant_EmptyAction(t *testing.T) {
	checker := new(mockDenyGrantChecker)

	denied, err := CheckDenyGrant(testCtx(t), checker, testUUID(t), testUUID(t), "")

	require.Error(t, err)
	assert.False(t, denied)
	assert.Contains(t, err.Error(), "action must not be empty")
	checker.AssertNotCalled(t, "CheckPermission")
}

// ============================================================================
// WriteDenyGrant
// ============================================================================

func TestWriteDenyGrant_Success(t *testing.T) {
	writer := new(mockDenyGrantWriter)

	tenantID := testUUID(t)
	userID := testUUID(t)
	action := "crm:contacts:delete"
	wantToken := "zed-token-abc123"

	grant := DenyGrant{TenantID: tenantID, UserID: userID, Action: action}
	expectedObjID := denyGrantObjectID(tenantID, action)
	expectedSubjectID := denyGrantSubjectID(tenantID, userID)

	writer.On("WriteRelationship",
		mock.Anything,
		"deny_grant", expectedObjID, "denied_user", "user", expectedSubjectID,
	).Return(wantToken, nil)

	token, err := WriteDenyGrant(testCtx(t), writer, grant)

	require.NoError(t, err)
	assert.Equal(t, wantToken, token)
	writer.AssertExpectations(t)
}

func TestWriteDenyGrant_WriterError(t *testing.T) {
	writer := new(mockDenyGrantWriter)

	tenantID := testUUID(t)
	userID := testUUID(t)
	action := "delete"

	grant := DenyGrant{TenantID: tenantID, UserID: userID, Action: action}
	expectedObjID := denyGrantObjectID(tenantID, action)
	expectedSubjectID := denyGrantSubjectID(tenantID, userID)

	writerErr := errors.New("spicedb write failed")
	writer.On("WriteRelationship",
		mock.Anything,
		"deny_grant", expectedObjID, "denied_user", "user", expectedSubjectID,
	).Return("", writerErr)

	token, err := WriteDenyGrant(testCtx(t), writer, grant)

	require.Error(t, err)
	assert.Empty(t, token)
	assert.ErrorIs(t, err, writerErr)
	assert.Contains(t, err.Error(), "WriteDenyGrant")
}

func TestWriteDenyGrant_NilTenantID(t *testing.T) {
	writer := new(mockDenyGrantWriter)

	grant := DenyGrant{TenantID: uuid.Nil, UserID: testUUID(t), Action: "delete"}

	token, err := WriteDenyGrant(testCtx(t), writer, grant)

	require.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "tenant ID must not be nil")
	writer.AssertNotCalled(t, "WriteRelationship")
}

func TestWriteDenyGrant_NilUserID(t *testing.T) {
	writer := new(mockDenyGrantWriter)

	grant := DenyGrant{TenantID: testUUID(t), UserID: uuid.Nil, Action: "delete"}

	token, err := WriteDenyGrant(testCtx(t), writer, grant)

	require.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "user ID must not be nil")
	writer.AssertNotCalled(t, "WriteRelationship")
}

func TestWriteDenyGrant_EmptyAction(t *testing.T) {
	writer := new(mockDenyGrantWriter)

	grant := DenyGrant{TenantID: testUUID(t), UserID: testUUID(t), Action: ""}

	token, err := WriteDenyGrant(testCtx(t), writer, grant)

	require.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "action must not be empty")
	writer.AssertNotCalled(t, "WriteRelationship")
}

// ============================================================================
// DeleteDenyGrant
// ============================================================================

func TestDeleteDenyGrant_Success(t *testing.T) {
	writer := new(mockDenyGrantWriter)

	tenantID := testUUID(t)
	userID := testUUID(t)
	action := "invoicing:invoices:approve"

	grant := DenyGrant{TenantID: tenantID, UserID: userID, Action: action}
	expectedObjID := denyGrantObjectID(tenantID, action)
	expectedSubjectID := denyGrantSubjectID(tenantID, userID)

	writer.On("DeleteRelationship",
		mock.Anything,
		"deny_grant", expectedObjID, "denied_user", "user", expectedSubjectID,
	).Return(nil)

	err := DeleteDenyGrant(testCtx(t), writer, grant)

	require.NoError(t, err)
	writer.AssertExpectations(t)
}

func TestDeleteDenyGrant_WriterError(t *testing.T) {
	writer := new(mockDenyGrantWriter)

	tenantID := testUUID(t)
	userID := testUUID(t)
	action := "export"

	grant := DenyGrant{TenantID: tenantID, UserID: userID, Action: action}
	expectedObjID := denyGrantObjectID(tenantID, action)
	expectedSubjectID := denyGrantSubjectID(tenantID, userID)

	deleteErr := errors.New("spicedb delete failed")
	writer.On("DeleteRelationship",
		mock.Anything,
		"deny_grant", expectedObjID, "denied_user", "user", expectedSubjectID,
	).Return(deleteErr)

	err := DeleteDenyGrant(testCtx(t), writer, grant)

	require.Error(t, err)
	assert.ErrorIs(t, err, deleteErr)
	assert.Contains(t, err.Error(), "DeleteDenyGrant")
}

func TestDeleteDenyGrant_NilTenantID(t *testing.T) {
	writer := new(mockDenyGrantWriter)

	grant := DenyGrant{TenantID: uuid.Nil, UserID: testUUID(t), Action: "delete"}

	err := DeleteDenyGrant(testCtx(t), writer, grant)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID must not be nil")
	writer.AssertNotCalled(t, "DeleteRelationship")
}

func TestDeleteDenyGrant_NilUserID(t *testing.T) {
	writer := new(mockDenyGrantWriter)

	grant := DenyGrant{TenantID: testUUID(t), UserID: uuid.Nil, Action: "delete"}

	err := DeleteDenyGrant(testCtx(t), writer, grant)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID must not be nil")
	writer.AssertNotCalled(t, "DeleteRelationship")
}

func TestDeleteDenyGrant_EmptyAction(t *testing.T) {
	writer := new(mockDenyGrantWriter)

	grant := DenyGrant{TenantID: testUUID(t), UserID: testUUID(t), Action: ""}

	err := DeleteDenyGrant(testCtx(t), writer, grant)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "action must not be empty")
	writer.AssertNotCalled(t, "DeleteRelationship")
}

// ============================================================================
// SpiceDB ObjectId regex compliance
// ============================================================================

func TestDenyGrantObjectID_MatchesSpiceDBRegex(t *testing.T) {
	tenantID := uuid.MustParse("12345678-1234-1234-1234-123456789abc")

	actions := []string{
		"delete",
		"reset_password",
		"crm:contacts:read",
		"invoicing:invoices:create",
		"hr:employees:bulk_operations",
		"iam:users:manage",
	}

	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			objID := denyGrantObjectID(tenantID, action)
			assert.True(t, spiceDBObjectIDRegex.MatchString(objID),
				"object ID %q does not match SpiceDB ObjectId regex", objID)
		})
	}
}

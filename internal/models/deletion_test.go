// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== DeletionRequest status constants ====================

func TestDeletionRequestStatusConstants(t *testing.T) {
	assert.Equal(t, "pending", DeletionRequestStatusPending)
	assert.Equal(t, "scheduled", DeletionRequestStatusScheduled)
	assert.Equal(t, "processing", DeletionRequestStatusProcessing)
	assert.Equal(t, "completed", DeletionRequestStatusCompleted)
	assert.Equal(t, "failed", DeletionRequestStatusFailed)
	assert.Equal(t, "cancelled", DeletionRequestStatusCancelled)
}

// ==================== DeletionRequest.IsActive ====================

func TestDeletionRequest_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected bool
	}{
		{
			name:     "should return true when status is pending",
			status:   DeletionRequestStatusPending,
			expected: true,
		},
		{
			name:     "should return true when status is scheduled",
			status:   DeletionRequestStatusScheduled,
			expected: true,
		},
		{
			name:     "should return false when status is processing",
			status:   DeletionRequestStatusProcessing,
			expected: false,
		},
		{
			name:     "should return false when status is completed",
			status:   DeletionRequestStatusCompleted,
			expected: false,
		},
		{
			name:     "should return false when status is failed",
			status:   DeletionRequestStatusFailed,
			expected: false,
		},
		{
			name:     "should return false when status is cancelled",
			status:   DeletionRequestStatusCancelled,
			expected: false,
		},
		{
			name:     "should return false when status is empty",
			status:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DeletionRequest{Status: tt.status}
			assert.Equal(t, tt.expected, d.IsActive())
		})
	}
}

// ==================== DeletionRequest.IsCancellable ====================

func TestDeletionRequest_IsCancellable(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected bool
	}{
		{
			name:     "should return true when status is pending",
			status:   DeletionRequestStatusPending,
			expected: true,
		},
		{
			name:     "should return true when status is scheduled",
			status:   DeletionRequestStatusScheduled,
			expected: true,
		},
		{
			name:     "should return false when status is processing",
			status:   DeletionRequestStatusProcessing,
			expected: false,
		},
		{
			name:     "should return false when status is completed",
			status:   DeletionRequestStatusCompleted,
			expected: false,
		},
		{
			name:     "should return false when status is failed",
			status:   DeletionRequestStatusFailed,
			expected: false,
		},
		{
			name:     "should return false when status is cancelled",
			status:   DeletionRequestStatusCancelled,
			expected: false,
		},
		{
			name:     "should return false when status is empty",
			status:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DeletionRequest{Status: tt.status}
			assert.Equal(t, tt.expected, d.IsCancellable())
		})
	}
}

// ==================== IsActive and IsCancellable parity ====================

func TestDeletionRequest_IsActive_IsCancellable_Parity(t *testing.T) {
	// IsActive and IsCancellable have identical logic — they must always agree.
	statuses := []string{
		DeletionRequestStatusPending,
		DeletionRequestStatusScheduled,
		DeletionRequestStatusProcessing,
		DeletionRequestStatusCompleted,
		DeletionRequestStatusFailed,
		DeletionRequestStatusCancelled,
		"",
		"unknown",
	}

	for _, status := range statuses {
		status := status
		t.Run(status, func(t *testing.T) {
			d := &DeletionRequest{Status: status}
			assert.Equal(t, d.IsActive(), d.IsCancellable(),
				"IsActive and IsCancellable must return the same value for status %q", status)
		})
	}
}

// ==================== DeletionRequest.ToResponse ====================

func TestDeletionRequest_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		userID := uuid.New()
		legalHoldSetBy := uuid.New()
		requestedBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		scheduled := now.Add(30 * 24 * time.Hour)
		processed := now.Add(1 * time.Hour)
		completed := now.Add(2 * time.Hour)
		legalHoldAt := now.Add(-1 * time.Hour)
		reason := "litigation hold active"
		notes := "User requested GDPR erasure"
		errMsg := "partial failure"

		d := &DeletionRequest{
			ID:                id,
			TenantID:          tenantID,
			UserID:            userID,
			Status:            DeletionRequestStatusScheduled,
			RequestedAt:       now,
			ScheduledDeleteAt: &scheduled,
			ProcessedAt:       &processed,
			CompletedAt:       &completed,
			LegalHold:         true,
			LegalHoldReason:   &reason,
			LegalHoldSetAt:    &legalHoldAt,
			LegalHoldSetBy:    &legalHoldSetBy,
			RequestedBy:       &requestedBy,
			Notes:             &notes,
			ErrorMessage:      &errMsg,
			CreatedAt:         now,
			UpdatedAt:         now,
		}

		resp := d.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id.String(), resp.ID)
		assert.Equal(t, tenantID.String(), resp.TenantID)
		assert.Equal(t, userID.String(), resp.UserID)
		assert.Equal(t, DeletionRequestStatusScheduled, resp.Status)
		assert.Equal(t, now, resp.RequestedAt)
		assert.Equal(t, &scheduled, resp.ScheduledDeleteAt)
		assert.Equal(t, &processed, resp.ProcessedAt)
		assert.Equal(t, &completed, resp.CompletedAt)
		assert.True(t, resp.LegalHold)
		assert.Equal(t, &reason, resp.LegalHoldReason)
		assert.Equal(t, &legalHoldAt, resp.LegalHoldSetAt)
		require.NotNil(t, resp.LegalHoldSetBy)
		assert.Equal(t, legalHoldSetBy.String(), *resp.LegalHoldSetBy)
		require.NotNil(t, resp.RequestedBy)
		assert.Equal(t, requestedBy.String(), *resp.RequestedBy)
		assert.Equal(t, &notes, resp.Notes)
		assert.Equal(t, &errMsg, resp.ErrorMessage)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
	})

	t.Run("should calculate DaysRemaining when status is scheduled with future date", func(t *testing.T) {
		scheduled := time.Now().Add(10 * 24 * time.Hour) // 10 days out

		d := &DeletionRequest{
			ID:                uuid.New(),
			TenantID:          uuid.New(),
			UserID:            uuid.New(),
			Status:            DeletionRequestStatusScheduled,
			ScheduledDeleteAt: &scheduled,
		}

		resp := d.ToResponse()

		require.NotNil(t, resp.DaysRemaining)
		// Allow a small variance since time.Until is live
		assert.GreaterOrEqual(t, *resp.DaysRemaining, 9, "should have at least 9 days remaining")
		assert.LessOrEqual(t, *resp.DaysRemaining, 10, "should have at most 10 days remaining")
	})

	t.Run("should clamp DaysRemaining to zero when scheduled date is in the past", func(t *testing.T) {
		past := time.Now().Add(-5 * 24 * time.Hour)

		d := &DeletionRequest{
			ID:                uuid.New(),
			TenantID:          uuid.New(),
			UserID:            uuid.New(),
			Status:            DeletionRequestStatusScheduled,
			ScheduledDeleteAt: &past,
		}

		resp := d.ToResponse()

		require.NotNil(t, resp.DaysRemaining)
		assert.Equal(t, 0, *resp.DaysRemaining)
	})

	t.Run("should not set DaysRemaining when status is not scheduled", func(t *testing.T) {
		scheduled := time.Now().Add(5 * 24 * time.Hour)

		nonScheduledStatuses := []string{
			DeletionRequestStatusPending,
			DeletionRequestStatusProcessing,
			DeletionRequestStatusCompleted,
			DeletionRequestStatusFailed,
			DeletionRequestStatusCancelled,
		}

		for _, status := range nonScheduledStatuses {
			status := status
			t.Run(status, func(t *testing.T) {
				d := &DeletionRequest{
					ID:                uuid.New(),
					TenantID:          uuid.New(),
					UserID:            uuid.New(),
					Status:            status,
					ScheduledDeleteAt: &scheduled,
				}

				resp := d.ToResponse()
				assert.Nil(t, resp.DaysRemaining,
					"DaysRemaining must be nil when status is %q", status)
			})
		}
	})

	t.Run("should not set DaysRemaining when ScheduledDeleteAt is nil", func(t *testing.T) {
		d := &DeletionRequest{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			UserID:   uuid.New(),
			Status:   DeletionRequestStatusScheduled,
		}

		resp := d.ToResponse()

		assert.Nil(t, resp.DaysRemaining)
	})

	t.Run("should handle nil optional fields gracefully", func(t *testing.T) {
		d := &DeletionRequest{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			UserID:      uuid.New(),
			Status:      DeletionRequestStatusPending,
			RequestedAt: time.Now(),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		resp := d.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.ScheduledDeleteAt)
		assert.Nil(t, resp.ProcessedAt)
		assert.Nil(t, resp.CompletedAt)
		assert.Nil(t, resp.LegalHoldReason)
		assert.Nil(t, resp.LegalHoldSetAt)
		assert.Nil(t, resp.LegalHoldSetBy)
		assert.Nil(t, resp.RequestedBy)
		assert.Nil(t, resp.Notes)
		assert.Nil(t, resp.ErrorMessage)
		assert.Nil(t, resp.DaysRemaining)
		assert.False(t, resp.LegalHold)
	})

	t.Run("should convert UUID fields to string representation", func(t *testing.T) {
		id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
		tenantID := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
		userID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

		d := &DeletionRequest{
			ID:       id,
			TenantID: tenantID,
			UserID:   userID,
			Status:   DeletionRequestStatusPending,
		}

		resp := d.ToResponse()

		assert.Equal(t, "11111111-2222-3333-4444-555555555555", resp.ID)
		assert.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", resp.TenantID)
		assert.Equal(t, "00000000-0000-0000-0000-000000000001", resp.UserID)
	})
}

// ==================== DeletionRequestResponse struct ====================

func TestDeletionRequestResponse_StructFields(t *testing.T) {
	t.Run("should instantiate with all fields", func(t *testing.T) {
		now := time.Now()
		scheduled := now.Add(24 * time.Hour)
		days := 1
		reason := "hold reason"
		notes := "test notes"
		setBy := "admin-uuid"
		reqBy := "user-uuid"
		errMsg := "error detail"

		resp := DeletionRequestResponse{
			ID:                "id-1",
			TenantID:          "tenant-1",
			UserID:            "user-1",
			Status:            DeletionRequestStatusPending,
			RequestedAt:       now,
			ScheduledDeleteAt: &scheduled,
			LegalHold:         true,
			LegalHoldReason:   &reason,
			LegalHoldSetAt:    &now,
			LegalHoldSetBy:    &setBy,
			RequestedBy:       &reqBy,
			Notes:             &notes,
			ErrorMessage:      &errMsg,
			DaysRemaining:     &days,
			CreatedAt:         now,
			UpdatedAt:         now,
		}

		assert.Equal(t, "id-1", resp.ID)
		assert.Equal(t, "tenant-1", resp.TenantID)
		assert.Equal(t, "user-1", resp.UserID)
		assert.Equal(t, DeletionRequestStatusPending, resp.Status)
		assert.True(t, resp.LegalHold)
		assert.Equal(t, &days, resp.DaysRemaining)
		assert.Equal(t, &reason, resp.LegalHoldReason)
	})
}

// ==================== DeletionRequestListResponse struct ====================

func TestDeletionRequestListResponse_StructFields(t *testing.T) {
	t.Run("should carry pagination and list fields", func(t *testing.T) {
		list := DeletionRequestListResponse{
			Requests:   []DeletionRequestResponse{{ID: "req-1", Status: DeletionRequestStatusPending}},
			Total:      1,
			Page:       1,
			PageSize:   20,
			TotalPages: 1,
		}

		assert.Len(t, list.Requests, 1)
		assert.Equal(t, 1, list.Total)
		assert.Equal(t, 1, list.Page)
		assert.Equal(t, 20, list.PageSize)
		assert.Equal(t, 1, list.TotalPages)
	})

	t.Run("should allow empty requests slice", func(t *testing.T) {
		list := DeletionRequestListResponse{
			Requests:   []DeletionRequestResponse{},
			Total:      0,
			Page:       1,
			PageSize:   20,
			TotalPages: 0,
		}

		assert.Empty(t, list.Requests)
		assert.Equal(t, 0, list.Total)
	})
}

// ==================== CreateDeletionRequestRequest ====================

func TestCreateDeletionRequestRequest_StructFields(t *testing.T) {
	t.Run("should carry UserID and optional Notes", func(t *testing.T) {
		userID := uuid.New()
		notes := "User wants data erased"

		req := CreateDeletionRequestRequest{
			UserID: userID,
			Notes:  &notes,
		}

		assert.Equal(t, userID, req.UserID)
		require.NotNil(t, req.Notes)
		assert.Equal(t, notes, *req.Notes)
	})

	t.Run("should allow nil Notes", func(t *testing.T) {
		req := CreateDeletionRequestRequest{
			UserID: uuid.New(),
			Notes:  nil,
		}

		assert.Nil(t, req.Notes)
	})
}

// ==================== SetLegalHoldRequest ====================

func TestSetLegalHoldRequest_StructFields(t *testing.T) {
	t.Run("should carry Reason field", func(t *testing.T) {
		req := SetLegalHoldRequest{
			Reason: "Active lawsuit — must preserve user data",
		}

		assert.Equal(t, "Active lawsuit — must preserve user data", req.Reason)
	})
}

// ==================== CancelDeletionRequest ====================

func TestCancelDeletionRequest_StructFields(t *testing.T) {
	t.Run("should allow optional Reason", func(t *testing.T) {
		reason := "User changed their mind"
		req := CancelDeletionRequest{Reason: &reason}

		require.NotNil(t, req.Reason)
		assert.Equal(t, reason, *req.Reason)
	})

	t.Run("should allow nil Reason", func(t *testing.T) {
		req := CancelDeletionRequest{}
		assert.Nil(t, req.Reason)
	})
}

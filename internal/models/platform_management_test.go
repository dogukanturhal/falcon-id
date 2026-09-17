// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAcmeCorp = "Acme Corp"

// ==================== TenantFilters ====================

func TestTenantFilters_StructFields(t *testing.T) {
	t.Run("should carry all filter fields", func(t *testing.T) {
		f := TenantFilters{
			Status: "active",
			Type:   "customer",
			Search: "acme",
			Plan:   "enterprise",
		}

		assert.Equal(t, "active", f.Status)
		assert.Equal(t, "customer", f.Type)
		assert.Equal(t, "acme", f.Search)
		assert.Equal(t, "enterprise", f.Plan)
	})

	t.Run("should allow zero-value filters", func(t *testing.T) {
		f := TenantFilters{}

		assert.Empty(t, f.Status)
		assert.Empty(t, f.Type)
		assert.Empty(t, f.Search)
		assert.Empty(t, f.Plan)
	})
}

// ==================== SuspendTenantRequest ====================

func TestSuspendTenantRequest_StructFields(t *testing.T) {
	t.Run("should carry the Reason field", func(t *testing.T) {
		req := SuspendTenantRequest{Reason: "Non-payment of invoice"}

		assert.Equal(t, "Non-payment of invoice", req.Reason)
	})

	t.Run("should allow empty reason", func(t *testing.T) {
		req := SuspendTenantRequest{}
		assert.Empty(t, req.Reason)
	})
}

// ==================== PaginationInfo ====================

func TestPaginationInfo_StructFields(t *testing.T) {
	t.Run("should carry all pagination fields", func(t *testing.T) {
		p := PaginationInfo{
			Page:       3,
			PageSize:   25,
			Total:      500,
			TotalPages: 20,
		}

		assert.Equal(t, 3, p.Page)
		assert.Equal(t, 25, p.PageSize)
		assert.Equal(t, int64(500), p.Total)
		assert.Equal(t, int64(20), p.TotalPages)
	})

	t.Run("should zero-value correctly", func(t *testing.T) {
		p := PaginationInfo{}
		assert.Equal(t, 0, p.Page)
		assert.Equal(t, int64(0), p.Total)
	})
}

// ==================== TenantResponse ====================

func TestTenantResponse_StructFields(t *testing.T) {
	t.Run("should carry all fields correctly", func(t *testing.T) {
		id := uuid.New()
		now := time.Now().Truncate(time.Second)
		domain := "acme.example.com"
		billingEmail := "billing@acme.com"
		trialEnd := now.Add(14 * 24 * time.Hour)
		suspended := now.Add(-1 * time.Hour)
		cancelled := now.Add(-30 * time.Minute)
		userCount := int64(42)
		activeCount := int64(30)

		resp := TenantResponse{
			ID:              id,
			Name:            testAcmeCorp,
			Slug:            "acme-corp",
			DisplayName:     "Acme Corporation",
			Domain:          &domain,
			Status:          "active",
			Type:            "customer",
			Plan:            "enterprise",
			BillingEmail:    &billingEmail,
			BillingExempt:   false,
			MaxUsers:        500,
			MaxStorage:      int64(100 * 1024 * 1024 * 1024),
			TrialEndsAt:     &trialEnd,
			SuspendedAt:     &suspended,
			CancelledAt:     &cancelled,
			CreatedAt:       now,
			UpdatedAt:       now,
			UserCount:       &userCount,
			ActiveUserCount: &activeCount,
		}

		assert.Equal(t, id, resp.ID)
		assert.Equal(t, testAcmeCorp, resp.Name)
		assert.Equal(t, "acme-corp", resp.Slug)
		assert.Equal(t, "Acme Corporation", resp.DisplayName)
		assert.Equal(t, &domain, resp.Domain)
		assert.Equal(t, "active", resp.Status)
		assert.Equal(t, "customer", resp.Type)
		assert.Equal(t, "enterprise", resp.Plan)
		assert.Equal(t, &billingEmail, resp.BillingEmail)
		assert.False(t, resp.BillingExempt)
		assert.Equal(t, 500, resp.MaxUsers)
		assert.Equal(t, int64(100*1024*1024*1024), resp.MaxStorage)
		assert.Equal(t, &trialEnd, resp.TrialEndsAt)
		assert.Equal(t, &suspended, resp.SuspendedAt)
		assert.Equal(t, &cancelled, resp.CancelledAt)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
		assert.Equal(t, &userCount, resp.UserCount)
		assert.Equal(t, &activeCount, resp.ActiveUserCount)
	})

	t.Run("should allow nil optional pointer fields", func(t *testing.T) {
		resp := TenantResponse{
			ID:     uuid.New(),
			Name:   "Minimal Tenant",
			Slug:   "minimal",
			Status: "active",
		}

		assert.Nil(t, resp.Domain)
		assert.Nil(t, resp.BillingEmail)
		assert.Nil(t, resp.TrialEndsAt)
		assert.Nil(t, resp.SuspendedAt)
		assert.Nil(t, resp.CancelledAt)
		assert.Nil(t, resp.UserCount)
		assert.Nil(t, resp.ActiveUserCount)
	})
}

// ==================== TenantListResponse ====================

func TestTenantListResponse_StructFields(t *testing.T) {
	t.Run("should carry tenants and pagination", func(t *testing.T) {
		tenants := []TenantResponse{
			{ID: uuid.New(), Name: "Tenant A", Status: "active"},
			{ID: uuid.New(), Name: "Tenant B", Status: "suspended"},
		}

		resp := TenantListResponse{
			Tenants: tenants,
			Pagination: PaginationInfo{
				Page:       1,
				PageSize:   20,
				Total:      2,
				TotalPages: 1,
			},
		}

		assert.Len(t, resp.Tenants, 2)
		assert.Equal(t, int64(2), resp.Pagination.Total)
	})
}

// ==================== PlatformResetPasswordRequest ====================

func TestPlatformResetPasswordRequest_StructFields(t *testing.T) {
	t.Run("should carry Password and optional MustChangePassword", func(t *testing.T) {
		mustChange := true
		req := PlatformResetPasswordRequest{
			Password:           "SecurePass123!",
			MustChangePassword: &mustChange,
		}

		assert.Equal(t, "SecurePass123!", req.Password)
		require.NotNil(t, req.MustChangePassword)
		assert.True(t, *req.MustChangePassword)
	})

	t.Run("should allow nil MustChangePassword", func(t *testing.T) {
		req := PlatformResetPasswordRequest{
			Password:           "SecurePass123!",
			MustChangePassword: nil,
		}

		assert.Nil(t, req.MustChangePassword)
	})
}

// ==================== BulkUserOperation ====================

func TestBulkUserOperation_StructFields(t *testing.T) {
	t.Run("should carry all bulk operation fields", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		initiatedBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		started := now.Add(-5 * time.Minute)
		completed := now
		inputURL := "https://storage.example.com/input.csv"
		outputURL := "https://storage.example.com/output.csv"
		errorURL := "https://storage.example.com/errors.csv"

		op := BulkUserOperation{
			ID:                id,
			TenantID:          tenantID,
			OperationType:     "deactivate",
			InitiatedBy:       initiatedBy,
			InitiatedByName:   "admin@example.com",
			TotalRecords:      100,
			ProcessedRecords:  100,
			SuccessfulRecords: 95,
			FailedRecords:     5,
			Status:            "completed",
			InputFileURL:      &inputURL,
			OutputFileURL:     &outputURL,
			ErrorFileURL:      &errorURL,
			StartedAt:         &started,
			CompletedAt:       &completed,
			CreatedAt:         now,
			UpdatedAt:         now,
		}

		assert.Equal(t, id, op.ID)
		assert.Equal(t, tenantID, op.TenantID)
		assert.Equal(t, "deactivate", op.OperationType)
		assert.Equal(t, initiatedBy, op.InitiatedBy)
		assert.Equal(t, "admin@example.com", op.InitiatedByName)
		assert.Equal(t, 100, op.TotalRecords)
		assert.Equal(t, 100, op.ProcessedRecords)
		assert.Equal(t, 95, op.SuccessfulRecords)
		assert.Equal(t, 5, op.FailedRecords)
		assert.Equal(t, "completed", op.Status)
		assert.Equal(t, &inputURL, op.InputFileURL)
		assert.Equal(t, &outputURL, op.OutputFileURL)
		assert.Equal(t, &errorURL, op.ErrorFileURL)
		assert.Equal(t, &started, op.StartedAt)
		assert.Equal(t, &completed, op.CompletedAt)
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		op := BulkUserOperation{
			ID:            uuid.New(),
			TenantID:      uuid.New(),
			OperationType: "activate",
			InitiatedBy:   uuid.New(),
			Status:        "pending",
		}

		assert.Nil(t, op.InputFileURL)
		assert.Nil(t, op.OutputFileURL)
		assert.Nil(t, op.ErrorFileURL)
		assert.Nil(t, op.StartedAt)
		assert.Nil(t, op.CompletedAt)
	})
}

// ==================== BulkRoleAssignmentRequest ====================

func TestBulkRoleAssignmentRequest_StructFields(t *testing.T) {
	t.Run("should carry UserIDs and RoleIDs", func(t *testing.T) {
		userIDs := []uuid.UUID{uuid.New(), uuid.New()}
		roleIDs := []uuid.UUID{uuid.New()}

		req := BulkRoleAssignmentRequest{
			UserIDs: userIDs,
			RoleIDs: roleIDs,
		}

		assert.Equal(t, userIDs, req.UserIDs)
		assert.Equal(t, roleIDs, req.RoleIDs)
	})
}

// ==================== BulkUserActionRequest ====================

func TestBulkUserActionRequest_StructFields(t *testing.T) {
	tests := []struct {
		name   string
		action string
	}{
		{name: "activate action", action: "activate"},
		{name: "deactivate action", action: "deactivate"},
		{name: "delete action", action: "delete"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := BulkUserActionRequest{
				UserIDs: []uuid.UUID{uuid.New()},
				Action:  tt.action,
			}

			assert.Equal(t, tt.action, req.Action)
			assert.Len(t, req.UserIDs, 1)
		})
	}
}

// ==================== PlatformAuditLog ====================

func TestPlatformAuditLog_StructFields(t *testing.T) {
	t.Run("should carry all audit log fields", func(t *testing.T) {
		id := uuid.New()
		adminUserID := uuid.New()
		targetTenantID := uuid.New()
		targetTenantName := testAcmeCorp
		targetUserID := uuid.New()
		targetResourceID := uuid.New()
		errMsg := "operation failed"
		now := time.Now().Truncate(time.Second)

		log := PlatformAuditLog{
			ID:                 id,
			AdminUserID:        adminUserID,
			AdminUsername:      "admin@example.com",
			TargetTenantID:     &targetTenantID,
			TargetTenantName:   &targetTenantName,
			TargetUserID:       &targetUserID,
			TargetResourceType: "tenant",
			TargetResourceID:   &targetResourceID,
			Action:             "suspend_tenant",
			ActionCategory:     "tenant_management",
			Details:            map[string]interface{}{"reason": "non-payment"},
			IPAddress:          "10.0.0.1",
			UserAgent:          "Go-http-client/1.1",
			RequestID:          "req-abc-123",
			Success:            false,
			ErrorMessage:       &errMsg,
			CreatedAt:          now,
		}

		assert.Equal(t, id, log.ID)
		assert.Equal(t, adminUserID, log.AdminUserID)
		assert.Equal(t, "admin@example.com", log.AdminUsername)
		assert.Equal(t, &targetTenantID, log.TargetTenantID)
		assert.Equal(t, &targetTenantName, log.TargetTenantName)
		assert.Equal(t, &targetUserID, log.TargetUserID)
		assert.Equal(t, "tenant", log.TargetResourceType)
		assert.Equal(t, &targetResourceID, log.TargetResourceID)
		assert.Equal(t, "suspend_tenant", log.Action)
		assert.Equal(t, "tenant_management", log.ActionCategory)
		assert.Equal(t, map[string]interface{}{"reason": "non-payment"}, log.Details)
		assert.Equal(t, "10.0.0.1", log.IPAddress)
		assert.Equal(t, "Go-http-client/1.1", log.UserAgent)
		assert.Equal(t, "req-abc-123", log.RequestID)
		assert.False(t, log.Success)
		assert.Equal(t, &errMsg, log.ErrorMessage)
		assert.Equal(t, now, log.CreatedAt)
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		log := PlatformAuditLog{
			ID:          uuid.New(),
			AdminUserID: uuid.New(),
			Action:      "list_tenants",
			Success:     true,
		}

		assert.Nil(t, log.TargetTenantID)
		assert.Nil(t, log.TargetTenantName)
		assert.Nil(t, log.TargetUserID)
		assert.Nil(t, log.TargetResourceID)
		assert.Nil(t, log.Details)
		assert.Nil(t, log.ErrorMessage)
	})
}

// ==================== PlatformAuditFilters ====================

func TestPlatformAuditFilters_StructFields(t *testing.T) {
	t.Run("should carry all filter fields", func(t *testing.T) {
		tenantID := uuid.New()
		adminID := uuid.New()
		now := time.Now()
		past := now.Add(-24 * time.Hour)

		f := PlatformAuditFilters{
			Action:         "suspend_tenant",
			TargetTenantID: &tenantID,
			AdminUserID:    &adminID,
			ActionCategory: "tenant_management",
			From:           &past,
			To:             &now,
		}

		assert.Equal(t, "suspend_tenant", f.Action)
		assert.Equal(t, &tenantID, f.TargetTenantID)
		assert.Equal(t, &adminID, f.AdminUserID)
		assert.Equal(t, "tenant_management", f.ActionCategory)
		assert.Equal(t, &past, f.From)
		assert.Equal(t, &now, f.To)
	})

	t.Run("should allow nil pointer filters", func(t *testing.T) {
		f := PlatformAuditFilters{}

		assert.Nil(t, f.TargetTenantID)
		assert.Nil(t, f.AdminUserID)
		assert.Nil(t, f.From)
		assert.Nil(t, f.To)
	})
}

// ==================== PlatformStatistics ====================

func TestPlatformStatistics_StructFields(t *testing.T) {
	t.Run("should carry nested statistics structs", func(t *testing.T) {
		now := time.Now()

		stats := PlatformStatistics{
			TenantStats: TenantStatistics{
				TotalTenants:     100,
				ActiveTenants:    80,
				TrialTenants:     10,
				SuspendedTenants: 5,
				ByPlan:           map[string]int64{"enterprise": 50, "pro": 30},
				ByType:           map[string]int64{"customer": 90, "internal": 10},
				NewThisMonth:     8,
				ChurnedThisMonth: 2,
			},
			UserStats: UserStatistics{
				TotalUsers:      5000,
				ActiveUsers:     4200,
				LockedUsers:     30,
				VerifiedUsers:   4800,
				MFAEnabledUsers: 3000,
				NewThisMonth:    150,
				LoginsThisMonth: 25000,
			},
			ActivityStats: ActivityStats{
				LoginAttemptsToday:    500,
				SuccessfulLoginsToday: 450,
				FailedLoginsToday:     50,
				PasswordResetsToday:   10,
				AccountLocksToday:     3,
				ImpersonationsToday:   1,
			},
			ResourceStats: ResourceStats{
				TotalStorageUsedBytes:  int64(10 * 1024 * 1024 * 1024),
				TotalAPICallsThisMonth: 1000000,
				AverageUsersPerTenant:  50.5,
			},
			CalculatedAt: now,
		}

		assert.Equal(t, int64(100), stats.TenantStats.TotalTenants)
		assert.Equal(t, int64(80), stats.TenantStats.ActiveTenants)
		assert.Equal(t, int64(50), stats.TenantStats.ByPlan["enterprise"])
		assert.Equal(t, int64(5000), stats.UserStats.TotalUsers)
		assert.Equal(t, int64(500), stats.ActivityStats.LoginAttemptsToday)
		assert.Equal(t, float64(50.5), stats.ResourceStats.AverageUsersPerTenant)
		assert.Equal(t, now, stats.CalculatedAt)
	})
}

// ==================== TenantStatistics ====================

func TestTenantStatistics_StructFields(t *testing.T) {
	t.Run("should support all plan and type breakdowns", func(t *testing.T) {
		stats := TenantStatistics{
			TotalTenants:     50,
			ActiveTenants:    40,
			TrialTenants:     5,
			SuspendedTenants: 3,
			ByPlan: map[string]int64{
				"free":       10,
				"starter":    15,
				"enterprise": 25,
			},
			ByType: map[string]int64{
				"customer": 45,
				"internal": 5,
			},
			NewThisMonth:     3,
			ChurnedThisMonth: 1,
		}

		assert.Equal(t, int64(50), stats.TotalTenants)
		assert.Equal(t, int64(10), stats.ByPlan["free"])
		assert.Equal(t, int64(45), stats.ByType["customer"])
	})
}

// ==================== EmailQuota ====================

func TestEmailQuota_StructFields(t *testing.T) {
	t.Run("should carry all quota fields correctly", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		lastWarn := now.Add(-1 * time.Hour)

		quota := EmailQuota{
			ID:                id,
			TenantID:          tenantID,
			HourlyLimit:       100,
			DailyLimit:        1000,
			MonthlyLimit:      20000,
			CurrentHourCount:  10,
			CurrentDayCount:   150,
			CurrentMonthCount: 3000,
			HourResetAt:       now,
			DayResetAt:        now,
			MonthResetAt:      now,
			IsEnforced:        true,
			AllowBurst:        true,
			BurstMultiplier:   1.5,
			NotifyAtPercent:   80,
			LastWarningSentAt: &lastWarn,
			CreatedAt:         now,
			UpdatedAt:         now,
		}

		assert.Equal(t, id, quota.ID)
		assert.Equal(t, tenantID, quota.TenantID)
		assert.Equal(t, 100, quota.HourlyLimit)
		assert.Equal(t, 1000, quota.DailyLimit)
		assert.Equal(t, 20000, quota.MonthlyLimit)
		assert.Equal(t, 10, quota.CurrentHourCount)
		assert.Equal(t, 150, quota.CurrentDayCount)
		assert.Equal(t, 3000, quota.CurrentMonthCount)
		assert.True(t, quota.IsEnforced)
		assert.True(t, quota.AllowBurst)
		assert.Equal(t, 1.5, quota.BurstMultiplier)
		assert.Equal(t, 80, quota.NotifyAtPercent)
		assert.Equal(t, &lastWarn, quota.LastWarningSentAt)
	})

	t.Run("should allow nil LastWarningSentAt", func(t *testing.T) {
		quota := EmailQuota{
			ID:       uuid.New(),
			TenantID: uuid.New(),
		}

		assert.Nil(t, quota.LastWarningSentAt)
	})
}

// ==================== UpdateEmailQuotaRequest ====================

func TestUpdateEmailQuotaRequest_StructFields(t *testing.T) {
	t.Run("should carry all optional update fields", func(t *testing.T) {
		hourly := 200
		daily := 2000
		monthly := 40000
		enforced := true
		burst := false
		multiplier := 2.0
		notifyAt := 90

		req := UpdateEmailQuotaRequest{
			HourlyLimit:     &hourly,
			DailyLimit:      &daily,
			MonthlyLimit:    &monthly,
			IsEnforced:      &enforced,
			AllowBurst:      &burst,
			BurstMultiplier: &multiplier,
			NotifyAtPercent: &notifyAt,
		}

		require.NotNil(t, req.HourlyLimit)
		assert.Equal(t, 200, *req.HourlyLimit)
		require.NotNil(t, req.DailyLimit)
		assert.Equal(t, 2000, *req.DailyLimit)
		require.NotNil(t, req.MonthlyLimit)
		assert.Equal(t, 40000, *req.MonthlyLimit)
		require.NotNil(t, req.IsEnforced)
		assert.True(t, *req.IsEnforced)
		require.NotNil(t, req.AllowBurst)
		assert.False(t, *req.AllowBurst)
		require.NotNil(t, req.BurstMultiplier)
		assert.Equal(t, 2.0, *req.BurstMultiplier)
		require.NotNil(t, req.NotifyAtPercent)
		assert.Equal(t, 90, *req.NotifyAtPercent)
	})

	t.Run("should allow all nil (partial patch)", func(t *testing.T) {
		req := UpdateEmailQuotaRequest{}

		assert.Nil(t, req.HourlyLimit)
		assert.Nil(t, req.DailyLimit)
		assert.Nil(t, req.MonthlyLimit)
		assert.Nil(t, req.IsEnforced)
		assert.Nil(t, req.AllowBurst)
		assert.Nil(t, req.BurstMultiplier)
		assert.Nil(t, req.NotifyAtPercent)
	})
}

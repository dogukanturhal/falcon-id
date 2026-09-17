// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func newIPRuleMock(t *testing.T) (pgxmock.PgxPoolIface, *IPRuleRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newIPRuleRepositoryWithMock(mock)
}

var ipRuleCols = []string{
	"id", "tenant_id", "name", "description", "ip_pattern", "rule_type", "priority",
	"is_active", "applies_to", "expires_at", "hit_count", "last_hit_at",
	"created_at", "updated_at", "created_by", "updated_by",
}

func sampleIPRule() *models.IPRule {
	desc := "Block suspicious traffic"
	return &models.IPRule{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Name:        "block-192",
		IPPattern:   "192.168.1.0/24",
		RuleType:    models.IPRuleTypeDeny,
		Priority:    100,
		IsActive:    true,
		AppliesTo:   models.IPRuleAppliesToAll,
		HitCount:    0,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Description: &desc,
	}
}

func TestIPRuleRepository_GetByID(t *testing.T) {
	now := time.Now()
	rule := sampleIPRule()

	t.Run("found", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		rows := mock.NewRows(ipRuleCols).AddRow(
			rule.ID, rule.TenantID, rule.Name, rule.Description, rule.IPPattern,
			rule.RuleType, rule.Priority, rule.IsActive, rule.AppliesTo, nil,
			int64(0), nil, now, now, nil, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(rule.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), rule.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, rule.ID, got.ID)
		assert.Equal(t, rule.Name, got.Name)
		assert.Equal(t, rule.IPPattern, got.IPPattern)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		rows := mock.NewRows(ipRuleCols)
		mock.ExpectQuery(`SELECT`).WithArgs(rule.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), rule.ID)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WithArgs(rule.ID).
			WillReturnError(fmt.Errorf("connection timeout"))

		got, err := repo.GetByID(context.Background(), rule.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get IP rule")
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestIPRuleRepository_GetByTenantID(t *testing.T) {
	now := time.Now()
	rule := sampleIPRule()

	t.Run("returns rules", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		rows := mock.NewRows(ipRuleCols).AddRow(
			rule.ID, rule.TenantID, rule.Name, rule.Description, rule.IPPattern,
			rule.RuleType, rule.Priority, rule.IsActive, rule.AppliesTo, nil,
			int64(0), nil, now, now, nil, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(rule.TenantID).WillReturnRows(rows)

		rules, err := repo.GetByTenantID(context.Background(), rule.TenantID)
		require.NoError(t, err)
		assert.Len(t, rules, 1)
		assert.Equal(t, rule.ID, rules[0].ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty result", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		rows := mock.NewRows(ipRuleCols)
		mock.ExpectQuery(`SELECT`).WithArgs(rule.TenantID).WillReturnRows(rows)

		rules, err := repo.GetByTenantID(context.Background(), rule.TenantID)
		require.NoError(t, err)
		assert.Empty(t, rules)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestIPRuleRepository_GetActiveRules(t *testing.T) {
	now := time.Now()
	rule := sampleIPRule()

	t.Run("returns active rules", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		rows := mock.NewRows(ipRuleCols).AddRow(
			rule.ID, rule.TenantID, rule.Name, rule.Description, rule.IPPattern,
			rule.RuleType, rule.Priority, rule.IsActive, rule.AppliesTo, nil,
			int64(5), nil, now, now, nil, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(rule.TenantID).WillReturnRows(rows)

		rules, err := repo.GetActiveRules(context.Background(), rule.TenantID)
		require.NoError(t, err)
		assert.Len(t, rules, 1)
		assert.True(t, rules[0].IsActive)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestIPRuleRepository_Create(t *testing.T) {
	now := time.Now()
	ruleID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		rule := sampleIPRule()
		rows := mock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(ruleID, now, now)
		mock.ExpectQuery(`INSERT INTO iam_ip_rules`).
			WithArgs(anyArgs(11)...).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), rule)
		assert.NoError(t, err)
		assert.Equal(t, ruleID, rule.ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		rule := sampleIPRule()
		mock.ExpectQuery(`INSERT INTO iam_ip_rules`).
			WithArgs(anyArgs(11)...).
			WillReturnError(fmt.Errorf("insert failed"))

		err := repo.Create(context.Background(), rule)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create IP rule")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestIPRuleRepository_Update(t *testing.T) {
	now := time.Now()

	t.Run("success", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		rule := sampleIPRule()
		rows := mock.NewRows([]string{"updated_at"}).AddRow(now)
		mock.ExpectQuery(`UPDATE iam_ip_rules`).
			WithArgs(anyArgs(10)...).
			WillReturnRows(rows)

		err := repo.Update(context.Background(), rule)
		assert.NoError(t, err)
		assert.Equal(t, now, rule.UpdatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		rule := sampleIPRule()
		rows := mock.NewRows([]string{"updated_at"})
		mock.ExpectQuery(`UPDATE iam_ip_rules`).
			WithArgs(anyArgs(10)...).
			WillReturnRows(rows)

		err := repo.Update(context.Background(), rule)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP rule not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestIPRuleRepository_Delete(t *testing.T) {
	ruleID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_ip_rules`).
			WithArgs(ruleID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(context.Background(), ruleID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_ip_rules`).
			WithArgs(ruleID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		err := repo.Delete(context.Background(), ruleID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP rule not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestIPRuleRepository_IncrementHitCount(t *testing.T) {
	ruleID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_ip_rules`).
			WithArgs(ruleID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.IncrementHitCount(context.Background(), ruleID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_ip_rules`).
			WithArgs(ruleID).
			WillReturnError(fmt.Errorf("connection refused"))

		err := repo.IncrementHitCount(context.Background(), ruleID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestIPRuleRepository_LogAction(t *testing.T) {
	now := time.Now()
	logID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		ruleID := uuid.New()
		tenantID := uuid.New()
		ipLog := &models.IPRuleLog{
			RuleID:    &ruleID,
			TenantID:  &tenantID,
			IPAddress: "10.0.0.1",
			Action:    "denied",
			Endpoint:  "/api/v1/users",
			UserAgent: "curl/7.68",
		}

		rows := mock.NewRows([]string{"id", "created_at"}).AddRow(logID, now)
		mock.ExpectQuery(`INSERT INTO iam_ip_rule_logs`).
			WithArgs(anyArgs(6)...).
			WillReturnRows(rows)

		err := repo.LogAction(context.Background(), ipLog)
		assert.NoError(t, err)
		assert.Equal(t, logID, ipLog.ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestIPRuleRepository_GetRecentLogs(t *testing.T) {
	now := time.Now()
	tenantID := uuid.New()

	t.Run("returns logs", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		ruleID := uuid.New()
		logCols := []string{"id", "rule_id", "tenant_id", "ip_address", "action", "endpoint", "user_agent", "created_at"}
		rows := mock.NewRows(logCols).
			AddRow(uuid.New(), &ruleID, &tenantID, "10.0.0.1", "denied", "/api/v1/users", "curl/7.68", now).
			AddRow(uuid.New(), nil, &tenantID, "10.0.0.2", "allowed", "/api/v1/profile", "", now)

		mock.ExpectQuery(`SELECT`).WithArgs(tenantID, 50).WillReturnRows(rows)

		logs, err := repo.GetRecentLogs(context.Background(), tenantID, 50)
		require.NoError(t, err)
		assert.Len(t, logs, 2)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no logs", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		logCols := []string{"id", "rule_id", "tenant_id", "ip_address", "action", "endpoint", "user_agent", "created_at"}
		rows := mock.NewRows(logCols)
		mock.ExpectQuery(`SELECT`).WithArgs(tenantID, 10).WillReturnRows(rows)

		logs, err := repo.GetRecentLogs(context.Background(), tenantID, 10)
		require.NoError(t, err)
		assert.Empty(t, logs)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestIPRuleRepository_CleanupOldLogs(t *testing.T) {
	t.Run("returns deleted count", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_ip_rule_logs`).
			WithArgs(anyArgs(1)...).
			WillReturnResult(pgxmock.NewResult("DELETE", 42))

		count, err := repo.CleanupOldLogs(context.Background(), 30)
		assert.NoError(t, err)
		assert.Equal(t, int64(42), count)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newIPRuleMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_ip_rule_logs`).
			WithArgs(anyArgs(1)...).
			WillReturnError(fmt.Errorf("timeout"))

		count, err := repo.CleanupOldLogs(context.Background(), 30)
		assert.Error(t, err)
		assert.Equal(t, int64(0), count)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

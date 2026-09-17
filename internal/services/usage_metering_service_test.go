// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ==================== Mock: usageRecordRepo ====================

type mockUsageRecordRepo struct {
	mock.Mock
}

func (m *mockUsageRecordRepo) Record(ctx context.Context, record *models.UsageRecord) error {
	args := m.Called(ctx, record)
	return args.Error(0)
}

func (m *mockUsageRecordRepo) GetByTenantAndProduct(
	ctx context.Context,
	tenantID, productID uuid.UUID,
	metricName string,
	periodStart, periodEnd time.Time,
) (*models.UsageRecord, error) {
	args := m.Called(ctx, tenantID, productID, metricName, periodStart, periodEnd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UsageRecord), args.Error(1)
}

func (m *mockUsageRecordRepo) ListByTenant(
	ctx context.Context,
	tenantID uuid.UUID,
	periodStart, periodEnd time.Time,
	page, pageSize int,
) ([]models.UsageRecord, int64, error) {
	args := m.Called(ctx, tenantID, periodStart, periodEnd, page, pageSize)
	return args.Get(0).([]models.UsageRecord), args.Get(1).(int64), args.Error(2)
}

func (m *mockUsageRecordRepo) Aggregate(
	ctx context.Context,
	tenantID, productID uuid.UUID,
	metricName string,
	from, to time.Time,
) (int64, error) {
	args := m.Called(ctx, tenantID, productID, metricName, from, to)
	return args.Get(0).(int64), args.Error(1)
}

// ==================== TestRecordUsage_Success ====================

func TestRecordUsage_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	productID := uuid.New()

	record := &models.UsageRecord{
		TenantID:   tenantID,
		ProductID:  productID,
		MetricName: "api_calls",
		Value:      100,
	}

	repo := new(mockUsageRecordRepo)
	repo.On("Record", ctx, record).Return(nil)

	svc := NewUsageMeteringService(repo)
	err := svc.RecordUsage(ctx, record)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

// TestRecordUsage_MissingTenantID verifies validation rejects empty tenant ID.
func TestRecordUsage_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	record := &models.UsageRecord{
		TenantID:   uuid.Nil,
		ProductID:  uuid.New(),
		MetricName: "api_calls",
		Value:      10,
	}

	svc := NewUsageMeteringService(new(mockUsageRecordRepo))
	err := svc.RecordUsage(ctx, record)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id is required")
}

// TestRecordUsage_MissingMetricName verifies validation rejects empty metric names.
func TestRecordUsage_MissingMetricName(t *testing.T) {
	ctx := context.Background()
	record := &models.UsageRecord{
		TenantID:  uuid.New(),
		ProductID: uuid.New(),
		Value:     10,
	}

	svc := NewUsageMeteringService(new(mockUsageRecordRepo))
	err := svc.RecordUsage(ctx, record)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "metric_name is required")
}

// ==================== TestGetUsageSummary_Success ====================

func TestGetUsageSummary_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()

	expected := []models.UsageRecord{
		{ID: uuid.New(), TenantID: tenantID, ProductID: uuid.New(), MetricName: "logins", Value: 50},
		{ID: uuid.New(), TenantID: tenantID, ProductID: uuid.New(), MetricName: "api_calls", Value: 200},
	}

	repo := new(mockUsageRecordRepo)
	repo.On("ListByTenant", ctx, tenantID, mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time"), 1, 1000).
		Return(expected, int64(2), nil)

	svc := NewUsageMeteringService(repo)
	records, err := svc.GetUsageSummary(ctx, tenantID, from, to)

	require.NoError(t, err)
	assert.Len(t, records, 2)
	repo.AssertExpectations(t)
}

// ==================== TestGetProductUsage_Aggregates ====================

func TestGetProductUsage_Aggregates(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	productID := uuid.New()
	metric := "storage_gb"
	from := time.Now().Add(-30 * 24 * time.Hour)
	to := time.Now()

	repo := new(mockUsageRecordRepo)
	repo.On("Aggregate", ctx, tenantID, productID, metric, from, to).Return(int64(512), nil)

	svc := NewUsageMeteringService(repo)
	total, err := svc.GetProductUsage(ctx, tenantID, productID, metric, from, to)

	require.NoError(t, err)
	assert.Equal(t, int64(512), total)
	repo.AssertExpectations(t)
}

// TestGetProductUsage_EmptyMetric verifies validation rejects an empty metric name.
func TestGetProductUsage_EmptyMetric(t *testing.T) {
	ctx := context.Background()

	svc := NewUsageMeteringService(new(mockUsageRecordRepo))
	total, err := svc.GetProductUsage(ctx, uuid.New(), uuid.New(), "", time.Now(), time.Now())

	require.Error(t, err)
	assert.Equal(t, int64(0), total)
	assert.Contains(t, err.Error(), "metric is required")
}

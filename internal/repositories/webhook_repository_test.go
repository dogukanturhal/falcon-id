// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func newWebhookMock(t *testing.T) (pgxmock.PgxPoolIface, *WebhookRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newWebhookRepositoryWithMock(mock)
}

var webhookCols = []string{
	"id", "tenant_id", "name", "description", "url", "secret_hash", "events", "headers",
	"is_active", "retry_count", "timeout_seconds", "created_at", "updated_at", "created_by",
}

func sampleWebhook() *models.Webhook {
	desc := "My webhook"
	return &models.Webhook{
		ID:             uuid.New(),
		TenantID:       uuid.New(),
		Name:           "Test Webhook",
		Description:    &desc,
		URL:            "https://example.com/webhook",
		SecretHash:     "sha256hash",
		Events:         pq.StringArray{"user.created", "user.deleted"},
		Headers:        map[string]string{"X-Custom": "value"},
		IsActive:       true,
		RetryCount:     3,
		TimeoutSeconds: 30,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
}

func TestWebhookRepository_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		w := sampleWebhook()
		mock.ExpectExec(`INSERT INTO iam_webhooks`).
			WithArgs(anyArgs(14)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.Create(context.Background(), w)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		w := sampleWebhook()
		mock.ExpectExec(`INSERT INTO iam_webhooks`).
			WithArgs(anyArgs(14)...).
			WillReturnError(fmt.Errorf("unique constraint"))

		err := repo.Create(context.Background(), w)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestWebhookRepository_GetByID(t *testing.T) {
	now := time.Now()
	w := sampleWebhook()
	headersJSON, _ := json.Marshal(w.Headers)

	t.Run("found", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		rows := mock.NewRows(webhookCols).AddRow(
			w.ID, w.TenantID, w.Name, w.Description, w.URL, w.SecretHash,
			w.Events, headersJSON, w.IsActive, w.RetryCount, w.TimeoutSeconds,
			now, now, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(w.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), w.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, w.ID, got.ID)
		assert.Equal(t, w.Name, got.Name)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		rows := mock.NewRows(webhookCols)
		mock.ExpectQuery(`SELECT`).WithArgs(w.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), w.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "webhook not found")
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestWebhookRepository_Update(t *testing.T) {
	w := sampleWebhook()

	t.Run("success", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_webhooks`).
			WithArgs(anyArgs(11)...).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.Update(context.Background(), w)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_webhooks`).
			WithArgs(anyArgs(11)...).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.Update(context.Background(), w)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "webhook not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestWebhookRepository_Delete(t *testing.T) {
	webhookID := uuid.New()
	tenantID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_webhooks`).
			WithArgs(webhookID, tenantID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(context.Background(), webhookID, tenantID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_webhooks`).
			WithArgs(webhookID, tenantID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		err := repo.Delete(context.Background(), webhookID, tenantID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "webhook not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestWebhookRepository_List(t *testing.T) {
	now := time.Now()
	w := sampleWebhook()
	headersJSON, _ := json.Marshal(w.Headers)

	t.Run("all webhooks", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		countRows := mock.NewRows([]string{"count"}).AddRow(1)
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(w.TenantID).WillReturnRows(countRows)

		listRows := mock.NewRows(webhookCols).AddRow(
			w.ID, w.TenantID, w.Name, w.Description, w.URL, w.SecretHash,
			w.Events, headersJSON, w.IsActive, w.RetryCount, w.TimeoutSeconds,
			now, now, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(w.TenantID, 10, 0).WillReturnRows(listRows)

		webhooks, total, err := repo.List(context.Background(), w.TenantID, 1, 10, false)
		require.NoError(t, err)
		assert.Equal(t, 1, total)
		assert.Len(t, webhooks, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("active only", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		countRows := mock.NewRows([]string{"count"}).AddRow(1)
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(w.TenantID).WillReturnRows(countRows)

		listRows := mock.NewRows(webhookCols).AddRow(
			w.ID, w.TenantID, w.Name, w.Description, w.URL, w.SecretHash,
			w.Events, headersJSON, w.IsActive, w.RetryCount, w.TimeoutSeconds,
			now, now, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(w.TenantID, 10, 0).WillReturnRows(listRows)

		webhooks, total, err := repo.List(context.Background(), w.TenantID, 1, 10, true)
		require.NoError(t, err)
		assert.Equal(t, 1, total)
		assert.Len(t, webhooks, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestWebhookRepository_GetActiveByEvent(t *testing.T) {
	now := time.Now()
	w := sampleWebhook()
	headersJSON, _ := json.Marshal(w.Headers)
	eventType := "user.created"

	t.Run("found matching webhooks", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		rows := mock.NewRows(webhookCols).AddRow(
			w.ID, w.TenantID, w.Name, w.Description, w.URL, w.SecretHash,
			w.Events, headersJSON, w.IsActive, w.RetryCount, w.TimeoutSeconds,
			now, now, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(w.TenantID, eventType).WillReturnRows(rows)

		webhooks, err := repo.GetActiveByEvent(context.Background(), w.TenantID, eventType)
		require.NoError(t, err)
		assert.Len(t, webhooks, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestWebhookRepository_CreateDelivery(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		eventID := uuid.New().String()
		delivery := &models.WebhookDelivery{
			ID:          uuid.New(),
			WebhookID:   uuid.New(),
			EventType:   "user.created",
			EventID:     &eventID,
			Payload:     map[string]interface{}{"key": "value"},
			Status:      "pending",
			Attempts:    0,
			MaxAttempts: 3,
			CreatedAt:   time.Now(),
		}

		mock.ExpectExec(`INSERT INTO iam_webhook_deliveries`).
			WithArgs(
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(),
			).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.CreateDelivery(context.Background(), delivery)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestWebhookRepository_UpdateDelivery(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		delivery := &models.WebhookDelivery{
			ID:       uuid.New(),
			Status:   "delivered",
			Attempts: 1,
		}

		mock.ExpectExec(`UPDATE iam_webhook_deliveries`).
			WithArgs(
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
			).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdateDelivery(context.Background(), delivery)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestWebhookRepository_MarkDeliveryProcessing(t *testing.T) {
	deliveryID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_webhook_deliveries`).
			WithArgs(pgxmock.AnyArg(), deliveryID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.MarkDeliveryProcessing(context.Background(), deliveryID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found or already processing", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_webhook_deliveries`).
			WithArgs(pgxmock.AnyArg(), deliveryID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.MarkDeliveryProcessing(context.Background(), deliveryID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestWebhookRepository_GetDeliveryStats(t *testing.T) {
	webhookID := uuid.New()

	t.Run("returns stats map", func(t *testing.T) {
		mock, repo := newWebhookMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"status", "count"}).
			AddRow("pending", 5).
			AddRow("delivered", 10)
		mock.ExpectQuery(`SELECT status`).WithArgs(webhookID).WillReturnRows(rows)

		stats, err := repo.GetDeliveryStats(context.Background(), webhookID)
		require.NoError(t, err)
		assert.Equal(t, 5, stats["pending"])
		assert.Equal(t, 10, stats["delivered"])
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

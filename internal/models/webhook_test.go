// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildWebhook returns a fully populated Webhook for use in tests.
func buildWebhook() *Webhook {
	id := uuid.New()
	tenantID := uuid.New()
	createdBy := uuid.New()
	now := time.Now().Truncate(time.Second)
	desc := "User lifecycle notifications"

	return &Webhook{ //nolint:gosec // test fixture value, not a real credential
		ID:             id,
		TenantID:       tenantID,
		Name:           "User Events",
		Description:    &desc,
		URL:            "https://example.com/webhooks",
		SecretHash:     "$argon2id$v=19$m=65536,t=3,p=4$secretHash",
		Events:         []string{"user.created", "user.updated", "user.deleted"},
		Headers:        map[string]string{"X-Custom-Header": "value"},
		IsActive:       true,
		RetryCount:     3,
		TimeoutSeconds: 30,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      &createdBy,
	}
}

// ==================== WebhookEventType constants ====================

func TestWebhookEventType_UserEventConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant WebhookEventType
		expected string
	}{
		{
			name:     "user.created constant",
			constant: WebhookEventUserCreated,
			expected: "user.created",
		},
		{
			name:     "user.updated constant",
			constant: WebhookEventUserUpdated,
			expected: "user.updated",
		},
		{
			name:     "user.deleted constant",
			constant: WebhookEventUserDeleted,
			expected: "user.deleted",
		},
		{
			name:     "user.locked constant",
			constant: WebhookEventUserLocked,
			expected: "user.locked",
		},
		{
			name:     "user.unlocked constant",
			constant: WebhookEventUserUnlocked,
			expected: "user.unlocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, WebhookEventType(tt.expected), tt.constant)
		})
	}
}

func TestWebhookEventType_RoleEventConstants(t *testing.T) {
	assert.Equal(t, WebhookEventType("role.created"), WebhookEventRoleCreated)
	assert.Equal(t, WebhookEventType("role.updated"), WebhookEventRoleUpdated)
	assert.Equal(t, WebhookEventType("role.deleted"), WebhookEventRoleDeleted)
	assert.Equal(t, WebhookEventType("role.assigned"), WebhookEventRoleAssigned)
	assert.Equal(t, WebhookEventType("role.revoked"), WebhookEventRoleRevoked)
}

func TestWebhookEventType_SessionEventConstants(t *testing.T) {
	assert.Equal(t, WebhookEventType("session.created"), WebhookEventSessionCreated)
	assert.Equal(t, WebhookEventType("session.revoked"), WebhookEventSessionRevoked)
	assert.Equal(t, WebhookEventType("session.expired"), WebhookEventSessionExpired)
}

func TestWebhookEventType_LoginEventConstants(t *testing.T) {
	assert.Equal(t, WebhookEventType("login.success"), WebhookEventLoginSuccess)
	assert.Equal(t, WebhookEventType("login.failed"), WebhookEventLoginFailed)
	assert.Equal(t, WebhookEventType("logout"), WebhookEventLogout)
}

func TestWebhookEventType_MFAEventConstants(t *testing.T) {
	assert.Equal(t, WebhookEventType("mfa.enabled"), WebhookEventMFAEnabled)
	assert.Equal(t, WebhookEventType("mfa.disabled"), WebhookEventMFADisabled)
	assert.Equal(t, WebhookEventType("mfa.challenge"), WebhookEventMFAChallenge)
}

func TestWebhookEventType_ImpersonationEventConstants(t *testing.T) {
	assert.Equal(t, WebhookEventType("impersonation.started"), WebhookEventImpersonationStarted)
	assert.Equal(t, WebhookEventType("impersonation.ended"), WebhookEventImpersonationEnded)
}

func TestWebhookEventType_PasswordEventConstants(t *testing.T) {
	assert.Equal(t, WebhookEventType("password.changed"), WebhookEventPasswordChanged)
	assert.Equal(t, WebhookEventType("password.reset"), WebhookEventPasswordReset)
}

// ==================== WebhookDeliveryStatus constants ====================

func TestWebhookDeliveryStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant WebhookDeliveryStatus
		expected string
	}{
		{"pending", WebhookDeliveryStatusPending, "pending"},
		{"processing", WebhookDeliveryStatusProcessing, "processing"},
		{"success", WebhookDeliveryStatusSuccess, "success"},
		{"failed", WebhookDeliveryStatusFailed, "failed"},
		{"cancelled", WebhookDeliveryStatusCancelled, "cancelled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, WebhookDeliveryStatus(tt.expected), tt.constant)
		})
	}
}

// ==================== AllWebhookEventTypes ====================

func TestAllWebhookEventTypes(t *testing.T) {
	all := AllWebhookEventTypes()

	t.Run("should return a non-empty slice", func(t *testing.T) {
		assert.NotEmpty(t, all)
	})

	t.Run("should contain all expected event types", func(t *testing.T) {
		expected := []WebhookEventType{
			WebhookEventUserCreated,
			WebhookEventUserUpdated,
			WebhookEventUserDeleted,
			WebhookEventUserLocked,
			WebhookEventUserUnlocked,
			WebhookEventRoleCreated,
			WebhookEventRoleUpdated,
			WebhookEventRoleDeleted,
			WebhookEventRoleAssigned,
			WebhookEventRoleRevoked,
			WebhookEventSessionCreated,
			WebhookEventSessionRevoked,
			WebhookEventSessionExpired,
			WebhookEventLoginSuccess,
			WebhookEventLoginFailed,
			WebhookEventLogout,
			WebhookEventMFAEnabled,
			WebhookEventMFADisabled,
			WebhookEventMFAChallenge,
			WebhookEventImpersonationStarted,
			WebhookEventImpersonationEnded,
			WebhookEventPasswordChanged,
			WebhookEventPasswordReset,
			WebhookEventApplicationCreated,
			WebhookEventApplicationUpdated,
			WebhookEventApplicationDeleted,
			WebhookEventSPProvisioned,
			WebhookEventSPEnabled,
			WebhookEventSPDisabled,
			WebhookEventSPDeleted,
			WebhookEventSPCredentialsRotated,
			WebhookEventSPCredentialsExpiring,
			WebhookEventConsentGranted,
			WebhookEventConsentRevoked,
		}

		assert.Len(t, all, len(expected))
		for _, evt := range expected {
			assert.Contains(t, all, evt, "missing event type: %s", evt)
		}
	})

	t.Run("should return same slice content on repeated calls", func(t *testing.T) {
		all1 := AllWebhookEventTypes()
		all2 := AllWebhookEventTypes()
		assert.Equal(t, all1, all2)
	})
}

// ==================== Webhook.ToResponse ====================

func TestWebhook_ToResponse(t *testing.T) {
	t.Run("should map all scalar fields correctly", func(t *testing.T) {
		w := buildWebhook()

		resp := w.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, w.ID, resp.ID)
		assert.Equal(t, w.TenantID, resp.TenantID)
		assert.Equal(t, w.Name, resp.Name)
		assert.Equal(t, w.Description, resp.Description)
		assert.Equal(t, w.URL, resp.URL)
		assert.ElementsMatch(t, w.Events, resp.Events)
		assert.Equal(t, w.Headers, resp.Headers)
		assert.Equal(t, w.IsActive, resp.IsActive)
		assert.Equal(t, w.RetryCount, resp.RetryCount)
		assert.Equal(t, w.TimeoutSeconds, resp.TimeoutSeconds)
		assert.Equal(t, w.CreatedAt, resp.CreatedAt)
		assert.Equal(t, w.UpdatedAt, resp.UpdatedAt)
		assert.Equal(t, w.CreatedBy, resp.CreatedBy)
	})

	t.Run("should NOT include SecretHash in response", func(t *testing.T) {
		w := buildWebhook()
		w.SecretHash = "$argon2id$this-must-not-leak"

		resp := w.ToResponse()

		require.NotNil(t, resp)
		// WebhookResponse has no SecretHash field — only SecretHint.
		data, err := json.Marshal(resp)
		require.NoError(t, err)

		assert.NotContains(t, string(data), "secret_hash")
		assert.NotContains(t, string(data), "this-must-not-leak")
	})

	t.Run("should return a fixed placeholder SecretHint", func(t *testing.T) {
		w := buildWebhook()
		resp := w.ToResponse()

		assert.Equal(t, "********", resp.SecretHint,
			"SecretHint should be a fixed placeholder since original secret is unavailable")
	})

	t.Run("should handle nil optional fields", func(t *testing.T) {
		w := &Webhook{ //nolint:gosec // test fixture value, not a real credential
			ID:             uuid.New(),
			TenantID:       uuid.New(),
			Name:           "Minimal Webhook",
			URL:            "https://example.com/hook",
			SecretHash:     "$argon2id$hash",
			Events:         []string{"user.created"},
			IsActive:       true,
			RetryCount:     3,
			TimeoutSeconds: 30,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}

		resp := w.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.Description)
		assert.Nil(t, resp.Headers)
		assert.Nil(t, resp.CreatedBy)
	})

	t.Run("should produce distinct instances on each call", func(t *testing.T) {
		w := buildWebhook()

		resp1 := w.ToResponse()
		resp2 := w.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})

	t.Run("inactive webhook should reflect in response", func(t *testing.T) {
		w := buildWebhook()
		w.IsActive = false

		resp := w.ToResponse()

		require.NotNil(t, resp)
		assert.False(t, resp.IsActive)
	})
}

// ==================== SecretHash json:"-" tag ====================

func TestWebhook_SecretHash_JSONDashTag(t *testing.T) {
	t.Run("SecretHash must not appear in JSON serialization of Webhook", func(t *testing.T) {
		w := &Webhook{ //nolint:gosec // test fixture value, not a real credential
			ID:         uuid.New(),
			TenantID:   uuid.New(),
			Name:       "test webhook",
			URL:        "https://example.com/hook",
			SecretHash: "$argon2id$do-not-expose-this",
			Events:     []string{"user.created"},
			IsActive:   true,
		}

		data, err := json.Marshal(w)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.NotContains(t, out, "secret_hash",
			"SecretHash must be excluded from JSON output via json:\"-\" tag")
		assert.NotContains(t, string(data), "do-not-expose-this")
	})
}

// ==================== CreateWebhookRequest validation tags ====================

func TestCreateWebhookRequest_FieldTags(t *testing.T) {
	t.Run("should accept a valid request with all fields", func(t *testing.T) {
		isActive := true
		retryCount := 5
		timeout := 60
		desc := "All events hook"

		req := CreateWebhookRequest{
			Name:           "All Events",
			Description:    &desc,
			URL:            "https://example.com/webhook",
			Secret:         "super-secret-key-at-least-16-chars",
			Events:         []string{"user.created", "user.deleted"},
			Headers:        map[string]string{"X-Api-Version": "v1"},
			IsActive:       &isActive,
			RetryCount:     &retryCount,
			TimeoutSeconds: &timeout,
		}

		assert.Equal(t, "All Events", req.Name)
		assert.Equal(t, &desc, req.Description)
		assert.Equal(t, "https://example.com/webhook", req.URL)
		assert.Len(t, req.Secret, 34)
		assert.ElementsMatch(t, []string{"user.created", "user.deleted"}, req.Events)
		assert.Equal(t, map[string]string{"X-Api-Version": "v1"}, req.Headers)
		assert.Equal(t, &isActive, req.IsActive)
		assert.Equal(t, &retryCount, req.RetryCount)
		assert.Equal(t, &timeout, req.TimeoutSeconds)
	})

	t.Run("secret must be at least 16 characters (validate tag)", func(t *testing.T) {
		// Exactly 16 characters — meets the min=16 constraint.
		req := CreateWebhookRequest{
			Name:   "Hook",
			URL:    "https://example.com",
			Secret: "1234567890123456",
			Events: []string{"user.created"},
		}
		assert.Len(t, req.Secret, 16)
	})

	t.Run("should allow omission of optional fields", func(t *testing.T) {
		req := CreateWebhookRequest{ //nolint:gosec // test fixture value, not a real credential
			Name:   "Minimal Hook",
			URL:    "https://example.com/hook",
			Secret: "minimum-16-char-secret!",
			Events: []string{"login.success"},
		}

		assert.Nil(t, req.Description)
		assert.Nil(t, req.Headers)
		assert.Nil(t, req.IsActive)
		assert.Nil(t, req.RetryCount)
		assert.Nil(t, req.TimeoutSeconds)
	})
}

// ==================== UpdateWebhookRequest field tags ====================

func TestUpdateWebhookRequest_FieldTags(t *testing.T) {
	t.Run("all fields are optional", func(t *testing.T) {
		req := UpdateWebhookRequest{}

		assert.Nil(t, req.Name)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.URL)
		assert.Nil(t, req.Secret)
		assert.Empty(t, req.Events)
		assert.Nil(t, req.Headers)
		assert.Nil(t, req.IsActive)
		assert.Nil(t, req.RetryCount)
		assert.Nil(t, req.TimeoutSeconds)
	})

	t.Run("should carry all populated fields correctly", func(t *testing.T) {
		name := "Updated Hook"
		url := "https://updated.example.com/hook"
		secret := "new-secret-at-least-16-chars!!" //nolint:gosec // test fixture value, not a real credential
		isActive := false
		retryCount := 2
		timeout := 15

		req := UpdateWebhookRequest{
			Name:           &name,
			URL:            &url,
			Secret:         &secret,
			Events:         []string{"user.updated"},
			IsActive:       &isActive,
			RetryCount:     &retryCount,
			TimeoutSeconds: &timeout,
		}

		assert.Equal(t, &name, req.Name)
		assert.Equal(t, &url, req.URL)
		assert.Equal(t, &secret, req.Secret)
		assert.ElementsMatch(t, []string{"user.updated"}, req.Events)
		assert.Equal(t, &isActive, req.IsActive)
		assert.Equal(t, &retryCount, req.RetryCount)
		assert.Equal(t, &timeout, req.TimeoutSeconds)
	})
}

// ==================== WebhookCreatedResponse ====================

func TestWebhookCreatedResponse_Fields(t *testing.T) {
	t.Run("should include the plain-text secret in response", func(t *testing.T) {
		w := buildWebhook()
		base := w.ToResponse()

		createdResp := WebhookCreatedResponse{
			WebhookResponse: *base,
			Secret:          "original-secret-value-shown-once",
		}

		assert.Equal(t, w.ID, createdResp.ID)
		assert.Equal(t, "original-secret-value-shown-once", createdResp.Secret)
	})

	t.Run("Secret field should appear in JSON output", func(t *testing.T) {
		w := buildWebhook()
		createdResp := WebhookCreatedResponse{ //nolint:gosec // test fixture value, not a real credential
			WebhookResponse: *w.ToResponse(),
			Secret:          "my-webhook-secret",
		}

		data, err := json.Marshal(createdResp) //nolint:gosec // test struct with secret field, not real credentials
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Equal(t, "my-webhook-secret", out["secret"])
		assert.NotContains(t, out, "secret_hash")
	})
}

// ==================== WebhookEvent ====================

func TestWebhookEvent_Fields(t *testing.T) {
	t.Run("should hold all event fields correctly", func(t *testing.T) {
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		username := "alice"
		email := "alice@example.com"

		evt := WebhookEvent{
			ID:        uuid.New().String(),
			Type:      WebhookEventUserCreated,
			Timestamp: now,
			TenantID:  tenantID,
			Actor: &WebhookEventActor{
				ID:       uuid.New().String(),
				Type:     "user",
				Username: &username,
				Email:    &email,
			},
			Data: map[string]interface{}{
				"user_id":  uuid.New().String(),
				"username": "newuser",
			},
		}

		assert.NotEmpty(t, evt.ID)
		assert.Equal(t, WebhookEventUserCreated, evt.Type)
		assert.Equal(t, now, evt.Timestamp)
		assert.Equal(t, tenantID, evt.TenantID)
		require.NotNil(t, evt.Actor)
		assert.Equal(t, "user", evt.Actor.Type)
		assert.Equal(t, &username, evt.Actor.Username)
		assert.Equal(t, &email, evt.Actor.Email)
		assert.NotEmpty(t, evt.Data)
	})

	t.Run("should allow nil actor for system-generated events", func(t *testing.T) {
		evt := WebhookEvent{
			ID:        uuid.New().String(),
			Type:      WebhookEventSessionExpired,
			Timestamp: time.Now(),
			TenantID:  uuid.New(),
			Actor:     nil,
			Data:      map[string]interface{}{"session_id": "sess-abc"},
		}

		assert.Nil(t, evt.Actor)
	})

	t.Run("should serialize to JSON with correct field names", func(t *testing.T) {
		evt := WebhookEvent{
			ID:        "evt-123",
			Type:      WebhookEventLoginSuccess,
			Timestamp: time.Now().Truncate(time.Second),
			TenantID:  uuid.New(),
			Data:      map[string]interface{}{"ip": "10.0.0.1"},
		}

		data, err := json.Marshal(evt)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Equal(t, "evt-123", out["id"])
		assert.Equal(t, "login.success", out["type"])
		assert.Contains(t, out, "timestamp")
		assert.Contains(t, out, "tenant_id")
		assert.Contains(t, out, "data")
		// Actor is nil, so it should be omitted.
		assert.NotContains(t, out, "actor")
	})
}

// ==================== WebhookDelivery ====================

func TestWebhookDelivery_Fields(t *testing.T) {
	t.Run("should hold all delivery fields correctly", func(t *testing.T) {
		id := uuid.New()
		webhookID := uuid.New()
		now := time.Now().Truncate(time.Second)
		nextRetry := now.Add(5 * time.Minute)
		lastAttempt := now.Add(-1 * time.Minute)
		statusCode := 200
		body := `{"received":true}`
		durationMs := 85
		eventID := "evt-123"

		delivery := &WebhookDelivery{
			ID:             id,
			WebhookID:      webhookID,
			EventType:      "user.created",
			EventID:        &eventID,
			Payload:        map[string]interface{}{"user_id": "u-123"},
			Status:         WebhookDeliveryStatusSuccess,
			Attempts:       1,
			MaxAttempts:    3,
			NextRetryAt:    &nextRetry,
			LastAttemptAt:  &lastAttempt,
			ResponseStatus: &statusCode,
			ResponseBody:   &body,
			DurationMs:     &durationMs,
			CreatedAt:      now,
		}

		assert.Equal(t, id, delivery.ID)
		assert.Equal(t, webhookID, delivery.WebhookID)
		assert.Equal(t, "user.created", delivery.EventType)
		assert.Equal(t, &eventID, delivery.EventID)
		assert.Equal(t, WebhookDeliveryStatusSuccess, delivery.Status)
		assert.Equal(t, 1, delivery.Attempts)
		assert.Equal(t, 3, delivery.MaxAttempts)
		assert.Equal(t, &statusCode, delivery.ResponseStatus)
		assert.Equal(t, &body, delivery.ResponseBody)
		assert.Equal(t, &durationMs, delivery.DurationMs)
	})
}

// ==================== WebhookResponse JSON marshaling ====================

func TestWebhookResponse_JSONMarshaling(t *testing.T) {
	t.Run("should omit nil optional fields", func(t *testing.T) {
		resp := &WebhookResponse{
			ID:             uuid.New(),
			TenantID:       uuid.New(),
			Name:           "Minimal Webhook",
			URL:            "https://example.com/hook",
			SecretHint:     "********",
			Events:         []string{"user.created"},
			IsActive:       true,
			RetryCount:     3,
			TimeoutSeconds: 30,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.NotContains(t, out, "description")
		assert.NotContains(t, out, "headers")
		assert.NotContains(t, out, "created_by")
		assert.NotContains(t, out, "secret_hash")
	})

	t.Run("all required fields should be present", func(t *testing.T) {
		resp := &WebhookResponse{
			ID:             uuid.New(),
			TenantID:       uuid.New(),
			Name:           "Hook",
			URL:            "https://example.com/hook",
			SecretHint:     "********",
			Events:         []string{"login.success"},
			IsActive:       true,
			RetryCount:     3,
			TimeoutSeconds: 30,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Contains(t, out, "id")
		assert.Contains(t, out, "tenant_id")
		assert.Contains(t, out, "name")
		assert.Contains(t, out, "url")
		assert.Contains(t, out, "secret_hint")
		assert.Contains(t, out, "events")
		assert.Contains(t, out, "is_active")
		assert.Contains(t, out, "retry_count")
		assert.Contains(t, out, "timeout_seconds")
		assert.Contains(t, out, "created_at")
		assert.Contains(t, out, "updated_at")
	})
}

// ==================== WebhookTestRequest ====================

func TestWebhookTestRequest_Fields(t *testing.T) {
	t.Run("should hold the event type field", func(t *testing.T) {
		req := WebhookTestRequest{
			EventType: "user.created",
		}
		assert.Equal(t, "user.created", req.EventType)
	})

	t.Run("should serialize event_type to JSON", func(t *testing.T) {
		req := WebhookTestRequest{EventType: "login.failed"}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Equal(t, "login.failed", out["event_type"])
	})
}

// ==================== WebhookListResponse ====================

func TestWebhookListResponse_Fields(t *testing.T) {
	t.Run("should hold paginated webhook responses", func(t *testing.T) {
		w := buildWebhook()
		resp1 := w.ToResponse()
		resp2 := w.ToResponse()

		listResp := WebhookListResponse{
			Webhooks:   []*WebhookResponse{resp1, resp2},
			Total:      42,
			Page:       1,
			PageSize:   20,
			TotalPages: 3,
		}

		assert.Len(t, listResp.Webhooks, 2)
		assert.Equal(t, 42, listResp.Total)
		assert.Equal(t, 1, listResp.Page)
		assert.Equal(t, 20, listResp.PageSize)
		assert.Equal(t, 3, listResp.TotalPages)
	})
}

// ==================== Webhook struct field mapping ====================

func TestWebhook_StructFields(t *testing.T) {
	t.Run("fully populated webhook should have all fields set", func(t *testing.T) {
		w := buildWebhook()

		assert.NotEqual(t, uuid.Nil, w.ID)
		assert.NotEqual(t, uuid.Nil, w.TenantID)
		assert.NotEmpty(t, w.Name)
		assert.NotNil(t, w.Description)
		assert.NotEmpty(t, w.URL)
		assert.NotEmpty(t, w.SecretHash)
		assert.NotEmpty(t, w.Events)
		assert.NotEmpty(t, w.Headers)
		assert.True(t, w.IsActive)
		assert.GreaterOrEqual(t, w.RetryCount, 0)
		assert.Greater(t, w.TimeoutSeconds, 0)
		assert.False(t, w.CreatedAt.IsZero())
		assert.False(t, w.UpdatedAt.IsZero())
		assert.NotNil(t, w.CreatedBy)
	})
}

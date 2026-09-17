// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// --- Mocks ---

type mockLifecycleProductRepo struct {
	products map[uuid.UUID]*models.Product
}

func (m *mockLifecycleProductRepo) GetByID(_ context.Context, id uuid.UUID) (*models.Product, error) {
	if p, ok := m.products[id]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("not found")
}

// --- Tests ---

func TestLifecycleCallbackDispatcher_Dispatch_NoLifecycleSpec(t *testing.T) {
	productID := uuid.New()
	product := &models.Product{ID: productID, Slug: "test-product"}
	// No manifest → no lifecycle → no callback
	productRepo := &mockLifecycleProductRepo{
		products: map[uuid.UUID]*models.Product{productID: product},
	}

	dispatcher := NewLifecycleCallbackDispatcher(productRepo, nil)

	err := dispatcher.Dispatch(context.Background(), productID, uuid.New(), uuid.New(), "provisioning.activated", "")
	assert.NoError(t, err, "should succeed silently when no lifecycle spec")
}

func TestLifecycleCallbackDispatcher_Dispatch_NoCallbackURL(t *testing.T) {
	productID := uuid.New()
	product := &models.Product{ID: productID, Slug: "test-product"}
	// Manifest with lifecycle but no on_activated URL
	_ = product.SetManifest(&models.ProductManifest{
		Lifecycle: &models.LifecycleSpec{
			OnFailed: "http://example.com/failed",
		},
	})
	productRepo := &mockLifecycleProductRepo{
		products: map[uuid.UUID]*models.Product{productID: product},
	}

	dispatcher := NewLifecycleCallbackDispatcher(productRepo, nil)

	err := dispatcher.Dispatch(context.Background(), productID, uuid.New(), uuid.New(), "provisioning.activated", "")
	assert.NoError(t, err, "should succeed silently when no URL for this event type")
}

func TestLifecycleCallbackDispatcher_Dispatch_CallsWebhook(t *testing.T) {
	var receivedBody models.LifecycleCallbackPayload
	var receivedSignature string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSignature = r.Header.Get("X-Falcon-Signature")
		err := json.NewDecoder(r.Body).Decode(&receivedBody)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	productID := uuid.New()
	instanceID := uuid.New()
	tenantID := uuid.New()

	product := &models.Product{ID: productID, Slug: "test-product"}
	_ = product.SetManifest(&models.ProductManifest{
		Lifecycle: &models.LifecycleSpec{
			OnActivated:   server.URL + "/activated",
			SigningSecret: "test-secret-key",
		},
	})

	productRepo := &mockLifecycleProductRepo{
		products: map[uuid.UUID]*models.Product{productID: product},
	}

	allowlist := []string{server.URL}
	dispatcher := NewLifecycleCallbackDispatcher(productRepo, allowlist)

	err := dispatcher.Dispatch(context.Background(), productID, instanceID, tenantID, "provisioning.activated", "")

	assert.NoError(t, err)
	assert.Equal(t, "provisioning.activated", receivedBody.EventType)
	assert.Equal(t, instanceID.String(), receivedBody.InstanceID)
	assert.Equal(t, tenantID.String(), receivedBody.TenantID)
	assert.Equal(t, productID.String(), receivedBody.ProductID)
	assert.NotEmpty(t, receivedSignature, "should include HMAC signature")
}

func TestLifecycleCallbackDispatcher_Dispatch_FailedEvent(t *testing.T) {
	var receivedBody models.LifecycleCallbackPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	productID := uuid.New()
	product := &models.Product{ID: productID, Slug: "test-product"}
	_ = product.SetManifest(&models.ProductManifest{
		Lifecycle: &models.LifecycleSpec{
			OnFailed: server.URL + "/failed",
		},
	})

	productRepo := &mockLifecycleProductRepo{
		products: map[uuid.UUID]*models.Product{productID: product},
	}

	dispatcher := NewLifecycleCallbackDispatcher(productRepo, []string{server.URL})

	err := dispatcher.Dispatch(context.Background(), productID, uuid.New(), uuid.New(), "provisioning.failed", "database timeout")

	assert.NoError(t, err)
	assert.Equal(t, "provisioning.failed", receivedBody.EventType)
	assert.Equal(t, "database timeout", receivedBody.Reason)
}

func TestLifecycleCallbackDispatcher_Dispatch_SSRFBlocksDisallowedURL(t *testing.T) {
	productID := uuid.New()
	product := &models.Product{ID: productID, Slug: "test-product"}
	_ = product.SetManifest(&models.ProductManifest{
		Lifecycle: &models.LifecycleSpec{
			OnActivated: "http://evil-external.com/steal-data",
		},
	})

	productRepo := &mockLifecycleProductRepo{
		products: map[uuid.UUID]*models.Product{productID: product},
	}

	// Allowlist only includes internal URLs
	dispatcher := NewLifecycleCallbackDispatcher(productRepo, []string{"http://internal-service:8080"})

	err := dispatcher.Dispatch(context.Background(), productID, uuid.New(), uuid.New(), "provisioning.activated", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not in allowlist")
}

func TestLifecycleCallbackDispatcher_Dispatch_NilAllowlist_BlocksAll(t *testing.T) {
	productID := uuid.New()
	product := &models.Product{ID: productID, Slug: "test-product"}
	_ = product.SetManifest(&models.ProductManifest{
		Lifecycle: &models.LifecycleSpec{
			OnActivated: "http://any-service.com/callback",
		},
	})

	productRepo := &mockLifecycleProductRepo{
		products: map[uuid.UUID]*models.Product{productID: product},
	}

	// Nil allowlist → block all
	dispatcher := NewLifecycleCallbackDispatcher(productRepo, nil)

	err := dispatcher.Dispatch(context.Background(), productID, uuid.New(), uuid.New(), "provisioning.activated", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not in allowlist")
}

func TestLifecycleCallbackDispatcher_Dispatch_DeletedEvent(t *testing.T) {
	var receivedBody models.LifecycleCallbackPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	productID := uuid.New()
	product := &models.Product{ID: productID, Slug: "test-product"}
	_ = product.SetManifest(&models.ProductManifest{
		Lifecycle: &models.LifecycleSpec{
			OnDeleted: server.URL + "/deleted",
		},
	})

	productRepo := &mockLifecycleProductRepo{
		products: map[uuid.UUID]*models.Product{productID: product},
	}

	dispatcher := NewLifecycleCallbackDispatcher(productRepo, []string{server.URL})

	err := dispatcher.Dispatch(context.Background(), productID, uuid.New(), uuid.New(), "provisioning.deleted", "")

	assert.NoError(t, err)
	assert.Equal(t, "provisioning.deleted", receivedBody.EventType)
}

func TestLifecycleCallbackDispatcher_Dispatch_WebhookReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	productID := uuid.New()
	product := &models.Product{ID: productID, Slug: "test-product"}
	_ = product.SetManifest(&models.ProductManifest{
		Lifecycle: &models.LifecycleSpec{
			OnActivated: server.URL + "/activated",
		},
	})

	productRepo := &mockLifecycleProductRepo{
		products: map[uuid.UUID]*models.Product{productID: product},
	}

	dispatcher := NewLifecycleCallbackDispatcher(productRepo, []string{server.URL})

	err := dispatcher.Dispatch(context.Background(), productID, uuid.New(), uuid.New(), "provisioning.activated", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "non-2xx")
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// lifecycleProductRepo resolves product details for lifecycle callbacks.
type lifecycleProductRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Product, error)
}

// LifecycleCallbackDispatcher calls product-registered webhook URLs
// when provisioning lifecycle events occur.
//
// Security invariants:
//   - SR-LCB-01: Callback URLs validated against an allowlist (SSRF prevention)
//   - SR-LCB-02: Payloads signed with HMAC-SHA256 when signing secret is configured
//   - SR-LCB-03: HTTP client has strict timeouts to prevent hanging
type LifecycleCallbackDispatcher struct {
	productRepo  lifecycleProductRepo
	urlAllowlist []string
	httpClient   *http.Client
}

// NewLifecycleCallbackDispatcher creates a new dispatcher.
// urlAllowlist is the list of allowed URL prefixes for SSRF prevention.
func NewLifecycleCallbackDispatcher(
	productRepo lifecycleProductRepo,
	urlAllowlist []string,
) *LifecycleCallbackDispatcher {
	return &LifecycleCallbackDispatcher{
		productRepo:  productRepo,
		urlAllowlist: urlAllowlist,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Dispatch sends a lifecycle callback to the product's registered webhook URL.
// Returns nil if the product has no lifecycle spec or no URL for the event type.
func (d *LifecycleCallbackDispatcher) Dispatch(
	ctx context.Context,
	productID, instanceID, tenantID uuid.UUID,
	eventType string,
	reason string,
) error {
	product, err := d.productRepo.GetByID(ctx, productID)
	if err != nil {
		return fmt.Errorf("lifecycle callback: product not found: %w", err)
	}

	manifest, err := product.ParseManifest()
	if err != nil || manifest == nil || manifest.Lifecycle == nil {
		return nil // No lifecycle config → silent success
	}

	callbackURL := d.resolveURL(manifest.Lifecycle, eventType)
	if callbackURL == "" {
		return nil // No URL for this event type
	}

	// SR-LCB-01: SSRF prevention — validate URL against allowlist
	if !d.isAllowedURL(callbackURL) {
		return fmt.Errorf("lifecycle callback: URL %q not in allowlist", callbackURL)
	}

	payload := models.LifecycleCallbackPayload{
		EventType:  eventType,
		InstanceID: instanceID.String(),
		TenantID:   tenantID.String(),
		ProductID:  productID.String(),
		Reason:     reason,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("lifecycle callback: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, callbackURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("lifecycle callback: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Falcon-Event", eventType)

	// SR-LCB-02: HMAC signature
	if manifest.Lifecycle.SigningSecret != "" {
		sig := computeHMAC(body, manifest.Lifecycle.SigningSecret)
		req.Header.Set("X-Falcon-Signature", sig)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("lifecycle callback: HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("lifecycle callback: non-2xx response: %d", resp.StatusCode)
	}

	logger.Info("Lifecycle callback dispatched",
		zap.String("event_type", eventType),
		zap.String("product_id", productID.String()),
		zap.String("callback_url", callbackURL),
		zap.Int("status_code", resp.StatusCode),
	)

	return nil
}

// resolveURL returns the callback URL for a given event type.
func (d *LifecycleCallbackDispatcher) resolveURL(spec *models.LifecycleSpec, eventType string) string {
	switch eventType {
	case "provisioning.activated":
		return spec.OnActivated
	case "provisioning.failed":
		return spec.OnFailed
	case "provisioning.deleted":
		return spec.OnDeleted
	case "provisioning.suspended":
		return spec.OnSuspended
	default:
		return ""
	}
}

// isAllowedURL checks if the URL starts with any of the allowed prefixes.
func (d *LifecycleCallbackDispatcher) isAllowedURL(url string) bool {
	for _, prefix := range d.urlAllowlist {
		if strings.HasPrefix(url, prefix) {
			return true
		}
	}
	return false
}

// computeHMAC computes HMAC-SHA256 of the body with the given secret.
func computeHMAC(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

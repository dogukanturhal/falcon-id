// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// autoscaleAWXClient is the interface subset of *services.AWXClient used by
// AutoscaleHandler, allowing the real client and a test double to be swapped in.
type autoscaleAWXClient interface {
	ProvisionHost(ctx context.Context, hostAlias, patroniCluster, datacenter string) (*services.AWXJobStatus, error)
	ExpandStorage(ctx context.Context, hostAlias, newSize string) (*services.AWXJobStatus, error)
	AddReplica(ctx context.Context, replicaHostAlias, primaryHostAlias, patroniCluster string) (*services.AWXJobStatus, error)
	DecommissionHost(ctx context.Context, hostAlias, hostID string) (*services.AWXJobStatus, error)
	ReplenishWarmPool(ctx context.Context, region string, count int) (*services.AWXJobStatus, error)
	LaunchJob(ctx context.Context, templateID int, extraVars map[string]interface{}) (*services.AWXJobStatus, error)
	IsDevMode() bool
}

const datacenterIstanbul = "istanbul"

// AlertManagerWebhook is the top-level structure sent by Prometheus AlertManager.
// See: https://prometheus.io/docs/alerting/latest/configuration/#webhook_config
type AlertManagerWebhook struct {
	Version           string            `json:"version"`
	GroupKey          string            `json:"groupKey"`
	TruncatedAlerts   int               `json:"truncatedAlerts"`
	Status            string            `json:"status"` // "firing" or "resolved"
	Receiver          string            `json:"receiver"`
	GroupLabels       map[string]string `json:"groupLabels"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	ExternalURL       string            `json:"externalURL"`
	Alerts            []Alert           `json:"alerts"`
}

// Alert is a single alert entry within the AlertManager webhook payload.
type Alert struct {
	Status       string            `json:"status"` // "firing" or "resolved"
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

// autoscaleAction represents a dispatched autoscaling action.
type autoscaleAction struct {
	AlertName string
	Action    string
	Labels    map[string]string
	JobID     int
	JobStatus string
	Error     string
}

// AutoscaleHandler receives AlertManager webhook payloads and dispatches
// Ansible AWX jobs in response to capacity alerts.
//
// Supported alert actions (set via alert labels in prometheus-rules.yml):
//   - scale             — provision a new host or add a replica to absorb connection load
//   - provision_new_host — provision a brand-new PostgreSQL host via AWX
//   - replenish_warmpool — trigger warm-pool replenishment for the alert's region
//   - expand_storage    — run LVM expand-storage.yml on the alert's host
//
// The webhook endpoint requires NO authentication because AlertManager is an
// internal system-to-system call on the private Docker network. The endpoint is
// NOT exposed through APISIX.
type AutoscaleHandler struct {
	awxClient autoscaleAWXClient
	log       *zap.SugaredLogger
}

// NewAutoscaleHandler creates an AutoscaleHandler wired to the given AWX client.
func NewAutoscaleHandler(awxClient autoscaleAWXClient, log *zap.SugaredLogger) *AutoscaleHandler {
	if log == nil {
		log = zap.NewNop().Sugar()
	}
	return &AutoscaleHandler{
		awxClient: awxClient,
		log:       log,
	}
}

// HandleWebhook is the HTTP handler for POST /api/v1/platform/autoscale/webhook.
// It is intentionally synchronous for the HTTP response but launches AWX jobs
// asynchronously so AlertManager doesn't time out waiting for provisioning to
// complete (which can take minutes).
func (h *AutoscaleHandler) HandleWebhook(c *gin.Context) {
	var webhook AlertManagerWebhook
	if err := c.ShouldBindJSON(&webhook); err != nil {
		h.log.Warnw("Autoscale webhook: invalid payload", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid payload: %s", err)})
		return
	}

	h.log.Infow("Autoscale webhook received",
		"status", webhook.Status,
		"alert_count", len(webhook.Alerts),
		"receiver", webhook.Receiver,
		"group_key", webhook.GroupKey,
	)

	// Dispatch each firing alert asynchronously so we can return 200 immediately.
	// AlertManager expects a fast response; provisioning tasks can take minutes.
	dispatched := make([]autoscaleAction, 0, len(webhook.Alerts))

	for i := range webhook.Alerts {
		alert := &webhook.Alerts[i]

		// Only act on firing alerts; resolved alerts are logged but ignored.
		if alert.Status != "firing" {
			h.log.Debugw("Autoscale webhook: skipping resolved alert",
				"alert", alert.Labels["alertname"],
				"fingerprint", alert.Fingerprint,
			)
			continue
		}

		action := alert.Labels["action"]
		alertName := alert.Labels["alertname"]

		h.log.Infow("Autoscale webhook: processing firing alert",
			"alert", alertName,
			"action", action,
			"severity", alert.Labels["severity"],
			"fingerprint", alert.Fingerprint,
		)

		result := autoscaleAction{
			AlertName: alertName,
			Action:    action,
			Labels:    alert.Labels,
		}

		// Dispatch the action in a goroutine — handler returns 200 immediately.
		// The goroutine owns its own context (background + timeout).
		go func(a *Alert, res autoscaleAction) {
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
			defer cancel()

			if err := h.dispatch(ctx, a); err != nil {
				h.log.Errorw("Autoscale dispatch failed",
					"alert", res.AlertName,
					"action", res.Action,
					"error", err,
				)
			}
		}(alert, result)

		dispatched = append(dispatched, result)
	}

	c.JSON(http.StatusOK, gin.H{
		"status":            "processed",
		"alerts_received":   len(webhook.Alerts),
		"alerts_dispatched": len(dispatched),
		"awx_dev_mode":      h.awxClient.IsDevMode(),
	})
}

// dispatch routes a single firing alert to the appropriate AWX job.
func (h *AutoscaleHandler) dispatch(ctx context.Context, alert *Alert) error {
	action := alert.Labels["action"]
	alertName := alert.Labels["alertname"]

	switch action {
	case "scale":
		return h.handleScale(ctx, alert)

	case "provision_new_host":
		return h.handleProvisionNewHost(ctx, alert)

	case "replenish_warmpool":
		return h.handleReplenishWarmPool(ctx, alert)

	case "expand_storage":
		return h.handleExpandStorage(ctx, alert)

	case "investigate":
		// Human-reviewed alerts — log but take no automated action.
		h.log.Infow("Autoscale webhook: investigate-only alert (no automated action)",
			"alert", alertName,
			"labels", alert.Labels,
			"annotations", alert.Annotations,
		)
		return nil

	default:
		h.log.Warnw("Autoscale webhook: unknown action label — no action taken",
			"alert", alertName,
			"action", action,
		)
		return nil
	}
}

// handleScale responds to connection saturation alerts.
// Strategy:
//  1. If there is a warm-pool host available, no AWX action is needed —
//     the ProductDBProvisioner will pick it up on next allocation.
//  2. Otherwise, trigger host provisioning.
func (h *AutoscaleHandler) handleScale(ctx context.Context, alert *Alert) error {
	instance := alert.Labels["instance"]
	cluster := alert.Labels["cluster"]
	if cluster == "" {
		cluster = "example-default"
	}
	datacenter := alert.Labels["datacenter"]
	if datacenter == "" {
		datacenter = datacenterIstanbul
	}

	h.log.Infow("Autoscale: scale action triggered",
		"instance", instance,
		"cluster", cluster,
		"datacenter", datacenter,
	)

	// Use the ReplenishWarmPool job to add capacity — it provisions a new host
	// and registers it. For connection-capacity alerts the most effective lever
	// is increasing the number of hosts so connections distribute.
	status, err := h.awxClient.ReplenishWarmPool(ctx, datacenter, 5)
	if err != nil {
		return fmt.Errorf("scale: replenish warm pool for region %s: %w", datacenter, err)
	}

	h.log.Infow("Autoscale: scale job launched",
		"job_id", status.ID,
		"job_status", status.Status,
		"datacenter", datacenter,
	)
	return nil
}

// handleProvisionNewHost triggers host provisioning when a host reaches database
// density capacity (example_host_databases_current / example_host_databases_max > 0.8).
func (h *AutoscaleHandler) handleProvisionNewHost(ctx context.Context, alert *Alert) error {
	hostAlias := alert.Labels["host_alias"]
	region := alert.Labels["region"]
	cluster := alert.Labels["cluster"]

	if region == "" {
		region = datacenterIstanbul
	}
	if cluster == "" {
		cluster = fmt.Sprintf("example-%s", region)
	}

	// AWX will select an available host from the inventory group for the region.
	// The new host alias is derived from a naming convention if not provided.
	newHostAlias := alert.Labels["new_host_alias"]
	if newHostAlias == "" {
		// Generate a candidate alias — AWX will validate it exists in inventory.
		// In production this would query a CMDB or host pool API.
		newHostAlias = fmt.Sprintf("pg-%s-auto", region[:3])
	}

	h.log.Infow("Autoscale: provision new host",
		"triggering_host", hostAlias,
		"new_host", newHostAlias,
		"region", region,
		"cluster", cluster,
	)

	status, err := h.awxClient.ProvisionHost(ctx, newHostAlias, cluster, region)
	if err != nil {
		return fmt.Errorf("provision new host %s (region %s): %w", newHostAlias, region, err)
	}

	h.log.Infow("Autoscale: provision-host job launched",
		"job_id", status.ID,
		"job_status", status.Status,
		"new_host", newHostAlias,
	)
	return nil
}

// handleReplenishWarmPool refills the warm pool for the alert's region.
func (h *AutoscaleHandler) handleReplenishWarmPool(ctx context.Context, alert *Alert) error {
	region := alert.Labels["region"]
	if region == "" {
		region = datacenterIstanbul
	}

	// Replenish to the default target of 10 pre-provisioned databases per region.
	replenishCount := 10

	// If the alert carries a current count we can compute the delta.
	if currentStr := alert.Labels["current_count"]; currentStr != "" {
		current, err := strconv.Atoi(currentStr)
		if err == nil && current >= 0 {
			replenishCount = 10 - current
			if replenishCount <= 0 {
				h.log.Infow("Autoscale: warm pool replenishment skipped — already at target",
					"region", region, "current", current)
				return nil
			}
		}
	}

	h.log.Infow("Autoscale: replenish warm pool",
		"region", region,
		"replenish_count", replenishCount,
	)

	status, err := h.awxClient.ReplenishWarmPool(ctx, region, replenishCount)
	if err != nil {
		return fmt.Errorf("replenish warm pool region %s: %w", region, err)
	}

	h.log.Infow("Autoscale: replenish-warmpool job launched",
		"job_id", status.ID,
		"job_status", status.Status,
		"region", region,
		"count", replenishCount,
	)
	return nil
}

// handleExpandStorage triggers LVM volume expansion on the alerting host.
func (h *AutoscaleHandler) handleExpandStorage(ctx context.Context, alert *Alert) error {
	// The instance label from node_exporter is "host:port" — extract just the host.
	instance := alert.Labels["instance"]
	hostAlias := alert.Labels["host_alias"]

	// Prefer the explicit host_alias label; fall back to stripping port from instance.
	if hostAlias == "" && instance != "" {
		// Strip :9100 or :9187 port suffix to get the host alias
		for i := len(instance) - 1; i >= 0; i-- {
			if instance[i] == ':' {
				hostAlias = instance[:i]
				break
			}
		}
		if hostAlias == "" {
			hostAlias = instance
		}
	}

	if hostAlias == "" {
		return fmt.Errorf("expand storage: cannot determine host from alert labels (instance=%q, host_alias=%q)",
			instance, alert.Labels["host_alias"])
	}

	// Default expansion: +50G. In prod this would be derived from the
	// current disk size and a configured expansion increment.
	newSize := alert.Labels["expand_size"]
	if newSize == "" {
		newSize = "+50G"
	}

	h.log.Infow("Autoscale: expand storage",
		"host", hostAlias,
		"new_size", newSize,
		"alert", alert.Labels["alertname"],
	)

	status, err := h.awxClient.ExpandStorage(ctx, hostAlias, newSize)
	if err != nil {
		return fmt.Errorf("expand storage on %s by %s: %w", hostAlias, newSize, err)
	}

	h.log.Infow("Autoscale: expand-storage job launched",
		"job_id", status.ID,
		"job_status", status.Status,
		"host", hostAlias,
		"new_size", newSize,
	)
	return nil
}

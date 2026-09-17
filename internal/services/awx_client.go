// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// awxJobTemplateIDs is the canonical mapping of ExampleSuite provisioning operations
// to AWX Job Template numeric IDs. These are populated when AWX is first configured
// and must match the IDs assigned by the AWX API.
// Override via environment variables: AWX_TEMPLATE_PROVISION_HOST, etc.
const (
	AWXTemplateProvisionHost     = 1
	AWXTemplateAddReplica        = 2
	AWXTemplateDecommissionHost  = 3
	AWXTemplateExpandStorage     = 4
	AWXTemplateReplenishWarmPool = 5

	awxJobStatusFailed = "failed"
)

// AWXJobStatus mirrors the AWX REST API unified_job status field.
type AWXJobStatus struct {
	ID              int    `json:"id"`
	Type            string `json:"type"`
	URL             string `json:"url"`
	Status          string `json:"status"` // pending, waiting, running, successful, failed, error, canceled
	Failed          bool   `json:"failed"`
	Started         string `json:"started"`
	Finished        string `json:"finished"`
	ExtraVars       string `json:"extra_vars"`
	JobArgs         string `json:"job_args"`
	ResultTraceback string `json:"result_traceback"`
	// Embedded job template reference
	JobTemplate int `json:"job_template"`
}

// awxJobLaunchRequest is the POST body sent to /api/v2/job_templates/:id/launch/.
type awxJobLaunchRequest struct {
	ExtraVars map[string]interface{} `json:"extra_vars,omitempty"`
	Limit     string                 `json:"limit,omitempty"` // Host pattern, e.g. "pg-ist-01"
	Tags      string                 `json:"job_tags,omitempty"`
	SkipTags  string                 `json:"skip_tags,omitempty"`
}

// awxJobLaunchResponse is the JSON body returned by the launch endpoint.
type awxJobLaunchResponse struct {
	Job           int                    `json:"job"`
	IgnoredFields map[string]interface{} `json:"ignored_fields"`
}

// AWXClient calls the Ansible AWX REST API to trigger provisioning playbooks.
// In dev mode (devMode=true), AWX calls are simulated so the service starts
// and runs without a real AWX instance.
type AWXClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
	log        *zap.SugaredLogger
	devMode    bool
}

// NewAWXClient creates a new AWX REST API client.
// baseURL should be the full AWX URL without trailing slash, e.g. "http://localhost:8052".
// token is an AWX user OAuth2 token or API token.
// If baseURL is empty the client operates in dev-simulation mode.
func NewAWXClient(baseURL, token string, log *zap.SugaredLogger) *AWXClient {
	devMode := baseURL == "" || baseURL == "disabled"
	if log == nil {
		log = zap.NewNop().Sugar()
	}
	if devMode {
		log.Warn("AWXClient: AWX_BASE_URL not configured — operating in dev-simulation mode. " +
			"Provisioning jobs will be logged but not executed.")
	}
	return &AWXClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		log:     log,
		devMode: devMode,
	}
}

// LaunchJob triggers an AWX Job Template with the provided extra variables.
// extraVars map is passed as JSON to the AWX job — these become Ansible extra_vars.
// Returns the initial job status (usually "pending" or "waiting").
func (c *AWXClient) LaunchJob(ctx context.Context, templateID int, extraVars map[string]interface{}) (*AWXJobStatus, error) {
	if c.devMode {
		return c.simulateLaunchJob(templateID, extraVars), nil
	}

	payload := awxJobLaunchRequest{
		ExtraVars: extraVars,
	}

	// If target_host is specified in extraVars, use it as the AWX limit pattern
	// so the playbook only runs against the target node.
	if host, ok := extraVars["target_host"].(string); ok && host != "" {
		payload.Limit = host
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("awx: marshal launch request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v2/job_templates/%d/launch/", c.baseURL, templateID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("awx: create launch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("awx: launch job template %d: %w", templateID, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("awx: read launch response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("awx: launch job template %d: HTTP %d: %s",
			templateID, resp.StatusCode, string(respBody))
	}

	var launched awxJobLaunchResponse
	if err := json.Unmarshal(respBody, &launched); err != nil {
		return nil, fmt.Errorf("awx: parse launch response: %w", err)
	}

	c.log.Infow("AWX job launched",
		"template_id", templateID,
		"job_id", launched.Job,
		"extra_vars", extraVars,
	)

	// Fetch initial status
	return c.GetJobStatus(ctx, launched.Job)
}

// GetJobStatus returns the current status of an AWX job by numeric ID.
func (c *AWXClient) GetJobStatus(ctx context.Context, jobID int) (*AWXJobStatus, error) {
	if c.devMode {
		return c.simulateJobStatus(jobID, "successful"), nil
	}

	url := fmt.Sprintf("%s/api/v2/jobs/%d/", c.baseURL, jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("awx: create status request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("awx: get job %d status: %w", jobID, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("awx: read job status response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("awx: get job %d status: HTTP %d: %s",
			jobID, resp.StatusCode, string(respBody))
	}

	var status AWXJobStatus
	if err := json.Unmarshal(respBody, &status); err != nil {
		return nil, fmt.Errorf("awx: parse job status: %w", err)
	}

	return &status, nil
}

// WaitForJob polls the AWX job status until it reaches a terminal state
// (successful, failed, error, canceled) or the timeout expires.
// Polling interval is 5 seconds.
// Returns an error if the job fails, is canceled, or times out.
func (c *AWXClient) WaitForJob(ctx context.Context, jobID int, timeout time.Duration) (*AWXJobStatus, error) {
	if c.devMode {
		c.log.Infow("AWX dev-mode: simulating job completion", "job_id", jobID)
		time.Sleep(500 * time.Millisecond) // Simulate minimal latency in tests
		return c.simulateJobStatus(jobID, "successful"), nil
	}

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("awx: wait for job %d canceled: %w", jobID, ctx.Err())

		case t := <-ticker.C:
			if t.After(deadline) {
				return nil, fmt.Errorf("awx: wait for job %d: timeout after %s", jobID, timeout)
			}

			status, err := c.GetJobStatus(ctx, jobID)
			if err != nil {
				// Transient error — log and retry
				c.log.Warnw("AWX job status poll error (will retry)", "job_id", jobID, "error", err)
				continue
			}

			c.log.Debugw("AWX job status poll", "job_id", jobID, "status", status.Status)

			switch status.Status {
			case "successful":
				return status, nil
			case awxJobStatusFailed, "error":
				return status, fmt.Errorf("awx: job %d %s: %s", jobID, status.Status, status.ResultTraceback)
			case "canceled":
				return status, fmt.Errorf("awx: job %d was canceled", jobID)
				// pending, waiting, running — continue polling
			}
		}
	}
}

// LaunchAndWait is a convenience wrapper that launches a job and waits for
// completion with a default 30-minute timeout. Suitable for provisioning tasks
// that complete in under 30 minutes in all normal cases.
func (c *AWXClient) LaunchAndWait(ctx context.Context, templateID int, extraVars map[string]interface{}) (*AWXJobStatus, error) {
	status, err := c.LaunchJob(ctx, templateID, extraVars)
	if err != nil {
		return nil, err
	}
	return c.WaitForJob(ctx, status.ID, 30*time.Minute)
}

// ProvisionHost triggers the provision-pg-host.yml playbook for the given host alias.
func (c *AWXClient) ProvisionHost(ctx context.Context, hostAlias, patroniCluster, datacenter string) (*AWXJobStatus, error) {
	c.log.Infow("Triggering AWX provision-pg-host job", "host", hostAlias, "cluster", patroniCluster)
	return c.LaunchJob(ctx, AWXTemplateProvisionHost, map[string]interface{}{
		"target_host":     hostAlias,
		"patroni_cluster": patroniCluster,
		"datacenter":      datacenter,
	})
}

// ExpandStorage triggers the expand-storage.yml playbook for the given host.
// newSize is an LVM size spec, e.g. "+50G" or "200G".
func (c *AWXClient) ExpandStorage(ctx context.Context, hostAlias, newSize string) (*AWXJobStatus, error) {
	c.log.Infow("Triggering AWX expand-storage job", "host", hostAlias, "new_size", newSize)
	return c.LaunchJob(ctx, AWXTemplateExpandStorage, map[string]interface{}{
		"target_host": hostAlias,
		"new_size":    newSize,
	})
}

// AddReplica triggers the add-replica.yml playbook to add a new replica node.
func (c *AWXClient) AddReplica(ctx context.Context, replicaHostAlias, primaryHostAlias, patroniCluster string) (*AWXJobStatus, error) {
	c.log.Infow("Triggering AWX add-replica job",
		"replica", replicaHostAlias,
		"primary", primaryHostAlias,
		"cluster", patroniCluster,
	)
	return c.LaunchJob(ctx, AWXTemplateAddReplica, map[string]interface{}{
		"target_host":     replicaHostAlias,
		"primary_host":    primaryHostAlias,
		"patroni_cluster": patroniCluster,
	})
}

// DecommissionHost triggers the decommission-host.yml playbook.
func (c *AWXClient) DecommissionHost(ctx context.Context, hostAlias, hostID string) (*AWXJobStatus, error) {
	c.log.Infow("Triggering AWX decommission-host job", "host", hostAlias, "host_id", hostID)
	return c.LaunchJob(ctx, AWXTemplateDecommissionHost, map[string]interface{}{
		"target_host":  hostAlias,
		"host_id":      hostID,
		"skip_confirm": true, // AWX-triggered jobs don't need interactive confirmation
	})
}

// ReplenishWarmPool triggers warm pool replenishment for the specified region.
func (c *AWXClient) ReplenishWarmPool(ctx context.Context, region string, count int) (*AWXJobStatus, error) {
	c.log.Infow("Triggering AWX replenish-warmpool job", "region", region, "count", count)
	return c.LaunchJob(ctx, AWXTemplateReplenishWarmPool, map[string]interface{}{
		"region":          region,
		"replenish_count": count,
		"warmpool_target": 10,
	})
}

// IsDevMode returns true when the client is operating in simulation mode.
func (c *AWXClient) IsDevMode() bool {
	return c.devMode
}

// simulateLaunchJob returns a fake "pending" job status for dev-mode.
func (c *AWXClient) simulateLaunchJob(templateID int, extraVars map[string]interface{}) *AWXJobStatus {
	jobID := templateID * 1000 // Deterministic fake ID based on template
	c.log.Infow("AWX dev-mode: simulating job launch",
		"template_id", templateID,
		"fake_job_id", jobID,
		"extra_vars", extraVars,
	)
	return &AWXJobStatus{
		ID:          jobID,
		Type:        "job",
		Status:      "pending",
		JobTemplate: templateID,
		Started:     time.Now().UTC().Format(time.RFC3339),
	}
}

// simulateJobStatus returns a fake completed status for dev-mode.
func (c *AWXClient) simulateJobStatus(jobID int, status string) *AWXJobStatus {
	now := time.Now().UTC().Format(time.RFC3339)
	return &AWXJobStatus{
		ID:       jobID,
		Type:     "job",
		Status:   status,
		Failed:   status != "successful",
		Started:  now,
		Finished: now,
	}
}

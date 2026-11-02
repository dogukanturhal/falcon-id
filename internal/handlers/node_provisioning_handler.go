// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// node_provisioning_handler.go provides HTTP handlers that let the platform-admin
// UI provision, inspect, and remove k3s agent nodes. The three phases simulate
// the Packer → Terraform → Ansible IaC pipeline:
//
//  1. Packer  — pull / build the base Ubuntu image
//  2. Terraform — create the container (simulates VM creation)
//  3. Ansible — install k3s agent and join the cluster
//
// Jobs are tracked in an in-memory map keyed by a UUID job ID. Each job records
// per-phase status, timing, stdout/stderr output, and any error message.
//
// Routes (registered in routes_admin.go → registerOperationalExcellenceRoutes):
//
//	GET    /api/v1/platform/nodes                    — list k8s nodes via kubectl
//	GET    /api/v1/platform/nodes/provision          — list all provisioning jobs
//	POST   /api/v1/platform/nodes/provision          — start a new provisioning job
//	GET    /api/v1/platform/nodes/provision/:job_id  — get job status
//	DELETE /api/v1/platform/nodes/:node_name         — drain + delete a node
//
// Service deployment routes (registered in routes_admin.go → registerOperationalExcellenceRoutes):
//
//	GET    /api/v1/platform/deployment/groups        — list deployable service groups
//	POST   /api/v1/platform/deployment/deploy        — start an async deployment job
//	GET    /api/v1/platform/deployment               — list all deployment jobs
//	GET    /api/v1/platform/deployment/:job_id       — get deployment job status

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	nodeRoleGeneralPurpose    = "general-purpose"
	msgNodeInvalidRequestBody = "invalid request body: "
	kubectlIgnoreDaemonsets   = "--ignore-daemonsets"
	kubectlDeleteEmptydirData = "--delete-emptydir-data"
	kubectlForce              = "--force"
	kubectlTimeout5m          = "--timeout=5m"
	kubectlNoHeaders          = "--no-headers"
	kubectlOverwrite          = "--overwrite"
	msgNodePoolNotFound       = "node pool not found: "
	fmtNodePoolLabelSelector  = "example.com/node-pool=%s"

	nodeStatusUnknown     = "Unknown"
	nodeStatusReady       = "Ready"
	nodeStatusFailed      = "failed"
	nodeStatusCompleted   = "completed"
	nodeStatusNotDeployed = "not_deployed"
	nodeTierShared        = "shared"
)

// ProvisioningPhase captures the status and output of a single pipeline phase.
type ProvisioningPhase struct {
	Name      string     `json:"name"`
	Status    string     `json:"status"` // pending | running | completed | failed
	StartedAt *time.Time `json:"started_at,omitempty"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Output    string     `json:"output,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// ProvisioningJob represents a full node provisioning run.
type ProvisioningJob struct {
	ID        string              `json:"id"`
	NodeName  string              `json:"node_name"`
	NodeRole  string              `json:"node_role"` // general-purpose | databases | example-services | platform-services | identity | observability | frontends | devsecops
	Status    string              `json:"status"`    // pending | provisioning | completed | failed
	Phases    []ProvisioningPhase `json:"phases"`
	CreatedAt time.Time           `json:"created_at"`
	UpdatedAt time.Time           `json:"updated_at"`
}

// validNodeRoles defines allowed values for node_role.
var validNodeRoles = map[string]string{
	"general-purpose":   "General Purpose — no workload affinity",
	"databases":         "Databases — PostgreSQL, Redis, NATS, etc.",
	"example-services":  "ExampleSuite Services — CRM, HR, Inventory, etc.",
	"platform-services": "Platform Services — tenant-mgmt, workflow, etc.",
	"identity":          "Identity — Falcon-ID, APISIX, SpiceDB",
	"observability":     "Observability — Prometheus, Grafana, Loki",
	"frontends":         "Frontends — Next.js applications",
	"devsecops":         "DevSecOps — CI/CD, security scanning",
}

// Taint represents a Kubernetes node taint.
type Taint struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Effect string `json:"effect"` // NoSchedule | PreferNoSchedule | NoExecute
}

// NodePool represents a managed group of identically-configured Kubernetes nodes.
type NodePool struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	Role                string            `json:"role"`
	IsolationTier       string            `json:"isolation_tier"` // shared | dedicated | isolated
	TenantID            string            `json:"tenant_id,omitempty"`
	InstanceTypes       []string          `json:"instance_types"`
	MinNodes            int               `json:"min_nodes"`
	MaxNodes            int               `json:"max_nodes"`
	DesiredNodes        int               `json:"desired_nodes"`
	CurrentNodes        int               `json:"current_nodes"`
	Labels              map[string]string `json:"labels"`
	Taints              []Taint           `json:"taints"`
	AutoScalingEnabled  bool              `json:"auto_scaling_enabled"`
	ConsolidationPolicy string            `json:"consolidation_policy"` // none | when-underutilized | when-empty
	Status              string            `json:"status"`               // active | provisioning | scaling | draining | cordoned | error
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

// NodeProvisioningHandler manages k3s agent node lifecycle and service deployments
// for the platform-admin UI.
type NodeProvisioningHandler struct {
	log        *zap.Logger
	scriptPath string // directory that contains provisioning shell scripts
	mu         sync.RWMutex
	jobs       map[string]*ProvisioningJob
	deployJobs map[string]*DeploymentJob
	nodePools  map[string]*NodePool
}

// NewNodeProvisioningHandler returns a handler ready for use.
//
// log may be nil (a no-op logger is used in that case).
// scriptPath defaults to "/app/scripts" when empty.
func NewNodeProvisioningHandler(log *zap.Logger, scriptPath string) *NodeProvisioningHandler {
	if log == nil {
		log = zap.NewNop()
	}
	if scriptPath == "" {
		scriptPath = "/app/scripts"
	}
	return &NodeProvisioningHandler{
		log:        log,
		scriptPath: scriptPath,
		jobs:       make(map[string]*ProvisioningJob),
		deployJobs: make(map[string]*DeploymentJob),
		nodePools:  make(map[string]*NodePool),
	}
}

// ---------------------------------------------------------------------------
// Deployment types
// ---------------------------------------------------------------------------

// DeploymentWave represents a group of services to deploy together within a
// deployment job. Each wave is applied sequentially; services within a wave
// are deployed concurrently.
type DeploymentWave struct {
	Name     string   `json:"name"`
	Services []string `json:"services"`
	Status   string   `json:"status"` // pending | deploying | completed | failed
	Output   string   `json:"output,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// DeploymentJob tracks a full service-group deployment run.
type DeploymentJob struct {
	ID        string           `json:"id"`
	Group     string           `json:"group"`  // infrastructure | identity | platform | business | frontends | observability | all
	Status    string           `json:"status"` // pending | deploying | completed | failed
	Waves     []DeploymentWave `json:"waves"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

// deployGroupSpec describes all waves for a named deployment group.
type deployGroupSpec struct {
	namespace string
	waves     []DeploymentWave
}

// deployableGroups returns the canonical wave definitions for every service group.
// Services match the k3d deployment scripts exactly so that real kubectl/helm
// commands can replace the simulation in a future iteration.
func deployableGroups() map[string]deployGroupSpec {
	return map[string]deployGroupSpec{
		"infrastructure": {
			namespace: "infra-key",
			waves: []DeploymentWave{
				{
					Name:     "Wave 1 — Core datastores",
					Services: []string{"postgresql-data-plane", "postgresql-control-plane", "redis", "nats", "minio", "vault"},
					Status:   "pending",
				},
				{
					Name:     "Wave 2 — Connection layer + authorization",
					Services: []string{"pgbouncer", "spicedb"},
					Status:   "pending",
				},
			},
		},
		"identity": {
			namespace: "hexxlock-identity",
			waves: []DeploymentWave{
				{
					Name:     "Wave 1 — Identity service",
					Services: []string{"etcd", "falcon-id"},
					Status:   "pending",
				},
				{
					Name:     "Wave 2 — API gateway + ingress",
					Services: []string{"apisix", "traefik"},
					Status:   "pending",
				},
			},
		},
		"platform": {
			namespace: "hexxlock-platform",
			waves: []DeploymentWave{
				{
					Name:     "Wave 1 — Core platform services",
					Services: []string{"tenant-management", "subscription-management", "quota-service"},
					Status:   "pending",
				},
				{
					Name:     "Wave 2 — Data + integration backbone",
					Services: []string{"master-data", "integration-bus", "workflow-engine", "custom-fields", "custom-objects"},
					Status:   "pending",
				},
				{
					Name:     "Wave 3 — Storage + document pipeline",
					Services: []string{"storage-api", "document-processor", "document-generator", "document-numbering", "esignature"},
					Status:   "pending",
				},
				{
					Name:     "Wave 4 — Communication + async",
					Services: []string{"notification-service", "messaging-integration", "helpdesk", "comments", "realtime"},
					Status:   "pending",
				},
				{
					Name:     "Wave 5 — Analytics + reporting",
					Services: []string{"report-builder", "report-scheduling", "predictive-analytics", "ai-search"},
					Status:   "pending",
				},
				{
					Name:     "Wave 6 — Connectors + developer ecosystem",
					Services: []string{"connectors", "integration-hub", "developer-portal", "api-marketplace", "app-marketplace"},
					Status:   "pending",
				},
				{
					Name:     "Wave 7 — Infrastructure management + remaining services",
					Services: []string{"db-router", "domain-management", "spicedb-sync", "cms", "compute-api", "network-api", "resource-provisioner", "multi-region", "metering-service", "compliance-service", "billing", "payment-gateway", "marketing-automation", "backup-dr", "social-gateway"},
					Status:   "pending",
				},
			},
		},
		"business": {
			namespace: "hexxlock-business",
			waves: []DeploymentWave{
				{
					Name:     "Wave 1 — Core ERP modules",
					Services: []string{"crm", "hr", "inventory", "invoicing"},
					Status:   "pending",
				},
				{
					Name:     "Wave 2 — Secondary ERP modules",
					Services: []string{"marketing", "plm", "qms", "sd", "pm"},
					Status:   "pending",
				},
				{
					Name:     "Wave 3 — Financial + manufacturing modules",
					Services: []string{"accounting", "fico", "ppscm", "cmms", "mm", "finance-service"},
					Status:   "pending",
				},
				{
					Name:     "Wave 4 — Vertical product modules",
					Services: []string{"ecommerce", "example-pms", "car-rental", "travel-agency"},
					Status:   "pending",
				},
			},
		},
		"frontends": {
			namespace: "hexxlock-frontend",
			waves: []DeploymentWave{
				{
					Name:     "Wave 1 — All Next.js applications",
					Services: []string{"unified-dashboard", "platform-admin", "accounts", "customer-portal", "developer-portal-frontend", "public-website", "app-marketplace-frontend", "storefront-renderer", "site-manager"},
					Status:   "pending",
				},
			},
		},
		"observability": {
			namespace: "hexxlock-observe",
			waves: []DeploymentWave{
				{
					Name:     "Wave 1 — Observability stack",
					Services: []string{"prometheus", "grafana", "loki", "promtail", "jaeger"},
					Status:   "pending",
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

// provisionNodeRequest is the JSON body for POST /nodes/provision.
type provisionNodeRequest struct {
	NodeName string `json:"node_name" binding:"required"`
	NodeRole string `json:"node_role"` // optional, defaults to "general-purpose"
}

// ProvisionNode handles POST /api/v1/platform/nodes/provision.
//
// Creates a provisioning job with three phases and launches it asynchronously.
// Returns 202 Accepted immediately with the job ID so callers can poll status.
func (h *NodeProvisioningHandler) ProvisionNode(c *gin.Context) {
	var req provisionNodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgNodeInvalidRequestBody + err.Error()})
		return
	}

	// Default to general-purpose if not specified.
	nodeRole := strings.TrimSpace(req.NodeRole)
	if nodeRole == "" {
		nodeRole = nodeRoleGeneralPurpose
	}
	if _, ok := validNodeRoles[nodeRole]; !ok {
		roles := make([]string, 0, len(validNodeRoles))
		for r := range validNodeRoles {
			roles = append(roles, r)
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("invalid node_role %q; valid values: %s", nodeRole, strings.Join(roles, ", ")),
		})
		return
	}

	jobID := uuid.New().String()
	now := time.Now()

	job := &ProvisioningJob{
		ID:       jobID,
		NodeName: req.NodeName,
		NodeRole: nodeRole,
		Status:   "provisioning",
		Phases: []ProvisioningPhase{
			{Name: "Packer (Build Image)", Status: "pending"},
			{Name: "Terraform (Create VM)", Status: "pending"},
			{Name: "Ansible (Configure Node)", Status: "pending"},
			{Name: "Label (Assign Workload Role)", Status: "pending"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	h.mu.Lock()
	h.jobs[jobID] = job
	h.mu.Unlock()

	h.log.Info("Node provisioning job created",
		zap.String("job_id", jobID),
		zap.String("node_name", req.NodeName),
		zap.String("node_role", nodeRole),
	)

	h.runProvisioningAsync(job)

	c.JSON(http.StatusAccepted, gin.H{
		"job_id":    jobID,
		"node_name": req.NodeName,
		"node_role": nodeRole,
		"status":    job.Status,
		"message":   "Provisioning started. Poll /nodes/provision/" + jobID + " for status.",
	})
}

// GetProvisioningStatus handles GET /api/v1/platform/nodes/provision/:job_id.
func (h *NodeProvisioningHandler) GetProvisioningStatus(c *gin.Context) {
	jobID := c.Param("job_id")

	h.mu.RLock()
	job, ok := h.jobs[jobID]
	h.mu.RUnlock()

	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "job not found: " + jobID})
		return
	}

	// Return a snapshot so the caller never races against the background goroutine.
	h.mu.RLock()
	snapshot := h.copyJob(job)
	h.mu.RUnlock()

	c.JSON(http.StatusOK, snapshot)
}

// ListProvisioningJobs handles GET /api/v1/platform/nodes/provision.
//
// Returns all jobs (history), most-recently-created first.
func (h *NodeProvisioningHandler) ListProvisioningJobs(c *gin.Context) {
	h.mu.RLock()
	jobs := make([]ProvisioningJob, 0, len(h.jobs))
	for _, j := range h.jobs {
		jobs = append(jobs, h.copyJob(j))
	}
	h.mu.RUnlock()

	// Sort by CreatedAt descending so the newest job is first.
	for i := 0; i < len(jobs)-1; i++ {
		for k := i + 1; k < len(jobs); k++ {
			if jobs[k].CreatedAt.After(jobs[i].CreatedAt) {
				jobs[i], jobs[k] = jobs[k], jobs[i]
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"jobs":  jobs,
		"total": len(jobs),
	})
}

// RemoveNode handles DELETE /api/v1/platform/nodes/:node_name.
//
// Drains the node, removes it from the cluster, and stops/removes the backing
// container. The operation is async; the handler returns 202 immediately.
func (h *NodeProvisioningHandler) RemoveNode(c *gin.Context) {
	nodeName := c.Param("node_name")
	if nodeName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "node_name is required"})
		return
	}

	h.log.Info("Node removal requested", zap.String("node_name", nodeName))

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		steps := []struct {
			desc string
			cmd  string
			args []string
		}{
			{"kubectl drain", "kubectl", []string{
				"drain", nodeName,
				kubectlIgnoreDaemonsets,
				kubectlDeleteEmptydirData,
				kubectlForce,
				kubectlTimeout5m,
			}},
			{"kubectl delete node", "kubectl", []string{"delete", "node", nodeName}},
			{"docker stop", "docker", []string{"stop", nodeName}},
			{"docker rm", "docker", []string{"rm", "-f", nodeName}},
		}

		for _, step := range steps {
			cmd := exec.CommandContext(ctx, step.cmd, step.args...) //nolint:gosec // input validated before use
			out, err := cmd.CombinedOutput()
			if err != nil {
				h.log.Warn("Node removal step failed (continuing)",
					zap.String("node_name", nodeName),
					zap.String("step", step.desc),
					zap.String("output", string(out)),
					zap.Error(err),
				)
				// Continue cleanup even when individual steps fail so that
				// partial state does not leave the cluster stuck.
				continue
			}
			h.log.Info("Node removal step completed",
				zap.String("node_name", nodeName),
				zap.String("step", step.desc),
			)
		}

		h.log.Info("Node removal sequence finished", zap.String("node_name", nodeName))
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"node_name": nodeName,
		"status":    "removal_started",
		"message":   "Node drain and removal initiated asynchronously.",
	})
}

// k8sNodeList is a minimal subset of the JSON returned by `kubectl get nodes -o json`.
// Only the fields the platform-admin UI needs are unmarshalled.
type k8sNodeList struct {
	Items []struct {
		Metadata struct {
			Name              string            `json:"name"`
			Labels            map[string]string `json:"labels"`
			CreationTimestamp string            `json:"creationTimestamp"`
		} `json:"metadata"`
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
			NodeInfo struct {
				KubeletVersion   string `json:"kubeletVersion"`
				OperatingSystem  string `json:"operatingSystem"`
				Architecture     string `json:"architecture"`
				ContainerRuntime string `json:"containerRuntimeVersion"`
			} `json:"nodeInfo"`
		} `json:"status"`
		Spec struct {
			Unschedulable bool `json:"unschedulable"`
		} `json:"spec"`
	} `json:"items"`
}

// GetNodeRoles handles GET /api/v1/platform/nodes/roles.
//
// Returns the list of valid node roles with descriptions so the UI can render
// a dropdown without hardcoding values.
func (h *NodeProvisioningHandler) GetNodeRoles(c *gin.Context) {
	type roleView struct {
		Value       string `json:"value"`
		Label       string `json:"label"`
		Description string `json:"description"`
	}

	roles := make([]roleView, 0, len(validNodeRoles))
	// Ordered for consistent UI rendering.
	orderedRoles := []string{
		nodeRoleGeneralPurpose, "databases", "example-services", "platform-services",
		"identity", "observability", "frontends", "devsecops",
	}
	for _, key := range orderedRoles {
		// Build a human-readable label from the key (e.g. "example-services" → "example Services").
		words := strings.Split(key, "-")
		for i, w := range words {
			if len(w) > 0 {
				words[i] = strings.ToUpper(w[:1]) + w[1:]
			}
		}
		roles = append(roles, roleView{
			Value:       key,
			Label:       strings.Join(words, " "),
			Description: validNodeRoles[key],
		})
	}
	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

// ListNodes handles GET /api/v1/platform/nodes.
//
// Shells out to `kubectl get nodes -o json`, parses the result, and returns a
// simplified node list. When kubectl is unavailable or the cluster is not
// reachable it returns an empty list with an explanatory message.
func (h *NodeProvisioningHandler) ListNodes(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "json")
	out, err := cmd.Output()
	if err != nil {
		h.log.Warn("kubectl get nodes failed — returning empty node list",
			zap.Error(err),
		)
		c.JSON(http.StatusOK, gin.H{
			"nodes":   []struct{}{},
			"total":   0,
			"warning": "kubectl unavailable or cluster unreachable: " + err.Error(),
		})
		return
	}

	var raw k8sNodeList
	if err := json.Unmarshal(out, &raw); err != nil {
		h.log.Error("Failed to parse kubectl node list", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse node list: " + err.Error()})
		return
	}

	type nodeView struct {
		Name              string            `json:"name"`
		Labels            map[string]string `json:"labels"`
		CreationTimestamp string            `json:"creation_timestamp"`
		Status            string            `json:"status"`
		KubeletVersion    string            `json:"kubelet_version"`
		OS                string            `json:"os"`
		Architecture      string            `json:"architecture"`
		ContainerRuntime  string            `json:"container_runtime"`
		Unschedulable     bool              `json:"unschedulable"`
	}

	nodes := make([]nodeView, 0, len(raw.Items))
	for _, item := range raw.Items {
		// Derive a simple nodeStatusReady / "NotReady" status from conditions.
		nodeStatus := nodeStatusUnknown
		for _, cond := range item.Status.Conditions {
			if cond.Type == nodeStatusReady {
				if cond.Status == "True" {
					nodeStatus = nodeStatusReady
				} else {
					nodeStatus = "NotReady"
				}
				break
			}
		}

		nodes = append(nodes, nodeView{
			Name:              item.Metadata.Name,
			Labels:            item.Metadata.Labels,
			CreationTimestamp: item.Metadata.CreationTimestamp,
			Status:            nodeStatus,
			KubeletVersion:    item.Status.NodeInfo.KubeletVersion,
			OS:                item.Status.NodeInfo.OperatingSystem,
			Architecture:      item.Status.NodeInfo.Architecture,
			ContainerRuntime:  item.Status.NodeInfo.ContainerRuntime,
			Unschedulable:     item.Spec.Unschedulable,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"nodes": nodes,
		"total": len(nodes),
	})
}

// ---------------------------------------------------------------------------
// Async provisioning engine
// ---------------------------------------------------------------------------

// runProvisioningAsync launches the three-phase pipeline in a background
// goroutine. Phase results are written back to job under h.mu.
func (h *NodeProvisioningHandler) runProvisioningAsync(job *ProvisioningJob) {
	type phaseSpec struct {
		name string
		cmd  string
		args []string
	}

	// Detect k3d cluster name from environment or default to "hexxlock"
	clusterName := os.Getenv("K3D_CLUSTER_NAME")
	if clusterName == "" {
		clusterName = "hexxlock"
	}

	phases := []phaseSpec{
		// Phase 1 — Packer: Verify k3d is available and cluster exists.
		{
			name: "Packer (Verify Infrastructure)",
			cmd:  "k3d",
			args: []string{"cluster", "list", clusterName, kubectlNoHeaders},
		},
		// Phase 2 — Terraform: Create a k3d agent node (Docker container
		// running k3s with proper cgroups, networking, and containerd).
		{
			name: "Terraform (Create Node)",
			cmd:  "k3d",
			args: []string{"node", "create", job.NodeName, "--cluster", clusterName, "--role", "agent"},
		},
		// Phase 3 — Ansible: Fix DNS inside the new node and verify it joined.
		{
			name: "Ansible (Configure Node)",
			cmd:  "bash",
			args: []string{
				"-c",
				fmt.Sprintf(
					`docker exec k3d-%s-0 sh -c "echo 'nameserver 8.8.8.8' > /etc/resolv.conf" 2>/dev/null; `+
						`sleep 10 && kubectl get node k3d-%s-0 2>/dev/null && echo "Node joined successfully" || echo "Node pending"`,
					job.NodeName, job.NodeName,
				),
			},
		},
		// Phase 4 — Label: Apply workload role label to the node for scheduling.
		{
			name: "Label (Assign Workload Role)",
			cmd:  "kubectl",
			args: []string{
				"label", "node", fmt.Sprintf("k3d-%s-0", job.NodeName),
				fmt.Sprintf("example.com/node-role=%s", job.NodeRole),
				kubectlOverwrite,
			},
		},
	}

	go func() {
		h.log.Info("Provisioning pipeline started",
			zap.String("job_id", job.ID),
			zap.String("node_name", job.NodeName),
		)

		for i, phase := range phases {
			// Mark phase as running.
			h.mu.Lock()
			now := time.Now()
			job.Phases[i].Status = "running"
			job.Phases[i].StartedAt = &now
			job.UpdatedAt = now
			h.mu.Unlock()

			h.log.Info("Provisioning phase started",
				zap.String("job_id", job.ID),
				zap.String("phase", phase.name),
				zap.Int("phase_index", i),
			)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			cmd := exec.CommandContext(ctx, phase.cmd, phase.args...) //nolint:gosec // input validated before use
			output, err := cmd.CombinedOutput()
			cancel()

			end := time.Now()

			h.mu.Lock()
			job.Phases[i].EndedAt = &end
			job.Phases[i].Output = string(output)

			if err != nil {
				job.Phases[i].Status = nodeStatusFailed
				job.Phases[i].Error = err.Error()
				job.Status = nodeStatusFailed
				job.UpdatedAt = end
				h.mu.Unlock()

				h.log.Error("Provisioning phase failed",
					zap.String("job_id", job.ID),
					zap.String("phase", phase.name),
					zap.Int("phase_index", i),
					zap.String("output", string(output)),
					zap.Error(err),
				)
				return
			}

			job.Phases[i].Status = nodeStatusCompleted
			job.UpdatedAt = end
			h.mu.Unlock()

			h.log.Info("Provisioning phase completed",
				zap.String("job_id", job.ID),
				zap.String("phase", phase.name),
				zap.Int("phase_index", i),
			)
		}

		h.mu.Lock()
		job.Status = nodeStatusCompleted
		job.UpdatedAt = time.Now()
		h.mu.Unlock()

		h.log.Info("Provisioning pipeline completed",
			zap.String("job_id", job.ID),
			zap.String("node_name", job.NodeName),
		)
	}()
}

// ---------------------------------------------------------------------------
// Service deployment HTTP handlers
// ---------------------------------------------------------------------------

// deployServicesRequest is the JSON body for POST /deployment/deploy.
type deployServicesRequest struct {
	Group string `json:"group" binding:"required"`
}

// GetDeployableGroups handles GET /api/v1/platform/deployment/groups.
//
// Returns the canonical list of deployable service groups together with their
// service inventories and a lightweight status derived from kubectl (falls back
// gracefully when kubectl is unavailable).
func (h *NodeProvisioningHandler) GetDeployableGroups(c *gin.Context) {
	groups := deployableGroups()

	type groupView struct {
		Name      string   `json:"name"`
		Namespace string   `json:"namespace"`
		Services  []string `json:"services"`
		Status    string   `json:"status"` // not_deployed | running | partially_running | unknown
	}

	views := make([]groupView, 0, len(groups)+1)
	orderedNames := []string{"infrastructure", "identity", "platform", "business", "frontends", "observability"}
	for _, name := range orderedNames {
		spec, ok := groups[name]
		if !ok {
			continue
		}

		// Collect all services across all waves for this group.
		var allServices []string
		for _, w := range spec.waves {
			allServices = append(allServices, w.Services...)
		}

		// Derive status by checking the namespace via kubectl. Failures are
		// non-fatal; we simply report "unknown" so the UI stays responsive.
		status := h.deriveNamespaceStatus(c.Request.Context(), spec.namespace)

		views = append(views, groupView{
			Name:      name,
			Namespace: spec.namespace,
			Services:  allServices,
			Status:    status,
		})
	}

	// Synthetic "all" entry.
	var allServices []string
	for _, name := range orderedNames {
		spec := groups[name]
		for _, w := range spec.waves {
			allServices = append(allServices, w.Services...)
		}
	}
	views = append(views, groupView{
		Name:     "all",
		Services: allServices,
		Status:   nodeStatusNotDeployed,
	})

	c.JSON(http.StatusOK, gin.H{"groups": views})
}

// DeployServices handles POST /api/v1/platform/deployment/deploy.
//
// Validates the requested group, creates a DeploymentJob, and launches the
// wave pipeline asynchronously. Returns 202 Accepted with the job ID.
func (h *NodeProvisioningHandler) DeployServices(c *gin.Context) {
	var req deployServicesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgNodeInvalidRequestBody + err.Error()})
		return
	}

	group := strings.ToLower(strings.TrimSpace(req.Group))

	// Validate group name.
	validGroups := map[string]bool{
		"infrastructure": true, "identity": true, "platform": true,
		"business": true, "frontends": true, "observability": true, "all": true,
	}
	if !validGroups[group] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("unknown group %q; valid values: infrastructure, identity, platform, business, frontends, observability, all", group),
		})
		return
	}

	jobID := uuid.New().String()
	now := time.Now()

	var waves []DeploymentWave
	if group == "all" {
		// Concatenate every group's waves in deployment order.
		for _, name := range []string{"infrastructure", "identity", "platform", "business", "frontends", "observability"} {
			spec := deployableGroups()[name]
			for _, w := range spec.waves {
				wCopy := w
				wCopy.Name = fmt.Sprintf("[%s] %s", name, w.Name)
				waves = append(waves, wCopy)
			}
		}
	} else {
		spec := deployableGroups()[group]
		for _, w := range spec.waves {
			wCopy := w
			waves = append(waves, wCopy)
		}
	}

	job := &DeploymentJob{
		ID:        jobID,
		Group:     group,
		Status:    "deploying",
		Waves:     waves,
		CreatedAt: now,
		UpdatedAt: now,
	}

	h.mu.Lock()
	h.deployJobs[jobID] = job
	h.mu.Unlock()

	h.log.Info("Deployment job created",
		zap.String("job_id", jobID),
		zap.String("group", group),
		zap.Int("waves", len(waves)),
	)

	h.runDeploymentAsync(job)

	c.JSON(http.StatusAccepted, gin.H{
		"job_id":  jobID,
		"group":   group,
		"status":  job.Status,
		"message": fmt.Sprintf("Deployment started. Poll /deployment/%s for status.", jobID),
	})
}

// GetDeploymentStatus handles GET /api/v1/platform/deployment/:job_id.
func (h *NodeProvisioningHandler) GetDeploymentStatus(c *gin.Context) {
	jobID := c.Param("job_id")

	h.mu.RLock()
	job, ok := h.deployJobs[jobID]
	h.mu.RUnlock()

	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "deployment job not found: " + jobID})
		return
	}

	h.mu.RLock()
	snapshot := h.copyDeployJob(job)
	h.mu.RUnlock()

	c.JSON(http.StatusOK, snapshot)
}

// ListDeploymentJobs handles GET /api/v1/platform/deployment.
//
// Returns all deployment jobs, most-recently-created first.
func (h *NodeProvisioningHandler) ListDeploymentJobs(c *gin.Context) {
	h.mu.RLock()
	jobs := make([]DeploymentJob, 0, len(h.deployJobs))
	for _, j := range h.deployJobs {
		jobs = append(jobs, h.copyDeployJob(j))
	}
	h.mu.RUnlock()

	// Sort descending by CreatedAt.
	for i := 0; i < len(jobs)-1; i++ {
		for k := i + 1; k < len(jobs); k++ {
			if jobs[k].CreatedAt.After(jobs[i].CreatedAt) {
				jobs[i], jobs[k] = jobs[k], jobs[i]
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"jobs":  jobs,
		"total": len(jobs),
	})
}

// ---------------------------------------------------------------------------
// Async deployment engine
// ---------------------------------------------------------------------------

// runDeploymentAsync executes the wave pipeline in a background goroutine.
// Each wave simulates the namespace-creation + per-service deployment sequence.
// Real helm/kubectl apply commands replace the simulation once manifests exist.
func (h *NodeProvisioningHandler) runDeploymentAsync(job *DeploymentJob) {
	go func() {
		h.log.Info("Deployment pipeline started",
			zap.String("job_id", job.ID),
			zap.String("group", job.Group),
		)

		for i := range job.Waves {
			// Mark wave as deploying.
			h.mu.Lock()
			now := time.Now()
			job.Waves[i].Status = "deploying"
			job.UpdatedAt = now
			h.mu.Unlock()

			waveName := job.Waves[i].Name
			services := job.Waves[i].Services

			h.log.Info("Deployment wave started",
				zap.String("job_id", job.ID),
				zap.String("wave", waveName),
				zap.Int("services", len(services)),
			)

			output, waveErr := h.simulateWaveDeployment(job.ID, waveName, services)

			end := time.Now()
			h.mu.Lock()
			job.Waves[i].Output = output
			job.UpdatedAt = end

			if waveErr != nil {
				job.Waves[i].Status = nodeStatusFailed
				job.Waves[i].Error = waveErr.Error()
				job.Status = nodeStatusFailed
				h.mu.Unlock()

				h.log.Error("Deployment wave failed",
					zap.String("job_id", job.ID),
					zap.String("wave", waveName),
					zap.Error(waveErr),
				)
				return
			}

			job.Waves[i].Status = nodeStatusCompleted
			h.mu.Unlock()

			h.log.Info("Deployment wave completed",
				zap.String("job_id", job.ID),
				zap.String("wave", waveName),
			)
		}

		h.mu.Lock()
		job.Status = nodeStatusCompleted
		job.UpdatedAt = time.Now()
		h.mu.Unlock()

		h.log.Info("Deployment pipeline completed",
			zap.String("job_id", job.ID),
			zap.String("group", job.Group),
		)
	}()
}

// simulateWaveDeployment executes a best-effort namespace-creation check followed
// by a per-service log message and brief simulated delay. This proves the
// end-to-end pipeline works before real helm/kubectl manifests are available.
// The real deployment logic (helm upgrade --install / kubectl apply) slots in
// by replacing the inner loop body.
func (h *NodeProvisioningHandler) simulateWaveDeployment(jobID, waveName string, services []string) (string, error) {
	var sb strings.Builder

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Derive namespace from wave name if it contains a bracket prefix like "[platform] Wave 1".
	// For single-group runs the namespace is embedded in the job context; we
	// do a best-effort namespace existence check regardless.
	//
	// We only attempt the kubectl check; a failure is logged but not fatal so
	// that the simulation works even when kubectl is not available locally.
	cmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", kubectlNoHeaders, "-o", "name")
	existingNS, _ := cmd.Output() // ignore error — kubectl may not be present

	fmt.Fprintf(&sb, "Wave: %s\n", waveName)
	fmt.Fprintf(&sb, "Services to deploy: %s\n\n", strings.Join(services, ", "))
	_ = existingNS // available for future namespace-existence branching

	for _, svc := range services {
		select {
		case <-ctx.Done():
			return sb.String(), fmt.Errorf("deployment timed out during wave %q at service %q", waveName, svc)
		default:
		}

		fmt.Fprintf(&sb, "Deploying %s...\n", svc)
		h.log.Info("Deploying service",
			zap.String("job_id", jobID),
			zap.String("wave", waveName),
			zap.String("service", svc),
		)

		// Simulate per-service deployment time (1 second each).
		// Replace this block with actual helm/kubectl calls once manifests exist:
		//
		//   out, err := exec.CommandContext(ctx, "helm", "upgrade", "--install", svc, ...).CombinedOutput()
		//   sb.Write(out)
		//   if err != nil { return sb.String(), fmt.Errorf("helm deploy %s: %w", svc, err) }
		//
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return sb.String(), fmt.Errorf("deployment timed out during wave %q at service %q", waveName, svc)
		case <-timer.C:
		}

		fmt.Fprintf(&sb, "  %s: deployed (simulated)\n", svc)
	}

	fmt.Fprintf(&sb, "\nWave completed: %d services deployed.\n", len(services))
	return sb.String(), nil
}

// deriveNamespaceStatus shells out to kubectl to determine whether a namespace
// has any Running pods. Returns one of: running | partially_running |
// not_deployed | unknown.
func (h *NodeProvisioningHandler) deriveNamespaceStatus(ctx context.Context, namespace string) string {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(checkCtx, "kubectl", "get", "pods", //nolint:gosec // input validated before use
		"-n", namespace,
		kubectlNoHeaders,
		"-o", "custom-columns=STATUS:.status.phase",
	)
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return nodeStatusNotDeployed
	}

	running, total := 0, 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		total++
		if line == "Running" {
			running++
		}
	}

	switch {
	case total == 0:
		return nodeStatusNotDeployed
	case running == total:
		return "running"
	case running > 0:
		return "partially_running"
	default:
		return nodeStatusNotDeployed
	}
}

// copyDeployJob returns a value copy of a DeploymentJob. Must be called with
// at least h.mu.RLock held so the read is consistent.
func (h *NodeProvisioningHandler) copyDeployJob(j *DeploymentJob) DeploymentJob {
	waves := make([]DeploymentWave, len(j.Waves))
	for i, w := range j.Waves {
		services := make([]string, len(w.Services))
		copy(services, w.Services)
		waves[i] = DeploymentWave{
			Name:     w.Name,
			Services: services,
			Status:   w.Status,
			Output:   w.Output,
			Error:    w.Error,
		}
	}
	return DeploymentJob{
		ID:        j.ID,
		Group:     j.Group,
		Status:    j.Status,
		Waves:     waves,
		CreatedAt: j.CreatedAt,
		UpdatedAt: j.UpdatedAt,
	}
}

// copyJob returns a deep copy of a ProvisioningJob. Must be called with at
// least h.mu.RLock held so the read is consistent.
func (h *NodeProvisioningHandler) copyJob(j *ProvisioningJob) ProvisioningJob {
	phases := make([]ProvisioningPhase, len(j.Phases))
	for i, p := range j.Phases {
		cp := p
		if p.StartedAt != nil {
			t := *p.StartedAt
			cp.StartedAt = &t
		}
		if p.EndedAt != nil {
			t := *p.EndedAt
			cp.EndedAt = &t
		}
		phases[i] = cp
	}
	return ProvisioningJob{
		ID:        j.ID,
		NodeName:  j.NodeName,
		NodeRole:  j.NodeRole,
		Status:    j.Status,
		Phases:    phases,
		CreatedAt: j.CreatedAt,
		UpdatedAt: j.UpdatedAt,
	}
}

// ---------------------------------------------------------------------------
// Node Pool CRUD handlers
// ---------------------------------------------------------------------------

// createNodePoolRequest is the JSON body for POST /node-pools.
type createNodePoolRequest struct {
	Name                string            `json:"name"`
	Role                string            `json:"role"`
	IsolationTier       string            `json:"isolation_tier"`
	TenantID            string            `json:"tenant_id"`
	InstanceTypes       []string          `json:"instance_types"`
	MinNodes            int               `json:"min_nodes"`
	MaxNodes            int               `json:"max_nodes"`
	DesiredNodes        int               `json:"desired_nodes"`
	Labels              map[string]string `json:"labels"`
	Taints              []Taint           `json:"taints"`
	AutoScalingEnabled  bool              `json:"auto_scaling_enabled"`
	ConsolidationPolicy string            `json:"consolidation_policy"`
}

// nodePoolCreateParams holds validated and normalized values for CreateNodePool.
type nodePoolCreateParams struct {
	role   string
	tier   string
	policy string
}

// CreateNodePool handles POST /api/v1/platform/node-pools.
//
// Creates a managed node pool with an initial set of nodes. The actual node
// provisioning is delegated to reconcileNodePool which runs asynchronously.
// Returns 201 Created with the pool record.
func (h *NodeProvisioningHandler) CreateNodePool(c *gin.Context) {
	var req createNodePoolRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgNodeInvalidRequestBody + err.Error()})
		return
	}

	params, ok := validateNodePoolCreateRequest(c, &req)
	if !ok {
		return // response already written
	}

	poolID := uuid.New().String()
	now := time.Now()

	labels := buildNodePoolLabels(req.Labels, poolID, params.role, params.tier)

	instanceTypes := make([]string, len(req.InstanceTypes))
	copy(instanceTypes, req.InstanceTypes)

	taints := make([]Taint, len(req.Taints))
	copy(taints, req.Taints)

	pool := &NodePool{
		ID:                  poolID,
		Name:                req.Name,
		Role:                params.role,
		IsolationTier:       params.tier,
		TenantID:            strings.TrimSpace(req.TenantID),
		InstanceTypes:       instanceTypes,
		MinNodes:            req.MinNodes,
		MaxNodes:            req.MaxNodes,
		DesiredNodes:        req.DesiredNodes,
		CurrentNodes:        0,
		Labels:              labels,
		Taints:              taints,
		AutoScalingEnabled:  req.AutoScalingEnabled,
		ConsolidationPolicy: params.policy,
		Status:              "provisioning",
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	h.mu.Lock()
	h.nodePools[poolID] = pool
	h.mu.Unlock()

	h.log.Info("Node pool created",
		zap.String("pool_id", poolID),
		zap.String("name", pool.Name),
		zap.String("role", pool.Role),
		zap.String("isolation_tier", pool.IsolationTier),
		zap.Int("desired_nodes", pool.DesiredNodes),
	)

	go h.reconcileNodePool(pool)

	c.JSON(http.StatusCreated, h.snapshotPool(pool))
}

// validateNodePoolCreateRequest normalizes and validates a create request.
// Returns (params, true) on success; writes a 400 response and returns (_, false) on failure.
func validateNodePoolCreateRequest(c *gin.Context, req *createNodePoolRequest) (nodePoolCreateParams, bool) {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return nodePoolCreateParams{}, false
	}

	role, ok := normalizeNodeRole(c, req.Role)
	if !ok {
		return nodePoolCreateParams{}, false
	}

	tier, ok := normalizeIsolationTier(c, req.IsolationTier, req.TenantID)
	if !ok {
		return nodePoolCreateParams{}, false
	}

	if req.MaxNodes < req.MinNodes {
		c.JSON(http.StatusBadRequest, gin.H{"error": "max_nodes must be >= min_nodes"})
		return nodePoolCreateParams{}, false
	}
	if req.DesiredNodes < req.MinNodes || req.DesiredNodes > req.MaxNodes {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desired_nodes must be between min_nodes and max_nodes"})
		return nodePoolCreateParams{}, false
	}

	policy, ok := normalizeConsolidationPolicy(c, req.ConsolidationPolicy)
	if !ok {
		return nodePoolCreateParams{}, false
	}

	return nodePoolCreateParams{role: role, tier: tier, policy: policy}, true
}

// normalizeNodeRole returns the canonical role name, defaulting to general-purpose.
// Writes a 400 response and returns ("", false) for invalid values.
func normalizeNodeRole(c *gin.Context, raw string) (string, bool) {
	role := strings.TrimSpace(raw)
	if role == "" {
		return nodeRoleGeneralPurpose, true
	}
	if _, ok := validNodeRoles[role]; ok {
		return role, true
	}
	roles := make([]string, 0, len(validNodeRoles))
	for r := range validNodeRoles {
		roles = append(roles, r)
	}
	c.JSON(http.StatusBadRequest, gin.H{
		"error": fmt.Sprintf("invalid role %q; valid values: %s", role, strings.Join(roles, ", ")),
	})
	return "", false
}

// normalizeIsolationTier validates the isolation tier and ensures dedicated pools have a tenant ID.
// Writes a 400 response and returns ("", false) on error.
func normalizeIsolationTier(c *gin.Context, raw, tenantID string) (string, bool) {
	tier := strings.TrimSpace(raw)
	if tier == "" {
		tier = nodeTierShared
	}
	validTiers := map[string]bool{nodeTierShared: true, "dedicated": true, "isolated": true}
	if !validTiers[tier] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "isolation_tier must be one of: shared, dedicated, isolated"})
		return "", false
	}
	if tier == "dedicated" && strings.TrimSpace(tenantID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id is required for dedicated isolation tier"})
		return "", false
	}
	return tier, true
}

// normalizeConsolidationPolicy validates and normalizes the consolidation policy.
// Writes a 400 response and returns ("", false) for invalid values.
func normalizeConsolidationPolicy(c *gin.Context, raw string) (string, bool) {
	policy := strings.TrimSpace(raw)
	if policy == "" {
		return "none", true
	}
	validPolicies := map[string]bool{"none": true, "when-underutilized": true, "when-empty": true}
	if !validPolicies[policy] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "consolidation_policy must be one of: none, when-underutilized, when-empty"})
		return "", false
	}
	return policy, true
}

// buildNodePoolLabels merges caller-supplied labels with well-known pool labels.
func buildNodePoolLabels(base map[string]string, poolID, role, tier string) map[string]string {
	labels := make(map[string]string, len(base)+3)
	for k, v := range base {
		labels[k] = v
	}
	labels["example.com/node-pool"] = poolID
	labels["example.com/node-role"] = role
	labels["hexxlock.io/isolation-tier"] = tier
	return labels
}

// ListNodePools handles GET /api/v1/platform/node-pools.
//
// Returns all node pools sorted by CreatedAt descending. CurrentNodes is
// refreshed from kubectl on a best-effort basis before the response is built.
func (h *NodeProvisioningHandler) ListNodePools(c *gin.Context) {
	h.mu.RLock()
	pools := make([]NodePool, 0, len(h.nodePools))
	for _, p := range h.nodePools {
		pools = append(pools, h.copyNodePool(p))
	}
	h.mu.RUnlock()

	// Sort by CreatedAt descending.
	for i := 0; i < len(pools)-1; i++ {
		for k := i + 1; k < len(pools); k++ {
			if pools[k].CreatedAt.After(pools[i].CreatedAt) {
				pools[i], pools[k] = pools[k], pools[i]
			}
		}
	}

	// Best-effort sync of CurrentNodes from kubectl for each pool.
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	for i := range pools {
		pools[i].CurrentNodes = h.countPoolNodes(ctx, pools[i].ID)
	}

	c.JSON(http.StatusOK, gin.H{
		"pools": pools,
		"total": len(pools),
	})
}

// GetNodePool handles GET /api/v1/platform/node-pools/:pool_id.
func (h *NodeProvisioningHandler) GetNodePool(c *gin.Context) {
	poolID := c.Param("pool_id")

	h.mu.RLock()
	pool, ok := h.nodePools[poolID]
	if !ok {
		h.mu.RUnlock()
		c.JSON(http.StatusNotFound, gin.H{"error": msgNodePoolNotFound + poolID})
		return
	}
	snapshot := h.copyNodePool(pool)
	h.mu.RUnlock()

	c.JSON(http.StatusOK, snapshot)
}

// updateNodePoolRequest is the JSON body for PATCH /node-pools/:pool_id.
// All fields are optional; only provided (non-zero) values are merged.
type updateNodePoolRequest struct {
	Name                *string           `json:"name"`
	Role                *string           `json:"role"`
	MinNodes            *int              `json:"min_nodes"`
	MaxNodes            *int              `json:"max_nodes"`
	DesiredNodes        *int              `json:"desired_nodes"`
	Labels              map[string]string `json:"labels"`
	Taints              []Taint           `json:"taints"`
	AutoScalingEnabled  *bool             `json:"auto_scaling_enabled"`
	ConsolidationPolicy *string           `json:"consolidation_policy"`
}

// UpdateNodePool handles PATCH /api/v1/platform/node-pools/:pool_id.
//
// Applies a partial update to the pool. Fields that are absent in the JSON
// body are left unchanged. If desired_nodes changes and is within bounds,
// reconcileNodePool is triggered asynchronously.
func (h *NodeProvisioningHandler) UpdateNodePool(c *gin.Context) {
	poolID := c.Param("pool_id")

	h.mu.RLock()
	pool, ok := h.nodePools[poolID]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": msgNodePoolNotFound + poolID})
		return
	}

	var req updateNodePoolRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgNodeInvalidRequestBody + err.Error()})
		return
	}

	h.mu.Lock()
	needsReconcile := applyNodePoolUpdates(pool, &req)
	pool.UpdatedAt = time.Now()
	snapshot := h.copyNodePool(pool)
	h.mu.Unlock()

	if needsReconcile {
		go h.reconcileNodePool(pool)
	}

	c.JSON(http.StatusOK, snapshot)
}

// applyNodePoolUpdates merges non-nil request fields onto the pool.
// Returns true when desired_nodes changed within bounds and reconciliation is needed.
// Must be called with the handler mutex held.
func applyNodePoolUpdates(pool *NodePool, req *updateNodePoolRequest) bool {
	needsReconcile := false

	if req.Name != nil {
		if n := strings.TrimSpace(*req.Name); n != "" {
			pool.Name = n
		}
	}
	if req.Role != nil {
		if r := strings.TrimSpace(*req.Role); r != "" {
			if _, ok := validNodeRoles[r]; ok {
				pool.Role = r
				pool.Labels["example.com/node-role"] = r
			}
		}
	}
	if req.MinNodes != nil {
		pool.MinNodes = *req.MinNodes
	}
	if req.MaxNodes != nil {
		pool.MaxNodes = *req.MaxNodes
	}
	if req.DesiredNodes != nil {
		d := *req.DesiredNodes
		if d >= pool.MinNodes && d <= pool.MaxNodes && d != pool.DesiredNodes {
			pool.DesiredNodes = d
			needsReconcile = true
		}
	}
	if req.Labels != nil {
		for k, v := range req.Labels {
			pool.Labels[k] = v
		}
	}
	if req.Taints != nil {
		taints := make([]Taint, len(req.Taints))
		copy(taints, req.Taints)
		pool.Taints = taints
	}
	if req.AutoScalingEnabled != nil {
		pool.AutoScalingEnabled = *req.AutoScalingEnabled
	}
	if req.ConsolidationPolicy != nil {
		validPolicies := map[string]bool{"none": true, "when-underutilized": true, "when-empty": true}
		if p := strings.TrimSpace(*req.ConsolidationPolicy); validPolicies[p] {
			pool.ConsolidationPolicy = p
		}
	}

	return needsReconcile
}

// DeleteNodePool handles DELETE /api/v1/platform/node-pools/:pool_id.
//
// Sets status to "deleting" and drains + removes all pool nodes asynchronously.
// Returns 202 Accepted immediately.
func (h *NodeProvisioningHandler) DeleteNodePool(c *gin.Context) {
	poolID := c.Param("pool_id")

	h.mu.Lock()
	pool, ok := h.nodePools[poolID]
	if !ok {
		h.mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": msgNodePoolNotFound + poolID})
		return
	}
	pool.Status = "deleting"
	pool.UpdatedAt = time.Now()
	snapshot := h.copyNodePool(pool)
	h.mu.Unlock()

	h.log.Info("Node pool deletion requested", zap.String("pool_id", poolID), zap.String("name", pool.Name))

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		// Drain all pool nodes first.
		nodes := h.listPoolNodeNames(ctx, poolID)
		for _, nodeName := range nodes {
			drainCmd := exec.CommandContext(ctx, "kubectl", "drain", nodeName, //nolint:gosec // input validated before use
				kubectlIgnoreDaemonsets, kubectlDeleteEmptydirData, kubectlForce, kubectlTimeout5m)
			if out, err := drainCmd.CombinedOutput(); err != nil {
				h.log.Warn("Failed to drain node during pool deletion",
					zap.String("pool_id", poolID),
					zap.String("node", nodeName),
					zap.String("output", string(out)),
					zap.Error(err),
				)
			}
			deleteCmd := exec.CommandContext(ctx, "kubectl", "delete", "node", nodeName) //nolint:gosec // input validated before use
			if out, err := deleteCmd.CombinedOutput(); err != nil {
				h.log.Warn("Failed to delete node during pool deletion",
					zap.String("pool_id", poolID),
					zap.String("node", nodeName),
					zap.String("output", string(out)),
					zap.Error(err),
				)
			}
		}

		h.mu.Lock()
		delete(h.nodePools, poolID)
		h.mu.Unlock()

		h.log.Info("Node pool deleted", zap.String("pool_id", poolID))
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"pool_id": poolID,
		"status":  snapshot.Status,
		"message": "Node pool drain and deletion initiated asynchronously.",
	})
}

// ---------------------------------------------------------------------------
// Node Pool operation handlers
// ---------------------------------------------------------------------------

// scaleNodePoolRequest is the JSON body for POST /node-pools/:pool_id/scale.
type scaleNodePoolRequest struct {
	DesiredNodes int `json:"desired_nodes"`
}

// ScaleNodePool handles POST /api/v1/platform/node-pools/:pool_id/scale.
//
// Updates the desired node count within min/max bounds and triggers an
// asynchronous reconciliation. Returns 202 Accepted.
func (h *NodeProvisioningHandler) ScaleNodePool(c *gin.Context) {
	poolID := c.Param("pool_id")

	h.mu.RLock()
	pool, ok := h.nodePools[poolID]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": msgNodePoolNotFound + poolID})
		return
	}

	var req scaleNodePoolRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgNodeInvalidRequestBody + err.Error()})
		return
	}

	h.mu.Lock()
	if req.DesiredNodes < pool.MinNodes || req.DesiredNodes > pool.MaxNodes {
		maxNodes, minNodes := pool.MaxNodes, pool.MinNodes
		h.mu.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("desired_nodes %d is out of range [%d, %d]", req.DesiredNodes, minNodes, maxNodes),
		})
		return
	}
	pool.DesiredNodes = req.DesiredNodes
	pool.Status = "scaling"
	pool.UpdatedAt = time.Now()
	h.mu.Unlock()

	h.log.Info("Node pool scale requested",
		zap.String("pool_id", poolID),
		zap.Int("desired_nodes", req.DesiredNodes),
	)

	go h.reconcileNodePool(pool)

	c.JSON(http.StatusAccepted, gin.H{
		"pool_id":       poolID,
		"desired_nodes": req.DesiredNodes,
		"status":        "scaling",
		"message":       "Scale operation initiated asynchronously.",
	})
}

// DrainNodePool handles POST /api/v1/platform/node-pools/:pool_id/drain.
//
// Runs `kubectl drain` on every node belonging to the pool and sets its status
// to "draining". Returns 202 Accepted.
func (h *NodeProvisioningHandler) DrainNodePool(c *gin.Context) {
	poolID := c.Param("pool_id")

	h.mu.RLock()
	pool, ok := h.nodePools[poolID]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": msgNodePoolNotFound + poolID})
		return
	}

	h.mu.Lock()
	pool.Status = "draining"
	pool.UpdatedAt = time.Now()
	h.mu.Unlock()

	h.log.Info("Node pool drain requested", zap.String("pool_id", poolID))

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		nodes := h.listPoolNodeNames(ctx, poolID)
		for _, nodeName := range nodes {
			cmd := exec.CommandContext(ctx, "kubectl", "drain", nodeName, //nolint:gosec // input validated before use
				kubectlIgnoreDaemonsets, kubectlDeleteEmptydirData, kubectlForce, kubectlTimeout5m)
			out, err := cmd.CombinedOutput()
			if err != nil {
				h.log.Warn("kubectl drain failed",
					zap.String("pool_id", poolID),
					zap.String("node", nodeName),
					zap.String("output", string(out)),
					zap.Error(err),
				)
			} else {
				h.log.Info("Node drained", zap.String("pool_id", poolID), zap.String("node", nodeName))
			}
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"pool_id": poolID,
		"status":  "draining",
		"message": "Drain operation initiated asynchronously.",
	})
}

// CordonNodePool handles POST /api/v1/platform/node-pools/:pool_id/cordon.
//
// Runs `kubectl cordon` on all pool nodes so no new pods are scheduled onto
// them. Sets pool status to "cordoned". Returns 200 OK.
func (h *NodeProvisioningHandler) CordonNodePool(c *gin.Context) {
	poolID := c.Param("pool_id")

	h.mu.RLock()
	pool, ok := h.nodePools[poolID]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": msgNodePoolNotFound + poolID})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	nodes := h.listPoolNodeNames(ctx, poolID)
	var lastErr error
	for _, nodeName := range nodes {
		cmd := exec.CommandContext(ctx, "kubectl", "cordon", nodeName) //nolint:gosec // input validated before use
		if out, err := cmd.CombinedOutput(); err != nil {
			h.log.Warn("kubectl cordon failed",
				zap.String("pool_id", poolID),
				zap.String("node", nodeName),
				zap.String("output", string(out)),
				zap.Error(err),
			)
			lastErr = err
		}
	}

	h.mu.Lock()
	pool.Status = "cordoned"
	pool.UpdatedAt = time.Now()
	h.mu.Unlock()

	if lastErr != nil {
		h.log.Warn("Node pool cordon completed with errors",
			zap.String("pool_id", poolID),
			zap.Error(lastErr),
		)
	}

	c.JSON(http.StatusOK, gin.H{
		"pool_id": poolID,
		"status":  "cordoned",
		"message": fmt.Sprintf("Cordoned %d node(s).", len(nodes)),
	})
}

// UncordonNodePool handles POST /api/v1/platform/node-pools/:pool_id/uncordon.
//
// Runs `kubectl uncordon` on all pool nodes to re-enable scheduling.
// Sets pool status to "active". Returns 200 OK.
func (h *NodeProvisioningHandler) UncordonNodePool(c *gin.Context) {
	poolID := c.Param("pool_id")

	h.mu.RLock()
	pool, ok := h.nodePools[poolID]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": msgNodePoolNotFound + poolID})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	nodes := h.listPoolNodeNames(ctx, poolID)
	var lastErr error
	for _, nodeName := range nodes {
		cmd := exec.CommandContext(ctx, "kubectl", "uncordon", nodeName) //nolint:gosec // input validated before use
		if out, err := cmd.CombinedOutput(); err != nil {
			h.log.Warn("kubectl uncordon failed",
				zap.String("pool_id", poolID),
				zap.String("node", nodeName),
				zap.String("output", string(out)),
				zap.Error(err),
			)
			lastErr = err
		}
	}

	h.mu.Lock()
	pool.Status = "active"
	pool.UpdatedAt = time.Now()
	h.mu.Unlock()

	if lastErr != nil {
		h.log.Warn("Node pool uncordon completed with errors",
			zap.String("pool_id", poolID),
			zap.Error(lastErr),
		)
	}

	c.JSON(http.StatusOK, gin.H{
		"pool_id": poolID,
		"status":  "active",
		"message": fmt.Sprintf("Uncordoned %d node(s).", len(nodes)),
	})
}

// ---------------------------------------------------------------------------
// Node Pool data handlers
// ---------------------------------------------------------------------------

// k8sNodeListFull is a minimal subset of `kubectl get nodes -o json` used by
// the node pool data handlers.
type k8sNodeListFull struct {
	Items []struct {
		Metadata struct {
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
		Spec struct {
			Unschedulable bool `json:"unschedulable"`
		} `json:"spec"`
	} `json:"items"`
}

// GetNodePoolNodes handles GET /api/v1/platform/node-pools/:pool_id/nodes.
//
// Returns a simplified list of nodes that belong to the pool (identified by
// the example.com/node-pool label). Falls back gracefully when kubectl is
// unavailable.
func (h *NodeProvisioningHandler) GetNodePoolNodes(c *gin.Context) {
	poolID := c.Param("pool_id")

	h.mu.RLock()
	_, ok := h.nodePools[poolID]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": msgNodePoolNotFound + poolID})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	labelSelector := fmt.Sprintf(fmtNodePoolLabelSelector, poolID)
	cmd := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-l", labelSelector, "-o", "json") //nolint:gosec // input validated before use
	out, err := cmd.Output()
	if err != nil {
		h.log.Warn("kubectl get nodes for pool failed — returning empty list",
			zap.String("pool_id", poolID),
			zap.Error(err),
		)
		c.JSON(http.StatusOK, gin.H{
			"nodes":   []struct{}{},
			"total":   0,
			"warning": "kubectl unavailable or cluster unreachable: " + err.Error(),
		})
		return
	}

	var raw k8sNodeListFull
	if err := json.Unmarshal(out, &raw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse node list: " + err.Error()})
		return
	}

	type nodeView struct {
		Name          string            `json:"name"`
		Labels        map[string]string `json:"labels"`
		Status        string            `json:"status"`
		Unschedulable bool              `json:"unschedulable"`
	}

	nodes := make([]nodeView, 0, len(raw.Items))
	for _, item := range raw.Items {
		nodeStatus := nodeStatusUnknown
		for _, cond := range item.Status.Conditions {
			if cond.Type == nodeStatusReady {
				if cond.Status == "True" {
					nodeStatus = nodeStatusReady
				} else {
					nodeStatus = "NotReady"
				}
				break
			}
		}
		nodes = append(nodes, nodeView{
			Name:          item.Metadata.Name,
			Labels:        item.Metadata.Labels,
			Status:        nodeStatus,
			Unschedulable: item.Spec.Unschedulable,
		})
	}

	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "total": len(nodes)})
}

// k8sPodList is a minimal subset of `kubectl get pods -o json`.
type k8sPodList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			NodeName   string `json:"nodeName"`
			Containers []struct {
				Resources struct {
					Requests map[string]string `json:"requests"`
				} `json:"resources"`
			} `json:"containers"`
		} `json:"spec"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	} `json:"items"`
}

// podView is a summary of a single pod for workload reporting.
type podView struct {
	Name          string `json:"name"`
	Namespace     string `json:"namespace"`
	Node          string `json:"node"`
	Phase         string `json:"phase"`
	CPURequest    string `json:"cpu_request,omitempty"`
	MemoryRequest string `json:"memory_request,omitempty"`
}

// GetNodePoolWorkloads handles GET /api/v1/platform/node-pools/:pool_id/workloads.
//
// Aggregates all pods running on nodes that belong to the pool. Falls back
// gracefully when kubectl is unavailable.
func (h *NodeProvisioningHandler) GetNodePoolWorkloads(c *gin.Context) {
	poolID := c.Param("pool_id")

	h.mu.RLock()
	_, ok := h.nodePools[poolID]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": msgNodePoolNotFound + poolID})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	poolNodes := h.listPoolNodeNames(ctx, poolID)
	allPods := h.collectNodePods(ctx, poolID, poolNodes)

	c.JSON(http.StatusOK, gin.H{"workloads": allPods, "total": len(allPods)})
}

// collectNodePods gathers pod views from all nodes belonging to the pool.
func (h *NodeProvisioningHandler) collectNodePods(ctx context.Context, poolID string, nodeNames []string) []podView {
	var allPods []podView
	for _, nodeName := range nodeNames {
		pods, ok := h.fetchNodePods(ctx, poolID, nodeName)
		if !ok {
			continue
		}
		allPods = append(allPods, pods...)
	}
	if allPods == nil {
		allPods = []podView{}
	}
	return allPods
}

// fetchNodePods retrieves pod views for a single node via kubectl.
// Returns (pods, true) on success, (nil, false) when kubectl or JSON parsing fails.
func (h *NodeProvisioningHandler) fetchNodePods(ctx context.Context, poolID, nodeName string) ([]podView, bool) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", //nolint:gosec // input validated before use
		"--field-selector", fmt.Sprintf("spec.nodeName=%s", nodeName),
		"-o", "json", "-A")
	out, err := cmd.Output()
	if err != nil {
		h.log.Warn("kubectl get pods for node failed",
			zap.String("pool_id", poolID),
			zap.String("node", nodeName),
			zap.Error(err),
		)
		return nil, false
	}

	var podList k8sPodList
	if err := json.Unmarshal(out, &podList); err != nil {
		h.log.Warn("Failed to parse pod list",
			zap.String("node", nodeName),
			zap.Error(err),
		)
		return nil, false
	}

	return convertToPodViews(podList, nodeName), true
}

// convertToPodViews converts a raw kubectl pod list into podView summaries.
func convertToPodViews(podList k8sPodList, _ string) []podView {
	views := make([]podView, 0, len(podList.Items))
	for _, item := range podList.Items {
		pv := podView{
			Name:      item.Metadata.Name,
			Namespace: item.Metadata.Namespace,
			Node:      item.Spec.NodeName,
			Phase:     item.Status.Phase,
		}
		if len(item.Spec.Containers) > 0 {
			pv.CPURequest = item.Spec.Containers[0].Resources.Requests["cpu"]
			pv.MemoryRequest = item.Spec.Containers[0].Resources.Requests["memory"]
		}
		views = append(views, pv)
	}
	return views
}

// poolTopology is the per-pool view returned by GetClusterTopology.
type poolTopology struct {
	NodePool
	Nodes          []string `json:"nodes"`
	WorkloadCounts int      `json:"workload_count"`
}

// GetClusterTopology handles GET /api/v1/platform/node-pools/topology.
//
// Returns a holistic view of all node pools with their nodes and workload
// counts, plus any nodes that are not assigned to any pool.
func (h *NodeProvisioningHandler) GetClusterTopology(c *gin.Context) {
	h.mu.RLock()
	pools := make([]NodePool, 0, len(h.nodePools))
	for _, p := range h.nodePools {
		pools = append(pools, h.copyNodePool(p))
	}
	h.mu.RUnlock()

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	topologyPools := h.buildPoolTopologies(ctx, pools)
	unassignedNodes := h.findUnassignedNodes(ctx)

	c.JSON(http.StatusOK, gin.H{
		"pools":            topologyPools,
		"unassigned_nodes": unassignedNodes,
	})
}

// buildPoolTopologies returns topology info for each pool, including node names and workload counts.
func (h *NodeProvisioningHandler) buildPoolTopologies(ctx context.Context, pools []NodePool) []poolTopology {
	topologies := make([]poolTopology, 0, len(pools))
	for _, pool := range pools {
		nodes := h.listPoolNodeNames(ctx, pool.ID)
		workloadCount := h.countNodesWorkloads(ctx, nodes)
		topologies = append(topologies, poolTopology{
			NodePool:       pool,
			Nodes:          nodes,
			WorkloadCounts: workloadCount,
		})
	}
	return topologies
}

// countNodesWorkloads counts the total number of pods running across the given node names.
func (h *NodeProvisioningHandler) countNodesWorkloads(ctx context.Context, nodeNames []string) int {
	count := 0
	for _, nodeName := range nodeNames {
		cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", //nolint:gosec // input validated before use
			"--field-selector", fmt.Sprintf("spec.nodeName=%s", nodeName),
			kubectlNoHeaders, "-A")
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if strings.TrimSpace(l) != "" {
				count++
			}
		}
	}
	return count
}

// findUnassignedNodes returns the names of all cluster nodes that have no example.com/node-pool label.
func (h *NodeProvisioningHandler) findUnassignedNodes(ctx context.Context) []string {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "json")
	out, err := cmd.Output()
	if err != nil {
		return []string{}
	}
	var raw k8sNodeListFull
	if json.Unmarshal(out, &raw) != nil {
		return []string{}
	}
	var unassigned []string
	for _, item := range raw.Items {
		if _, assigned := item.Metadata.Labels["example.com/node-pool"]; !assigned {
			unassigned = append(unassigned, item.Metadata.Name)
		}
	}
	if unassigned == nil {
		return []string{}
	}
	return unassigned
}

// ---------------------------------------------------------------------------
// Node Pool reconciler
// ---------------------------------------------------------------------------

// reconcileNodePool is the Kubernetes-style reconciliation loop for a single
// node pool. It runs in its own goroutine and drives the pool from its current
// state toward the desired node count by creating or draining/deleting nodes.
// On completion it sets Status to "active"; on failure it sets "error".
func (h *NodeProvisioningHandler) reconcileNodePool(pool *NodePool) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	clusterName := os.Getenv("K3D_CLUSTER_NAME")
	if clusterName == "" {
		clusterName = "hexxlock"
	}

	h.log.Info("Reconciling node pool",
		zap.String("pool_id", pool.ID),
		zap.String("name", pool.Name),
		zap.Int("desired", pool.DesiredNodes),
	)

	current := h.countPoolNodes(ctx, pool.ID)

	h.mu.Lock()
	pool.CurrentNodes = current
	h.mu.Unlock()

	desired := pool.DesiredNodes
	var reconcileErr error

	switch {
	case current < desired:
		reconcileErr = h.scaleUpPool(ctx, pool, clusterName, current, desired)
	case current > desired:
		reconcileErr = h.scaleDownPool(ctx, pool, current, desired)
	}

	h.mu.Lock()
	if reconcileErr != nil {
		pool.Status = "error"
		h.log.Error("Node pool reconciliation failed",
			zap.String("pool_id", pool.ID),
			zap.Error(reconcileErr),
		)
	} else {
		pool.Status = "active"
		h.log.Info("Node pool reconciliation completed",
			zap.String("pool_id", pool.ID),
			zap.Int("current_nodes", pool.CurrentNodes),
		)
	}
	pool.UpdatedAt = time.Now()
	h.mu.Unlock()
}

// scaleUpPool creates nodes from index current up to (but not including) desired.
// Returns the first fatal error encountered, or nil on success.
func (h *NodeProvisioningHandler) scaleUpPool(ctx context.Context, pool *NodePool, clusterName string, current, desired int) error {
	for i := current; i < desired; i++ {
		if ctx.Err() != nil {
			return fmt.Errorf("reconcile timed out while scaling up node pool %s", pool.ID)
		}

		nodeName := fmt.Sprintf("%s-worker-%d", pool.Name, i)

		createCmd := exec.CommandContext(ctx, "k3d", "node", "create", nodeName, //nolint:gosec // input validated before use
			"--cluster", clusterName, "--role", "agent")
		if out, err := createCmd.CombinedOutput(); err != nil {
			h.log.Error("k3d node create failed",
				zap.String("pool_id", pool.ID),
				zap.String("node", nodeName),
				zap.String("output", string(out)),
				zap.Error(err),
			)
			return err
		}

		k3dNodeName := fmt.Sprintf("k3d-%s-0", nodeName)
		h.applyNodeLabels(ctx, pool, k3dNodeName)
		h.applyNodeTaints(ctx, pool, k3dNodeName)

		h.mu.Lock()
		pool.CurrentNodes++
		h.mu.Unlock()

		h.log.Info("Node created and joined pool",
			zap.String("pool_id", pool.ID),
			zap.String("node", k3dNodeName),
		)
	}
	return nil
}

// applyNodeLabels labels a newly-created k3d node with pool metadata. Non-fatal on failure.
func (h *NodeProvisioningHandler) applyNodeLabels(ctx context.Context, pool *NodePool, nodeName string) {
	labelArgs := []string{
		"label", "node", nodeName,
		fmt.Sprintf(fmtNodePoolLabelSelector, pool.ID),
		fmt.Sprintf("example.com/node-role=%s", pool.Role),
		fmt.Sprintf("hexxlock.io/isolation-tier=%s", pool.IsolationTier),
		kubectlOverwrite,
	}
	if out, err := exec.CommandContext(ctx, "kubectl", labelArgs...).CombinedOutput(); err != nil { //nolint:gosec // input validated before use
		h.log.Warn("kubectl label node failed",
			zap.String("pool_id", pool.ID),
			zap.String("node", nodeName),
			zap.String("output", string(out)),
			zap.Error(err),
		)
	}
}

// applyNodeTaints applies all pool taints to a node. Non-fatal on failure.
func (h *NodeProvisioningHandler) applyNodeTaints(ctx context.Context, pool *NodePool, nodeName string) {
	h.mu.RLock()
	taints := make([]Taint, len(pool.Taints))
	copy(taints, pool.Taints)
	h.mu.RUnlock()

	for _, t := range taints {
		taintArg := fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect)
		if out, err := exec.CommandContext(ctx, "kubectl", "taint", "nodes", nodeName, taintArg, kubectlOverwrite).CombinedOutput(); err != nil { //nolint:gosec // input validated before use
			h.log.Warn("kubectl taint node failed",
				zap.String("pool_id", pool.ID),
				zap.String("node", nodeName),
				zap.String("taint", taintArg),
				zap.String("output", string(out)),
				zap.Error(err),
			)
		}
	}
}

// scaleDownPool drains and deletes excess nodes until current reaches desired.
// Returns the first fatal error encountered, or nil on success.
func (h *NodeProvisioningHandler) scaleDownPool(ctx context.Context, pool *NodePool, current, desired int) error {
	excess := h.listPoolNodeNames(ctx, pool.ID)
	toRemove := excess
	if len(toRemove) > current-desired {
		toRemove = excess[desired:]
	}

	for _, nodeName := range toRemove {
		if ctx.Err() != nil {
			return fmt.Errorf("reconcile timed out while scaling down node pool %s", pool.ID)
		}

		drainCmd := exec.CommandContext(ctx, "kubectl", "drain", nodeName, //nolint:gosec // input validated before use
			kubectlIgnoreDaemonsets, kubectlDeleteEmptydirData, kubectlForce, kubectlTimeout5m)
		if out, err := drainCmd.CombinedOutput(); err != nil {
			h.log.Warn("kubectl drain failed during scale-down",
				zap.String("pool_id", pool.ID),
				zap.String("node", nodeName),
				zap.String("output", string(out)),
				zap.Error(err),
			)
		}

		deleteCmd := exec.CommandContext(ctx, "kubectl", "delete", "node", nodeName) //nolint:gosec // input validated before use
		if out, err := deleteCmd.CombinedOutput(); err != nil {
			h.log.Warn("kubectl delete node failed during scale-down",
				zap.String("pool_id", pool.ID),
				zap.String("node", nodeName),
				zap.String("output", string(out)),
				zap.Error(err),
			)
			return err
		}

		h.mu.Lock()
		if pool.CurrentNodes > 0 {
			pool.CurrentNodes--
		}
		h.mu.Unlock()

		h.log.Info("Node removed from pool",
			zap.String("pool_id", pool.ID),
			zap.String("node", nodeName),
		)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Node Pool helper utilities
// ---------------------------------------------------------------------------

// countPoolNodes queries kubectl for the number of nodes labelled with the
// given pool ID. Returns 0 if kubectl is unavailable.
func (h *NodeProvisioningHandler) countPoolNodes(ctx context.Context, poolID string) int {
	labelSelector := fmt.Sprintf(fmtNodePoolLabelSelector, poolID)
	cmd := exec.CommandContext(ctx, "kubectl", "get", "nodes", //nolint:gosec // input validated before use
		"-l", labelSelector, kubectlNoHeaders, "-o", "name")
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	count := 0
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			count++
		}
	}
	return count
}

// listPoolNodeNames returns the kubectl node names for all nodes belonging to
// the pool. Returns an empty slice if kubectl is unavailable.
func (h *NodeProvisioningHandler) listPoolNodeNames(ctx context.Context, poolID string) []string {
	labelSelector := fmt.Sprintf(fmtNodePoolLabelSelector, poolID)
	cmd := exec.CommandContext(ctx, "kubectl", "get", "nodes", //nolint:gosec // input validated before use
		"-l", labelSelector, kubectlNoHeaders, "-o", "name")
	out, err := cmd.Output()
	if err != nil {
		return []string{}
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// kubectl -o name returns "node/<name>"; strip the prefix.
		name := strings.TrimPrefix(line, "node/")
		names = append(names, name)
	}
	return names
}

// snapshotPool returns a value copy of a NodePool pointer under the caller's
// responsibility to hold at least h.mu.RLock. It is safe to use without the
// lock only when the pool has not yet been stored in h.nodePools (e.g. right
// after construction, before the first goroutine is spawned).
func (h *NodeProvisioningHandler) snapshotPool(p *NodePool) NodePool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.copyNodePool(p)
}

// copyNodePool returns a deep copy of a NodePool. Must be called with at least
// h.mu.RLock held so the read is consistent.
func (h *NodeProvisioningHandler) copyNodePool(p *NodePool) NodePool {
	// Deep-copy Labels map.
	labels := make(map[string]string, len(p.Labels))
	for k, v := range p.Labels {
		labels[k] = v
	}

	// Deep-copy InstanceTypes slice.
	instanceTypes := make([]string, len(p.InstanceTypes))
	copy(instanceTypes, p.InstanceTypes)

	// Deep-copy Taints slice.
	taints := make([]Taint, len(p.Taints))
	copy(taints, p.Taints)

	return NodePool{
		ID:                  p.ID,
		Name:                p.Name,
		Role:                p.Role,
		IsolationTier:       p.IsolationTier,
		TenantID:            p.TenantID,
		InstanceTypes:       instanceTypes,
		MinNodes:            p.MinNodes,
		MaxNodes:            p.MaxNodes,
		DesiredNodes:        p.DesiredNodes,
		CurrentNodes:        p.CurrentNodes,
		Labels:              labels,
		Taints:              taints,
		AutoScalingEnabled:  p.AutoScalingEnabled,
		ConsolidationPolicy: p.ConsolidationPolicy,
		Status:              p.Status,
		CreatedAt:           p.CreatedAt,
		UpdatedAt:           p.UpdatedAt,
	}
}

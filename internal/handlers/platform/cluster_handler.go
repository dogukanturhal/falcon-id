// SPDX-License-Identifier: AGPL-3.0-or-later

// Package platform provides platform-level HTTP handlers.
package platform

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	msgClusterServerNotFound = "Server not found"
)

// ClusterHandler handles database cluster management API
type ClusterHandler struct {
	db *sql.DB
}

// NewClusterHandler creates a new cluster handler
func NewClusterHandler(db *sql.DB) *ClusterHandler {
	return &ClusterHandler{db: db}
}

// DatabaseServerResponse is an exported identifier.
type DatabaseServerResponse struct {
	ID                 uuid.UUID  `json:"id"`
	Name               string     `json:"name"`
	Host               string     `json:"host"`
	Port               int        `json:"port"`
	ClusterID          *uuid.UUID `json:"cluster_id,omitempty"`
	ClusterName        string     `json:"cluster_name,omitempty"`
	Role               string     `json:"role"`
	Region             string     `json:"region"`
	AvailabilityZone   string     `json:"availability_zone,omitempty"`
	Site               string     `json:"site,omitempty"`
	Status             string     `json:"status"`
	HealthStatus       string     `json:"health_status"`
	AcceptsWrites      bool       `json:"accepts_writes"`
	AcceptsReads       bool       `json:"accepts_reads"`
	ReplicationLagMs   int        `json:"replication_lag_ms"`
	CurrentConnections int        `json:"current_connections"`
	MaxConnections     int        `json:"max_connections"`
	CurrentTenants     int        `json:"current_tenants"`
	MaxTenants         int        `json:"max_tenants"`
	UsedStorageGB      int        `json:"used_storage_gb"`
	MaxStorageGB       int        `json:"max_storage_gb"`
	LastHealthCheck    *time.Time `json:"last_health_check,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
}

// DatabaseClusterResponse is an exported type.
type DatabaseClusterResponse struct {
	ID                    uuid.UUID                `json:"id"`
	Name                  string                   `json:"name"`
	Description           string                   `json:"description,omitempty"`
	ClusterType           string                   `json:"cluster_type"`
	ShardCount            int                      `json:"shard_count"`
	ShardAlgorithm        string                   `json:"shard_algorithm,omitempty"`
	AutoFailover          bool                     `json:"auto_failover"`
	ReadWriteSplitEnabled bool                     `json:"read_write_split_enabled"`
	Status                string                   `json:"status"`
	PrimaryServerID       *uuid.UUID               `json:"primary_server_id,omitempty"`
	PrimaryServerName     string                   `json:"primary_server_name,omitempty"`
	TotalServers          int                      `json:"total_servers"`
	HealthyServers        int                      `json:"healthy_servers"`
	TotalTenants          int                      `json:"total_tenants"`
	Servers               []DatabaseServerResponse `json:"servers,omitempty"`
	CreatedAt             time.Time                `json:"created_at"`
}

// CreateServerRequest is an exported type.
type CreateServerRequest struct {
	Name             string                 `json:"name" binding:"required"`
	Host             string                 `json:"host" binding:"required"`
	Port             int                    `json:"port" binding:"required"`
	ClusterID        *uuid.UUID             `json:"cluster_id"`
	Role             string                 `json:"role" binding:"required,oneof=primary replica standalone"`
	PrimaryServerID  *uuid.UUID             `json:"primary_server_id"`
	Region           string                 `json:"region"`
	AvailabilityZone string                 `json:"availability_zone"`
	Site             string                 `json:"site"`
	MaxConnections   int                    `json:"max_connections"`
	MaxTenants       int                    `json:"max_tenants"`
	MaxStorageGB     int                    `json:"max_storage_gb"`
	SSLMode          string                 `json:"ssl_mode"`
	Tags             map[string]interface{} `json:"tags"`
}

// CreateClusterRequest is an exported type.
type CreateClusterRequest struct {
	Name                  string `json:"name" binding:"required"`
	Description           string `json:"description"`
	ClusterType           string `json:"cluster_type" binding:"required,oneof=replication sharded federated"`
	ShardCount            int    `json:"shard_count"`
	ShardAlgorithm        string `json:"shard_algorithm"`
	AutoFailover          bool   `json:"auto_failover"`
	ReadWriteSplitEnabled bool   `json:"read_write_split_enabled"`
}

// AssignTenantRequest is an exported type.
type AssignTenantRequest struct {
	TenantID  uuid.UUID  `json:"tenant_id" binding:"required"`
	ClusterID *uuid.UUID `json:"cluster_id"`
	ServerID  *uuid.UUID `json:"server_id"`
	Reason    string     `json:"reason"`
}

// PromoteServerRequest is an exported type.
type PromoteServerRequest struct {
	ServerID     uuid.UUID `json:"server_id" binding:"required"`
	Reason       string    `json:"reason" binding:"required"`
	Confirmation string    `json:"confirmation" binding:"required"` // Must be "PROMOTE"
}

// TenantAssignmentResponse is an exported type.
type TenantAssignmentResponse struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	TenantName  string    `json:"tenant_name"`
	TenantSlug  string    `json:"tenant_slug"`
	ClusterID   uuid.UUID `json:"cluster_id"`
	ClusterName string    `json:"cluster_name"`
	ServerID    uuid.UUID `json:"server_id"`
	ServerName  string    `json:"server_name"`
	ServerHost  string    `json:"server_host"`
	ShardIndex  int       `json:"shard_index"`
	Plan        string    `json:"plan"`
	AssignedAt  time.Time `json:"assigned_at"`
}

// ClusterStatsResponse is an exported type.
type ClusterStatsResponse struct {
	TotalClusters     int            `json:"total_clusters"`
	TotalServers      int            `json:"total_servers"`
	HealthyServers    int            `json:"healthy_servers"`
	TotalTenants      int            `json:"total_tenants"`
	TotalConnections  int            `json:"total_connections"`
	AvgReplicationLag float64        `json:"avg_replication_lag_ms"`
	StorageUsedGB     int            `json:"storage_used_gb"`
	StorageTotalGB    int            `json:"storage_total_gb"`
	ServersByRole     map[string]int `json:"servers_by_role"`
	ServersByStatus   map[string]int `json:"servers_by_status"`
	TenantsByCluster  map[string]int `json:"tenants_by_cluster"`
}

// ===========================================
// HANDLERS
// ===========================================

// ListClusters returns all database clusters
// GET /api/v1/platform/clusters
func (h *ClusterHandler) ListClusters(c *gin.Context) {
	rows, err := h.db.QueryContext(c.Request.Context(), `
		SELECT
			dc.id, dc.name, dc.description, dc.cluster_type,
			dc.shard_count, dc.shard_algorithm, dc.auto_failover,
			dc.read_write_split_enabled, dc.status, dc.primary_server_id,
			dc.created_at,
			ds.name as primary_name,
			(SELECT COUNT(*) FROM database_servers WHERE cluster_id = dc.id) as total_servers,
			(SELECT COUNT(*) FROM database_servers WHERE cluster_id = dc.id AND health_status = 'healthy') as healthy_servers,
			(SELECT COUNT(*) FROM tenant_shard_assignments WHERE cluster_id = dc.id) as total_tenants
		FROM database_clusters dc
		LEFT JOIN database_servers ds ON ds.id = dc.primary_server_id
		ORDER BY dc.name
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch clusters"})
		return
	}
	defer rows.Close() //nolint:errcheck

	var clusters []DatabaseClusterResponse
	for rows.Next() {
		var cluster DatabaseClusterResponse
		var desc, algo, primaryName sql.NullString
		var primaryID sql.NullString

		err := rows.Scan(
			&cluster.ID, &cluster.Name, &desc, &cluster.ClusterType,
			&cluster.ShardCount, &algo, &cluster.AutoFailover,
			&cluster.ReadWriteSplitEnabled, &cluster.Status, &primaryID,
			&cluster.CreatedAt, &primaryName,
			&cluster.TotalServers, &cluster.HealthyServers, &cluster.TotalTenants,
		)
		if err != nil {
			continue
		}

		if desc.Valid {
			cluster.Description = desc.String
		}
		if algo.Valid {
			cluster.ShardAlgorithm = algo.String
		}
		if primaryID.Valid {
			id, _ := uuid.Parse(primaryID.String)
			cluster.PrimaryServerID = &id
		}
		if primaryName.Valid {
			cluster.PrimaryServerName = primaryName.String
		}

		clusters = append(clusters, cluster)
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch clusters"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"clusters": clusters})
}

// GetCluster returns a specific cluster with its servers
// GET /api/v1/platform/clusters/:id
func (h *ClusterHandler) GetCluster(c *gin.Context) {
	clusterID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster ID"})
		return
	}

	cluster, err := h.queryClusterRow(c, clusterID)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch cluster"})
		return
	}

	cluster.Servers = h.queryClusterServers(c, clusterID)
	c.JSON(http.StatusOK, cluster)
}

// queryClusterRow fetches a single cluster row from the database.
func (h *ClusterHandler) queryClusterRow(c *gin.Context, clusterID uuid.UUID) (DatabaseClusterResponse, error) {
	var cluster DatabaseClusterResponse
	var desc, algo, primaryName, primaryID sql.NullString

	err := h.db.QueryRowContext(c.Request.Context(), `
		SELECT
			dc.id, dc.name, dc.description, dc.cluster_type,
			dc.shard_count, dc.shard_algorithm, dc.auto_failover,
			dc.read_write_split_enabled, dc.status, dc.primary_server_id,
			dc.created_at,
			ds.name as primary_name,
			(SELECT COUNT(*) FROM database_servers WHERE cluster_id = dc.id) as total_servers,
			(SELECT COUNT(*) FROM database_servers WHERE cluster_id = dc.id AND health_status = 'healthy') as healthy_servers,
			(SELECT COUNT(*) FROM tenant_shard_assignments WHERE cluster_id = dc.id) as total_tenants
		FROM database_clusters dc
		LEFT JOIN database_servers ds ON ds.id = dc.primary_server_id
		WHERE dc.id = $1
	`, clusterID).Scan(
		&cluster.ID, &cluster.Name, &desc, &cluster.ClusterType,
		&cluster.ShardCount, &algo, &cluster.AutoFailover,
		&cluster.ReadWriteSplitEnabled, &cluster.Status, &primaryID,
		&cluster.CreatedAt, &primaryName,
		&cluster.TotalServers, &cluster.HealthyServers, &cluster.TotalTenants,
	)
	if err != nil {
		return cluster, err
	}

	if desc.Valid {
		cluster.Description = desc.String
	}
	if algo.Valid {
		cluster.ShardAlgorithm = algo.String
	}
	if primaryID.Valid {
		id, _ := uuid.Parse(primaryID.String)
		cluster.PrimaryServerID = &id
	}
	if primaryName.Valid {
		cluster.PrimaryServerName = primaryName.String
	}
	return cluster, nil
}

// queryClusterServers fetches all servers belonging to a cluster.
func (h *ClusterHandler) queryClusterServers(c *gin.Context, clusterID uuid.UUID) []DatabaseServerResponse {
	rows, err := h.db.QueryContext(c.Request.Context(), `
		SELECT
			id, name, host, port, role, region, availability_zone, site,
			status, health_status, accepts_writes, accepts_reads,
			replication_lag_ms, current_connections, max_connections,
			current_tenants, max_tenants, used_storage_gb, max_storage_gb,
			last_health_check, created_at
		FROM database_servers
		WHERE cluster_id = $1
		ORDER BY role, name
	`, clusterID)
	if err != nil {
		return nil
	}
	defer rows.Close() //nolint:errcheck

	var servers []DatabaseServerResponse
	for rows.Next() {
		var server DatabaseServerResponse
		var az, site sql.NullString
		var lastCheck sql.NullTime

		rows.Scan( //nolint:errcheck,gosec
			&server.ID, &server.Name, &server.Host, &server.Port,
			&server.Role, &server.Region, &az, &site,
			&server.Status, &server.HealthStatus, &server.AcceptsWrites, &server.AcceptsReads,
			&server.ReplicationLagMs, &server.CurrentConnections, &server.MaxConnections,
			&server.CurrentTenants, &server.MaxTenants, &server.UsedStorageGB, &server.MaxStorageGB,
			&lastCheck, &server.CreatedAt,
		)
		if az.Valid {
			server.AvailabilityZone = az.String
		}
		if site.Valid {
			server.Site = site.String
		}
		if lastCheck.Valid {
			server.LastHealthCheck = &lastCheck.Time
		}
		servers = append(servers, server)
	}
	return servers
}

// ListServers returns all database servers
// GET /api/v1/platform/servers
func (h *ClusterHandler) ListServers(c *gin.Context) {
	query, args := buildServerListQuery(c.Query("cluster_id"), c.Query("role"), c.Query("status"))

	rows, err := h.db.QueryContext(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch servers"})
		return
	}
	defer rows.Close() //nolint:errcheck

	var servers []DatabaseServerResponse
	for rows.Next() {
		server, ok := scanServerRow(rows)
		if !ok {
			continue
		}
		servers = append(servers, server)
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch servers"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"servers": servers})
}

// buildServerListQuery constructs the parameterized server list query from optional filters.
func buildServerListQuery(clusterFilter, roleFilter, statusFilter string) (string, []interface{}) {
	query := `
		SELECT
			ds.id, ds.name, ds.host, ds.port, ds.cluster_id, dc.name,
			ds.role, ds.region, ds.availability_zone, ds.site,
			ds.status, ds.health_status, ds.accepts_writes, ds.accepts_reads,
			ds.replication_lag_ms, ds.current_connections, ds.max_connections,
			ds.current_tenants, ds.max_tenants, ds.used_storage_gb, ds.max_storage_gb,
			ds.last_health_check, ds.created_at
		FROM database_servers ds
		LEFT JOIN database_clusters dc ON dc.id = ds.cluster_id
		WHERE 1=1
	`
	var args []interface{}
	argNum := 1

	if clusterFilter != "" {
		query += fmt.Sprintf(" AND ds.cluster_id = $%d", argNum)
		args = append(args, clusterFilter)
		argNum++
	}
	if roleFilter != "" {
		query += fmt.Sprintf(" AND ds.role = $%d", argNum)
		args = append(args, roleFilter)
		argNum++
	}
	if statusFilter != "" {
		query += fmt.Sprintf(" AND ds.status = $%d", argNum)
		args = append(args, statusFilter)
		argNum++
	}
	_ = argNum // suppress unused-variable lint for clarity

	query += " ORDER BY ds.cluster_id, ds.role, ds.name"
	return query, args
}

// scanServerRow scans one row from a server list query into a DatabaseServerResponse.
// Returns the response and true on success, or the zero value and false on scan error.
func scanServerRow(rows interface {
	Scan(dest ...interface{}) error
},
) (DatabaseServerResponse, bool) {
	var server DatabaseServerResponse
	var clusterID, clusterName, az, site sql.NullString
	var lastCheck sql.NullTime

	err := rows.Scan(
		&server.ID, &server.Name, &server.Host, &server.Port, &clusterID, &clusterName,
		&server.Role, &server.Region, &az, &site,
		&server.Status, &server.HealthStatus, &server.AcceptsWrites, &server.AcceptsReads,
		&server.ReplicationLagMs, &server.CurrentConnections, &server.MaxConnections,
		&server.CurrentTenants, &server.MaxTenants, &server.UsedStorageGB, &server.MaxStorageGB,
		&lastCheck, &server.CreatedAt,
	)
	if err != nil {
		return server, false
	}
	if clusterID.Valid {
		id, _ := uuid.Parse(clusterID.String)
		server.ClusterID = &id
	}
	if clusterName.Valid {
		server.ClusterName = clusterName.String
	}
	if az.Valid {
		server.AvailabilityZone = az.String
	}
	if site.Valid {
		server.Site = site.String
	}
	if lastCheck.Valid {
		server.LastHealthCheck = &lastCheck.Time
	}
	return server, true
}

// CreateServer adds a new database server
// POST /api/v1/platform/servers
func (h *ClusterHandler) CreateServer(c *gin.Context) {
	var req CreateServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	if req.Port == 0 {
		req.Port = 5432
	}
	if req.MaxConnections == 0 {
		req.MaxConnections = 500
	}
	if req.MaxTenants == 0 {
		req.MaxTenants = 1000
	}
	if req.MaxStorageGB == 0 {
		req.MaxStorageGB = 1000
	}
	if req.SSLMode == "" {
		req.SSLMode = "require"
	}

	serverID := uuid.New()

	_, err := h.db.ExecContext(c.Request.Context(), `
		INSERT INTO database_servers (
			id, name, host, port, cluster_id, role, primary_server_id,
			region, availability_zone, site, max_connections, max_tenants,
			max_storage_gb, ssl_mode, status, health_status, tags
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'active', 'unknown', $15)
	`, serverID, req.Name, req.Host, req.Port, req.ClusterID, req.Role,
		req.PrimaryServerID, req.Region, req.AvailabilityZone, req.Site,
		req.MaxConnections, req.MaxTenants, req.MaxStorageGB, req.SSLMode, req.Tags)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create server"})
		return
	}

	// Log audit event
	h.logAuditEvent(c, "database_server_created", serverID, map[string]interface{}{
		"name": req.Name,
		"host": req.Host,
		"role": req.Role,
	})

	c.JSON(http.StatusCreated, gin.H{
		"message":   "Server created successfully",
		"server_id": serverID,
	})
}

// CreateCluster creates a new database cluster
// POST /api/v1/platform/clusters
func (h *ClusterHandler) CreateCluster(c *gin.Context) {
	var req CreateClusterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.ShardCount == 0 {
		req.ShardCount = 1
	}

	clusterID := uuid.New()

	_, err := h.db.ExecContext(c.Request.Context(), `
		INSERT INTO database_clusters (
			id, name, description, cluster_type, shard_count, shard_algorithm,
			auto_failover, read_write_split_enabled, status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active')
	`, clusterID, req.Name, req.Description, req.ClusterType, req.ShardCount,
		req.ShardAlgorithm, req.AutoFailover, req.ReadWriteSplitEnabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create cluster"})
		return
	}

	h.logAuditEvent(c, "database_cluster_created", clusterID, map[string]interface{}{
		"name":         req.Name,
		"cluster_type": req.ClusterType,
	})

	c.JSON(http.StatusCreated, gin.H{
		"message":    "Cluster created successfully",
		"cluster_id": clusterID,
	})
}

// GetTenantAssignments returns tenant-to-server assignments
// GET /api/v1/platform/tenant-assignments
func (h *ClusterHandler) GetTenantAssignments(c *gin.Context) {
	clusterFilter := c.Query("cluster_id")
	serverFilter := c.Query("server_id")

	query := `
		SELECT
			tsa.tenant_id, t.name, t.slug,
			tsa.cluster_id, dc.name,
			tsa.server_id, ds.name, ds.host,
			tsa.shard_index,
			COALESCE(t.plan, 'trial') as plan,
			tsa.created_at
		FROM tenant_shard_assignments tsa
		JOIN iam_tenants t ON t.id = tsa.tenant_id
		JOIN database_clusters dc ON dc.id = tsa.cluster_id
		JOIN database_servers ds ON ds.id = tsa.server_id
		WHERE 1=1
	`
	var args []interface{}
	argNum := 1

	if clusterFilter != "" {
		query += fmt.Sprintf(" AND tsa.cluster_id = $%d", argNum)
		args = append(args, clusterFilter)
		argNum++
	}
	if serverFilter != "" {
		query += fmt.Sprintf(" AND tsa.server_id = $%d", argNum) //nolint:gosec // SQL built with safe identifier components
		args = append(args, serverFilter)
	}

	query += " ORDER BY t.name"

	rows, err := h.db.QueryContext(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch assignments"})
		return
	}
	defer rows.Close() //nolint:errcheck

	var assignments []TenantAssignmentResponse
	for rows.Next() {
		var a TenantAssignmentResponse
		if err := rows.Scan(
			&a.TenantID, &a.TenantName, &a.TenantSlug,
			&a.ClusterID, &a.ClusterName,
			&a.ServerID, &a.ServerName, &a.ServerHost,
			&a.ShardIndex, &a.Plan, &a.AssignedAt,
		); err != nil {
			continue
		}
		assignments = append(assignments, a)
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch assignments"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"assignments": assignments})
}

// AssignTenant assigns a tenant to a specific server/cluster
// POST /api/v1/platform/tenant-assignments
func (h *ClusterHandler) AssignTenant(c *gin.Context) {
	var req AssignTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Determine cluster and server
	var clusterID, serverID uuid.UUID
	var shardIndex int

	switch {
	case req.ServerID != nil:
		serverID = *req.ServerID
		// Get cluster from server
		err := h.db.QueryRowContext(c.Request.Context(),
			"SELECT cluster_id FROM database_servers WHERE id = $1", serverID).Scan(&clusterID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": msgClusterServerNotFound})
			return
		}
	case req.ClusterID != nil:
		clusterID = *req.ClusterID
		// Get primary server from cluster
		err := h.db.QueryRowContext(c.Request.Context(),
			"SELECT primary_server_id FROM database_clusters WHERE id = $1", clusterID).Scan(&serverID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cluster not found"})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Either cluster_id or server_id is required"})
		return
	}

	// Insert or update assignment
	_, err := h.db.ExecContext(c.Request.Context(), `
		INSERT INTO tenant_shard_assignments (tenant_id, cluster_id, shard_index, server_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id) DO UPDATE SET
			cluster_id = EXCLUDED.cluster_id,
			shard_index = EXCLUDED.shard_index,
			server_id = EXCLUDED.server_id,
			updated_at = NOW()
	`, req.TenantID, clusterID, shardIndex, serverID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign tenant"})
		return
	}

	h.logAuditEvent(c, "tenant_reassigned", req.TenantID, map[string]interface{}{
		"cluster_id": clusterID,
		"server_id":  serverID,
		"reason":     req.Reason,
	})

	c.JSON(http.StatusOK, gin.H{
		"message":    "Tenant assigned successfully",
		"tenant_id":  req.TenantID,
		"cluster_id": clusterID,
		"server_id":  serverID,
	})
}

// PromoteServer promotes a replica to primary (PROTECTED OPERATION)
// POST /api/v1/platform/servers/:id/promote
func (h *ClusterHandler) PromoteServer(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var req PromoteServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Require explicit confirmation
	if req.Confirmation != "PROMOTE" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Confirmation required. Set confirmation to 'PROMOTE' to proceed.",
		})
		return
	}

	// Get server and cluster info
	var role, clusterID string
	err = h.db.QueryRowContext(c.Request.Context(),
		"SELECT role, cluster_id FROM database_servers WHERE id = $1", serverID).Scan(&role, &clusterID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgClusterServerNotFound})
		return
	}

	if role != "replica" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only replicas can be promoted"})
		return
	}

	// Call the promotion function
	_, err = h.db.ExecContext(c.Request.Context(),
		"SELECT promote_replica_to_primary($1::UUID, $2::UUID)", clusterID, serverID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Promotion failed"})
		return
	}

	h.logAuditEvent(c, "server_promoted", serverID, map[string]interface{}{
		"cluster_id": clusterID,
		"reason":     req.Reason,
	})

	c.JSON(http.StatusOK, gin.H{
		"message":   "Server promoted to primary successfully",
		"server_id": serverID,
		"warning":   "Ensure old primary is reconfigured as replica",
	})
}

// GetClusterStats returns overall cluster statistics
// GET /api/v1/platform/clusters/stats
func (h *ClusterHandler) GetClusterStats(c *gin.Context) {
	var stats ClusterStatsResponse

	// Get aggregate stats
	_ = h.db.QueryRowContext(c.Request.Context(), `
		SELECT
			(SELECT COUNT(*) FROM database_clusters WHERE status = 'active'),
			(SELECT COUNT(*) FROM database_servers WHERE status != 'offline'),
			(SELECT COUNT(*) FROM database_servers WHERE health_status = 'healthy'),
			(SELECT COUNT(*) FROM tenant_shard_assignments),
			(SELECT COALESCE(SUM(current_connections), 0) FROM database_servers),
			(SELECT COALESCE(AVG(replication_lag_ms), 0) FROM database_servers WHERE role = 'replica'),
			(SELECT COALESCE(SUM(used_storage_gb), 0) FROM database_servers),
			(SELECT COALESCE(SUM(max_storage_gb), 0) FROM database_servers)
	`).Scan( //nolint:errcheck,gosec // best-effort stats query
		&stats.TotalClusters, &stats.TotalServers, &stats.HealthyServers,
		&stats.TotalTenants, &stats.TotalConnections, &stats.AvgReplicationLag,
		&stats.StorageUsedGB, &stats.StorageTotalGB,
	)

	// Get servers by role
	stats.ServersByRole = make(map[string]int)
	roleRows, _ := h.db.QueryContext(c.Request.Context(),
		"SELECT role, COUNT(*) FROM database_servers GROUP BY role")
	if roleRows != nil {
		defer roleRows.Close() //nolint:errcheck
		for roleRows.Next() {
			var role string
			var count int
			roleRows.Scan(&role, &count) //nolint:errcheck,gosec
			stats.ServersByRole[role] = count
		}
	}

	// Get servers by status
	stats.ServersByStatus = make(map[string]int)
	statusRows, _ := h.db.QueryContext(c.Request.Context(),
		"SELECT health_status, COUNT(*) FROM database_servers GROUP BY health_status")
	if statusRows != nil {
		defer statusRows.Close() //nolint:errcheck
		for statusRows.Next() {
			var status string
			var count int
			statusRows.Scan(&status, &count) //nolint:errcheck,gosec
			stats.ServersByStatus[status] = count
		}
	}

	// Get tenants by cluster
	stats.TenantsByCluster = make(map[string]int)
	clusterRows, _ := h.db.QueryContext(c.Request.Context(), `
		SELECT dc.name, COUNT(tsa.tenant_id)
		FROM database_clusters dc
		LEFT JOIN tenant_shard_assignments tsa ON tsa.cluster_id = dc.id
		GROUP BY dc.id, dc.name
	`)
	if clusterRows != nil {
		defer clusterRows.Close() //nolint:errcheck
		for clusterRows.Next() {
			var name string
			var count int
			clusterRows.Scan(&name, &count) //nolint:errcheck,gosec
			stats.TenantsByCluster[name] = count
		}
	}

	c.JSON(http.StatusOK, stats)
}

// TestServerConnection tests connectivity to a server
// POST /api/v1/platform/servers/:id/test
func (h *ClusterHandler) TestServerConnection(c *gin.Context) {
	serverID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var host string
	var port int
	var sslMode string

	err = h.db.QueryRowContext(c.Request.Context(),
		"SELECT host, port, ssl_mode FROM database_servers WHERE id = $1",
		serverID).Scan(&host, &port, &sslMode)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgClusterServerNotFound})
		return
	}

	// Test connection
	connStr := fmt.Sprintf("host=%s port=%d sslmode=%s connect_timeout=5", host, port, sslMode)
	testDB, err := sql.Open("postgres", connStr)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	defer testDB.Close() //nolint:errcheck

	start := time.Now()
	err = testDB.PingContext(c.Request.Context())
	latency := time.Since(start).Milliseconds()

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success":    false,
			"error":      err.Error(),
			"latency_ms": latency,
		})
		return
	}

	// Update health status
	_, _ = h.db.ExecContext(c.Request.Context(), `
		UPDATE database_servers
		SET health_status = 'healthy', last_health_check = NOW()
		WHERE id = $1
	`, serverID)

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"latency_ms": latency,
		"message":    "Connection successful",
	})
}

// logAuditEvent logs an audit event
func (h *ClusterHandler) logAuditEvent(c *gin.Context, action string, entityID uuid.UUID, details map[string]interface{}) {
	userID, _ := c.Get("user_id")
	_, _ = h.db.ExecContext(c.Request.Context(), `
		INSERT INTO audit_logs (user_id, action, entity_type, entity_id, new_values, ip_address)
		VALUES ($1, $2, 'database_infrastructure', $3, $4, $5)
	`, userID, action, entityID, details, c.ClientIP())
}

// RegisterRoutes registers all cluster management routes
func (h *ClusterHandler) RegisterRoutes(rg *gin.RouterGroup) {
	platform := rg.Group("/platform")
	{
		// Clusters
		platform.GET("/clusters", h.ListClusters)
		platform.GET("/clusters/stats", h.GetClusterStats)
		platform.POST("/clusters", h.CreateCluster)
		platform.GET("/clusters/:id", h.GetCluster)

		// Servers
		platform.GET("/servers", h.ListServers)
		platform.POST("/servers", h.CreateServer)
		platform.POST("/servers/:id/test", h.TestServerConnection)
		platform.POST("/servers/:id/promote", h.PromoteServer)

		// Tenant Assignments
		platform.GET("/tenant-assignments", h.GetTenantAssignments)
		platform.POST("/tenant-assignments", h.AssignTenant)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// AdminQueryHandler provides a read-only SQL query endpoint for
// platform admin dashboards (pg_stat_statements, pg_stat_activity, etc.).
// Only SELECT queries are allowed — mutations are rejected.
type AdminQueryHandler struct {
	pool *pgxpool.Pool
	log  *zap.SugaredLogger
}

// NewAdminQueryHandler is an exported function.
func NewAdminQueryHandler(pool *pgxpool.Pool, log *zap.SugaredLogger) *AdminQueryHandler {
	return &AdminQueryHandler{pool: pool, log: log}
}

type adminQueryRequest struct {
	SQL string `json:"sql" binding:"required"`
}

// Query executes a read-only SQL statement and returns the result as JSON rows.
func (h *AdminQueryHandler) Query(c *gin.Context) {
	var req adminQueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sql field is required"})
		return
	}

	// Security: only allow SELECT and SHOW statements
	trimmed := strings.TrimSpace(strings.ToUpper(req.SQL))
	if !strings.HasPrefix(trimmed, "SELECT") && !strings.HasPrefix(trimmed, "SHOW") {
		c.JSON(http.StatusForbidden, gin.H{"error": "only SELECT and SHOW queries are allowed"})
		return
	}

	// Reject dangerous patterns
	lower := strings.ToLower(req.SQL)
	for _, keyword := range []string{"insert ", "update ", "delete ", "drop ", "alter ", "truncate ", "create ", "grant ", "revoke "} {
		if strings.Contains(lower, keyword) {
			c.JSON(http.StatusForbidden, gin.H{"error": "mutation queries are not allowed"})
			return
		}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	rows, err := h.pool.Query(ctx, req.SQL)
	if err != nil {
		h.log.Warnw("admin query failed", "err", err, "sql", req.SQL[:min(len(req.SQL), 100)])
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	// Read column names from field descriptions
	fields := rows.FieldDescriptions()
	colNames := make([]string, len(fields))
	for i, f := range fields {
		colNames[i] = f.Name
	}

	// Read all rows as maps
	var result []map[string]interface{}
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			h.log.Warnw("admin query row scan error", "err", err)
			continue
		}
		row := make(map[string]interface{}, len(colNames))
		for i, col := range colNames {
			row[col] = values[i]
		}
		result = append(result, row)
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if result == nil {
		result = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"rows": result, "columns": colNames, "count": len(result)})
}

// VacuumTable runs VACUUM ANALYZE on a specific table.
// Only allows schema-qualified table names to prevent injection.
func (h *AdminQueryHandler) VacuumTable(c *gin.Context) {
	var req struct {
		Schema string `json:"schema"`
		Table  string `json:"table" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "table field is required"})
		return
	}

	if !isSafeIdentifier(req.Table) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid table name"})
		return
	}

	schema := req.Schema
	if schema == "" {
		schema = "public"
	}
	if !isSafeIdentifier(schema) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid schema name"})
		return
	}

	qualifiedName := schema + "." + req.Table
	h.log.Infow("admin vacuum requested", "table", qualifiedName)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	start := time.Now()
	_, err := h.pool.Exec(ctx, "VACUUM ANALYZE "+qualifiedName)
	duration := time.Since(start)

	if err != nil {
		h.log.Warnw("admin vacuum failed", "table", qualifiedName, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.log.Infow("admin vacuum completed", "table", qualifiedName, "duration", duration)
	c.JSON(http.StatusOK, gin.H{
		"table":    qualifiedName,
		"action":   "VACUUM ANALYZE",
		"duration": duration.String(),
		"success":  true,
	})
}

// isSafeIdentifier reports whether name is safe to interpolate into SQL as a schema or table identifier.
// Accepts only alphanumeric characters and underscores.
func isSafeIdentifier(name string) bool {
	for _, ch := range name {
		isLower := ch >= 'a' && ch <= 'z'
		isUpper := ch >= 'A' && ch <= 'Z'
		isDigit := ch >= '0' && ch <= '9'
		if !isLower && !isUpper && !isDigit && ch != '_' {
			return false
		}
	}
	return len(name) > 0
}

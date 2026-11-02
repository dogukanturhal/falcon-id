// SPDX-License-Identifier: AGPL-3.0-or-later

package opsconsole

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/opsaudit"
)

const (
	auditDefaultLimit = 50
	auditMaxLimit     = 200
	// ExportRowCap bounds one export file.
	ExportRowCap = 100000
	// ExportTTL is how long a generated export can be downloaded.
	ExportTTL      = 15 * time.Minute
	exportPageSize = 2000
)

// auditFilters are the unified audit stream filters. The JSON key order is the
// canonical form the export approval payload hash is computed over.
type auditFilters struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Source   string `json:"source"`
	TenantID string `json:"tenant_id"`
	Q        string `json:"q"`
}

type auditRow struct {
	ID          string
	Source      string
	OccurredAt  time.Time
	Actor       string
	ActorID     *string
	Action      string
	Resource    *string
	TenantID    *string
	ReasonCode  *string
	Reason      *string
	RequestID   *string
	Success     bool
	ElevationID *string
	ApprovalID  *string
	EntryHash   *string
}

func (r auditRow) outcome() string {
	if r.Success {
		return "success"
	}
	return "failure"
}

// actorLabel masks tenant-side (iam) actors; operator actors are staff and
// stay readable for accountability.
func (r auditRow) actorLabel() string {
	if r.Source == "iam" {
		return MaskUsername(r.Actor)
	}
	return r.Actor
}

func (r auditRow) json() gin.H {
	return gin.H{
		"id": r.ID, "source": r.Source, "occurred_at": r.OccurredAt, "actor": r.actorLabel(), "actor_id": r.ActorID,
		"action": r.Action, "resource": r.Resource, "tenant_id": r.TenantID, "reason_code": r.ReasonCode, "reason": r.Reason,
		"request_id": r.RequestID, "outcome": r.outcome(), "elevation_id": r.ElevationID, "approval_id": r.ApprovalID,
		"entry_hash": r.EntryHash,
	}
}

var errInvalidFilters = errors.New("invalid_filters")

func (f *auditFilters) normalize() error {
	f.Source = strings.ToLower(strings.TrimSpace(f.Source))
	if f.Source == "" {
		f.Source = "all"
	}
	if f.Source != "all" && f.Source != "operator" && f.Source != "iam" {
		return errInvalidFilters
	}
	for _, t := range []string{f.From, f.To} {
		if t != "" {
			if _, err := time.Parse(time.RFC3339, t); err != nil {
				return errInvalidFilters
			}
		}
	}
	if f.TenantID != "" {
		if _, err := uuid.Parse(f.TenantID); err != nil {
			return errInvalidFilters
		}
	}
	return nil
}

// canonicalExportPayload is the string whose sha256 an audit.export approval
// is bound to.
func canonicalExportPayload(f auditFilters, format string) string {
	// normalize() turns an unset source into "all"; the approval was requested
	// with the filters as the operator set them ("" = unset), so hash that form.
	if f.Source == "all" {
		f.Source = ""
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(struct {
		Filters auditFilters `json:"filters"`
		Format  string       `json:"format"`
	}{f, format})
	return strings.TrimSuffix(buf.String(), "\n")
}

// buildAuditSQL assembles the UNION over both sources for filters f. cursor is
// optional keyset position (ts, id).
func buildAuditSQL(f auditFilters, curTS *time.Time, curID string, limit int) (string, []interface{}) {
	var args []interface{}
	arg := func(v interface{}) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	// shared placeholders so both subqueries reuse one argument each
	var pFrom, pTo, pActorID, pActorLike, pAction, pTenant, pQ, pCurTS, pCurID string
	if f.From != "" {
		t, _ := time.Parse(time.RFC3339, f.From)
		pFrom = arg(t)
	}
	if f.To != "" {
		t, _ := time.Parse(time.RFC3339, f.To)
		pTo = arg(t)
	}
	if f.Actor != "" {
		if id, err := uuid.Parse(f.Actor); err == nil {
			pActorID = arg(id.String())
		} else {
			pActorLike = arg(escapeLike(strings.ToLower(f.Actor)) + "%")
		}
	}
	if f.Action != "" {
		pAction = arg(f.Action)
	}
	if f.TenantID != "" {
		pTenant = arg(f.TenantID)
	}
	if f.Q != "" {
		pQ = arg("%" + escapeLike(strings.ToLower(f.Q)) + "%")
	}
	if curTS != nil {
		pCurTS, pCurID = arg(*curTS), arg(curID)
	}
	lim := arg(limit + 1)

	conds := func(ts, actorName, actorID, action, tenant, resource string) string {
		var w []string
		if pFrom != "" {
			w = append(w, ts+" >= "+pFrom)
		}
		if pTo != "" {
			w = append(w, ts+" <= "+pTo)
		}
		if pActorID != "" {
			w = append(w, actorID+" = "+pActorID)
		}
		if pActorLike != "" {
			w = append(w, "lower("+actorName+`) LIKE `+pActorLike+` ESCAPE '\'`)
		}
		if pAction != "" {
			w = append(w, action+" = "+pAction)
		}
		if pTenant != "" {
			w = append(w, tenant+" = "+pTenant)
		}
		if pQ != "" {
			w = append(w, "(lower("+action+") LIKE "+pQ+` ESCAPE '\' OR lower(coalesce(`+resource+`,'')) LIKE `+pQ+` ESCAPE '\' OR lower(coalesce(`+actorName+`,'')) LIKE `+pQ+` ESCAPE '\')`)
		}
		if pCurTS != "" {
			w = append(w, fmt.Sprintf("(%s, id_text) < (%s, %s)", ts, pCurTS, pCurID))
		}
		if len(w) == 0 {
			return ""
		}
		return " WHERE " + strings.Join(w, " AND ")
	}

	op := `SELECT id::text AS id_text, COALESCE(occurred_at, created_at) AS ts, admin_username AS actor, admin_user_id::text AS actor_id,
		action, COALESCE(resource, NULLIF(concat_ws(':', target_resource_type::text, target_resource_id::text), '')) AS resource,
		target_tenant_id::text AS tenant_id, reason_code, reason, request_id::text AS request_id, success,
		elevation_id::text AS elevation_id, approval_id::text AS approval_id, entry_hash, 'operator'::text AS source
		FROM platform_admin_audit_log`
	iam := `SELECT a.id::text AS id_text, a.created_at AS ts, COALESCE(u.username, a.user_id::text, '') AS actor, a.user_id::text AS actor_id,
		a.action AS action, NULLIF(concat_ws(':', a.resource_type::text, a.resource_id::text), '') AS resource,
		a.tenant_id::text AS tenant_id, NULL::text AS reason_code, NULL::text AS reason, NULL::text AS request_id, a.success AS success,
		NULL::text AS elevation_id, NULL::text AS approval_id, NULL::text AS entry_hash, 'iam'::text AS source
		FROM iam_audit_log a LEFT JOIN iam_users u ON u.id = a.user_id`

	var parts []string
	if f.Source == "all" || f.Source == "operator" {
		parts = append(parts, "(SELECT * FROM ("+op+") o"+conds("ts", "actor", "actor_id", "action", "tenant_id", "resource")+
			" ORDER BY ts DESC, id_text DESC LIMIT "+lim+")")
	}
	if f.Source == "all" || f.Source == "iam" {
		parts = append(parts, "(SELECT * FROM ("+iam+") i"+conds("ts", "actor", "actor_id", "action", "tenant_id", "resource")+
			" ORDER BY ts DESC, id_text DESC LIMIT "+lim+")")
	}
	sql := "SELECT id_text, ts, actor, actor_id, action, resource, tenant_id, reason_code, reason, request_id, success, elevation_id, approval_id, entry_hash, source FROM (" +
		strings.Join(parts, " UNION ALL ") + ") u ORDER BY ts DESC, id_text DESC LIMIT " + lim
	return sql, args
}

type auditQuerier interface {
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
}

// queryAudit returns up to limit rows after the cursor plus whether more exist.
func queryAudit(ctx context.Context, db auditQuerier, f auditFilters, curTS *time.Time, curID string, limit int) ([]auditRow, bool, error) {
	sql, args := buildAuditSQL(f, curTS, curID, limit)
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		var actor *string
		if err := rows.Scan(&r.ID, &r.OccurredAt, &actor, &r.ActorID, &r.Action, &r.Resource, &r.TenantID, &r.ReasonCode, &r.Reason,
			&r.RequestID, &r.Success, &r.ElevationID, &r.ApprovalID, &r.EntryHash, &r.Source); err != nil {
			return nil, false, err
		}
		if actor != nil {
			r.Actor = *actor
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

func filtersFromQuery(c *gin.Context) auditFilters {
	return auditFilters{
		From: c.Query("from"), To: c.Query("to"), Actor: strings.TrimSpace(c.Query("actor")), Action: strings.TrimSpace(c.Query("action")),
		Source: c.Query("source"), TenantID: c.Query("tenant_id"), Q: strings.TrimSpace(c.Query("q")),
	}
}

// ListAudit: GET /ops/audit.
func (cs *Console) ListAudit(c *gin.Context) {
	f := filtersFromQuery(c)
	if err := f.normalize(); err != nil {
		fail(c, http.StatusBadRequest, "invalid_filters")
		return
	}
	limit := clampLimit(c.Query("limit"), auditDefaultLimit, auditMaxLimit)
	var curTS *time.Time
	var curID string
	if cur := c.Query("cursor"); cur != "" {
		ts, id, err := decodeCursor(cur)
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid_cursor")
			return
		}
		curTS, curID = &ts, id
	}
	rows, more, err := queryAudit(c.Request.Context(), cs.DB, f, curTS, curID, limit)
	if err != nil {
		cs.internalErr(c, "audit list", err)
		return
	}
	items := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		items = append(items, r.json())
	}
	var next interface{}
	if more && len(rows) > 0 {
		last := rows[len(rows)-1]
		next = encodeCursor(last.OccurredAt, last.ID)
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "next_cursor": next})
}

// AuditIntegrity: GET /ops/audit/integrity. Verifies, for the newest `limit`
// hash-chained rows of platform_admin_audit_log, both the prev_hash linkage and
// the row-content hash (recomputed from the stored fields, see
// opsaudit.HashInput). The console only displays this result.
func (cs *Console) AuditIntegrity(c *gin.Context) {
	limit := clampLimit(c.Query("limit"), 10000, 100000)
	rep, err := opsaudit.Verify(c.Request.Context(), cs.DB, limit)
	if err != nil {
		cs.internalErr(c, "audit integrity", err)
		return
	}
	var firstBad interface{}
	var reason interface{}
	if rep.FirstBad != "" {
		firstBad, reason = rep.FirstBad, rep.Reason
	}
	c.JSON(http.StatusOK, gin.H{"ok": rep.OK, "checked": rep.Checked, "first_bad_id": firstBad,
		"first_bad_reason": reason, "head_hash": rep.HeadHash, "unsequenced_rows": rep.Unsequenced})
}

// ---- exports ---------------------------------------------------------------

type exportRow struct {
	ID           uuid.UUID
	RequesterID  uuid.UUID
	Format       string
	RowCount     int
	Truncated    bool
	ExpiresAt    time.Time
	DownloadedAt *time.Time
}

func (e exportRow) json() gin.H {
	return gin.H{
		"id": e.ID, "status": "ready", "format": e.Format, "row_count": e.RowCount, "truncated": e.Truncated,
		"expires_at": e.ExpiresAt, "downloaded_at": e.DownloadedAt,
		"download_path": "/internal/v1/ops/audit/exports/" + e.ID.String() + "/download",
	}
}

var exportHeader = []string{"id", "source", "occurred_at", "actor", "actor_id", "action", "resource", "tenant_id", "reason_code", "reason", "request_id", "outcome", "elevation_id", "approval_id", "entry_hash"}

func sv(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func renderExport(rows []auditRow, format string) ([]byte, error) {
	var buf bytes.Buffer
	if format == "csv" {
		w := csv.NewWriter(&buf)
		_ = w.Write(exportHeader)
		for _, r := range rows {
			// Guard against spreadsheet formula injection from free text.
			rec := []string{r.ID, r.Source, r.OccurredAt.UTC().Format(time.RFC3339Nano), csvSafe(r.actorLabel()), sv(r.ActorID), csvSafe(r.Action), csvSafe(sv(r.Resource)),
				sv(r.TenantID), sv(r.ReasonCode), csvSafe(sv(r.Reason)), sv(r.RequestID), r.outcome(), sv(r.ElevationID), sv(r.ApprovalID), sv(r.EntryHash)}
			_ = w.Write(rec)
		}
		w.Flush()
		return buf.Bytes(), w.Error()
	}
	enc := json.NewEncoder(&buf)
	for _, r := range rows {
		if err := enc.Encode(r.json()); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// CreateExport: POST /ops/audit/exports. T3: step-up (chain) + approval.
func (cs *Console) CreateExport(c *gin.Context) {
	ctx := c.Request.Context()
	actor := actorOf(c)
	var req struct {
		Filters    auditFilters `json:"filters"`
		Format     string       `json:"format"`
		ApprovalID string       `json:"approval_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid_body")
		return
	}
	if req.Format != "csv" && req.Format != "ndjson" {
		fail(c, http.StatusBadRequest, "invalid_format")
		return
	}
	if err := req.Filters.normalize(); err != nil {
		fail(c, http.StatusBadRequest, "invalid_filters")
		return
	}
	aid, err := uuid.Parse(req.ApprovalID)
	if err != nil {
		fail(c, http.StatusForbidden, "approval_required")
		return
	}
	SetAudit(c, "audit", req.Filters.TenantID)

	// Generate first (read only), then spend the approval, then store.
	var all []auditRow
	var curTS *time.Time
	curID := ""
	truncated := false
	for len(all) < ExportRowCap {
		page, more, qErr := queryAudit(ctx, cs.DB, req.Filters, curTS, curID, exportPageSize)
		if qErr != nil {
			cs.internalErr(c, "audit export query", qErr)
			return
		}
		room := ExportRowCap - len(all)
		if len(page) > room {
			page, more, truncated = page[:room], true, true
		}
		all = append(all, page...)
		if !more || len(page) == 0 {
			break
		}
		last := page[len(page)-1]
		t := last.OccurredAt
		curTS, curID = &t, last.ID
		if len(all) >= ExportRowCap {
			truncated = true
		}
	}
	content, err := renderExport(all, req.Format)
	if err != nil {
		cs.internalErr(c, "audit export render", err)
		return
	}
	if _, err := cs.ConsumeLocal(ctx, actor.UserID, aid, "audit.export", "audit", PayloadHash(canonicalExportPayload(req.Filters, req.Format))); err != nil {
		fail(c, http.StatusForbidden, "approval_required")
		return
	}
	c.Set(ctxAuditApproval, aid.String())

	_, _ = cs.DB.Exec(ctx, `DELETE FROM ops_audit_exports WHERE expires_at < now() - interval '1 hour'`)
	r := reasonFrom(c)
	filtersJSON, _ := json.Marshal(req.Filters)
	var e exportRow
	e.RequesterID, e.Format, e.RowCount, e.Truncated = actor.UserID, req.Format, len(all), truncated
	err = cs.DB.QueryRow(ctx, `
		INSERT INTO ops_audit_exports (requester_id, approval_id, format, filters, reason_code, reason, row_count, truncated, content, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now() + make_interval(secs => $10))
		RETURNING id, expires_at`,
		actor.UserID, aid, req.Format, filtersJSON, string(r.Code), r.Text, len(all), truncated, content, ExportTTL.Seconds()).Scan(&e.ID, &e.ExpiresAt)
	if err != nil {
		cs.internalErr(c, "audit export store", err)
		return
	}
	SetAudit(c, "audit_export:"+e.ID.String(), req.Filters.TenantID)
	c.Set(ctxAuditDetails, map[string]interface{}{"format": req.Format, "row_count": len(all), "truncated": truncated})
	c.JSON(http.StatusCreated, e.json())
}

func (cs *Console) loadExport(c *gin.Context) (*exportRow, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid_id")
		return nil, false
	}
	var e exportRow
	err = cs.DB.QueryRow(c.Request.Context(), `SELECT id, requester_id, format, row_count, truncated, expires_at, downloaded_at
		FROM ops_audit_exports WHERE id = $1`, id).Scan(&e.ID, &e.RequesterID, &e.Format, &e.RowCount, &e.Truncated, &e.ExpiresAt, &e.DownloadedAt)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && e.RequesterID != actorOf(c).UserID) {
		fail(c, http.StatusNotFound, "not_found")
		return nil, false
	}
	if err != nil {
		cs.internalErr(c, "audit export load", err)
		return nil, false
	}
	return &e, true
}

// GetExport: GET /ops/audit/exports/:id.
func (cs *Console) GetExport(c *gin.Context) {
	if e, ok := cs.loadExport(c); ok {
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, e.json())
	}
}

// DownloadExport: GET /ops/audit/exports/:id/download. Requester only, once.
func (cs *Console) DownloadExport(c *gin.Context) {
	e, ok := cs.loadExport(c)
	if !ok {
		return
	}
	SetAudit(c, "audit_export:"+e.ID.String(), "")
	if e.DownloadedAt != nil {
		fail(c, http.StatusGone, "export_consumed")
		return
	}
	if time.Now().After(e.ExpiresAt) {
		fail(c, http.StatusGone, "export_expired")
		return
	}
	var content []byte
	err := cs.DB.QueryRow(c.Request.Context(), `
		UPDATE ops_audit_exports SET downloaded_at = now()
		 WHERE id = $1 AND requester_id = $2 AND downloaded_at IS NULL AND expires_at > now()
		RETURNING content`, e.ID, actorOf(c).UserID).Scan(&content)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(c, http.StatusGone, "export_consumed")
		return
	}
	if err != nil {
		cs.internalErr(c, "audit export download", err)
		return
	}
	ctype, ext := "text/csv; charset=utf-8", "csv"
	if e.Format == "ndjson" {
		ctype, ext = "application/x-ndjson", "ndjson"
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="audit-export-%s.%s"`, e.ID, ext))
	c.Data(http.StatusOK, ctype, content)
}

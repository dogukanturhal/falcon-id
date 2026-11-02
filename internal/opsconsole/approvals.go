// SPDX-License-Identifier: AGPL-3.0-or-later

package opsconsole

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/operatorauth"

	"github.com/dogukanturhal/falcon-id/internal/opsaudit"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// ActionPerms maps a four-eyes action to the ops permission both requester and
// approver must hold. An action missing here cannot be requested.
var ActionPerms = map[string]string{
	"tenant.purge.apply":            "ops:tenants:purge",
	"tenant.legal_hold.release":     "ops:tenants:lifecycle",
	"refund.over_threshold":         "ops:billing:refund",
	"payment.provider_config":       "ops:billing:refund",
	"catalog.price_change":          "ops:catalog:write",
	"edoc.credit.manual_load":       "ops:edoc:write",
	"user.hard_delete":              "ops:users:write",
	"audit.export":                  "ops:audit:export",
	"staff.offboard":                "ops:staff:manage",
	"notification.template.publish": "ops:notify:write",
}

// Approval lifetimes.
const (
	ApprovalDefaultTTL = time.Hour
	ApprovalMinTTL     = time.Minute
	ApprovalMaxTTL     = 24 * time.Hour
	ApprovalTokenTTL   = 15 * time.Minute
	// LocalAudience is the audience of approvals consumed by falcon-id itself.
	LocalAudience = "falcon-id"
)

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

var (
	errApprovalNotFound    = errors.New("approval_not_found")
	errSelfApproval        = errors.New("self_approval_not_allowed")
	errApprovalNotPending  = errors.New("approval_not_pending")
	errApprovalExpired     = errors.New("approval_expired")
	ErrApprovalInvalid     = errors.New("approval_invalid")
	errApprovalPermDenied  = errors.New("operator_permission_denied")
	errApprovalNotRequestr = errors.New("not_requester")
)

type approvalRow struct {
	ID           uuid.UUID
	Action       string
	Resource     string
	Audience     string
	TenantID     *uuid.UUID
	PayloadSHA   string
	ReasonCode   *string
	Reason       string
	RequesterID  uuid.UUID
	ApproverID   *uuid.UUID
	Status       string
	DecisionNote *string
	ExpiresAt    time.Time
	DecidedAt    *time.Time
	UsedAt       *time.Time
	CreatedAt    time.Time
}

const approvalCols = `id, action, resource, audience, tenant_id, payload_sha256, reason_code, reason,
	requester_id, approver_id, status, decision_note, expires_at, decided_at, used_at, created_at`

func scanApproval(row pgx.Row) (*approvalRow, error) {
	var a approvalRow
	err := row.Scan(&a.ID, &a.Action, &a.Resource, &a.Audience, &a.TenantID, &a.PayloadSHA, &a.ReasonCode, &a.Reason,
		&a.RequesterID, &a.ApproverID, &a.Status, &a.DecisionNote, &a.ExpiresAt, &a.DecidedAt, &a.UsedAt, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

type approvalStore struct {
	db     repositories.DBTX
	users  *repositories.UserRepository
	signer TokenSigner
}

// expire lazily flips overdue open approvals to expired.
func (s *approvalStore) expire(ctx context.Context) {
	_, _ = s.db.Exec(ctx, `UPDATE ops_approval_requests SET status = 'expired'
		WHERE status IN ('pending','approved') AND expires_at <= now()`)
}

func (s *approvalStore) get(ctx context.Context, id uuid.UUID) (*approvalRow, error) {
	s.expire(ctx)
	a, err := scanApproval(s.db.QueryRow(ctx, `SELECT `+approvalCols+` FROM ops_approval_requests WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errApprovalNotFound
	}
	return a, err
}

// PayloadHash is the canonical approval payload hash helper: sha256 hex of s.
func PayloadHash(s string) string { return hashHex(s) }

// consume atomically spends an approved approval. Every binding must match or
// nothing is consumed (fail closed).
func (s *approvalStore) consume(ctx context.Context, id uuid.UUID, audience, action, resource, sha string) (*approvalRow, error) {
	a, err := scanApproval(s.db.QueryRow(ctx, `
		UPDATE ops_approval_requests
		   SET used_at = now(), status = 'consumed'
		 WHERE id = $1 AND used_at IS NULL AND status = 'approved' AND expires_at > now()
		   AND audience = $2 AND action = $3 AND resource = $4 AND payload_sha256 = $5
		RETURNING `+approvalCols, id, audience, action, resource, sha))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrApprovalInvalid
	}
	return a, err
}

// ConsumeLocal spends an approval that must have been requested by `actor`
// (the operator executing the guarded action) for falcon-id itself.
func (cs *Console) ConsumeLocal(ctx context.Context, actor uuid.UUID, id uuid.UUID, action, resource, sha string) (*approvalRow, error) {
	a, err := cs.approvals.get(ctx, id)
	if err != nil {
		return nil, ErrApprovalInvalid
	}
	if a.RequesterID != actor {
		return nil, ErrApprovalInvalid
	}
	return cs.approvals.consume(ctx, id, LocalAudience, action, resource, sha)
}

// ---- JSON ------------------------------------------------------------------

func (cs *Console) approvalJSON(ctx context.Context, a *approvalRow, actor *operatorauth.Actor, labels map[uuid.UUID]string) gin.H {
	label := func(id uuid.UUID) string {
		if l, ok := labels[id]; ok {
			return l
		}
		l := ""
		if u, err := cs.Users.GetByID(ctx, id); err == nil && u != nil {
			l = MaskEmail(u.Email)
		}
		labels[id] = l
		return l
	}
	var approver, approverLabel interface{}
	if a.ApproverID != nil {
		approver, approverLabel = *a.ApproverID, label(*a.ApproverID)
	}
	perm := ActionPerms[a.Action]
	canApprove := a.Status == "pending" && actor != nil && a.RequesterID != actor.UserID && perm != "" && actor.HasPerm(perm)
	return gin.H{
		"id": a.ID, "action": a.Action, "resource": a.Resource, "audience": a.Audience,
		"tenant_id": a.TenantID, "payload_sha256": a.PayloadSHA, "reason_code": a.ReasonCode, "reason": a.Reason,
		"status": a.Status, "requester_id": a.RequesterID, "requester_email_masked": label(a.RequesterID),
		"approver_id": approver, "approver_email_masked": approverLabel, "decision_note": a.DecisionNote,
		"expires_at": a.ExpiresAt, "decided_at": a.DecidedAt, "used_at": a.UsedAt, "created_at": a.CreatedAt,
		"can_approve": canApprove,
	}
}

func approvalErr(c *gin.Context, err error) bool {
	switch {
	case errors.Is(err, errApprovalNotFound):
		fail(c, http.StatusNotFound, "not_found")
	case errors.Is(err, errSelfApproval):
		fail(c, http.StatusForbidden, "self_approval_not_allowed")
	case errors.Is(err, errApprovalPermDenied):
		fail(c, http.StatusForbidden, "operator_permission_denied")
	case errors.Is(err, errApprovalNotRequestr):
		fail(c, http.StatusForbidden, "not_requester")
	case errors.Is(err, errApprovalNotPending):
		fail(c, http.StatusConflict, "approval_not_pending")
	case errors.Is(err, errApprovalExpired):
		fail(c, http.StatusConflict, "approval_expired")
	default:
		return false
	}
	return true
}

// ---- handlers --------------------------------------------------------------

// CreateApproval: POST /ops-approvals.
func (cs *Console) CreateApproval(c *gin.Context) {
	ctx := c.Request.Context()
	actor := actorOf(c)
	var req struct {
		Action        string `json:"action"`
		Resource      string `json:"resource"`
		Audience      string `json:"audience"`
		PayloadSHA256 string `json:"payload_sha256"`
		TenantID      string `json:"tenant_id"`
		TTLSeconds    int    `json:"ttl_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid_body")
		return
	}
	perm, ok := ActionPerms[req.Action]
	if !ok {
		fail(c, http.StatusBadRequest, "unknown_action")
		return
	}
	if !actor.HasPerm(perm) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "operator_permission_denied", "required": perm})
		return
	}
	req.Resource, req.Audience = strings.TrimSpace(req.Resource), strings.TrimSpace(req.Audience)
	if req.Resource == "" || req.Audience == "" || !sha256Re.MatchString(req.PayloadSHA256) {
		fail(c, http.StatusBadRequest, "invalid_body")
		return
	}
	ttl := ApprovalDefaultTTL
	if req.TTLSeconds != 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
		if ttl < ApprovalMinTTL || ttl > ApprovalMaxTTL {
			fail(c, http.StatusBadRequest, "invalid_ttl")
			return
		}
	}
	var tenant *uuid.UUID
	if req.TenantID != "" {
		t, err := uuid.Parse(req.TenantID)
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid_tenant_id")
			return
		}
		tenant = &t
	}
	r := reasonFrom(c)
	row, err := scanApproval(cs.DB.QueryRow(ctx, `
		INSERT INTO ops_approval_requests
			(action, resource, audience, payload_sha256, reason, reason_code, requester_id, tenant_id, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now() + make_interval(secs => $9))
		RETURNING `+approvalCols,
		req.Action, req.Resource, req.Audience, req.PayloadSHA256, r.Text, string(r.Code), actor.UserID, tenant, ttl.Seconds()))
	if err != nil {
		cs.internalErr(c, "create approval", err)
		return
	}
	c.Set(ctxAuditApproval, row.ID.String())
	SetAudit(c, "approval:"+row.ID.String(), strOf(tenant))
	c.Set(ctxAuditDetails, map[string]interface{}{"approval_action": req.Action, "approval_resource": req.Resource, "audience": req.Audience})
	c.JSON(http.StatusCreated, cs.approvalJSON(ctx, row, actor, map[uuid.UUID]string{}))
}

// ListApprovals: GET /ops-approvals.
func (cs *Console) ListApprovals(c *gin.Context) {
	ctx := c.Request.Context()
	actor := actorOf(c)
	cs.approvals.expire(ctx)
	limit := clampLimit(c.Query("limit"), 25, 100)

	var allowed []string
	for action, perm := range ActionPerms {
		if actor.HasPerm(perm) {
			allowed = append(allowed, action)
		}
	}
	where := " WHERE 1=1"
	var args []interface{}
	arg := func(v interface{}) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	switch c.DefaultQuery("scope", "all") {
	case "mine":
		where += " AND requester_id = " + arg(actor.UserID)
	case "pending_for_me":
		where += " AND status = 'pending' AND requester_id <> " + arg(actor.UserID) + " AND action = ANY(" + arg(allowed) + ")"
	case "all":
		where += " AND (requester_id = " + arg(actor.UserID) + " OR action = ANY(" + arg(allowed) + "))"
	default:
		fail(c, http.StatusBadRequest, "invalid_scope")
		return
	}
	if st := c.Query("status"); st != "" {
		where += " AND status = " + arg(st)
	}
	if ac := c.Query("action"); ac != "" {
		where += " AND action = " + arg(ac)
	}
	if cur := c.Query("cursor"); cur != "" {
		ts, id, err := decodeCursor(cur)
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid_cursor")
			return
		}
		where += fmt.Sprintf(" AND (created_at, id::text) < (%s, %s)", arg(ts), arg(id))
	}
	rows, err := cs.DB.Query(ctx, `SELECT `+approvalCols+` FROM ops_approval_requests`+where+
		fmt.Sprintf(` ORDER BY created_at DESC, id::text DESC LIMIT %s`, arg(limit+1)), args...)
	if err != nil {
		cs.internalErr(c, "list approvals", err)
		return
	}
	var list []*approvalRow
	for rows.Next() {
		a, sErr := scanApproval(rows)
		if sErr != nil {
			rows.Close()
			cs.internalErr(c, "scan approval", sErr)
			return
		}
		list = append(list, a)
	}
	rows.Close()
	var next interface{}
	if len(list) > limit {
		next = encodeCursor(list[limit-1].CreatedAt, list[limit-1].ID.String())
		list = list[:limit]
	}
	labels := map[uuid.UUID]string{}
	items := make([]gin.H, 0, len(list))
	for _, a := range list {
		items = append(items, cs.approvalJSON(ctx, a, actor, labels))
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "next_cursor": next})
}

// visibleTo reports whether the operator may see an approval.
func visibleTo(a *approvalRow, actor *operatorauth.Actor) bool {
	if a.RequesterID == actor.UserID {
		return true
	}
	perm, ok := ActionPerms[a.Action]
	return ok && actor.HasPerm(perm)
}

// GetApproval: GET /ops-approvals/:id.
func (cs *Console) GetApproval(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid_id")
		return
	}
	a, err := cs.approvals.get(c.Request.Context(), id)
	if err != nil || !visibleTo(a, actorOf(c)) {
		fail(c, http.StatusNotFound, "not_found")
		return
	}
	c.JSON(http.StatusOK, cs.approvalJSON(c.Request.Context(), a, actorOf(c), map[uuid.UUID]string{}))
}

// DecideApproval returns the approve / reject handler.
func (cs *Console) DecideApproval(approve bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		actor := actorOf(c)
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid_id")
			return
		}
		var body struct {
			Note string `json:"note"`
		}
		_ = c.ShouldBindJSON(&body)
		if !approve && strings.TrimSpace(body.Note) == "" {
			fail(c, http.StatusBadRequest, "note_required")
			return
		}
		cur, err := cs.approvals.get(ctx, id)
		if err != nil {
			approvalErr(c, err)
			return
		}
		perm := ActionPerms[cur.Action]
		if perm == "" || !actor.HasPerm(perm) {
			approvalErr(c, errApprovalPermDenied)
			return
		}
		if cur.RequesterID == actor.UserID {
			approvalErr(c, errSelfApproval)
			return
		}
		status := "rejected"
		if approve {
			status = "approved"
		}
		row, err := scanApproval(cs.DB.QueryRow(ctx, `
			UPDATE ops_approval_requests
			   SET status = $2, approver_id = $3, decided_at = now(), decision_note = NULLIF($4,'')
			 WHERE id = $1 AND status = 'pending' AND expires_at > now() AND requester_id <> $3
			RETURNING `+approvalCols, id, status, actor.UserID, strings.TrimSpace(body.Note)))
		if errors.Is(err, pgx.ErrNoRows) {
			if now, gErr := cs.approvals.get(ctx, id); gErr == nil && now.Status == "expired" {
				approvalErr(c, errApprovalExpired)
			} else {
				approvalErr(c, errApprovalNotPending)
			}
			return
		}
		if err != nil {
			cs.internalErr(c, "decide approval", err)
			return
		}
		c.Set(ctxAuditApproval, row.ID.String())
		SetAudit(c, "approval:"+row.ID.String(), strOf(row.TenantID))
		c.Set(ctxAuditDetails, map[string]interface{}{"approval_action": row.Action, "approval_resource": row.Resource, "decision": status})

		out := cs.approvalJSON(ctx, row, actor, map[uuid.UUID]string{})
		if approve {
			exp := time.Now().Add(ApprovalTokenTTL)
			if row.ExpiresAt.Before(exp) {
				exp = row.ExpiresAt
			}
			now := time.Now()
			tok, sErr := cs.approvals.signer.SignOpsToken(jwt.MapClaims{
				"aud": []string{row.Audience}, "sub": row.ID.String(), "gty": "ops_approval",
				"act": row.Action, "res": row.Resource, "psh": row.PayloadSHA,
				"req": row.RequesterID.String(), "apr": actor.UserID.String(),
				"iat": now.Unix(), "nbf": now.Unix(), "exp": exp.Unix(), "jti": uuid.NewString(),
			})
			if sErr != nil {
				cs.internalErr(c, "sign approval token", sErr)
				return
			}
			out["approval_token"] = tok
		}
		c.JSON(http.StatusOK, out)
	}
}

// CancelApproval: POST /ops-approvals/:id/cancel (requester only).
func (cs *Console) CancelApproval(c *gin.Context) {
	ctx := c.Request.Context()
	actor := actorOf(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid_id")
		return
	}
	cur, err := cs.approvals.get(ctx, id)
	if err != nil {
		approvalErr(c, err)
		return
	}
	if cur.RequesterID != actor.UserID {
		approvalErr(c, errApprovalNotRequestr)
		return
	}
	row, err := scanApproval(cs.DB.QueryRow(ctx, `
		UPDATE ops_approval_requests SET status = 'cancelled', decided_at = now()
		 WHERE id = $1 AND requester_id = $2 AND status IN ('pending','approved') RETURNING `+approvalCols, id, actor.UserID))
	if errors.Is(err, pgx.ErrNoRows) {
		approvalErr(c, errApprovalNotPending)
		return
	}
	if err != nil {
		cs.internalErr(c, "cancel approval", err)
		return
	}
	c.Set(ctxAuditApproval, row.ID.String())
	SetAudit(c, "approval:"+row.ID.String(), strOf(row.TenantID))
	c.JSON(http.StatusOK, cs.approvalJSON(ctx, row, actor, map[uuid.UUID]string{}))
}

// ConsumeApproval: POST /ops-approvals/:id/consume. Service-scope only; fails
// closed on any mismatch.
func (cs *Console) ConsumeApproval(c *gin.Context) {
	ctx := c.Request.Context()
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid_id")
		return
	}
	var req struct {
		Audience      string `json:"audience"`
		Action        string `json:"action"`
		Resource      string `json:"resource"`
		PayloadSHA256 string `json:"payload_sha256"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Audience == "" || req.Action == "" || req.Resource == "" || !sha256Re.MatchString(req.PayloadSHA256) {
		fail(c, http.StatusBadRequest, "invalid_body")
		return
	}
	cs.approvals.expire(ctx)
	row, err := cs.approvals.consume(ctx, id, req.Audience, req.Action, req.Resource, req.PayloadSHA256)
	if errors.Is(err, ErrApprovalInvalid) {
		fail(c, http.StatusConflict, "approval_invalid")
		return
	}
	if err != nil {
		cs.internalErr(c, "consume approval", err)
		return
	}
	// Service call: attribute the audit row to the approver (the human whose
	// authority was spent).
	if row.ApproverID != nil && cs.Audit != nil {
		if aErr := cs.Audit.Record(ctx, opsaudit.Event{
			ActorUserID: *row.ApproverID, Action: "approval.consume", ApprovalID: row.ID.String(),
			Resource: row.Resource, TenantID: strOf(row.TenantID), Success: true,
			ReasonCode: strVal(row.ReasonCode), Reason: row.Reason, RequestID: c.GetHeader("X-Request-ID"),
			IPAddress: c.ClientIP(), UserAgent: c.Request.UserAgent(),
			Details: mustJSON(map[string]interface{}{"approval_action": row.Action, "audience": row.Audience, "requester_id": row.RequesterID}),
		}); aErr != nil {
			cs.Log.Error("ops audit write failed", zap.String("action", "approval.consume"), zap.Error(aErr))
		}
	}
	c.JSON(http.StatusOK, gin.H{"id": row.ID, "approver_id": row.ApproverID, "requester_id": row.RequesterID, "consumed_at": row.UsedAt})
}

func strOf(u *uuid.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

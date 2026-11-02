// SPDX-License-Identifier: AGPL-3.0-or-later

package opsconsole

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

const (
	searchDefaultLimit = 25
	searchMaxLimit     = 100
)

type tenantInfo struct{ ID, Slug, Name string }

// userStatus folds the account flags into the console's three states.
func userStatus(isActive, isLocked bool, activation string) string {
	switch activation {
	case "deactivated", "admin_deleted", "pending_deletion", "suspended":
		return "disabled"
	}
	if !isActive {
		return "disabled"
	}
	if isLocked {
		return "locked"
	}
	return "active"
}

func displayName(u *models.User) string {
	if u.DisplayName != nil && strings.TrimSpace(*u.DisplayName) != "" {
		return *u.DisplayName
	}
	var parts []string
	if u.FirstName != nil && *u.FirstName != "" {
		parts = append(parts, *u.FirstName)
	}
	if u.LastName != nil && *u.LastName != "" {
		parts = append(parts, *u.LastName)
	}
	if len(parts) > 0 {
		return strings.Join(parts, " ")
	}
	return u.Username
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// statusClause is the SQL predicate for a status filter ("" when unfiltered).
func statusClause(status string) (string, bool) {
	const disabled = `(NOT u.is_active OR COALESCE(u.activation_status,'') IN ('deactivated','admin_deleted','pending_deletion','suspended'))`
	switch status {
	case "":
		return "", true
	case "disabled":
		return " AND " + disabled, true
	case "locked":
		return " AND u.is_locked AND NOT " + disabled, true
	case "active":
		return " AND NOT u.is_locked AND NOT " + disabled, true
	}
	return "", false
}

func (cs *Console) tenantInfos(c *gin.Context, ids []uuid.UUID) (map[uuid.UUID]tenantInfo, error) {
	out := map[uuid.UUID]tenantInfo{}
	if len(ids) == 0 {
		return out, nil
	}
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	rows, err := cs.DB.Query(c.Request.Context(), `SELECT id, slug, name FROM iam_tenants WHERE id = ANY($1::uuid[])`, strs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var t tenantInfo
		if err := rows.Scan(&id, &t.Slug, &t.Name); err != nil {
			return nil, err
		}
		t.ID = id.String()
		out[id] = t
	}
	return out, rows.Err()
}

// SearchUsers: GET /ops/users. Cross-tenant, masked.
func (cs *Console) SearchUsers(c *gin.Context) {
	ctx := c.Request.Context()
	q := strings.TrimSpace(c.Query("q"))
	limit := clampLimit(c.Query("limit"), searchDefaultLimit, searchMaxLimit)

	sc, ok := statusClause(c.Query("status"))
	if !ok {
		fail(c, http.StatusBadRequest, "invalid_status")
		return
	}
	where := ` WHERE u.username NOT ILIKE 'svc-%'` + sc
	var args []interface{}
	arg := func(v interface{}) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if t := c.Query("tenant_id"); t != "" {
		tid, err := uuid.Parse(t)
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid_tenant_id")
			return
		}
		where += " AND u.tenant_id = " + arg(tid)
	}
	if q != "" {
		if id, err := uuid.Parse(q); err == nil {
			where += " AND u.id = " + arg(id)
		} else if strings.Contains(q, "@") {
			where += " AND u.email_hash = " + arg(repositories.EmailLookupHash(q))
		} else {
			lq := strings.ToLower(q)
			like := arg(escapeLike(lq) + "%")
			slug := arg(lq)
			where += ` AND (lower(u.username) LIKE ` + like + ` ESCAPE '\' OR u.tenant_id IN (SELECT t.id FROM iam_tenants t WHERE lower(t.slug) = ` + slug + `))`
		}
	}
	if cur := c.Query("cursor"); cur != "" {
		ts, id, err := decodeCursor(cur)
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid_cursor")
			return
		}
		where += fmt.Sprintf(" AND (u.created_at, u.id::text) < (%s, %s)", arg(ts), arg(id))
	}
	sql := `SELECT u.id, u.created_at FROM iam_users u` + where +
		fmt.Sprintf(` ORDER BY u.created_at DESC, u.id::text DESC LIMIT %s`, arg(limit+1))

	rows, err := cs.DB.Query(ctx, sql, args...)
	if err != nil {
		cs.internalErr(c, "user search", err)
		return
	}
	type hit struct {
		id uuid.UUID
		at time.Time
	}
	var hits []hit
	for rows.Next() {
		var h hit
		if err := rows.Scan(&h.id, &h.at); err != nil {
			rows.Close()
			cs.internalErr(c, "user search scan", err)
			return
		}
		hits = append(hits, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		cs.internalErr(c, "user search rows", err)
		return
	}
	var next interface{}
	if len(hits) > limit {
		last := hits[limit-1]
		next = encodeCursor(last.at, last.id.String())
		hits = hits[:limit]
	}

	users := make([]*models.User, 0, len(hits))
	tids := map[uuid.UUID]struct{}{}
	for _, h := range hits {
		u, err := cs.Users.GetByID(ctx, h.id)
		if err != nil || u == nil {
			if err != nil {
				cs.Log.Warn("ops user search: hydrate failed", zap.String("user_id", h.id.String()), zap.Error(err))
			}
			continue
		}
		users = append(users, u)
		tids[u.TenantID] = struct{}{}
	}
	tenantIDs := make([]uuid.UUID, 0, len(tids))
	for id := range tids {
		tenantIDs = append(tenantIDs, id)
	}
	tmap, err := cs.tenantInfos(c, tenantIDs)
	if err != nil {
		cs.internalErr(c, "tenant lookup", err)
		return
	}

	items := make([]gin.H, 0, len(users))
	for _, u := range users {
		t := tmap[u.TenantID]
		items = append(items, gin.H{
			"id":                  u.ID,
			"display_name_masked": MaskName(displayName(u)),
			"email_masked":        MaskEmail(u.Email),
			"tenant_id":           u.TenantID,
			"tenant_slug":         t.Slug,
			"tenant_name":         t.Name,
			"status":              userStatus(u.IsActive, u.IsLocked, u.ActivationStatus),
			"mfa_enabled":         u.MFAEnabled,
			"last_login_at":       u.LastLoginAt,
			"created_at":          u.CreatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "next_cursor": next})
}

// GetUser: GET /ops/users/:id. Masked detail with memberships across tenants.
func (cs *Console) GetUser(c *gin.Context) {
	ctx := c.Request.Context()
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid_user_id")
		return
	}
	u, err := cs.Users.GetByID(ctx, id)
	if err != nil {
		cs.internalErr(c, "get user", err)
		return
	}
	if u == nil {
		fail(c, http.StatusNotFound, "not_found")
		return
	}

	var memberships []gin.H
	err = repositories.WithUserMembershipScope(ctx, cs.DB, id, func(tx pgx.Tx) error {
		rows, qErr := tx.Query(ctx, `
			SELECT m.tenant_id, t.slug, t.name, m.seat_class, m.status
			  FROM iam_user_memberships m
			  JOIN iam_tenants t ON t.id = m.tenant_id
			 WHERE m.user_id = $1
			 ORDER BY m.created_at`, id)
		if qErr != nil {
			return qErr
		}
		defer rows.Close()
		for rows.Next() {
			var tid uuid.UUID
			var slug, name, seat, status string
			if sErr := rows.Scan(&tid, &slug, &name, &seat, &status); sErr != nil {
				return sErr
			}
			memberships = append(memberships, gin.H{"tenant_id": tid, "tenant_slug": slug, "tenant_name": name, "seat_class": seat, "status": status})
		}
		return rows.Err()
	})
	if err != nil {
		cs.internalErr(c, "memberships", err)
		return
	}
	if memberships == nil {
		memberships = []gin.H{}
	}

	tmap, err := cs.tenantInfos(c, []uuid.UUID{u.TenantID})
	if err != nil {
		cs.internalErr(c, "tenant lookup", err)
		return
	}
	t := tmap[u.TenantID]

	methods := []string{}
	if u.MFATOTPEnabled {
		methods = append(methods, "totp")
	}
	if u.MFAEmailEnabled {
		methods = append(methods, "email")
	}
	if has, wErr := cs.Users.HasActiveWebAuthnCredential(ctx, id); wErr == nil && has {
		methods = append(methods, "webauthn")
	}
	sessions, sErr := cs.Sessions.CountActiveSessions(ctx, id)
	if sErr != nil {
		cs.Log.Warn("ops user detail: session count failed", zap.Error(sErr))
	}
	isStaff := false
	if roles, rErr := cs.PlatformAuthority.ActiveRoles(ctx, id); rErr == nil {
		isStaff = len(roles) > 0
	}

	var phone interface{}
	if u.Phone != nil && *u.Phone != "" {
		phone = MaskPhone(*u.Phone)
	}
	c.JSON(http.StatusOK, gin.H{
		"id":                   u.ID,
		"display_name_masked":  MaskName(displayName(u)),
		"email_masked":         MaskEmail(u.Email),
		"phone_masked":         phone,
		"username_masked":      MaskUsername(u.Username),
		"tenant_id":            u.TenantID,
		"tenant_slug":          t.Slug,
		"tenant_name":          t.Name,
		"status":               userStatus(u.IsActive, u.IsLocked, u.ActivationStatus),
		"lock_reason":          u.LockReason,
		"locked_until":         u.LockedUntil,
		"email_verified":       u.IsEmailVerified,
		"mfa_enabled":          u.MFAEnabled,
		"mfa_methods":          methods,
		"active_session_count": sessions,
		"last_login_at":        u.LastLoginAt,
		"created_at":           u.CreatedAt,
		"is_platform_staff":    isStaff,
		"memberships":          memberships,
	})
}

// UserElevations: GET /ops/users/:id/elevations. JIT + break-glass history.
func (cs *Console) UserElevations(c *gin.Context) {
	ctx := c.Request.Context()
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid_user_id")
		return
	}
	filter := models.ElevationListFilter{RequesterID: &id}
	el, err := cs.JIT.ListElevations(ctx, filter, 1, 100)
	if err != nil {
		cs.internalErr(c, "list elevations", err)
		return
	}
	bg, err := cs.JIT.ListBreakGlass(ctx, filter, 1, 100)
	if err != nil {
		cs.internalErr(c, "list break-glass", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"elevations": el.Elevations, "break_glass": bg.Elevations})
}

// piiFields maps the API field name to its extractor.
var piiFields = map[string]func(*models.User) string{
	"email": func(u *models.User) string { return u.Email },
	"phone": func(u *models.User) string {
		if u.Phone != nil {
			return *u.Phone
		}
		return ""
	},
	"name":     displayName,
	"username": func(u *models.User) string { return u.Username },
}

const (
	piiRevealLimit  = 20
	piiRevealWindow = time.Hour
	piiRevealTTL    = 60
)

// RevealPII: POST /ops/pii-reveals. T2; the value is never logged.
func (cs *Console) RevealPII(c *gin.Context) {
	ctx := c.Request.Context()
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
		Field       string `json:"field"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid_body")
		return
	}
	extract, ok := piiFields[req.Field]
	if req.SubjectType != "user" || !ok {
		fail(c, http.StatusBadRequest, "invalid_subject_or_field")
		return
	}
	uid, err := uuid.Parse(req.SubjectID)
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid_subject_id")
		return
	}
	a := actorOf(c)
	u, err := cs.Users.GetByID(ctx, uid)
	if err != nil {
		cs.internalErr(c, "pii reveal lookup", err)
		return
	}
	if u == nil {
		fail(c, http.StatusNotFound, "not_found")
		return
	}
	SetAudit(c, fmt.Sprintf("user:%s:%s", uid, req.Field), u.TenantID.String())

	// Fail closed: a reveal that cannot be rate limited is refused.
	if cs.Limiter == nil {
		fail(c, http.StatusServiceUnavailable, "rate_limiter_unavailable")
		return
	}
	res, err := cs.Limiter.Check(ctx, "ops_pii_reveal:"+a.UserID.String(), piiRevealLimit, piiRevealWindow, 0)
	if err != nil {
		cs.Log.Error("ops pii reveal: rate limiter failed", zap.Error(err))
		fail(c, http.StatusServiceUnavailable, "rate_limiter_unavailable")
		return
	}
	if !res.Allowed {
		retry := int(res.RetryAfter / time.Second)
		if retry < 1 {
			retry = 60
		}
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited", "retry_after_seconds": retry})
		return
	}

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, gin.H{
		"field":       req.Field,
		"value":       extract(u),
		"revealed_at": time.Now().UTC(),
		"expires_in":  piiRevealTTL,
	})
}

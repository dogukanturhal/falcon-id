// SPDX-License-Identifier: AGPL-3.0-or-later

package opsconsole

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// The adapters below put the operator chain in front of the existing tenant
// admin handlers (sessions, MFA, devices, unlock, impersonation) without
// reimplementing them: they only translate the console's route shape into the
// path params / query / body those handlers already read. The synthetic
// platform-admin CurrentUser set by the chain's bridge is what lets the
// handlers act across tenants.

// SessionsList serves GET /ops/users/:id/sessions via the admin session list.
func SessionsList(listAll gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		q := c.Request.URL.Query()
		q.Set("user_id", c.Param("id"))
		c.Request.URL.RawQuery = q.Encode()
		listAll(c)
	}
}

// RevokeSession serves POST /ops/users/:id/sessions/:session_id/revoke. The
// session must belong to :id.
func (cs *Console) RevokeSession(revoke gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid, err := uuid.Parse(c.Param("id"))
		sid, sErr := uuid.Parse(c.Param("session_id"))
		if err != nil || sErr != nil {
			fail(c, http.StatusBadRequest, "invalid_id")
			return
		}
		sess, err := cs.Sessions.GetByID(c.Request.Context(), sid)
		if err != nil || sess == nil || sess.UserID != uid {
			fail(c, http.StatusNotFound, "not_found")
			return
		}
		SetAudit(c, "session:"+sid.String(), "")
		c.Set(ctxAuditDetails, map[string]interface{}{"user_id": uid.String()})
		setParam(c, "id", sid.String())
		revoke(c)
	}
}

// MFAReset serves POST /ops/users/:id/mfa/reset via the admin MFA setter with
// enabled=false (clears every factor; the user re-enrols).
func MFAReset(setMFA gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = io.NopCloser(bytes.NewReader([]byte(`{"enabled":false}`)))
		c.Request.ContentLength = int64(len(`{"enabled":false}`))
		setMFA(c)
	}
}

// Unlock serves POST /ops/users/:id/unlock via the platform-management unlock,
// which wants the user's tenant in the path.
func (cs *Console) Unlock(unlock gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid, err := uuid.Parse(c.Param("id"))
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid_user_id")
			return
		}
		u, err := cs.Users.GetByID(c.Request.Context(), uid)
		if err != nil {
			cs.internalErr(c, "unlock lookup", err)
			return
		}
		if u == nil {
			fail(c, http.StatusNotFound, "not_found")
			return
		}
		SetAudit(c, "user:"+uid.String(), u.TenantID.String())
		c.Params = append(c.Params,
			gin.Param{Key: "tenant_id", Value: u.TenantID.String()},
			gin.Param{Key: "user_id", Value: uid.String()})
		unlock(c)
	}
}

// ScopeUserTenant sets the audit tenant for routes keyed by :id (user).
func (cs *Console) ScopeUserTenant(c *gin.Context) {
	uid, err := uuid.Parse(c.Param("id"))
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid_user_id")
		return
	}
	u, err := cs.Users.GetByID(c.Request.Context(), uid)
	if err != nil {
		cs.internalErr(c, "user lookup", err)
		return
	}
	if u == nil {
		fail(c, http.StatusNotFound, "not_found")
		return
	}
	SetAudit(c, "user:"+uid.String(), u.TenantID.String())
	c.Next()
}

// ImpersonationList serves GET /ops/impersonations (tenant_id required: the
// underlying listing is tenant scoped).
func ImpersonationList(list gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		tid, err := uuid.Parse(c.Query("tenant_id"))
		if err != nil {
			fail(c, http.StatusBadRequest, "tenant_id_required")
			return
		}
		c.Set("tenant_id", tid)
		list(c)
	}
}

// ImpersonationEnd serves POST /ops/impersonations/:id/end, scoping the
// handler to the session's own tenant.
func ImpersonationEnd(end gin.HandlerFunc, tenantOf func(ctx context.Context, id uuid.UUID) (uuid.UUID, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		sid, err := uuid.Parse(c.Param("id"))
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid_id")
			return
		}
		tid, err := tenantOf(c.Request.Context(), sid)
		if err != nil {
			fail(c, http.StatusNotFound, "not_found")
			return
		}
		SetAudit(c, "impersonation:"+sid.String(), tid.String())
		c.Set("tenant_id", tid)
		end(c)
	}
}

func setParam(c *gin.Context, key, val string) {
	for i := range c.Params {
		if c.Params[i].Key == key {
			c.Params[i].Value = val
			return
		}
	}
	c.Params = append(c.Params, gin.Param{Key: key, Value: val})
}

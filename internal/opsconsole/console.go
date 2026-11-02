// SPDX-License-Identifier: AGPL-3.0-or-later

package opsconsole

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/operatorauth"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/opsaudit"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

// StepUpMaxAge is the auth_time freshness T2/T3 routes demand.
const StepUpMaxAge = 5 * time.Minute

// Context keys handlers use to enrich the audit row written by the chain.
const (
	ctxReason        = "ops_reason"
	ctxAuditResource = "ops_audit_resource"
	ctxAuditTenant   = "ops_audit_tenant"
	ctxAuditApproval = "ops_audit_approval"
	ctxAuditDetails  = "ops_audit_details"
)

// RateLimiter is the per-operator limiter (*redis.RateLimiter).
type RateLimiter interface {
	Check(ctx context.Context, key string, limit int, window time.Duration, blockDuration time.Duration) (*redispkg.RateLimitResult, error)
}

// TokenSigner signs approval tokens (*services.OAuthProviderService).
type TokenSigner interface {
	SignOpsToken(claims jwt.MapClaims) (string, error)
}

// StandingRoleStore is the SpiceDB slice offboarding / viewer revoke needs
// (*spicedb.Client).
type StandingRoleStore interface {
	DeletePlatformElevation(ctx context.Context, userID uuid.UUID, roleKey string) (string, error)
}

// Deps are the collaborators of Console.
type Deps struct {
	DB          repositories.DBTX
	Verifier    *operatorauth.Verifier
	ServiceAuth gin.HandlerFunc
	Audit       *opsaudit.Consumer
	Log         *zap.Logger

	Users    *repositories.UserRepository
	Sessions *repositories.SessionRepository
	// PlatformAuthority reads the live role projection (is this user staff).
	PlatformAuthority *repositories.PlatformAuthorityRepository
	Authority         *services.PlatformAuthority
	JITRepo           *repositories.PlatformElevationRepository
	JIT               *services.PlatformJITService
	Spice             StandingRoleStore
	Signer            TokenSigner
	Limiter           RateLimiter
	// LiveState overrides how an operator's live standing is read (tests);
	// default: Users + Authority.
	LiveState func(ctx context.Context, a *operatorauth.Actor) (liveState, error)
	// KillSessions ends every session and token of a user (offboarding).
	KillSessions func(ctx context.Context, userID uuid.UUID, reason string) error
}

// Console holds the operator-chain handlers and middleware.
type Console struct {
	Deps
	approvals *approvalStore
	live      liveness
}

// New builds a Console.
func New(d Deps) *Console {
	if d.Log == nil {
		d.Log = zap.NewNop()
	}
	c := &Console{Deps: d}
	c.approvals = &approvalStore{db: d.DB, users: d.Users, signer: d.Signer}
	return c
}

// Spec describes one route's guard rails.
type Spec struct {
	// Scope is the ServiceClient scope the calling BFF needs.
	Scope string
	// Perm is the ops:<domain>:<verb> permission in the assertion.
	Perm string
	// StepUp demands auth_time <= 5 min with a second factor (T2/T3).
	StepUp bool
	// Action, when set, marks a mutation: reason_code + reason are required in
	// the JSON body and the call is audited under this action name.
	Action string
	// NoReason skips the reason_code/reason requirement for an audited
	// mutation whose body carries its own justification (approval decisions).
	NoReason bool
	// Resource derives the audit resource (and tenant) from the request; a
	// handler can override via SetAudit. Optional.
	Resource func(c *gin.Context) (resource, tenant string)
}

// Chain returns the full middleware chain for a route: ServiceAuth ->
// RequireScope -> RequireOperator -> [RequireStepUp] -> bridge -> [reason ->
// audit] -> handlers.
func (cs *Console) Chain(sp Spec, handlers ...gin.HandlerFunc) []gin.HandlerFunc {
	chain := []gin.HandlerFunc{
		cs.ServiceAuth,
		middleware.RequireScope(sp.Scope),
		cs.Verifier.RequireOperator(sp.Perm),
		cs.liveCheck,
	}
	if sp.StepUp {
		chain = append(chain, operatorauth.RequireStepUp(StepUpMaxAge))
	}
	chain = append(chain, cs.bridge)
	if sp.Action != "" {
		if !sp.NoReason {
			// Standing platform_admin gets reason_code/reason auto-filled
			// (also for the bridged legacy handlers that re-read the body).
			chain = append(chain, operatorauth.DirectReason(operatorauth.ReasonInBody), cs.reasonMW)
		}
		chain = append(chain, cs.auditMW(sp))
	}
	return append(chain, handlers...)
}

// ServiceChain is the chain of a service-only route (no operator): used by
// approval consumption.
func (cs *Console) ServiceChain(scope string, handlers ...gin.HandlerFunc) []gin.HandlerFunc {
	return append([]gin.HandlerFunc{cs.ServiceAuth, middleware.RequireScope(scope)}, handlers...)
}

// bridge exposes the verified operator under the context keys the legacy admin
// handlers (JIT, sessions, MFA, devices, impersonation) read, so they serve
// the operator chain unchanged. The synthetic CurrentUser is an internal-tenant
// platform admin; that is what lets those handlers act across tenants, and it
// exists only after operatorauth verified the assertion and its permission.
func (cs *Console) bridge(c *gin.Context) {
	a := operatorauth.ActorFrom(c)
	if a == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "actor_assertion_required"})
		return
	}
	tenant, err := uuid.Parse(a.TenantID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "operator_requires_internal_tenant"})
		return
	}
	middleware.SetOperatorActor(c, a.UserID, tenant)
	c.Set("user_id", a.UserID)
	c.Set("tenant_id", tenant)
	c.Set(middleware.CurrentUserKey, &models.CurrentUser{
		ID:                        a.UserID,
		TenantID:                  tenant,
		Email:                     a.Email,
		IsPlatformAdmin:           true,
		PlatformAuthorityVerified: true,
	})
	c.Next()
}

// reasonMW requires {reason_code, reason} in the JSON body and leaves the body
// readable for the handler.
func (cs *Console) reasonMW(c *gin.Context) {
	var raw []byte
	if c.Request.Body != nil {
		raw, _ = io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	r, ok := parseReasonBody(raw)
	if !ok {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error":  "reason_required",
			"detail": "reason_code from the fixed list and a reason of at least 20 characters are required",
		})
		return
	}
	c.Set(ctxReason, r)
	c.Next()
}

// auditMW audits a mutation in two rows of platform_admin_audit_log, because
// the wrapped handlers mutate through their own pools / SpiceDB / session
// stores and cannot share one DB transaction with the audit insert:
//
//  1. BEFORE the handler: an intent row "<action>.attempt" (with the reason).
//     If it cannot be written the mutation is refused (503 audit_unavailable):
//     fail closed, nothing has changed yet.
//  2. AFTER the handler: the result row "<action>" (success / failure, resource,
//     tenant, approval) linked to the intent by details.intent_event_id.
//
// A failure of the result write is logged loudly; the intent row remains, so
// the trail never loses the fact that the operator attempted the action.
func (cs *Console) auditMW(sp Spec) gin.HandlerFunc {
	return func(c *gin.Context) {
		intentID, ok := cs.recordIntent(c, sp)
		if !ok {
			return
		}
		c.Next()
		cs.recordResult(c, sp, intentID)
	}
}

// baseEvent is the part of an audit event known before the handler runs.
func (cs *Console) baseEvent(c *gin.Context, sp Spec, a *operatorauth.Actor) opsaudit.Event {
	ev := opsaudit.Event{
		EventID:     uuid.New(),
		ActorUserID: a.UserID,
		ActorEmail:  a.Email,
		ElevationID: a.ElevationID,
		Action:      sp.Action,
		RequestID:   c.GetHeader("X-Request-ID"),
		IPAddress:   c.ClientIP(),
		UserAgent:   c.Request.UserAgent(),
	}
	if sp.Resource != nil {
		ev.Resource, ev.TenantID = sp.Resource(c)
	}
	if rr := reasonFrom(c); rr.Code != "" {
		ev.ReasonCode, ev.Reason = string(rr.Code), rr.Text
	}
	return ev
}

// recordIntent writes the pre-mutation row; on failure it aborts the request.
func (cs *Console) recordIntent(c *gin.Context, sp Spec) (uuid.UUID, bool) {
	a := operatorauth.ActorFrom(c)
	if a == nil || cs.Audit == nil {
		cs.Log.Error("ops audit unavailable: refusing mutation", zap.String("action", sp.Action))
		fail(c, http.StatusServiceUnavailable, "audit_unavailable")
		return uuid.Nil, false
	}
	ev := cs.baseEvent(c, sp, a)
	ev.Action = sp.Action + ".attempt"
	ev.Success = true
	ev.Details = mustJSON(map[string]interface{}{"phase": "intent", "route": c.FullPath()})
	if err := cs.Audit.Record(c.Request.Context(), ev); err != nil {
		cs.Log.Error("ops audit intent write failed: refusing mutation", zap.String("action", sp.Action), zap.String("actor", a.UserID.String()), zap.Error(err))
		fail(c, http.StatusServiceUnavailable, "audit_unavailable")
		return uuid.Nil, false
	}
	return ev.EventID, true
}

func (cs *Console) recordResult(c *gin.Context, sp Spec, intentID uuid.UUID) {
	a := operatorauth.ActorFrom(c)
	if a == nil || cs.Audit == nil {
		return
	}
	ev := cs.baseEvent(c, sp, a)
	ev.EventID = uuid.New()
	ev.Success = c.Writer.Status() < http.StatusBadRequest
	if v, ok := c.Get(ctxAuditResource); ok {
		ev.Resource, _ = v.(string)
	}
	if v, ok := c.Get(ctxAuditTenant); ok {
		ev.TenantID, _ = v.(string)
	}
	if v, ok := c.Get(ctxAuditApproval); ok {
		ev.ApprovalID, _ = v.(string)
	}
	details := map[string]interface{}{"status": c.Writer.Status(), "route": c.FullPath(), "phase": "result", "intent_event_id": intentID.String()}
	if v, ok := c.Get(ctxAuditDetails); ok {
		if m, ok := v.(map[string]interface{}); ok {
			for k, val := range m {
				details[k] = val
			}
		}
	}
	ev.Details = mustJSON(details)
	if err := cs.Audit.Record(c.Request.Context(), ev); err != nil {
		cs.Log.Error("ops audit result write failed (intent row exists)", zap.String("action", sp.Action), zap.String("intent_event_id", intentID.String()), zap.String("actor", a.UserID.String()), zap.Error(err))
	}
}

// SetAudit lets a handler name the audited resource / tenant.
func SetAudit(c *gin.Context, resource, tenant string) {
	if resource != "" {
		c.Set(ctxAuditResource, resource)
	}
	if tenant != "" {
		c.Set(ctxAuditTenant, tenant)
	}
}

// ParamResource is a Spec.Resource that audits "<kind>:<:param>".
func ParamResource(kind, param string) func(*gin.Context) (string, string) {
	return func(c *gin.Context) (string, string) { return kind + ":" + c.Param(param), "" }
}

func fail(c *gin.Context, status int, code string) {
	c.AbortWithStatusJSON(status, gin.H{"error": code})
}

func (cs *Console) internalErr(c *gin.Context, what string, err error) {
	cs.Log.Error("ops console: "+what, zap.Error(err))
	fail(c, http.StatusInternalServerError, "internal_error")
}

// ---- cursors ---------------------------------------------------------------

func encodeCursor(ts time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(ts.UTC().Format(time.RFC3339Nano) + "|" + id))
}

var errBadCursor = errors.New("invalid cursor")

func decodeCursor(s string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, "", errBadCursor
	}
	ts, id, ok := strings.Cut(string(raw), "|")
	if !ok || id == "" {
		return time.Time{}, "", errBadCursor
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, "", errBadCursor
	}
	return t, id, nil
}

func clampLimit(raw string, def, max int) int {
	n := def
	if raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			n = v
		}
	}
	if n > max {
		n = max
	}
	return n
}

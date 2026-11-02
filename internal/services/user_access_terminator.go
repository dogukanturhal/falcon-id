// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"go.uber.org/zap"
)

// defaultUserBlacklistTTL is used when no config-derived TTL is supplied.
const defaultUserBlacklistTTL = 16 * time.Minute

// UserBlacklistTTL derives the flat user-level blacklist TTL from config:
// access-token lifetime + clock-skew leeway + 1m. Sessions and refresh tokens
// are already dead when it is written, so it only has to outlive in-flight
// JWTs; kept short because the marker has no issued-before semantics and would
// otherwise block a re-enabled user. (Re-enable also clears it explicitly.)
func UserBlacklistTTL(cfg *config.Config) time.Duration {
	if cfg == nil || cfg.AccessTokenExpiry <= 0 {
		return defaultUserBlacklistTTL
	}
	return cfg.AccessTokenExpiry + cfg.JWTClockSkewLeeway + time.Minute
}

// terminatorSessionRepo is the session-row surface the terminator needs.
type terminatorSessionRepo interface {
	GetActiveSessions(ctx context.Context, userID uuid.UUID) ([]models.Session, error)
	EndSession(ctx context.Context, id uuid.UUID, reason string) error
	EndAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error
	EndAllUserSessionsExcept(ctx context.Context, userID uuid.UUID, exceptID uuid.UUID, reason string) error
}

// terminatorTokenRevoker revokes OAuth tokens (satisfied by *TokenService).
type terminatorTokenRevoker interface {
	RevokeAllUserOAuthTokens(ctx context.Context, userID uuid.UUID, reason string) error
	RevokeOAuthTokensBySession(ctx context.Context, sessionID, userID uuid.UUID) error
}

// terminatorSSOCache drops IdP SSO sessions (satisfied by *redis.SessionCache).
type terminatorSSOCache interface {
	DeleteAllIdpSessionsByUserExcept(ctx context.Context, userID, exceptRowID uuid.UUID) ([]uuid.UUID, error)
	DeleteIdpSessionsByRowID(ctx context.Context, userID, rowID uuid.UUID) ([]uuid.UUID, error)
}

// terminatorBlacklist is the access-token blacklist (satisfied by *redis.TokenBlacklist).
type terminatorBlacklist interface {
	BlacklistUserTokens(ctx context.Context, userID uuid.UUID, reason string, ttl time.Duration) error
	BlacklistSession(ctx context.Context, sessionID uuid.UUID, reason string, ttl time.Duration) error
	ClearUser(ctx context.Context, userID uuid.UUID) error
}

// terminatorBackchannel fans out OIDC back-channel logout.
type terminatorBackchannel interface {
	NotifyLogout(ctx context.Context, userID uuid.UUID, sessionID string, tenantID uuid.UUID) error
}

// Exported aliases so wiring code outside the package can hold the optional
// Redis-backed dependencies as nil-able interfaces.
type (
	UserAccessTerminatorSSOCache    = terminatorSSOCache
	UserAccessTerminatorBlacklist   = terminatorBlacklist
	UserAccessTerminatorBackchannel = terminatorBackchannel
)

// accessTerminator is the narrow surface callers depend on; satisfied by
// *UserAccessTerminator.
type accessTerminator interface {
	TerminateUserAccess(ctx context.Context, userID, tenantID uuid.UUID, reason string, exceptSessionID *uuid.UUID) error
	TerminateUserAccessWith(ctx context.Context, userID, tenantID uuid.UUID, reason string, opts TerminateOptions) error
	TerminateSession(ctx context.Context, userID, tenantID, sessionID uuid.UUID, reason string) error
	ClearUserBlock(ctx context.Context, userID uuid.UUID)
}

// UserAccessTerminator is the single place that ends everything a user can
// still present after an access-removing event (disable, delete, password
// reset, MFA reset, SCIM deactivate, admin revoke): session rows, OAuth
// tokens, IdP SSO cookies, blacklisted access JWTs, RP sessions and CAE
// receivers. Every step is best-effort: failures are logged, the remaining
// steps still run, and the joined error is returned.
type UserAccessTerminator struct {
	sessionRepo terminatorSessionRepo
	tokens      terminatorTokenRevoker
	ssoCache    terminatorSSOCache
	blacklist   terminatorBlacklist
	backchannel terminatorBackchannel
	caeService  *CAEService
	caepEmitter *CAEPEmitter
	logger      *zap.Logger

	blacklistTTL time.Duration
}

// NewUserAccessTerminator builds a terminator. Any dependency may be nil; the
// corresponding step is skipped.
func NewUserAccessTerminator(
	sessionRepo terminatorSessionRepo,
	tokens terminatorTokenRevoker,
	ssoCache terminatorSSOCache,
	blacklist terminatorBlacklist,
	backchannel terminatorBackchannel,
	caeService *CAEService,
	blacklistTTL time.Duration,
	logger *zap.Logger,
) *UserAccessTerminator {
	if blacklistTTL <= 0 {
		blacklistTTL = defaultUserBlacklistTTL
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &UserAccessTerminator{
		sessionRepo: sessionRepo, tokens: tokens, ssoCache: ssoCache,
		blacklist: blacklist, backchannel: backchannel, caeService: caeService, blacklistTTL: blacklistTTL, logger: logger,
	}
}

// SetBackchannel wires the OIDC back-channel logout fan-out (built later in
// startup than the terminator itself).
func (t *UserAccessTerminator) SetBackchannel(b terminatorBackchannel) { t.backchannel = b }

// SetCAEPEmitter wires the off-process CAEP transmitter (optional).
func (t *UserAccessTerminator) SetCAEPEmitter(em *CAEPEmitter) { t.caepEmitter = em }

// TerminateOptions tunes TerminateUserAccessWith.
type TerminateOptions struct {
	// ExceptSessionID keeps this iam_sessions row (and its IdP SSO session) alive.
	ExceptSessionID *uuid.UUID
	// BlacklistUser also writes the flat user-level token blacklist. It blocks
	// every token of the user for userBlacklistTTL, including freshly minted
	// ones, so credential-rotation flows (password reset/change) leave it off
	// and rely on per-session blacklisting instead.
	BlacklistUser bool
}

// TerminateUserAccess ends all of a user's access (hard termination). With
// exceptSessionID nil everything dies and the user-level blacklist is written;
// with it set the named session survives and the user-level blacklist is
// skipped (it would kill the survivor).
func (t *UserAccessTerminator) TerminateUserAccess(ctx context.Context, userID, tenantID uuid.UUID, reason string, exceptSessionID *uuid.UUID) error {
	return t.TerminateUserAccessWith(ctx, userID, tenantID, reason, TerminateOptions{
		ExceptSessionID: exceptSessionID,
		BlacklistUser:   exceptSessionID == nil,
	})
}

// TerminateUserAccessWith is TerminateUserAccess with explicit options.
func (t *UserAccessTerminator) TerminateUserAccessWith(ctx context.Context, userID, tenantID uuid.UUID, reason string, opts TerminateOptions) error {
	if t == nil || userID == uuid.Nil {
		return nil
	}
	except := uuid.Nil
	if opts.ExceptSessionID != nil {
		except = *opts.ExceptSessionID
	}
	var errs []error
	fail := func(step string, err error) {
		if err == nil {
			return
		}
		t.logger.Error("UserAccessTerminator: step failed",
			zap.String("step", step), zap.String("user_id", userID.String()),
			zap.String("reason", reason), zap.Error(err))
		errs = append(errs, fmt.Errorf("%s: %w", step, err))
	}

	// Snapshot the live session rows first so each can be blacklisted after it is ended.
	var sessionIDs []uuid.UUID
	if t.sessionRepo != nil {
		sessions, err := t.sessionRepo.GetActiveSessions(ctx, userID)
		fail("list_sessions", err)
		for _, s := range sessions {
			if s.ID != except {
				sessionIDs = append(sessionIDs, s.ID)
			}
		}
		if except != uuid.Nil {
			fail("end_sessions", t.sessionRepo.EndAllUserSessionsExcept(ctx, userID, except, reason))
		} else {
			fail("end_sessions", t.sessionRepo.EndAllUserSessions(ctx, userID, reason))
		}
	}
	if t.tokens != nil {
		fail("revoke_oauth_tokens", t.tokens.RevokeAllUserOAuthTokens(ctx, userID, reason))
	}
	var ssoIDs []uuid.UUID
	if t.ssoCache != nil {
		ids, err := t.ssoCache.DeleteAllIdpSessionsByUserExcept(ctx, userID, except)
		fail("delete_idp_sessions", err)
		ssoIDs = ids
	}
	if t.blacklist != nil {
		for _, id := range sessionIDs {
			fail("blacklist_session", t.blacklist.BlacklistSession(ctx, id, reason, t.blacklistTTL))
		}
		if opts.BlacklistUser {
			fail("blacklist_user", t.blacklist.BlacklistUserTokens(ctx, userID, reason, t.blacklistTTL))
		}
	}
	if t.backchannel != nil {
		if except == uuid.Nil {
			// Empty sessionID = sub-wide logout (only when nothing survives).
			fail("backchannel_logout", t.backchannel.NotifyLogout(ctx, userID, "", tenantID))
		}
		// App tokens carry sid = the SSO session id, so notify per SSO session.
		for _, id := range ssoIDs {
			fail("backchannel_logout_sid", t.backchannel.NotifyLogout(ctx, userID, id.String(), tenantID))
		}
	}
	if except == uuid.Nil {
		t.publish(ctx, userID, tenantID, reason, "")
	}
	return errors.Join(errs...)
}

// ClearUserBlock removes the flat user-level blacklist marker so a re-enabled
// or restored account can log in immediately.
func (t *UserAccessTerminator) ClearUserBlock(ctx context.Context, userID uuid.UUID) {
	if t == nil || t.blacklist == nil || userID == uuid.Nil {
		return
	}
	if err := t.blacklist.ClearUser(ctx, userID); err != nil {
		t.logger.Warn("UserAccessTerminator: clear user blacklist failed",
			zap.String("user_id", userID.String()), zap.Error(err))
	}
}

// TerminateSession ends exactly one login session: its row, the OAuth tokens
// bound to it (by row id and by each backing IdP SSO id), the SSO cookie
// state, and the access JWTs carrying it. Other sessions are untouched.
func (t *UserAccessTerminator) TerminateSession(ctx context.Context, userID, tenantID, sessionID uuid.UUID, reason string) error {
	if t == nil || sessionID == uuid.Nil {
		return nil
	}
	var errs []error
	fail := func(step string, err error) {
		if err == nil {
			return
		}
		t.logger.Error("UserAccessTerminator: session step failed",
			zap.String("step", step), zap.String("session_id", sessionID.String()),
			zap.String("reason", reason), zap.Error(err))
		errs = append(errs, fmt.Errorf("%s: %w", step, err))
	}
	if t.sessionRepo != nil {
		fail("end_session", t.sessionRepo.EndSession(ctx, sessionID, reason))
	}
	if t.tokens != nil {
		fail("revoke_session_tokens", t.tokens.RevokeOAuthTokensBySession(ctx, sessionID, userID))
	}
	var idpIDs []uuid.UUID
	if t.ssoCache != nil {
		var err error
		idpIDs, err = t.ssoCache.DeleteIdpSessionsByRowID(ctx, userID, sessionID)
		fail("delete_idp_sessions", err)
		if t.tokens != nil {
			for _, id := range idpIDs {
				fail("revoke_idp_bound_tokens", t.tokens.RevokeOAuthTokensBySession(ctx, id, userID))
			}
		}
	}
	if t.blacklist != nil {
		fail("blacklist_session", t.blacklist.BlacklistSession(ctx, sessionID, reason, t.blacklistTTL))
	}
	if t.backchannel != nil {
		fail("backchannel_logout", t.backchannel.NotifyLogout(ctx, userID, sessionID.String(), tenantID))
		for _, id := range idpIDs {
			fail("backchannel_logout_sid", t.backchannel.NotifyLogout(ctx, userID, id.String(), tenantID))
		}
	}
	t.publish(ctx, userID, tenantID, reason, sessionID.String())
	return errors.Join(errs...)
}

func (t *UserAccessTerminator) publish(ctx context.Context, userID, tenantID uuid.UUID, reason, sessionID string) {
	if t.caeService != nil {
		md := map[string]string{"reason": reason}
		if sessionID != "" {
			md["session_id"] = sessionID
		}
		if err := t.caeService.PublishEvent(ctx, CAEEvent{
			Type: CAESessionRevoked, UserID: userID, TenantID: tenantID,
			Timestamp: time.Now().UTC(), Metadata: md,
		}); err != nil {
			t.logger.Warn("UserAccessTerminator: CAE publish failed", zap.Error(err))
		}
	}
	if t.caepEmitter != nil && tenantID != uuid.Nil {
		go func() { //nolint:gosec // must outlive the request ctx
			_ = t.caepEmitter.EmitSessionRevoked(context.Background(), tenantID, userID, reason)
		}()
	}
}

// detachedTerminationCtx returns a context that outlives the request (the
// credential change is already committed) but is bounded to 30s.
func detachedTerminationCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

// errUserNotEligible is returned when the token owner is disabled, deleted or locked.
var errUserNotEligible = errors.New("invalid_grant: user account is not active")

// userEligibleForTokens gates token issuance/refresh on the owner's current
// status. A nil user (client_credentials, tokens with no UserID) is eligible:
// there is no account to check.
func userEligibleForTokens(user *models.User) error {
	if user == nil {
		return nil
	}
	if !user.EligibleForTokens(time.Now()) {
		return errUserNotEligible
	}
	return nil
}

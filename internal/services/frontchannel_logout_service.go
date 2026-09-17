// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/metrics"
)

// FrontchannelLogoutClient is the minimal RP record needed to render an FCL iframe.
type FrontchannelLogoutClient struct {
	// ClientID is the OAuth client identifier — logged, never rendered.
	ClientID string
	// FrontchannelLogoutURI is the absolute HTTPS URL of the RP's iframe handler.
	FrontchannelLogoutURI string
	// SessionRequired is the RP-side opt-in to receive `sid` in the iframe URL.
	// Maps to OAuth client metadata frontchannel_logout_session_required (spec §2).
	SessionRequired bool
}

// FrontchannelLogoutLister returns the RPs to render iframes for.
type FrontchannelLogoutLister interface {
	GetClientsWithFrontchannelLogout(ctx context.Context, tenantID uuid.UUID) ([]FrontchannelLogoutClient, error)
}

// FrontchannelLogoutIFrame is one iframe to embed on the OP's RP-initiated
// logout page. Both fields are safe for HTML rendering after the standard
// html/template escaping (Src is a serialised URL with only iss + sid in
// the query string).
type FrontchannelLogoutIFrame struct {
	// ClientID identifies which RP this iframe targets — for log lines and
	// HTML comments. NEVER use this as a query parameter.
	ClientID string
	// Src is the iframe `src` URL with iss (always) and sid (when the RP
	// opted in via frontchannel_logout_session_required).
	Src string
}

// FrontchannelLogoutService implements the OP side of OpenID Connect
// Front-Channel Logout 1.0 (https://openid.net/specs/openid-connect-frontchannel-1_0.html).
//
// Front-Channel Logout complements Back-Channel Logout (RFC OIDC-BCL-1.0).
// The two are NOT redundant: BCL is a server-to-server POST that fails
// silently when the RP has no reachable backend (static SPAs, JAMstack RPs,
// network-isolated RPs); FCL is a browser-driven iframe load that works
// in those cases. FAPI 2.0 baseline expects both.
//
// SECURITY (spec §3, §5):
//   - The iframe URL carries `iss` and `sid` ONLY. Anything more leaks via
//     Referer / browser history.
//   - The OP MUST NOT authenticate the iframe load with a bearer secret —
//     the browser doesn't have one, and the RP's iss-validation IS the
//     auth. Sending a shared secret would defeat that defense.
//   - The RP-side handler must validate `iss` against its expected issuer
//     URL, set Cache-Control: no-store, and CSP frame-ancestors to the
//     OP's logout-page origin only.
type FrontchannelLogoutService struct {
	lister FrontchannelLogoutLister
	logger *zap.Logger
}

// NewFrontchannelLogoutService constructs an FCL service. lister may be nil;
// the service degrades to "no iframes" rather than blocking startup.
func NewFrontchannelLogoutService(lister FrontchannelLogoutLister, logger *zap.Logger) *FrontchannelLogoutService {
	return &FrontchannelLogoutService{lister: lister, logger: logger}
}

// SetLister injects the lister dependency after construction (mirrors the
// SetClientLister pattern on BackchannelLogoutService).
func (s *FrontchannelLogoutService) SetLister(lister FrontchannelLogoutLister) {
	s.lister = lister
}

// BuildIFrames returns the iframes to render on the OP's RP-initiated
// logout page for the given tenant. sid is the IdP session identifier
// from the falcon_idp_session cookie (already validated as a UUID by the
// caller); when empty, RPs registered with
// frontchannel_logout_session_required=true are SKIPPED — the spec
// requires the OP to send sid to those RPs and a sid-less iframe would
// either be rejected or cascade to the wrong session.
//
// Returns nil (not an empty slice) on internal errors so the caller can
// fall through to the cookie-only logout path without rendering an empty
// iframe shell.
func (s *FrontchannelLogoutService) BuildIFrames(ctx context.Context, tenantID uuid.UUID, sid string) []FrontchannelLogoutIFrame {
	if s == nil || s.lister == nil {
		return nil
	}

	issuer := getOIDCIssuer()
	if issuer == "" {
		s.logger.Warn("FrontchannelLogout.BuildIFrames: empty issuer, skipping iframe render")
		return nil
	}

	clients, err := s.lister.GetClientsWithFrontchannelLogout(ctx, tenantID)
	if err != nil {
		s.logger.Error("FrontchannelLogout.BuildIFrames: lister failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		return nil
	}
	if len(clients) == 0 {
		// REGRESSION SIGNAL — see same path on BackchannelLogoutService
		// for the rationale. After 2026-05-10 SLO seed restoration the
		// platform tenant MUST have at minimum svc-talon and svc-accounts
		// registered for FCL. Zero-clients on the platform tenant is a
		// fresh-initdb regression signal.
		metrics.OAuthFCLNoClients.WithLabelValues(tenantID.String()).Inc()
		s.logger.Warn("FrontchannelLogout.BuildIFrames: zero RPs registered for tenant — Sign Out iframe pane will be empty",
			zap.String("tenant_id", tenantID.String()),
		)
		return nil
	}

	iframes := make([]FrontchannelLogoutIFrame, 0, len(clients))
	for _, c := range clients {
		if c.FrontchannelLogoutURI == "" {
			continue
		}
		// Spec §2 requires HTTPS. Reject anything else here so a
		// misconfigured DB row can't drop the iframe to plaintext.
		if !strings.HasPrefix(c.FrontchannelLogoutURI, "https://") {
			s.logger.Warn("FrontchannelLogout.BuildIFrames: skipping non-HTTPS URI",
				zap.String("client_id", c.ClientID),
				zap.String("uri", c.FrontchannelLogoutURI),
			)
			continue
		}
		// Skip session-required RPs when we don't have a sid — the iframe
		// would be ambiguous and could clear the wrong session if the user
		// has multiple accounts in the browser.
		if c.SessionRequired && sid == "" {
			s.logger.Debug("FrontchannelLogout.BuildIFrames: skipping session-required RP without sid",
				zap.String("client_id", c.ClientID),
			)
			continue
		}

		u, err := url.Parse(c.FrontchannelLogoutURI)
		if err != nil {
			s.logger.Warn("FrontchannelLogout.BuildIFrames: invalid URI",
				zap.String("client_id", c.ClientID),
				zap.String("uri", c.FrontchannelLogoutURI),
				zap.Error(err),
			)
			continue
		}

		// Spec §3 — query carries iss + sid ONLY. Rebuild the query
		// from scratch so any RP-stored extra params are dropped (the
		// RP's URL is admin-controlled, but we still defend in depth).
		q := url.Values{}
		q.Set("iss", issuer)
		if c.SessionRequired && sid != "" {
			q.Set("sid", sid)
		}
		u.RawQuery = q.Encode()

		iframes = append(iframes, FrontchannelLogoutIFrame{
			ClientID: c.ClientID,
			Src:      u.String(),
		})
	}

	if len(iframes) > 0 {
		s.logger.Info("FrontchannelLogout.BuildIFrames: rendering iframes",
			zap.String("tenant_id", tenantID.String()),
			zap.Int("count", len(iframes)),
		)
	}
	return iframes
}

// getOIDCIssuer returns the canonical issuer URL used to populate the
// `iss` query parameter on FCL iframes. Reads OAUTH_ISSUER — the same
// env var OAuthProviderService.getIssuer() uses for the discovery doc
// `issuer` field and id_token `iss` claim — so the iss the RP receives
// in the iframe matches what it has cached from discovery.
func getOIDCIssuer() string {
	return os.Getenv("OAUTH_ISSUER")
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// AuthorizeContinuationPath is the only path an OIDC continuation may point at.
const AuthorizeContinuationPath = "/oauth/authorize"

// MaxAuthorizeContinuationLen bounds a stored/echoed continuation. It matches the
// CHECK on iam_signup_requests.continuation.
const MaxAuthorizeContinuationLen = 4096

// ErrInvalidAuthorizeContinuation is returned for any continuation that is not a
// well-formed, registered /oauth/authorize request.
var ErrInvalidAuthorizeContinuation = errors.New("invalid authorize continuation")

// ParseAuthorizeContinuation checks the SHAPE of an authorize continuation and
// returns its query. It must be a relative URL (no scheme, host, userinfo or
// fragment, not protocol-relative) whose path is exactly /oauth/authorize, free
// of control characters, and at most MaxAuthorizeContinuationLen bytes. A
// prefix match is not enough: "/oauth/authorize-evil" or a dot-segment path are
// not the authorize endpoint.
//
// This is the part of validation that needs no database; the login redirect
// uses it on its own, signup adds ValidateAuthorizeContinuation on top.
func ParseAuthorizeContinuation(raw string) (url.Values, error) {
	if raw == "" || len(raw) > MaxAuthorizeContinuationLen {
		return nil, ErrInvalidAuthorizeContinuation
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return nil, ErrInvalidAuthorizeContinuation
		}
	}
	if !strings.HasPrefix(raw, AuthorizeContinuationPath) {
		return nil, ErrInvalidAuthorizeContinuation
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, ErrInvalidAuthorizeContinuation
	}
	if u.Path != AuthorizeContinuationPath || u.EscapedPath() != AuthorizeContinuationPath {
		return nil, ErrInvalidAuthorizeContinuation
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, ErrInvalidAuthorizeContinuation
	}
	return q, nil
}

// ValidateAuthorizeContinuation accepts raw only when it is a well-formed
// /oauth/authorize URL (ParseAuthorizeContinuation) naming an ACTIVE client and
// a redirect_uri registered for that client, and the client to be first-party
// (an arbitrary registered third-party client must not be a post-signup landing), so a stored continuation can never
// send the browser anywhere /oauth/authorize itself would refuse.
func (s *OAuthProviderService) ValidateAuthorizeContinuation(ctx context.Context, raw string) error {
	q, err := ParseAuthorizeContinuation(raw)
	if err != nil {
		return err
	}
	clientID, redirectURI := q.Get("client_id"), q.Get("redirect_uri")
	if clientID == "" || redirectURI == "" {
		return ErrInvalidAuthorizeContinuation
	}
	client, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, repositories.ErrOAuthClientNotFound) {
			return ErrInvalidAuthorizeContinuation
		}
		return fmt.Errorf("validate authorize continuation: client lookup: %w", err)
	}
	if client == nil || !client.IsActive || !client.IsFirstParty || !matchRedirectURI(client.RedirectURIs, redirectURI) {
		return ErrInvalidAuthorizeContinuation
	}
	return nil
}

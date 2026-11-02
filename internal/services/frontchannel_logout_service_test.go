// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// stubFCLLister is an in-memory FrontchannelLogoutLister used to drive
// BuildIFrames through every spec edge case without a live DB.
type stubFCLLister struct {
	clients []FrontchannelLogoutClient
	err     error
}

func (s *stubFCLLister) GetClientsWithFrontchannelLogout(_ context.Context, _ uuid.UUID) ([]FrontchannelLogoutClient, error) {
	return s.clients, s.err
}

// withIssuer sets OAUTH_ISSUER for the duration of the test, restoring
// the original value (or unset state) on cleanup.
func withIssuer(t *testing.T, issuer string) {
	t.Helper()
	t.Setenv("OAUTH_ISSUER", issuer)
}

func TestFrontchannelLogout_BuildIFrames_HappyPath_SessionRequired(t *testing.T) {
	withIssuer(t, "https://id.example.com")
	lister := &stubFCLLister{
		clients: []FrontchannelLogoutClient{
			{
				ClientID:              "svc-talon",
				FrontchannelLogoutURI: "https://auth.internal.example.com/auth/frontchannel-logout",
				SessionRequired:       true,
			},
		},
	}
	svc := NewFrontchannelLogoutService(lister, zap.NewNop())

	frames := svc.BuildIFrames(context.Background(), uuid.New(), "39c8c5d2-0c5e-4b35-9a3a-9c1c8f7e5a91")
	require.Len(t, frames, 1)
	assert.Equal(t, "svc-talon", frames[0].ClientID)

	u, err := url.Parse(frames[0].Src)
	require.NoError(t, err)
	assert.Equal(t, "https", u.Scheme)
	assert.Equal(t, "auth.internal.example.com", u.Host)
	assert.Equal(t, "/auth/frontchannel-logout", u.Path)
	q := u.Query()
	assert.Equal(t, "https://id.example.com", q.Get("iss"), "iss MUST match OAUTH_ISSUER")
	assert.Equal(t, "39c8c5d2-0c5e-4b35-9a3a-9c1c8f7e5a91", q.Get("sid"), "sid MUST be passed for session-required RPs")
	assert.Len(t, q, 2, "FCL §3 — query carries iss + sid ONLY (no extra claims)")
}

func TestFrontchannelLogout_BuildIFrames_OmitsSidWhenSessionNotRequired(t *testing.T) {
	withIssuer(t, "https://id.example.com")
	lister := &stubFCLLister{
		clients: []FrontchannelLogoutClient{
			{
				ClientID:              "third-party",
				FrontchannelLogoutURI: "https://3p.example.com/fcl",
				SessionRequired:       false,
			},
		},
	}
	svc := NewFrontchannelLogoutService(lister, zap.NewNop())

	frames := svc.BuildIFrames(context.Background(), uuid.New(), "any-sid-value")
	require.Len(t, frames, 1)
	q := mustParseQuery(t, frames[0].Src)
	assert.Equal(t, "https://id.example.com", q.Get("iss"))
	assert.Empty(t, q.Get("sid"), "RP did not opt in via session_required, no sid in URL")
	assert.Len(t, q, 1)
}

func TestFrontchannelLogout_BuildIFrames_SkipsSessionRequiredWithoutSid(t *testing.T) {
	withIssuer(t, "https://id.example.com")
	// One session-required RP and one non-session-required RP. With sid=""
	// the session-required one MUST be dropped (cannot scope safely);
	// the other one MUST still render.
	lister := &stubFCLLister{
		clients: []FrontchannelLogoutClient{
			{ClientID: "svc-needs-sid", FrontchannelLogoutURI: "https://a.example.com/fcl", SessionRequired: true},
			{ClientID: "third-party", FrontchannelLogoutURI: "https://b.example.com/fcl", SessionRequired: false},
		},
	}
	svc := NewFrontchannelLogoutService(lister, zap.NewNop())

	frames := svc.BuildIFrames(context.Background(), uuid.New(), "")
	require.Len(t, frames, 1)
	assert.Equal(t, "third-party", frames[0].ClientID)
}

func TestFrontchannelLogout_BuildIFrames_RebuildsQueryDroppingExtraParams(t *testing.T) {
	withIssuer(t, "https://id.example.com")
	// A maliciously-stored URI with extra params MUST get the query stripped
	// down to iss + sid only — defense in depth.
	lister := &stubFCLLister{
		clients: []FrontchannelLogoutClient{
			{
				ClientID:              "svc-talon",
				FrontchannelLogoutURI: "https://auth.internal.example.com/auth/frontchannel-logout?token=abc&trick=xyz",
				SessionRequired:       true,
			},
		},
	}
	svc := NewFrontchannelLogoutService(lister, zap.NewNop())

	frames := svc.BuildIFrames(context.Background(), uuid.New(), "sid-val")
	require.Len(t, frames, 1)
	q := mustParseQuery(t, frames[0].Src)
	assert.Equal(t, "sid-val", q.Get("sid"))
	assert.Equal(t, "https://id.example.com", q.Get("iss"))
	assert.Empty(t, q.Get("token"), "extra DB-stored params MUST be stripped")
	assert.Empty(t, q.Get("trick"))
	assert.Len(t, q, 2, "rebuilt query MUST be exactly iss + sid")
}

func TestFrontchannelLogout_BuildIFrames_RejectsNonHTTPS(t *testing.T) {
	withIssuer(t, "https://id.example.com")
	lister := &stubFCLLister{
		clients: []FrontchannelLogoutClient{
			{ClientID: "ok", FrontchannelLogoutURI: "https://ok.example.com/fcl", SessionRequired: true},
			{ClientID: "plaintext-bad", FrontchannelLogoutURI: "http://insecure.example.com/fcl", SessionRequired: true},
		},
	}
	svc := NewFrontchannelLogoutService(lister, zap.NewNop())

	frames := svc.BuildIFrames(context.Background(), uuid.New(), "sid-val")
	require.Len(t, frames, 1, "spec §2 mandates HTTPS — http:// URIs MUST be skipped")
	assert.Equal(t, "ok", frames[0].ClientID)
}

func TestFrontchannelLogout_BuildIFrames_NoIssuerReturnsNil(t *testing.T) {
	t.Setenv("OAUTH_ISSUER", "")
	lister := &stubFCLLister{
		clients: []FrontchannelLogoutClient{
			{ClientID: "x", FrontchannelLogoutURI: "https://example.com/fcl", SessionRequired: true},
		},
	}
	svc := NewFrontchannelLogoutService(lister, zap.NewNop())
	assert.Nil(t, svc.BuildIFrames(context.Background(), uuid.New(), "sid-val"))
}

func TestFrontchannelLogout_BuildIFrames_ListerErrorReturnsNil(t *testing.T) {
	withIssuer(t, "https://id.example.com")
	svc := NewFrontchannelLogoutService(&stubFCLLister{err: errors.New("db down")}, zap.NewNop())
	assert.Nil(t, svc.BuildIFrames(context.Background(), uuid.New(), "sid-val"))
}

func TestFrontchannelLogout_BuildIFrames_NilServiceOrListerSafe(t *testing.T) {
	// Nil receiver — handler must tolerate this when the FCL service
	// hasn't been wired (development / test environments).
	var svc *FrontchannelLogoutService
	assert.Nil(t, svc.BuildIFrames(context.Background(), uuid.New(), "sid"))

	// Nil lister — service constructed but lister never injected.
	svc2 := NewFrontchannelLogoutService(nil, zap.NewNop())
	assert.Nil(t, svc2.BuildIFrames(context.Background(), uuid.New(), "sid"))
}

func mustParseQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u.Query()
}

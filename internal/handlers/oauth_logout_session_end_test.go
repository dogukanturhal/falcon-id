// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

type fakeTerminator struct {
	hintSID, hintSub uuid.UUID
	revoked          []uuid.UUID
	revokedFor       []uuid.UUID
	hinted           []uuid.UUID
	ended            map[uuid.UUID]string
}

func (f *fakeTerminator) RevokeSessionTokens(_ context.Context, id, user uuid.UUID) error {
	f.revoked = append(f.revoked, id)
	f.revokedFor = append(f.revokedFor, user)
	return nil
}
func (f *fakeTerminator) LogoutHintSID(string) (uuid.UUID, uuid.UUID, bool) {
	return f.hintSID, f.hintSub, f.hintSID != uuid.Nil
}
func (f *fakeTerminator) EndHintedSession(_ context.Context, sid, _ uuid.UUID) error {
	f.hinted = append(f.hinted, sid)
	return nil
}
func (f *fakeTerminator) EndLoginSession(_ context.Context, id uuid.UUID, reason string) error {
	if f.ended == nil {
		f.ended = map[uuid.UUID]string{}
	}
	f.ended[id] = reason
	return nil
}

func logoutCtx(t *testing.T, hint string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/oauth/logout?client_id=acmeapp-bff&id_token_hint="+hint, nil)
	return c, w
}

// A valid id_token_hint is an explicit RP-initiated logout: it ends the
// iam_sessions row ("logout") and revokes the tokens bound to the idp session.
func TestEndSession_ValidHint_EndsRowAndRevokesTokens(t *testing.T) {
	cache, _ := newTestSessionCacheForEndSession(t)
	subject, rowID, idpID := uuid.New(), uuid.New(), uuid.New()
	term := &fakeTerminator{}
	h := &OAuthProviderHandler{logger: zap.NewNop(), sessionCache: cache, sessionTerminator: term,
		logoutService: auth2LogoutService{client: &models.OAuthClient{ClientID: "acmeapp-bff"}, valid: true, subject: &subject}}
	require.NoError(t, cache.SetIdpSession(context.Background(), idpID,
		&redispkg.IdpSessionData{UserID: subject, TenantID: uuid.New(), SessionID: rowID}))

	c, _ := logoutCtx(t, "valid")
	c.Request.AddCookie(&http.Cookie{Name: "falcon_idp_session", Value: idpID.String()})
	h.EndSession(c)

	assert.Equal(t, []uuid.UUID{idpID}, term.revoked)
	assert.Equal(t, []uuid.UUID{subject}, term.revokedFor, "scoped to the session's user")
	assert.Equal(t, "logout", term.ended[rowID])
}

// No valid hint = a bare GET (logout CSRF): cookie and Redis teardown only,
// the victim's refresh tokens and session row stay.
func TestEndSession_NoValidHint_DoesNotRevokeTokens(t *testing.T) {
	cache, _ := newTestSessionCacheForEndSession(t)
	userID, rowID, idpID := uuid.New(), uuid.New(), uuid.New()
	term := &fakeTerminator{hintSID: uuid.New()}
	h := &OAuthProviderHandler{logger: zap.NewNop(), sessionCache: cache, sessionTerminator: term,
		logoutService: auth2LogoutService{client: &models.OAuthClient{ClientID: "acmeapp-bff"}}}
	require.NoError(t, cache.SetIdpSession(context.Background(), idpID,
		&redispkg.IdpSessionData{UserID: userID, TenantID: uuid.New(), SessionID: rowID}))

	c, _ := logoutCtx(t, "invalid")
	c.Request.AddCookie(&http.Cookie{Name: "falcon_idp_session", Value: idpID.String()})
	h.EndSession(c)

	assert.Empty(t, term.revoked)
	assert.Empty(t, term.ended)
	after, err := cache.GetIdpSession(context.Background(), idpID)
	require.NoError(t, err)
	assert.Nil(t, after, "browser-local Redis/cookie teardown still happens")
}

// Valid hint but no Redis entry: revoke by the hint's own sid claim.
func TestEndSession_ValidHint_NoRedisData_RevokesByHintSID(t *testing.T) {
	cache, _ := newTestSessionCacheForEndSession(t)
	subject, hintSID := uuid.New(), uuid.New()
	term := &fakeTerminator{hintSID: hintSID, hintSub: subject}
	h := &OAuthProviderHandler{logger: zap.NewNop(), sessionCache: cache, sessionTerminator: term,
		logoutService: auth2LogoutService{client: &models.OAuthClient{ClientID: "acmeapp-bff"}, valid: true, subject: &subject}}

	c, _ := logoutCtx(t, "valid")
	h.EndSession(c)

	assert.Equal(t, []uuid.UUID{hintSID}, term.hinted)
	assert.Empty(t, term.revoked)
}

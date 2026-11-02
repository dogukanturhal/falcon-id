// SPDX-License-Identifier: AGPL-3.0-or-later

package opsconsole

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/operatorauth"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/opsaudit"
)

const testIssuer = "https://id.test"

type testEnv struct {
	revoked bool
	// noAudit leaves Console.Audit nil to exercise the fail-closed path.
	noAudit  bool
	key      *rsa.PrivateKey
	verifier *operatorauth.Verifier
	jwks     *httptest.Server
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(srv.Close)
	v, err := operatorauth.NewVerifier(operatorauth.Config{JWKSURL: srv.URL, Issuer: testIssuer})
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{key: key, verifier: v, jwks: srv}
}

func (e *testEnv) assertion(t *testing.T, perms []string, authAge time.Duration, amr []string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": testIssuer, "aud": []string{operatorauth.Audience}, "sub": uuid.NewString(), "user_id": uuid.NewString(),
		"email": "op@example.com", "tid": operatorauth.InternalTenantID, "tenant_id": operatorauth.InternalTenantID,
		"gty": "operator_exchange", "platform_roles": []string{"platform_support"}, "ops_perms": perms,
		"amr": amr, "auth_time": now.Add(-authAge).Unix(), "iat": now.Unix(), "nbf": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "jti": uuid.NewString(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(e.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// live is the operator-standing stub: active, holding platform_support (the role
// every test assertion claims) unless revoked is set.
func (e *testEnv) live(_ context.Context, _ *operatorauth.Actor) (liveState, error) {
	if e.revoked {
		return liveState{ok: false}, nil
	}
	return liveState{ok: true, roles: map[string]bool{"platform_support": true}}, nil
}

func anyArgs(n int) []interface{} {
	out := make([]interface{}, n)
	for i := range out {
		out[i] = pgxmock.AnyArg()
	}
	return out
}

// auditStub is an audit sink over a pgxmock pool that accepts any number of
// chain appends (intent + result rows), so mutation routes run end to end.
func auditStub(t *testing.T) *opsaudit.Consumer {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mock.Close)
	mock.MatchExpectationsInOrder(false)
	for i := 0; i < 8; i++ {
		mock.ExpectBegin()
		mock.ExpectExec(`pg_advisory_xact_lock`).WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
		mock.ExpectQuery(`SELECT EXISTS`).WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
		mock.ExpectQuery(`FROM platform_admin_audit_log`).
			WillReturnRows(pgxmock.NewRows([]string{"prev", "seq"}).AddRow("", int64(0)))
		mock.ExpectExec(`INSERT INTO platform_admin_audit_log`).WithArgs(anyArgs(22)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectCommit()
	}
	return opsaudit.NewConsumer(mock)
}

func (e *testEnv) router(t *testing.T, sp Spec, hit *bool) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	var audit *opsaudit.Consumer
	if !e.noAudit {
		audit = auditStub(t)
	}
	cs := &Console{Deps: Deps{
		Audit:     audit,
		Log:       zap.NewNop(),
		Verifier:  e.verifier,
		LiveState: e.live,
		// stand-in for ServiceAuth: grants every scope
		ServiceAuth: func(c *gin.Context) {
			c.Set(middleware.CtxKeyServiceSlug, "svc-test")
			c.Set(middleware.CtxKeyServiceScopes, "platform:ops-users platform:ops-staff")
			c.Next()
		},
	}}
	r := gin.New()
	r.POST("/x/:id", cs.Chain(sp, func(c *gin.Context) {
		*hit = true
		if operatorauth.ActorFrom(c) == nil || middleware.GetActorUserID(c) == uuid.Nil {
			t.Error("actor not bridged")
		}
		var body map[string]interface{}
		if err := c.ShouldBindJSON(&body); err != nil || body["reason"] == nil {
			t.Errorf("body not restored for handler: %v", err)
		}
		c.Status(http.StatusNoContent)
	})...)
	return r
}

func do(r *gin.Engine, assertion, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/x/1", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if assertion != "" {
		req.Header.Set(operatorauth.HeaderActorAssertion, assertion)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

const goodBody = `{"reason_code":"support_ticket","reason":"customer asked us to reset, ticket 4711"}`

func TestChainGuardRails(t *testing.T) {
	env := newTestEnv(t)
	sp := Spec{Scope: "platform:ops-users", Perm: "ops:users:write", StepUp: true}
	perm := []string{"ops:users:write"}

	cases := []struct {
		name      string
		assertion string
		body      string
		spec      Spec
		want      int
		hit       bool
	}{
		{"no assertion", "", goodBody, sp, 401, false},
		{"missing perm", env.assertion(t, []string{"ops:users:read"}, time.Minute, []string{"pwd", "otp"}), goodBody, sp, 403, false},
		{"stale auth_time", env.assertion(t, perm, 10*time.Minute, []string{"pwd", "otp"}), goodBody, sp, 401, false},
		{"no second factor", env.assertion(t, perm, time.Minute, []string{"pwd"}), goodBody, sp, 401, false},
		{"wrong scope", env.assertion(t, perm, time.Minute, []string{"pwd", "otp"}), goodBody, Spec{Scope: "platform:ops-audit", Perm: "ops:users:write", StepUp: true}, 403, false},
		{"ok T2 without action", env.assertion(t, perm, time.Minute, []string{"pwd", "otp"}), goodBody, sp, 204, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit := false
			w := do(env.router(t, tc.spec, &hit), tc.assertion, tc.body)
			if w.Code != tc.want || hit != tc.hit {
				t.Fatalf("code=%d hit=%v body=%s", w.Code, hit, w.Body.String())
			}
		})
	}
}

func TestChainRequiresReasonOnMutation(t *testing.T) {
	env := newTestEnv(t)
	sp := Spec{Scope: "platform:ops-users", Perm: "ops:users:write", StepUp: true, Action: "user.unlock"}
	a := env.assertion(t, []string{"ops:users:write"}, time.Minute, []string{"pwd", "otp"})

	for name, body := range map[string]string{
		"empty":       `{}`,
		"short":       `{"reason_code":"support_ticket","reason":"too short"}`,
		"bad code":    `{"reason_code":"because","reason":"a perfectly long justification text"}`,
		"not json":    `nope`,
		"code absent": `{"reason":"a perfectly long justification text"}`,
	} {
		t.Run(name, func(t *testing.T) {
			hit := false
			w := do(env.router(t, sp, &hit), a, body)
			if w.Code != http.StatusBadRequest || hit || !strings.Contains(w.Body.String(), "reason_required") {
				t.Fatalf("code=%d hit=%v body=%s", w.Code, hit, w.Body.String())
			}
		})
	}
	hit := false
	if w := do(env.router(t, sp, &hit), a, goodBody); w.Code != http.StatusNoContent || !hit {
		t.Fatalf("valid reason refused: %d %s", w.Code, w.Body.String())
	}
}

func TestStatusAndHelpers(t *testing.T) {
	if userStatus(true, false, "") != "active" || userStatus(true, true, "") != "locked" ||
		userStatus(false, false, "") != "disabled" || userStatus(true, false, "admin_deleted") != "disabled" {
		t.Fatal("userStatus")
	}
	if got := escapeLike(`a_b%c\d`); got != `a\_b\%c\\d` {
		t.Fatalf("escapeLike %q", got)
	}
	if _, ok := statusClause("bogus"); ok {
		t.Fatal("bogus status accepted")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	ts, id, err := decodeCursor(encodeCursor(now, "abc"))
	if err != nil || !ts.Equal(now) || id != "abc" {
		t.Fatalf("cursor roundtrip %v %v %v", ts, id, err)
	}
	if _, _, err := decodeCursor("%%%"); err == nil {
		t.Fatal("bad cursor accepted")
	}
	if clampLimit("", 25, 100) != 25 || clampLimit("500", 25, 100) != 100 || clampLimit("x", 25, 100) != 25 || clampLimit("7", 25, 100) != 7 {
		t.Fatal("clampLimit")
	}
}

func TestExportPayloadIsCanonical(t *testing.T) {
	f := auditFilters{From: "2026-10-01T00:00:00Z", Source: "operator", Q: "a<b&c"}
	got := canonicalExportPayload(f, "csv")
	want := `{"filters":{"from":"2026-10-01T00:00:00Z","to":"","actor":"","action":"","source":"operator","tenant_id":"","q":"a<b&c"},"format":"csv"}`
	if got != want {
		t.Fatalf("canonical payload\n got %s\nwant %s", got, want)
	}
	if PayloadHash(got) == PayloadHash(canonicalExportPayload(f, "ndjson")) {
		t.Fatal("format must change the hash")
	}
}

func TestAuditFiltersNormalize(t *testing.T) {
	ok := auditFilters{From: "2026-10-01T00:00:00Z", Source: "IAM"}
	if err := ok.normalize(); err != nil || ok.Source != "iam" {
		t.Fatalf("normalize %v %v", err, ok.Source)
	}
	empty := auditFilters{}
	_ = empty.normalize()
	if empty.Source != "all" {
		t.Fatal("default source")
	}
	for _, bad := range []auditFilters{{Source: "x"}, {From: "yesterday"}, {TenantID: "nope"}} {
		if bad.normalize() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestBuildAuditSQLPlaceholdersAreAllUsed(t *testing.T) {
	ts := time.Now()
	f := auditFilters{From: "2026-10-01T00:00:00Z", To: "2026-10-02T00:00:00Z", Actor: "bob", Action: "x", Source: "all", TenantID: uuid.NewString(), Q: "q"}
	sql, args := buildAuditSQL(f, &ts, "id", 10)
	for i := 1; i <= len(args); i++ {
		if !strings.Contains(sql, "$"+itoa(i)) {
			t.Fatalf("placeholder $%d unused in %s", i, sql)
		}
	}
	if !strings.Contains(sql, "platform_admin_audit_log") || !strings.Contains(sql, "iam_audit_log") {
		t.Fatal("both sources expected for source=all")
	}
	sql, _ = buildAuditSQL(auditFilters{Source: "operator"}, nil, "", 10)
	if strings.Contains(sql, "iam_audit_log") {
		t.Fatal("iam source leaked into operator-only query")
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestRenderExportEscapesFormulas(t *testing.T) {
	rows := []auditRow{{ID: "1", Source: "operator", OccurredAt: time.Unix(0, 0), Actor: "=cmd", Action: "a", Success: true}}
	out, err := renderExport(rows, "csv")
	if err != nil || !strings.Contains(string(out), "'=cmd") {
		t.Fatalf("csv formula guard: %s %v", out, err)
	}
	out, err = renderExport(rows, "ndjson")
	if err != nil || !strings.HasSuffix(string(out), "\n") || !strings.Contains(string(out), `"outcome":"success"`) {
		t.Fatalf("ndjson: %s %v", out, err)
	}
}

func TestIAMActorsAreMaskedInAudit(t *testing.T) {
	r := auditRow{Source: "iam", Actor: "jane@acme.com"}
	if r.actorLabel() != "j***@a***.com" {
		t.Fatalf("got %s", r.actorLabel())
	}
	if (auditRow{Source: "operator", Actor: "op@example.com"}).actorLabel() != "op@example.com" {
		t.Fatal("operator actor must stay readable")
	}
}

func TestActionPermsAreOpsPerms(t *testing.T) {
	for action, perm := range ActionPerms {
		if !strings.HasPrefix(perm, "ops:") || strings.Count(perm, ":") != 2 {
			t.Fatalf("%s -> %s", action, perm)
		}
	}
	if sha256Re.MatchString("zz") || !sha256Re.MatchString(PayloadHash("x")) {
		t.Fatal("sha256Re")
	}
}

// A mutation is refused (and its handler never runs) when the intent audit row
// cannot be written; here no audit sink is wired.
func TestChainFailsClosedWithoutAuditSink(t *testing.T) {
	env := newTestEnv(t)
	env.noAudit = true
	sp := Spec{Scope: "platform:ops-users", Perm: "ops:users:write", StepUp: true, Action: "user.unlock"}
	a := env.assertion(t, []string{"ops:users:write"}, time.Minute, []string{"pwd", "otp"})
	hit := false
	w := do(env.router(t, sp, &hit), a, goodBody)
	if w.Code != http.StatusServiceUnavailable || hit || !strings.Contains(w.Body.String(), "audit_unavailable") {
		t.Fatalf("code=%d hit=%v body=%s", w.Code, hit, w.Body.String())
	}
}

// A revoked operator fails at once even with a valid, unexpired assertion.
func TestChainRejectsRevokedOperator(t *testing.T) {
	env := newTestEnv(t)
	env.revoked = true
	sp := Spec{Scope: "platform:ops-users", Perm: "ops:users:read"}
	a := env.assertion(t, []string{"ops:users:read"}, time.Minute, []string{"pwd", "otp"})
	hit := false
	w := do(env.router(t, sp, &hit), a, goodBody)
	if w.Code != http.StatusUnauthorized || hit || !strings.Contains(w.Body.String(), "actor_assertion_revoked") {
		t.Fatalf("code=%d hit=%v body=%s", w.Code, hit, w.Body.String())
	}
}

// normalize() must not change the approval payload hash: an unset source is ""
// both before and after it.
func TestExportPayloadIgnoresSourceNormalisation(t *testing.T) {
	raw := auditFilters{From: "2026-10-01T00:00:00Z"}
	norm := raw
	if err := norm.normalize(); err != nil {
		t.Fatal(err)
	}
	if canonicalExportPayload(raw, "csv") != canonicalExportPayload(norm, "csv") {
		t.Fatalf("payload changed by normalize: %s vs %s", canonicalExportPayload(raw, "csv"), canonicalExportPayload(norm, "csv"))
	}
}

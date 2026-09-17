//go:build integration

// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories_test

// PR-time guard for the 2026-07-21 OAuth migration-gap P1 outage (Fix C).
//
// THE OUTAGE: the a52ed36 merge shipped migration 0009
// (iam_oauth_tokens.token_family_id) plus code that writes that column on every
// token issuance, but no Keystone bundle was rendered, so the column never
// existed in prod. Every /oauth/token exchange's token-row INSERT failed with
// SQLSTATE 42703 and returned 0x200 / all 400 — cluster-wide SSO down. CI did
// not catch it because the test suite ran against a database migrated to
// internal/migrations HEAD, which already had the column; the *released* schema
// (what production actually had) did not.
//
// THIS TEST reconstructs the LAST-RELEASED schema — the OAuth token/code tables
// at baseline PLUS only the migrations whose Keystone bundle is recorded as
// released in internal/migrations/bundled.lock (NOT internal/migrations HEAD) —
// and then runs the REAL OAuthClientRepository writes that the authorization_code
// and refresh_token grant exchanges perform against iam_oauth_tokens. If the
// code depends on a column supplied by a migration whose bundle has not been
// released (exactly like token_family_id was), CreateOAuthToken fails with 42703
// and this test fails, reproducing the outage BEFORE the merge.
//
// It is docker/ephemeral-Postgres gated: it self-skips unless TEST_DATABASE_URL
// (or DATABASE_URL) points at a reachable Postgres. In CI the oauth-schema-gap
// MR-gate job provides a postgres service container. Run locally with e.g.:
//
//	TEST_DATABASE_URL=postgres://test:test@localhost:5432/test?sslmode=disable \
//	  go test -tags=integration -run TestReleasedSchemaGap ./internal/repositories/...

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/migrations"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// oauthGapFixtureTables are the OAuth tables the token exchanges touch. Their
// BASELINE shape (below) deliberately omits every column added by an incremental
// migration — most importantly iam_oauth_tokens.token_family_id (migration
// 0009). Those columns must be supplied by the RELEASED migrations applied on
// top; that is the whole point of the test.
var oauthGapFixtureTables = []string{"iam_oauth_tokens", "iam_oauth_authorization_codes"}

// baselineSchema is the pre-incremental DDL for the OAuth exchange tables. It
// mirrors the columns the repository reads/writes MINUS anything an
// internal/migrations file adds. In production these tables come from the
// Keystone SchemaDefinition baseline (schema-definition-main.yaml), which is not
// carried in this repo — so the test provides the baseline explicitly and then
// layers the released incrementals from bundled.lock on top, reproducing the
// exact "baseline + released bundles" state prod runs.
const baselineSchema = `
CREATE TABLE iam_oauth_authorization_codes (
    id                    UUID PRIMARY KEY,
    tenant_id             UUID NOT NULL,
    client_id             UUID NOT NULL,
    user_id               UUID NOT NULL,
    code                  TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scopes                TEXT[] NOT NULL DEFAULT '{}',
    state                 TEXT,
    nonce                 TEXT,
    code_challenge        TEXT,
    code_challenge_method TEXT,
    is_used               BOOLEAN NOT NULL DEFAULT false,
    used_at               TIMESTAMPTZ,
    expires_at            TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    auth_methods_used     TEXT[] NOT NULL DEFAULT '{}',
    idp_session_id        UUID
);

CREATE TABLE iam_oauth_tokens (
    id                UUID PRIMARY KEY,
    tenant_id         UUID NOT NULL,
    client_id         UUID NOT NULL,
    user_id           UUID,
    token_type        TEXT NOT NULL,
    token             TEXT NOT NULL,
    scopes            TEXT[] NOT NULL DEFAULT '{}',
    refresh_token     TEXT,
    ip_address        TEXT,
    user_agent        TEXT,
    is_revoked        BOOLEAN NOT NULL DEFAULT false,
    revoked_at        TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    auth_methods_used TEXT[] NOT NULL DEFAULT '{}',
    idp_session_id    UUID
    -- token_family_id is intentionally ABSENT here: it is added by the released
    -- incremental migration 0009_oauth_token_family.sql. If 0009's bundle is not
    -- recorded in bundled.lock (the outage state), it is never applied below and
    -- the token INSERT fails with SQLSTATE 42703 — reproducing the outage.
);
`

// TestReleasedSchemaGap_OAuthTokenExchanges is the outage regression: the OAuth
// token-persistence writes that both the authorization_code and refresh_token
// grants perform MUST succeed against the last-released schema.
func TestReleasedSchemaGap_OAuthTokenExchanges(t *testing.T) {
	dsn := testDSN()
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL/DATABASE_URL not set — ephemeral Postgres unavailable; skipping schema-gap test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := newReleasedSchemaPool(ctx, t, dsn)
	defer pool.Close()

	repo := repositories.NewOAuthClientRepository(pool)

	// Diagnostic: prove the released set actually supplies token_family_id. If a
	// future change un-releases the migration that adds it (drops the 0009 entry
	// from bundled.lock), this fails here with a precise pointer instead of an
	// opaque 42703 downstream.
	require.True(t, columnExists(ctx, t, pool, "iam_oauth_tokens", "token_family_id"),
		"the last-released schema (bundled.lock) does not provide iam_oauth_tokens.token_family_id, "+
			"but the code writes it — this is the 2026-07-21 outage class. Release the bundle for the "+
			"migration that adds the column and record it in internal/migrations/bundled.lock.")

	tenantID := uuid.New()
	clientID := uuid.New()
	userID := uuid.New()

	// --- authorization_code grant: consume the code + persist the ROOT token ---
	// This is the exact write sequence that 400'd in production.
	authCode := &models.OAuthAuthorizationCode{
		ID:          uuid.New(),
		TenantID:    tenantID,
		ClientID:    clientID,
		UserID:      userID,
		Code:        "opaque-authorization-code-" + uuid.NewString(),
		RedirectURI: "https://rp.example.com/callback",
		Scopes:      []string{"openid", "profile"},
		IsUsed:      false,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		CreatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateAuthorizationCode(ctx, authCode))

	fetchedCode, err := repo.GetAuthorizationCode(ctx, authCode.Code)
	require.NoError(t, err)
	require.False(t, fetchedCode.IsUsed)
	require.NoError(t, repo.MarkAuthorizationCodeUsed(ctx, fetchedCode.ID))

	rootID := uuid.New()
	refreshRoot := "refresh-root-" + uuid.NewString()
	rootToken := newToken(rootID, tenantID, clientID, userID, refreshRoot, rootID /* root => family = self */)
	require.NoError(t, repo.CreateOAuthToken(ctx, rootToken),
		"authorization_code token INSERT must succeed against the released schema — "+
			"this is the exact iam_oauth_tokens write that returned SQLSTATE 42703 in the outage")

	// --- refresh_token grant: rotate the token, revoke the reused family ---
	fetchedToken, err := repo.GetOAuthTokenByHash(ctx, refreshRoot)
	require.NoError(t, err)
	require.NotNil(t, fetchedToken.TokenFamilyID)
	require.Equal(t, rootID, *fetchedToken.TokenFamilyID, "root token must be its own family root")

	won, err := repo.ConsumeRefreshToken(ctx, rootID)
	require.NoError(t, err)
	require.True(t, won, "the live refresh token must be consumable exactly once")

	rotatedID := uuid.New()
	rotatedToken := newToken(rotatedID, tenantID, clientID, userID, "refresh-rot-"+uuid.NewString(), rootID /* inherit family */)
	require.NoError(t, repo.CreateOAuthToken(ctx, rotatedToken),
		"refresh_token rotation must persist the descendant token against the released schema")

	// Simulate detected reuse: the whole lineage is revoked in one statement.
	revoked, err := repo.RevokeRefreshTokenFamily(ctx, rootID)
	require.NoError(t, err)
	require.GreaterOrEqual(t, revoked, int64(1),
		"RevokeRefreshTokenFamily must revoke at least the still-live rotated descendant")
}

// newToken builds a refresh-token row with the given family lineage.
func newToken(id, tenantID, clientID, userID uuid.UUID, refresh string, familyID uuid.UUID) *models.OAuthToken {
	now := time.Now()
	fam := familyID
	uid := userID
	return &models.OAuthToken{
		ID:              id,
		TenantID:        tenantID,
		ClientID:        clientID,
		UserID:          &uid,
		TokenType:       "refresh_token",
		Token:           "access-" + uuid.NewString(),
		Scopes:          []string{"openid"},
		RefreshToken:    &refresh,
		IsRevoked:       false,
		ExpiresAt:       now.Add(time.Hour),
		CreatedAt:       now,
		UpdatedAt:       now,
		AuthMethodsUsed: []string{"pwd"},
		TokenFamilyID:   &fam,
	}
}

// newReleasedSchemaPool provisions an isolated schema populated with the OAuth
// baseline + only the RELEASED incremental migrations (per bundled.lock), and
// returns a pool whose search_path is scoped to it. The schema is dropped on
// test cleanup.
func newReleasedSchemaPool(ctx context.Context, t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()

	schema := "oauth_gap_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skipf("cannot reach Postgres at TEST_DATABASE_URL (%v) — skipping schema-gap test", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create schema: %v", err)
	}
	_ = admin.Close(ctx)
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	})

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	// Scope every pooled connection to the isolated schema so the repository's
	// unqualified table names resolve there.
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)

	// 1. baseline OAuth tables (pre-incremental).
	_, err = pool.Exec(ctx, baselineSchema)
	require.NoError(t, err, "apply baseline OAuth schema")

	// 2. released incrementals that touch the OAuth tables, in migration order.
	for _, file := range releasedOAuthMigrations(t) {
		sqlBytes, err := migrations.ReadSQL(file)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, string(sqlBytes), pgx.QueryExecModeSimpleProtocol)
		require.NoErrorf(t, err, "apply released migration %s", file)
	}

	return pool
}

// releasedOAuthMigrations returns, in migration order, the migration files that
// (a) are recorded as released in bundled.lock and (b) modify one of the OAuth
// fixture tables. Applying only these models "DB migrated to the last-released
// bundle set". A migration present on disk but absent from the lock (an
// unreleased bundle — the outage state) is therefore NOT applied.
func releasedOAuthMigrations(t *testing.T) []string {
	t.Helper()
	entries, err := migrations.LockEntries()
	require.NoError(t, err)

	var files []string
	for _, e := range entries {
		sqlBytes, err := migrations.ReadSQL(e.File)
		require.NoErrorf(t, err, "released migration %s recorded in bundled.lock is missing on disk", e.File)
		lower := strings.ToLower(string(sqlBytes))
		for _, tbl := range oauthGapFixtureTables {
			if strings.Contains(lower, tbl) {
				files = append(files, e.File)
				break
			}
		}
	}
	sort.Strings(files)
	return files
}

func columnExists(ctx context.Context, t *testing.T, pool *pgxpool.Pool, table, column string) bool {
	t.Helper()
	var n int
	err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`,
		table, column).Scan(&n)
	require.NoError(t, err)
	return n > 0
}

func testDSN() string {
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		return v
	}
	return os.Getenv("DATABASE_URL")
}

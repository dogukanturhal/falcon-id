// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func newOAuthClientMock(t *testing.T) (pgxmock.PgxPoolIface, *OAuthClientRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newOAuthClientRepositoryWithMock(mock)
}

// oauthClientCols is the column list matching the SELECT in GetByID / GetByClientID.
// The order must exactly match oauthClientColumns in the production repository.
var oauthClientCols = []string{
	"id", "tenant_id", "client_id", "client_secret_hash", "client_name", "client_description",
	"grant_types", "response_types", "redirect_uris", "scopes",
	"access_token_lifetime", "refresh_token_lifetime", "id_token_lifetime",
	"is_public", "is_confidential", "is_first_party", "require_pkce", "is_active",
	"revoked_at", "revoked_by", "logo_url", "tos_url", "policy_url", "contact_email",
	"contacts", "token_endpoint_auth_method", "id_token_signed_response_alg",
	"post_logout_redirect_uris", "allowed_cors_origins",
	"backchannel_logout_uri", "backchannel_logout_session_required",
	"frontchannel_logout_uri", "frontchannel_logout_session_required",
	"created_at", "updated_at", "created_by", "updated_by",
	"app_category", "require_assignment",
	"require_pushed_authorization_requests", // FAPI 2.0 Baseline / RFC 9126 §2.1 (migration 223 / IAM-13)
	"jwks", "request_object_signing_alg",    // RFC 9101 JAR (migration 226)
	"client_uri",                    // RFC 7591 §2 client homepage URL (migration 227)
	"allow_external_jwt_exchange",   // RFC 8693 :jwt token-exchange permission (migration 237)
	"refresh_token_rotation_policy", // Duende BFF reuse-vs-rotate per-client policy (migration 242)
}

func sampleOAuthClient() *models.OAuthClient {
	now := time.Now()
	return &models.OAuthClient{
		ID:                       uuid.New(),
		TenantID:                 uuid.New(),
		ClientID:                 "test-client-id",
		ClientSecret:             "hashed-secret",
		Name:                     "Test OAuth Client",
		GrantTypes:               []string{"authorization_code", "refresh_token"},
		ResponseTypes:            []string{"code"},
		RedirectURIs:             []string{"https://example.com/callback"},
		Scopes:                   []string{"openid", "profile", "email"},
		AccessTokenLifetime:      3600,
		RefreshTokenLifetime:     2592000,
		IDTokenLifetime:          3600,
		IsPublic:                 false,
		IsConfidential:           true,
		IsFirstParty:             true,
		RequirePKCE:              true,
		IsActive:                 true,
		AppCategory:              "general",
		RequireAssignment:        false,
		Contacts:                 []string{},
		TokenEndpointAuthMethod:  "client_secret_basic",
		IDTokenSignedResponseAlg: "RS256",
		PostLogoutRedirectURIs:   []string{},
		AllowedCORSOrigins:       []string{},
		CreatedAt:                now,
		UpdatedAt:                now,
	}
}

// addOAuthClientRow adds a row to pgxmock rows that matches oauthClientCols.
func addOAuthClientRow(rows *pgxmock.Rows, c *models.OAuthClient) *pgxmock.Rows {
	return rows.AddRow(
		c.ID, c.TenantID, c.ClientID, c.ClientSecret,
		c.Name, c.Description,
		c.GrantTypes, c.ResponseTypes, c.RedirectURIs, c.Scopes,
		c.AccessTokenLifetime, c.RefreshTokenLifetime, c.IDTokenLifetime,
		c.IsPublic, c.IsConfidential, c.IsFirstParty, c.RequirePKCE, c.IsActive,
		c.RevokedAt, c.RevokedBy, c.LogoURL, c.TosURL, c.PolicyURL, c.ContactEmail,
		c.Contacts, c.TokenEndpointAuthMethod, c.IDTokenSignedResponseAlg,
		c.PostLogoutRedirectURIs, c.AllowedCORSOrigins,
		c.BackchannelLogoutURI, c.BackchannelLogoutSessionRequired,
		c.FrontchannelLogoutURI, c.FrontchannelLogoutSessionRequired,
		c.CreatedAt, c.UpdatedAt, c.CreatedBy, c.UpdatedBy,
		c.AppCategory, c.RequireAssignment,
		c.RequirePushedAuthorizationRequests,
		c.Jwks, c.RequestObjectSigningAlg, // RFC 9101 JAR
		c.ClientURI,                  // RFC 7591 §2 (migration 227)
		c.AllowExternalJWTExchange,   // RFC 8693 :jwt (migration 237)
		c.RefreshTokenRotationPolicy, // Migration 242
	)
}

// ─── GetByID ─────────────────────────────────────────────────────────────────

func TestOAuthClientRepository_GetByID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		client := sampleOAuthClient()
		rows := addOAuthClientRow(mock.NewRows(oauthClientCols), client)
		mock.ExpectQuery(`SELECT`).WithArgs(client.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), client.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, client.ID, got.ID)
		assert.Equal(t, client.ClientID, got.ClientID)
		assert.Equal(t, client.Name, got.Name)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(id).WillReturnRows(mock.NewRows(oauthClientCols))

		got, err := repo.GetByID(context.Background(), id)
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(id).WillReturnError(fmt.Errorf("connection timeout"))

		got, err := repo.GetByID(context.Background(), id)
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByClientID ───────────────────────────────────────────────────────────

func TestOAuthClientRepository_GetByClientID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		client := sampleOAuthClient()
		rows := addOAuthClientRow(mock.NewRows(oauthClientCols), client)
		mock.ExpectQuery(`SELECT`).WithArgs(client.ClientID).WillReturnRows(rows)

		got, err := repo.GetByClientID(context.Background(), client.ClientID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, client.ClientID, got.ClientID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WithArgs("nonexistent-client").WillReturnRows(mock.NewRows(oauthClientCols))

		got, err := repo.GetByClientID(context.Background(), "nonexistent-client")
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByTenantID ───────────────────────────────────────────────────────────

func TestOAuthClientRepository_GetByTenantID(t *testing.T) {
	t.Run("returns clients with total", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		client := sampleOAuthClient()

		// COUNT query
		countRows := mock.NewRows([]string{"count"}).AddRow(int64(1))
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(client.TenantID).WillReturnRows(countRows)

		// SELECT query
		rows := addOAuthClientRow(mock.NewRows(oauthClientCols), client)
		mock.ExpectQuery(`SELECT`).WithArgs(client.TenantID, pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(rows)

		clients, total, err := repo.GetByTenantID(context.Background(), client.TenantID, 1, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Len(t, clients, 1)
		assert.Equal(t, client.ID, clients[0].ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty result returns zero total", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(tenantID).WillReturnRows(mock.NewRows([]string{"count"}).AddRow(int64(0)))
		mock.ExpectQuery(`SELECT`).WithArgs(tenantID, pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(mock.NewRows(oauthClientCols))

		clients, total, err := repo.GetByTenantID(context.Background(), tenantID, 1, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(0), total)
		assert.Empty(t, clients)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("count query error propagates", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(tenantID).WillReturnError(fmt.Errorf("db error"))

		_, _, err := repo.GetByTenantID(context.Background(), tenantID, 1, 10)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Create ──────────────────────────────────────────────────────────────────

func TestOAuthClientRepository_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		client := sampleOAuthClient()
		// 38 args for INSERT (37 prior + refresh_token_rotation_policy
		// from migration 242).
		mock.ExpectExec(`INSERT INTO iam_oauth_clients`).
			WithArgs(anyArgs(38)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.Create(context.Background(), client)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("duplicate client_id returns error", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		client := sampleOAuthClient()
		mock.ExpectExec(`INSERT INTO iam_oauth_clients`).
			WithArgs(anyArgs(38)...).
			WillReturnError(fmt.Errorf("duplicate key value violates unique constraint"))

		err := repo.Create(context.Background(), client)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Update ──────────────────────────────────────────────────────────────────

func TestOAuthClientRepository_Update(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		client := sampleOAuthClient()
		// 34 args: 31 SET fields (30 prior + refresh_token_rotation_policy
		// from migration 242) + updated_at, updated_by, WHERE id
		mock.ExpectExec(`UPDATE iam_oauth_clients SET`).
			WithArgs(anyArgs(34)...).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.Update(context.Background(), client)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		client := sampleOAuthClient()
		mock.ExpectExec(`UPDATE iam_oauth_clients SET`).
			WithArgs(anyArgs(34)...).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.Update(context.Background(), client)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		client := sampleOAuthClient()
		mock.ExpectExec(`UPDATE iam_oauth_clients SET`).
			WithArgs(anyArgs(34)...).
			WillReturnError(fmt.Errorf("connection lost"))

		err := repo.Update(context.Background(), client)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Delete ──────────────────────────────────────────────────────────────────

func TestOAuthClientRepository_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_oauth_clients`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(context.Background(), id)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_oauth_clients`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		err := repo.Delete(context.Background(), id)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── UpdateSecret ────────────────────────────────────────────────────────────

func TestOAuthClientRepository_UpdateSecret(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_oauth_clients SET client_secret_hash`).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdateSecret(context.Background(), id, "new-hashed-secret")
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_oauth_clients SET client_secret_hash`).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.UpdateSecret(context.Background(), id, "new-hashed-secret")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── CreateAuthorizationCode ─────────────────────────────────────────────────

func TestOAuthClientRepository_CreateAuthorizationCode(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		code := &models.OAuthAuthorizationCode{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			ClientID:    uuid.New(),
			UserID:      uuid.New(),
			Code:        "auth-code-123",
			RedirectURI: "https://example.com/callback",
			Scopes:      []string{"openid"},
			IsUsed:      false,
			ExpiresAt:   time.Now().Add(10 * time.Minute),
			CreatedAt:   time.Now(),
		}

		// 16 args for the INSERT (14 original + auth_methods_used + idp_session_id from migration 220)
		mock.ExpectExec(`INSERT INTO iam_oauth_authorization_codes`).
			WithArgs(anyArgs(16)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.CreateAuthorizationCode(context.Background(), code)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		code := &models.OAuthAuthorizationCode{
			ID: uuid.New(), TenantID: uuid.New(), ClientID: uuid.New(), UserID: uuid.New(),
			Code: "dup-code", RedirectURI: "https://example.com/cb",
			Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(5 * time.Minute), CreatedAt: time.Now(),
		}
		mock.ExpectExec(`INSERT INTO iam_oauth_authorization_codes`).
			WithArgs(anyArgs(16)...).
			WillReturnError(fmt.Errorf("duplicate code"))

		err := repo.CreateAuthorizationCode(context.Background(), code)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetAuthorizationCode ────────────────────────────────────────────────────

var authCodeCols = []string{
	"id", "tenant_id", "client_id", "user_id", "code", "redirect_uri", "scopes",
	"state", "nonce", "code_challenge", "code_challenge_method",
	"is_used", "used_at", "expires_at", "created_at",
	"auth_methods_used", "idp_session_id",
}

func TestOAuthClientRepository_GetAuthorizationCode(t *testing.T) {
	now := time.Now()

	t.Run("found", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		rows := mock.NewRows(authCodeCols).AddRow(
			uuid.New(), uuid.New(), uuid.New(), uuid.New(),
			"code-abc", "https://example.com/cb", []string{"openid"},
			nil, nil, nil, nil,
			false, nil, now.Add(10*time.Minute), now,
			[]string{}, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs("code-abc").WillReturnRows(rows)

		got, err := repo.GetAuthorizationCode(context.Background(), "code-abc")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "code-abc", got.Code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WithArgs("missing-code").WillReturnRows(mock.NewRows(authCodeCols))

		got, err := repo.GetAuthorizationCode(context.Background(), "missing-code")
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── MarkAuthorizationCodeUsed ───────────────────────────────────────────────

func TestOAuthClientRepository_MarkAuthorizationCodeUsed(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_oauth_authorization_codes SET is_used`).
			WithArgs(pgxmock.AnyArg(), id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.MarkAuthorizationCodeUsed(context.Background(), id)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_oauth_authorization_codes SET is_used`).
			WithArgs(pgxmock.AnyArg(), id).
			WillReturnError(fmt.Errorf("update failed"))

		err := repo.MarkAuthorizationCodeUsed(context.Background(), id)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── CreateOAuthToken ────────────────────────────────────────────────────────

func TestOAuthClientRepository_CreateOAuthToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		token := &models.OAuthToken{
			ID: uuid.New(), TenantID: uuid.New(), ClientID: uuid.New(),
			TokenType: "access_token", Token: "hashed-token", Scopes: []string{"openid"},
			IsRevoked: false, ExpiresAt: time.Now().Add(time.Hour),
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}

		// 18 args for INSERT (14 original + auth_methods_used + idp_session_id
		// from migration 220 + token_family_id from migration 0009 +
		// session_id from migration 0028)
		mock.ExpectExec(`INSERT INTO iam_oauth_tokens`).
			WithArgs(anyArgs(18)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.CreateOAuthToken(context.Background(), token)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetOAuthTokenByHash ─────────────────────────────────────────────────────

var oauthTokenCols = []string{
	"id", "tenant_id", "client_id", "user_id", "token_type", "token", "scopes",
	"refresh_token", "ip_address", "user_agent", "is_revoked", "revoked_at",
	"expires_at", "created_at", "updated_at",
	"auth_methods_used", "idp_session_id", "token_family_id", "session_id", "replaced_by", "revoke_reason", "recovery_count",
}

func TestOAuthClientRepository_GetOAuthTokenByHash(t *testing.T) {
	now := time.Now()

	t.Run("found by token hash", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		rows := mock.NewRows(oauthTokenCols).AddRow(
			uuid.New(), uuid.New(), uuid.New(), nil,
			"access_token", "hashed-token", []string{"openid"},
			nil, nil, nil, false, nil,
			now.Add(time.Hour), now, now,
			[]string{}, nil, nil, nil, nil, nil, int16(0),
		)
		mock.ExpectQuery(`SELECT`).WithArgs("hashed-token").WillReturnRows(rows)

		got, err := repo.GetOAuthTokenByHash(context.Background(), "hashed-token")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "hashed-token", got.Token)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WithArgs("missing-hash").WillReturnRows(mock.NewRows(oauthTokenCols))

		got, err := repo.GetOAuthTokenByHash(context.Background(), "missing-hash")
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── RevokeOAuthToken ────────────────────────────────────────────────────────

func TestOAuthClientRepository_RevokeOAuthToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_oauth_tokens SET is_revoked`).
			WithArgs(pgxmock.AnyArg(), "token-hash").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.RevokeOAuthToken(context.Background(), "token-hash")
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── RevokeTokensBySession ───────────────────────────────────────────────────

func TestOAuthClientRepository_RevokeTokensBySession(t *testing.T) {
	t.Run("revokes bound tokens and their families", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		sid, uid := uuid.New(), uuid.New()
		mock.ExpectExec(`(?s)UPDATE iam_oauth_tokens\s+SET is_revoked = true.*user_id = \$3.*session_id = \$2 OR idp_session_id = \$2.*token_family_id IN`).
			WithArgs(pgxmock.AnyArg(), sid, uid).
			WillReturnResult(pgxmock.NewResult("UPDATE", 3))

		n, err := repo.RevokeTokensBySession(context.Background(), sid, uid)
		assert.NoError(t, err)
		assert.Equal(t, int64(3), n)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("propagates database error", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_oauth_tokens`).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnError(assert.AnError)

		_, err := repo.RevokeTokensBySession(context.Background(), uuid.New(), uuid.New())
		assert.Error(t, err)
	})
}

// ─── RevokeAllClientTokens ───────────────────────────────────────────────────

func TestOAuthClientRepository_RevokeAllClientTokens(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		clientID := uuid.New()
		mock.ExpectExec(`UPDATE iam_oauth_tokens SET is_revoked`).
			WithArgs(pgxmock.AnyArg(), clientID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 5))

		err := repo.RevokeAllClientTokens(context.Background(), clientID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── RevokeUserClientTokens ──────────────────────────────────────────────────

func TestOAuthClientRepository_RevokeUserClientTokens(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		userID := uuid.New()
		clientID := uuid.New()
		mock.ExpectExec(`UPDATE iam_oauth_tokens SET is_revoked`).
			WithArgs(pgxmock.AnyArg(), userID, clientID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 2))

		err := repo.RevokeUserClientTokens(context.Background(), userID, clientID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetConsent ──────────────────────────────────────────────────────────────

var consentCols = []string{"id", "user_id", "client_id", "scopes", "granted_at", "expires_at", "revoked_at"}

func TestOAuthClientRepository_GetConsent(t *testing.T) {
	now := time.Now()

	t.Run("consent found", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		userID := uuid.New()
		clientID := uuid.New()
		rows := mock.NewRows(consentCols).AddRow(
			uuid.New(), userID, clientID, []string{"openid", "profile"},
			now, nil, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(userID, clientID).WillReturnRows(rows)

		got, err := repo.GetConsent(context.Background(), userID, clientID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, userID, got.UserID)
		assert.Equal(t, clientID, got.ClientID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no consent returns nil", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		userID := uuid.New()
		clientID := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(userID, clientID).WillReturnRows(mock.NewRows(consentCols))

		got, err := repo.GetConsent(context.Background(), userID, clientID)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		userID := uuid.New()
		clientID := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(userID, clientID).WillReturnError(fmt.Errorf("db error"))

		got, err := repo.GetConsent(context.Background(), userID, clientID)
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── CreateOrUpdateConsent ───────────────────────────────────────────────────

func TestOAuthClientRepository_CreateOrUpdateConsent(t *testing.T) {
	t.Run("success insert", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		consent := &models.OAuthConsent{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			ClientID:  uuid.New(),
			Scopes:    []string{"openid"},
			GrantedAt: time.Now(),
		}

		// 6 args: id, user_id, client_id, scopes, granted_at, expires_at
		mock.ExpectExec(`INSERT INTO iam_oauth_consents`).
			WithArgs(anyArgs(6)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.CreateOrUpdateConsent(context.Background(), consent)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── RevokeConsent ───────────────────────────────────────────────────────────

func TestOAuthClientRepository_RevokeConsent(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		userID := uuid.New()
		clientID := uuid.New()
		mock.ExpectExec(`UPDATE iam_oauth_consents SET revoked_at`).
			WithArgs(pgxmock.AnyArg(), userID, clientID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.RevokeConsent(context.Background(), userID, clientID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetUserConsents ─────────────────────────────────────────────────────────

func TestOAuthClientRepository_GetUserConsents(t *testing.T) {
	now := time.Now()

	t.Run("returns consents for user", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		userID := uuid.New()
		rows := mock.NewRows(consentCols).
			AddRow(uuid.New(), userID, uuid.New(), []string{"openid"}, now, nil, nil).
			AddRow(uuid.New(), userID, uuid.New(), []string{"profile"}, now, nil, nil)
		mock.ExpectQuery(`SELECT`).WithArgs(userID).WillReturnRows(rows)

		consents, err := repo.GetUserConsents(context.Background(), userID)
		require.NoError(t, err)
		assert.Len(t, consents, 2)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no consents returns empty slice", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		userID := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(userID).WillReturnRows(mock.NewRows(consentCols))

		consents, err := repo.GetUserConsents(context.Background(), userID)
		require.NoError(t, err)
		assert.Empty(t, consents)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── CreateOAuthState ────────────────────────────────────────────────────────

func TestOAuthClientRepository_CreateOAuthState(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		state := &models.OAuthState{
			ID: uuid.New(), TenantID: uuid.New(), ClientID: uuid.New(),
			State:       "random-state-value",
			RedirectURI: "https://example.com/cb",
			IsUsed:      false,
			ExpiresAt:   time.Now().Add(10 * time.Minute),
			CreatedAt:   time.Now(),
		}

		// 12 args for INSERT
		mock.ExpectExec(`INSERT INTO iam_oauth_states`).
			WithArgs(anyArgs(12)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.CreateOAuthState(context.Background(), state)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetOAuthState ───────────────────────────────────────────────────────────

var oauthStateCols = []string{
	"id", "tenant_id", "client_id", "user_id", "state", "redirect_uri", "nonce",
	"code_challenge", "code_challenge_method", "is_used", "used_at", "expires_at", "created_at",
}

func TestOAuthClientRepository_GetOAuthState(t *testing.T) {
	now := time.Now()

	t.Run("found", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		rows := mock.NewRows(oauthStateCols).AddRow(
			uuid.New(), uuid.New(), uuid.New(), nil,
			"state-xyz", "https://example.com/cb", nil,
			nil, nil, false, nil, now.Add(10*time.Minute), now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs("state-xyz").WillReturnRows(rows)

		got, err := repo.GetOAuthState(context.Background(), "state-xyz")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "state-xyz", got.State)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WithArgs("bad-state").WillReturnRows(mock.NewRows(oauthStateCols))

		got, err := repo.GetOAuthState(context.Background(), "bad-state")
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── MarkOAuthStateUsed ──────────────────────────────────────────────────────

func TestOAuthClientRepository_MarkOAuthStateUsed(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_oauth_states SET is_used`).
			WithArgs(pgxmock.AnyArg(), id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.MarkOAuthStateUsed(context.Background(), id)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── CleanupExpiredStates ────────────────────────────────────────────────────

func TestOAuthClientRepository_CleanupExpiredStates(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_oauth_states`).
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("DELETE", 3))

		err := repo.CleanupExpiredStates(context.Background())
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── CleanupExpiredCodes ─────────────────────────────────────────────────────

func TestOAuthClientRepository_CleanupExpiredCodes(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_oauth_authorization_codes`).
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("DELETE", 7))

		err := repo.CleanupExpiredCodes(context.Background())
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestOAuthClientColumnsBoundaryWhitespace is a regression guard for the
// 2026-05-01 outage in which oauthClientColumns ended with the bare
// identifier `client_uri` and was concatenated directly against `FROM
// iam_oauth_clients` with no separator, producing the mashed identifier
// `client_uriFROM`. PG then parsed the SQL with no FROM clause and rejected
// `id` as undefined (SQLSTATE 42703), which the OAuth service collapsed to
// `invalid_client: client not found` for every /oauth/authorize,
// /oauth/token, and /oauth/introspect call. The bug was invisible until
// the prior version happened to end in a `)` (a hard PG token boundary).
//
// Asserting the constant's leading and trailing whitespace at compile-time
// is cheaper than reproducing the SQL through pgxmock and is sufficient
// because every call site relies on the same boundary contract: the SQL
// fragments around oauthClientColumns provide no whitespace themselves.
func TestOAuthClientColumnsBoundaryWhitespace(t *testing.T) {
	if oauthClientColumns == "" {
		t.Fatal("oauthClientColumns is empty")
	}
	first := oauthClientColumns[0]
	last := oauthClientColumns[len(oauthClientColumns)-1]
	if first != '\n' && first != ' ' && first != '\t' {
		t.Errorf("oauthClientColumns must start with whitespace to separate from the literal `SELECT`; got first byte %q", first)
	}
	if last != '\n' && last != ' ' && last != '\t' {
		t.Errorf("oauthClientColumns must end with whitespace to separate from the literal `FROM iam_oauth_clients ...`; got last byte %q. This is the 2026-05-01 outage shape — a bare-identifier last column mashes into FROM and PG rejects the SELECT with SQLSTATE 42703.", last)
	}
}

// TestOAuthClientColumnsCoalescesNullableSecretHash guards the 2026-05-29
// regression: public clients (is_public=true, no client_secret_hash) cannot
// be loaded if the SELECT returns NULL for client_secret_hash, because
// scanOAuthClient targets a *string field that cannot accept NULL ("cannot
// scan NULL into *string"). The fix is the same COALESCE pattern already
// applied to require_assignment, app_category, etc. on this column list —
// the cheapest assertion is that the column list contains it.
//
// Trigger: svc-jess (Jess CLI OIDC client) was the first public client
// inserted via Keystone bundle without an explicit client_secret_hash, so
// the row had NULL there and every /oauth/authorize against it failed with
// "invalid_client: failed to get OAuth client: can't scan into dest[3]
// (col: client_secret_hash): cannot scan NULL into *string".
func TestOAuthClientColumnsCoalescesNullableSecretHash(t *testing.T) {
	const want = "COALESCE(client_secret_hash, '')"
	if !strings.Contains(oauthClientColumns, want) {
		t.Errorf("oauthClientColumns must SELECT %s so public clients with NULL secret_hash scan cleanly into the *string field; got column list:\n%s", want, oauthClientColumns)
	}
}

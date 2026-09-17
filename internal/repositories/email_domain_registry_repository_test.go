// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func newEmailDomainRepoMock(t *testing.T) (*EmailDomainRegistryRepository, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return &EmailDomainRegistryRepository{db: mock}, mock
}

func emailDomainCols() []string {
	return []string{
		"id", "tenant_id", "domain", "is_verified",
		"verification_token", "verification_method", "verified_at",
		"auto_enroll", "created_at", "updated_at",
	}
}

func newTestEmailDomain(tenantID uuid.UUID) *models.EmailDomainRegistry {
	now := time.Now().UTC()
	token := "tok-abc123"
	verifiedAt := now
	return &models.EmailDomainRegistry{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Domain:             "example.com",
		IsVerified:         true,
		VerificationToken:  &token,
		VerificationMethod: "dns_txt",
		VerifiedAt:         &verifiedAt,
		AutoEnroll:         false,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

func emailDomainRow(e *models.EmailDomainRegistry) []interface{} {
	return []interface{}{
		e.ID, e.TenantID, e.Domain, e.IsVerified,
		e.VerificationToken, e.VerificationMethod, e.VerifiedAt,
		e.AutoEnroll, e.CreatedAt, e.UpdatedAt,
	}
}

// ─── GetVerifiedByDomain ─────────────────────────────────────────────────────

func TestEmailDomainRegistry_GetVerifiedByDomain(t *testing.T) {
	t.Run("found verified domain", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		entry := newTestEmailDomain(tenantID)

		rows := pgxmock.NewRows(emailDomainCols()).AddRow(emailDomainRow(entry)...)
		mock.ExpectQuery(`SELECT .+ FROM iam_email_domain_registry WHERE domain = \$1 AND is_verified = true`).
			WithArgs("example.com").
			WillReturnRows(rows)

		got, err := repo.GetVerifiedByDomain(ctx, "example.com")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, entry.ID, got.ID)
		assert.Equal(t, entry.TenantID, got.TenantID)
		assert.Equal(t, "example.com", got.Domain)
		assert.True(t, got.IsVerified)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil nil", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		mock.ExpectQuery(`SELECT .+ FROM iam_email_domain_registry WHERE domain = \$1 AND is_verified = true`).
			WithArgs("unknown.com").
			WillReturnRows(pgxmock.NewRows(emailDomainCols()))

		got, err := repo.GetVerifiedByDomain(ctx, "unknown.com")
		require.NoError(t, err)
		assert.Nil(t, got)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		mock.ExpectQuery(`SELECT .+ FROM iam_email_domain_registry WHERE domain = \$1 AND is_verified = true`).
			WithArgs("fail.com").
			WillReturnError(errors.New("connection reset"))

		_, err := repo.GetVerifiedByDomain(ctx, "fail.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "GetVerifiedByDomain")
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByID ─────────────────────────────────────────────────────────────────

func TestEmailDomainRegistry_GetByID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		entry := newTestEmailDomain(tenantID)

		rows := pgxmock.NewRows(emailDomainCols()).AddRow(emailDomainRow(entry)...)
		mock.ExpectQuery(`SELECT .+ FROM iam_email_domain_registry WHERE id = \$1`).
			WithArgs(entry.ID).
			WillReturnRows(rows)

		got, err := repo.GetByID(ctx, entry.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, entry.ID, got.ID)
		assert.Equal(t, "dns_txt", got.VerificationMethod)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil nil", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_email_domain_registry WHERE id = \$1`).
			WithArgs(id).
			WillReturnRows(pgxmock.NewRows(emailDomainCols()))

		got, err := repo.GetByID(ctx, id)
		require.NoError(t, err)
		assert.Nil(t, got)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_email_domain_registry WHERE id = \$1`).
			WithArgs(id).
			WillReturnError(errors.New("db error"))

		_, err := repo.GetByID(ctx, id)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "GetByID")
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── ListByTenant ─────────────────────────────────────────────────────────────

func TestEmailDomainRegistry_ListByTenant(t *testing.T) {
	t.Run("returns all domains for tenant", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		e1 := newTestEmailDomain(tenantID)
		e1.Domain = "alpha.com"
		e2 := newTestEmailDomain(tenantID)
		e2.ID = uuid.New()
		e2.Domain = "beta.com"

		rows := pgxmock.NewRows(emailDomainCols()).
			AddRow(emailDomainRow(e1)...).
			AddRow(emailDomainRow(e2)...)

		mock.ExpectQuery(`SELECT .+ FROM iam_email_domain_registry WHERE tenant_id = \$1 ORDER BY domain`).
			WithArgs(tenantID).
			WillReturnRows(rows)

		got, err := repo.ListByTenant(ctx, tenantID)
		require.NoError(t, err)
		assert.Len(t, got, 2)
		assert.Equal(t, "alpha.com", got[0].Domain)
		assert.Equal(t, "beta.com", got[1].Domain)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty tenant returns nil slice", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_email_domain_registry WHERE tenant_id = \$1 ORDER BY domain`).
			WithArgs(tenantID).
			WillReturnRows(pgxmock.NewRows(emailDomainCols()))

		got, err := repo.ListByTenant(ctx, tenantID)
		require.NoError(t, err)
		assert.Empty(t, got)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_email_domain_registry WHERE tenant_id = \$1 ORDER BY domain`).
			WithArgs(tenantID).
			WillReturnError(errors.New("db error"))

		_, err := repo.ListByTenant(ctx, tenantID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ListByTenant")
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Create ──────────────────────────────────────────────────────────────────

func TestEmailDomainRegistry_Create(t *testing.T) {
	t.Run("creates domain with generated uuid", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		now := time.Now().UTC()
		token := "verification-token"
		entry := &models.EmailDomainRegistry{
			TenantID:           uuid.New(),
			Domain:             "corp.example.com",
			VerificationToken:  &token,
			VerificationMethod: "dns_txt",
			AutoEnroll:         true,
		}

		mock.ExpectQuery(`INSERT INTO iam_email_domain_registry`).
			WithArgs(
				pgxmock.AnyArg(), // id (auto-generated)
				entry.TenantID,
				entry.Domain,
				entry.VerificationToken,
				entry.VerificationMethod,
				entry.AutoEnroll,
			).
			WillReturnRows(pgxmock.NewRows([]string{"is_verified", "verified_at", "created_at", "updated_at"}).
				AddRow(false, nil, now, now))

		err := repo.Create(ctx, entry)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, entry.ID)
		assert.False(t, entry.IsVerified)
		assert.Equal(t, now.UTC().Truncate(time.Second), entry.CreatedAt.UTC().Truncate(time.Second))
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("creates domain with pre-set uuid", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		now := time.Now().UTC()
		token := "tok-preset"
		presetID := uuid.New()
		entry := &models.EmailDomainRegistry{
			ID:                 presetID,
			TenantID:           uuid.New(),
			Domain:             "preset.example.com",
			VerificationToken:  &token,
			VerificationMethod: "http_file",
			AutoEnroll:         false,
		}

		mock.ExpectQuery(`INSERT INTO iam_email_domain_registry`).
			WithArgs(presetID, entry.TenantID, entry.Domain, entry.VerificationToken, entry.VerificationMethod, entry.AutoEnroll).
			WillReturnRows(pgxmock.NewRows([]string{"is_verified", "verified_at", "created_at", "updated_at"}).
				AddRow(false, nil, now, now))

		err := repo.Create(ctx, entry)
		require.NoError(t, err)
		assert.Equal(t, presetID, entry.ID)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		token := "tok"
		entry := &models.EmailDomainRegistry{
			TenantID:           uuid.New(),
			Domain:             "dup.com",
			VerificationToken:  &token,
			VerificationMethod: "dns_txt",
		}

		mock.ExpectQuery(`INSERT INTO iam_email_domain_registry`).
			WithArgs(pgxmock.AnyArg(), entry.TenantID, entry.Domain, entry.VerificationToken, entry.VerificationMethod, entry.AutoEnroll).
			WillReturnError(errors.New("unique constraint violation"))

		err := repo.Create(ctx, entry)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Verify ──────────────────────────────────────────────────────────────────

func TestEmailDomainRegistry_Verify(t *testing.T) {
	t.Run("marks domain as verified", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_email_domain_registry`).
			WithArgs(id, pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.Verify(ctx, id)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_email_domain_registry`).
			WithArgs(id, pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.Verify(ctx, id)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_email_domain_registry`).
			WithArgs(id, pgxmock.AnyArg()).
			WillReturnError(errors.New("db error"))

		err := repo.Verify(ctx, id)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Verify")
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Delete ──────────────────────────────────────────────────────────────────

func TestEmailDomainRegistry_Delete(t *testing.T) {
	t.Run("deletes domain registration", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_email_domain_registry WHERE id = \$1`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(ctx, id)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("delete of non-existent row is not an error", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_email_domain_registry WHERE id = \$1`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		err := repo.Delete(ctx, id)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newEmailDomainRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_email_domain_registry WHERE id = \$1`).
			WithArgs(id).
			WillReturnError(errors.New("db error"))

		err := repo.Delete(ctx, id)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Delete")
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

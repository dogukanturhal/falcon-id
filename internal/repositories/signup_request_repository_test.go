// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// newSignupRequestRepositoryWithMock constructs a repository backed by a mock pool.
func newSignupRequestRepositoryWithMock(mock pgxmock.PgxPoolIface) *SignupRequestRepository {
	return &SignupRequestRepository{db: mock}
}

// signupRequestColumns is the ordered list of columns returned by the SELECT queries,
// matching the scan order in scanSignupRequest.
var signupRequestColumns = []string{
	"id", "email", "first_name", "last_name", "account_type",
	"company_name", "company_slug", "verification_token",
	"verified", "verified_at", "completed", "completed_at",
	"tenant_id", "user_id", "ip_address", "user_agent",
	"expires_at", "created_at", "updated_at", "continuation", "completion_secret_hash",
	"verification_code_hash", "verification_code_expires_at", "verification_attempts",
	"verification_failed_total",
}

// buildSignupRows returns a *pgxmock.Rows pre-populated with one signup request.
func buildSignupRows(req *models.SignupRequest) *pgxmock.Rows {
	return pgxmock.NewRows(signupRequestColumns).AddRow(
		req.ID,
		req.Email,
		req.FirstName,
		req.LastName,
		req.AccountType,
		req.CompanyName,
		req.CompanySlug,
		req.VerificationToken,
		req.Verified,
		req.VerifiedAt,
		req.Completed,
		req.CompletedAt,
		req.TenantID,
		req.UserID,
		req.IPAddress,
		req.UserAgent,
		req.ExpiresAt,
		req.CreatedAt,
		req.UpdatedAt,
		req.Continuation,
		req.CompletionSecretHash,
		req.VerificationCodeHash,
		req.VerificationCodeExpiresAt,
		req.VerificationAttempts,
		req.VerificationFailedTotal,
	)
}

// newTestSignupRequest creates a minimal SignupRequest suitable for unit tests.
func newTestSignupRequest() *models.SignupRequest {
	ip := "127.0.0.1"
	ua := "Go-http-client/1.1"
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &models.SignupRequest{
		ID:                uuid.New(),
		Email:             "jane.doe@example.com",
		AccountType:       "personal",
		VerificationToken: "test-token-abc123",
		Verified:          false,
		Completed:         false,
		IPAddress:         &ip,
		UserAgent:         &ua,
		ExpiresAt:         now.Add(24 * time.Hour),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestSignupRequestRepository_Create_Success(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	req := newTestSignupRequest()

	mock.ExpectExec(`INSERT INTO iam_signup_requests`).
		WithArgs(anyArgs(14)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err = repo.Create(context.Background(), req)
	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_Create_BusinessAccount(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	companyName := "Acme Corp"
	companySlug := "acme-corp"
	firstName := "John"
	lastName := "Smith"
	req := newTestSignupRequest()
	req.AccountType = "business"
	req.FirstName = &firstName
	req.LastName = &lastName
	req.CompanyName = &companyName
	req.CompanySlug = &companySlug

	mock.ExpectExec(`INSERT INTO iam_signup_requests`).
		WithArgs(anyArgs(14)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err = repo.Create(context.Background(), req)
	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_Create_DBError(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	req := newTestSignupRequest()

	mock.ExpectExec(`INSERT INTO iam_signup_requests`).
		WithArgs(anyArgs(14)...).
		WillReturnError(fmt.Errorf("unique_violation: duplicate key"))

	err = repo.Create(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create signup request")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// GetByToken
// ---------------------------------------------------------------------------

func TestSignupRequestRepository_GetByToken_Found(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	req := newTestSignupRequest()

	mock.ExpectQuery(`SELECT .+ FROM iam_signup_requests`).
		WithArgs(req.VerificationToken).
		WillReturnRows(buildSignupRows(req))

	result, err := repo.GetByToken(context.Background(), req.VerificationToken)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, req.ID, result.ID)
	assert.Equal(t, req.Email, result.Email)
	assert.Equal(t, req.VerificationToken, result.VerificationToken)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_GetByToken_NotFound(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	mock.ExpectQuery(`SELECT .+ FROM iam_signup_requests`).
		WithArgs("nonexistent-token").
		WillReturnError(pgx.ErrNoRows)

	result, err := repo.GetByToken(context.Background(), "nonexistent-token")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "signup request not found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_GetByToken_DBError(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	mock.ExpectQuery(`SELECT .+ FROM iam_signup_requests`).
		WithArgs("bad-token").
		WillReturnError(fmt.Errorf("connection refused"))

	result, err := repo.GetByToken(context.Background(), "bad-token")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "get signup request by token")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// GetByID
// ---------------------------------------------------------------------------

func TestSignupRequestRepository_GetByID_Found(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	req := newTestSignupRequest()

	mock.ExpectQuery(`SELECT .+ FROM iam_signup_requests`).
		WithArgs(req.ID).
		WillReturnRows(buildSignupRows(req))

	result, err := repo.GetByID(context.Background(), req.ID)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, req.ID, result.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_GetByID_NotFound(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	id := uuid.New()

	mock.ExpectQuery(`SELECT .+ FROM iam_signup_requests`).
		WithArgs(id).
		WillReturnError(pgx.ErrNoRows)

	result, err := repo.GetByID(context.Background(), id)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "signup request not found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// GetPendingByEmail
// ---------------------------------------------------------------------------

func TestSignupRequestRepository_GetPendingByEmail_Found(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	req := newTestSignupRequest()

	mock.ExpectQuery(`SELECT .+ FROM iam_signup_requests`).
		WithArgs(req.Email).
		WillReturnRows(buildSignupRows(req))

	result, err := repo.GetPendingByEmail(context.Background(), req.Email)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, req.Email, result.Email)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_GetPendingByEmail_NotFound(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	mock.ExpectQuery(`SELECT .+ FROM iam_signup_requests`).
		WithArgs("nobody@example.com").
		WillReturnError(pgx.ErrNoRows)

	result, err := repo.GetPendingByEmail(context.Background(), "nobody@example.com")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no pending signup request")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_GetPendingByEmail_DBError(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	mock.ExpectQuery(`SELECT .+ FROM iam_signup_requests`).
		WithArgs("broken@example.com").
		WillReturnError(fmt.Errorf("timeout"))

	result, err := repo.GetPendingByEmail(context.Background(), "broken@example.com")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "get pending signup request")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// MarkVerified
// ---------------------------------------------------------------------------

func TestSignupRequestRepository_MarkVerified_Success(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	id := uuid.New()

	mock.ExpectExec(`UPDATE iam_signup_requests`).
		WithArgs(id).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err = repo.MarkVerified(context.Background(), id)
	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_MarkVerified_DBError(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	id := uuid.New()

	mock.ExpectExec(`UPDATE iam_signup_requests`).
		WithArgs(id).
		WillReturnError(fmt.Errorf("db error"))

	err = repo.MarkVerified(context.Background(), id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mark signup request verified")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// MarkCompleted
// ---------------------------------------------------------------------------

func TestSignupRequestRepository_MarkCompleted_Success(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	signupID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()

	mock.ExpectExec(`UPDATE iam_signup_requests`).
		WithArgs(signupID, tenantID, userID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err = repo.MarkCompleted(context.Background(), signupID, tenantID, userID)
	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_MarkCompleted_DBError(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	signupID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()

	mock.ExpectExec(`UPDATE iam_signup_requests`).
		WithArgs(signupID, tenantID, userID).
		WillReturnError(fmt.Errorf("constraint violation"))

	err = repo.MarkCompleted(context.Background(), signupID, tenantID, userID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mark signup request completed")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// SetProvisionedTenant
// ---------------------------------------------------------------------------

func TestSignupRequestRepository_SetProvisionedTenant_Success(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	signupID := uuid.New()
	tenantID := uuid.New()

	mock.ExpectExec(`UPDATE iam_signup_requests`).
		WithArgs(signupID, tenantID, "acme-corp").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err = repo.SetProvisionedTenant(context.Background(), signupID, tenantID, "acme-corp")
	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_SetProvisionedTenant_DBError(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	signupID := uuid.New()
	tenantID := uuid.New()

	mock.ExpectExec(`UPDATE iam_signup_requests`).
		WithArgs(signupID, tenantID, "acme-corp").
		WillReturnError(fmt.Errorf("connection reset"))

	err = repo.SetProvisionedTenant(context.Background(), signupID, tenantID, "acme-corp")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set provisioned tenant on signup request")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_SetCompanyDetails(t *testing.T) {
	t.Parallel()

	signupID := uuid.New()
	tests := []struct {
		name    string
		rows    int64
		wantErr bool
	}{
		{"updates an unprovisioned request", 1, false},
		{"provisioned or completed request is untouched", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
			require.NoError(t, err)
			repo := newSignupRequestRepositoryWithMock(mock)

			mock.ExpectExec(`UPDATE iam_signup_requests[\s\S]*tenant_id IS NULL AND completed = false`).
				WithArgs(signupID, "Acme", "acme").
				WillReturnResult(pgxmock.NewResult("UPDATE", tt.rows))

			err = repo.SetCompanyDetails(context.Background(), signupID, "Acme", "acme")
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// ---------------------------------------------------------------------------
// CountStalledSignups
// ---------------------------------------------------------------------------

func TestSignupRequestRepository_CountStalledSignups_Success(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	cutoff := time.Now().Add(-time.Hour)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_signup_requests`).
		WithArgs(cutoff).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(3))

	count, err := repo.CountStalledSignups(context.Background(), cutoff)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_CountStalledSignups_DBError(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	cutoff := time.Now().Add(-time.Hour)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_signup_requests`).
		WithArgs(cutoff).
		WillReturnError(fmt.Errorf("connection reset"))

	_, err = repo.CountStalledSignups(context.Background(), cutoff)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "count stalled signup requests")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSignupRequestRepository_CountStalledSignups_PredicateExcludesCompleted
// is the positive control the reaping/stall predicate work requires: a
// completed signup — the shape of a real, live account — must never be
// reachable through this query. This is proven at the SQL-shape level
// (the WHERE clause has an unconditional "AND NOT completed" that no
// argument can defeat), and mirrored here by asserting the literal query
// text sent to the DB contains that clause, so a future edit that
// accidentally drops it fails this test rather than shipping quietly.
func TestSignupRequestRepository_CountStalledSignups_PredicateExcludesCompleted(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	cutoff := time.Now().Add(-time.Hour)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_signup_requests\s+WHERE verified AND NOT completed AND expires_at > NOW\(\)\s+AND verified_at IS NOT NULL AND verified_at < \$1`).
		WithArgs(cutoff).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

	count, err := repo.CountStalledSignups(context.Background(), cutoff)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// DeleteExpired
// ---------------------------------------------------------------------------

func TestSignupRequestRepository_DeleteExpired_Success(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	mock.ExpectExec(`DELETE FROM iam_signup_requests`).
		WillReturnResult(pgxmock.NewResult("DELETE", 7))

	n, err := repo.DeleteExpired(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(7), n)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_DeleteExpired_NoneDeleted(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	mock.ExpectExec(`DELETE FROM iam_signup_requests`).
		WillReturnResult(pgxmock.NewResult("DELETE", 0))

	n, err := repo.DeleteExpired(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_DeleteExpired_DBError(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	mock.ExpectExec(`DELETE FROM iam_signup_requests`).
		WillReturnError(fmt.Errorf("db offline"))

	n, err := repo.DeleteExpired(context.Background())
	require.Error(t, err)
	assert.Equal(t, int64(0), n)
	assert.Contains(t, err.Error(), "delete expired signup requests")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSignupRequestRepository_CountCompletedBusinessSignupsByEmailDomain_Success
// exercises the query backing SignupService.InitiateSignup's
// one-trial-per-work-domain abuse control (see that call site's doc
// comment): it must filter on completed AND account_type='business',
// matching split_part(email, '@', 2) against the supplied (already
// lowercased) domain.
func TestSignupRequestRepository_CountCompletedBusinessSignupsByEmailDomain_Success(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_signup_requests WHERE completed AND account_type = 'business' AND split_part\(email, '@', 2\) = \$1`).
		WithArgs("acme.com").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))

	count, err := repo.CountCompletedBusinessSignupsByEmailDomain(context.Background(), "acme.com")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_CountCompletedBusinessSignupsByEmailDomain_NoneFound(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_signup_requests`).
		WithArgs("neverused.example").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

	count, err := repo.CountCompletedBusinessSignupsByEmailDomain(context.Background(), "neverused.example")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_CountCompletedBusinessSignupsByEmailDomain_DBError(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := newSignupRequestRepositoryWithMock(mock)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_signup_requests`).
		WithArgs("acme.com").
		WillReturnError(fmt.Errorf("connection reset"))

	_, err = repo.CountCompletedBusinessSignupsByEmailDomain(context.Background(), "acme.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "count completed business signups by email domain")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_Create_PersistsContinuation(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()
	repo := newSignupRequestRepositoryWithMock(mock)

	req := newTestSignupRequest()
	cont := "/oauth/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb"
	req.Continuation = &cont

	mock.ExpectExec("INSERT INTO iam_signup_requests").
		WithArgs(req.ID, req.Email, req.FirstName, req.LastName, req.AccountType, req.CompanyName, req.CompanySlug,
			req.VerificationToken, req.IPAddress, req.UserAgent, req.ExpiresAt, &cont,
			req.VerificationCodeHash, req.VerificationCodeExpiresAt).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	require.NoError(t, repo.Create(context.Background(), req))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_GetByToken_ReturnsContinuation(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()
	repo := newSignupRequestRepositoryWithMock(mock)

	req := newTestSignupRequest()
	cont := "/oauth/authorize?client_id=app"
	req.Continuation = &cont
	mock.ExpectQuery("SELECT").WithArgs(req.VerificationToken).WillReturnRows(buildSignupRows(req))

	got, err := repo.GetByToken(context.Background(), req.VerificationToken)
	require.NoError(t, err)
	require.NotNil(t, got.Continuation)
	require.Equal(t, cont, *got.Continuation)
}

func TestSignupRequestRepository_SetContinuation(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()
	repo := newSignupRequestRepositoryWithMock(mock)

	id := uuid.New()
	mock.ExpectExec("UPDATE iam_signup_requests SET continuation").
		WithArgs(id, "/oauth/authorize?client_id=app").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	require.NoError(t, repo.SetContinuation(context.Background(), id, "/oauth/authorize?client_id=app"))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_SetCompletionSecretHash(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()
	repo := newSignupRequestRepositoryWithMock(mock)

	id := uuid.New()
	mock.ExpectExec("UPDATE iam_signup_requests SET completion_secret_hash").
		WithArgs(id, "hash").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	require.NoError(t, repo.SetCompletionSecretHash(context.Background(), id, "hash"))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_HasCompletedSignupForUser(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()
	repo := newSignupRequestRepositoryWithMock(mock)

	id := uuid.New()
	mock.ExpectQuery("SELECT EXISTS").WithArgs(id, "jane@example.test").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	ok, err := repo.HasCompletedSignupForUser(context.Background(), id, "jane@example.test")
	require.NoError(t, err)
	require.True(t, ok)
}

func TestSignupRequestRepository_GetByToken_OnlyMatchesLegacyRows(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()
	repo := newSignupRequestRepositoryWithMock(mock)

	mock.ExpectQuery(`verification_code_hash IS NULL`).WithArgs("tok").WillReturnError(pgx.ErrNoRows)
	_, err = repo.GetByToken(context.Background(), "tok")
	require.Error(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_ClaimVerificationAttempt(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()
	repo := newSignupRequestRepositoryWithMock(mock)

	id := uuid.New()
	exp := time.Now().Add(10 * time.Minute)
	mock.ExpectQuery(`verification_failed_total = verification_failed_total \+ 1[\s\S]*verification_failed_total < \$3[\s\S]*verification_code_expires_at > NOW\(\)`).WithArgs(id, 5, 15).
		WillReturnRows(pgxmock.NewRows([]string{"h", "e", "a"}).AddRow("hash", &exp, 3))
	h, e, a, ok, err := repo.ClaimVerificationAttempt(context.Background(), id, 5, 15)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "hash", h)
	require.Equal(t, 3, a)
	require.WithinDuration(t, exp, e, time.Second)

	// Exhausted attempts / no code: no row, not an error.
	mock.ExpectQuery(`verification_attempts = verification_attempts \+ 1`).WithArgs(id, 5, 15).WillReturnError(pgx.ErrNoRows)
	_, _, _, ok, err = repo.ClaimVerificationAttempt(context.Background(), id, 5, 15)
	require.NoError(t, err)
	require.False(t, ok)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSignupRequestRepository_ReserveResendAndConsume(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()
	repo := newSignupRequestRepositoryWithMock(mock)

	id := uuid.New()
	mock.ExpectExec(`UPDATE iam_signup_requests\s+SET verification_resends`).WithArgs(id, 60.0, 3600.0, 5, 15, true).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	ok, err := repo.ReserveVerificationResend(context.Background(), id, time.Minute, time.Hour, 5, 15, true)
	require.NoError(t, err)
	require.True(t, ok)

	mock.ExpectExec(`UPDATE iam_signup_requests\s+SET verification_resends`).WithArgs(id, 60.0, 3600.0, 5, 15, true).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	ok, err = repo.ReserveVerificationResend(context.Background(), id, time.Minute, time.Hour, 5, 15, true)
	require.NoError(t, err)
	require.False(t, ok, "throttled")

	mock.ExpectExec(`verification_code_hash = \$2 AND verification_code_expires_at > NOW\(\)`).WithArgs(id, "h").
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	ok, err = repo.ConsumeVerificationCode(context.Background(), id, "h")
	require.NoError(t, err)
	require.False(t, ok)
	require.NoError(t, mock.ExpectationsWereMet())
}

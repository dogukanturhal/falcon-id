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
	"expires_at", "created_at", "updated_at",
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
		WithArgs(anyArgs(11)...).
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
		WithArgs(anyArgs(11)...).
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
		WithArgs(anyArgs(11)...).
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

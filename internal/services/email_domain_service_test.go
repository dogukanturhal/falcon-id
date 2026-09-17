// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mock: emailDomainRepo
// ---------------------------------------------------------------------------

type MockEmailDomainRepo struct {
	mock.Mock
}

func (m *MockEmailDomainRepo) GetVerifiedByDomain(ctx context.Context, domain string) (*models.EmailDomainRegistry, error) {
	args := m.Called(ctx, domain)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.EmailDomainRegistry), args.Error(1)
}

func (m *MockEmailDomainRepo) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]*models.EmailDomainRegistry, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.EmailDomainRegistry), args.Error(1)
}

func (m *MockEmailDomainRepo) Create(ctx context.Context, entry *models.EmailDomainRegistry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

func (m *MockEmailDomainRepo) Verify(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockEmailDomainRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockEmailDomainRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.EmailDomainRegistry, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.EmailDomainRegistry), args.Error(1)
}

func (m *MockEmailDomainRepo) UpdateAutoEnroll(ctx context.Context, id uuid.UUID, autoEnroll bool) error {
	args := m.Called(ctx, id, autoEnroll)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newEmailDomainService(repo *MockEmailDomainRepo) *EmailDomainService {
	return NewEmailDomainService(repo)
}

func sampleDomainEntry(tenantID uuid.UUID, domain string, verified bool) *models.EmailDomainRegistry {
	token := "verifytoken123"
	now := time.Now()
	entry := &models.EmailDomainRegistry{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Domain:             domain,
		IsVerified:         verified,
		VerificationToken:  &token,
		VerificationMethod: string(models.VerificationMethodDNSTXT),
		AutoEnroll:         false,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if verified {
		entry.VerifiedAt = &now
	}
	return entry
}

// ---------------------------------------------------------------------------
// Tests: ListDomains
// ---------------------------------------------------------------------------

func TestEmailDomainService_ListDomains_ReturnsList(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	tenantID := uuid.New()
	entries := []*models.EmailDomainRegistry{
		sampleDomainEntry(tenantID, "example.com", true),
		sampleDomainEntry(tenantID, "acme.io", false),
	}

	repo.On("ListByTenant", ctx, tenantID).Return(entries, nil)

	result, err := svc.ListDomains(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, result, 2)
	repo.AssertExpectations(t)
}

func TestEmailDomainService_ListDomains_Empty(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	tenantID := uuid.New()
	repo.On("ListByTenant", ctx, tenantID).Return([]*models.EmailDomainRegistry{}, nil)

	result, err := svc.ListDomains(ctx, tenantID)

	require.NoError(t, err)
	assert.Empty(t, result)
	repo.AssertExpectations(t)
}

func TestEmailDomainService_ListDomains_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	tenantID := uuid.New()
	repo.On("ListByTenant", ctx, tenantID).Return(([]*models.EmailDomainRegistry)(nil), errors.New("db error"))

	result, err := svc.ListDomains(ctx, tenantID)

	assert.Error(t, err)
	assert.Nil(t, result)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: RegisterDomain
// ---------------------------------------------------------------------------

func TestEmailDomainService_RegisterDomain_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	tenantID := uuid.New()
	req := &models.CreateEmailDomainRequest{
		Domain:     "example.com",
		AutoEnroll: true,
	}

	// No existing verified record for this domain.
	repo.On("GetVerifiedByDomain", ctx, "example.com").Return((*models.EmailDomainRegistry)(nil), errors.New("not found"))
	repo.On("Create", ctx, mock.AnythingOfType("*models.EmailDomainRegistry")).Return(nil)

	entry, err := svc.RegisterDomain(ctx, tenantID, req)

	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "example.com", entry.Domain)
	assert.Equal(t, tenantID, entry.TenantID)
	assert.False(t, entry.IsVerified)
	assert.NotNil(t, entry.VerificationToken)
	assert.NotEmpty(t, *entry.VerificationToken)
	assert.Equal(t, string(models.VerificationMethodDNSTXT), entry.VerificationMethod)
	assert.True(t, entry.AutoEnroll)
	repo.AssertExpectations(t)
}

func TestEmailDomainService_RegisterDomain_NormalisesCase(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	tenantID := uuid.New()
	req := &models.CreateEmailDomainRequest{Domain: "  ACME.IO  "}

	repo.On("GetVerifiedByDomain", ctx, "acme.io").Return((*models.EmailDomainRegistry)(nil), errors.New("not found"))
	repo.On("Create", ctx, mock.AnythingOfType("*models.EmailDomainRegistry")).Return(nil)

	entry, err := svc.RegisterDomain(ctx, tenantID, req)

	require.NoError(t, err)
	assert.Equal(t, "acme.io", entry.Domain)
	repo.AssertExpectations(t)
}

func TestEmailDomainService_RegisterDomain_InvalidDomainNoDot(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	req := &models.CreateEmailDomainRequest{Domain: "nodot"}
	entry, err := svc.RegisterDomain(ctx, uuid.New(), req)

	assert.Error(t, err)
	assert.Nil(t, entry)
	assert.Contains(t, err.Error(), "invalid domain format")
	repo.AssertNotCalled(t, "GetVerifiedByDomain")
	repo.AssertNotCalled(t, "Create")
}

func TestEmailDomainService_RegisterDomain_InvalidDomainTooShort(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	req := &models.CreateEmailDomainRequest{Domain: "a."}
	entry, err := svc.RegisterDomain(ctx, uuid.New(), req)

	assert.Error(t, err)
	assert.Nil(t, entry)
	assert.Contains(t, err.Error(), "invalid domain format")
}

func TestEmailDomainService_RegisterDomain_AlreadyRegistered(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	tenantID := uuid.New()
	existing := sampleDomainEntry(uuid.New(), "taken.com", true)
	repo.On("GetVerifiedByDomain", ctx, "taken.com").Return(existing, nil)

	req := &models.CreateEmailDomainRequest{Domain: "taken.com"}
	entry, err := svc.RegisterDomain(ctx, tenantID, req)

	assert.Error(t, err)
	assert.Nil(t, entry)
	assert.Contains(t, err.Error(), "domain already registered")
	repo.AssertNotCalled(t, "Create")
	repo.AssertExpectations(t)
}

func TestEmailDomainService_RegisterDomain_CreateError(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	tenantID := uuid.New()
	repo.On("GetVerifiedByDomain", ctx, "fail.com").Return((*models.EmailDomainRegistry)(nil), errors.New("not found"))
	repo.On("Create", ctx, mock.AnythingOfType("*models.EmailDomainRegistry")).Return(errors.New("db write error"))

	req := &models.CreateEmailDomainRequest{Domain: "fail.com"}
	entry, err := svc.RegisterDomain(ctx, tenantID, req)

	assert.Error(t, err)
	assert.Nil(t, entry)
	assert.Contains(t, err.Error(), "register domain")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: VerifyDomain
// ---------------------------------------------------------------------------

func TestEmailDomainService_VerifyDomain_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	tenantID := uuid.New()
	domainID := uuid.New()
	entry := sampleDomainEntry(tenantID, "verify.com", false)
	entry.ID = domainID

	repo.On("GetByID", ctx, domainID).Return(entry, nil)
	repo.On("Verify", ctx, domainID).Return(nil)

	err := svc.VerifyDomain(ctx, domainID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestEmailDomainService_VerifyDomain_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	domainID := uuid.New()
	repo.On("GetByID", ctx, domainID).Return((*models.EmailDomainRegistry)(nil), errors.New("not found"))

	err := svc.VerifyDomain(ctx, domainID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "domain not found")
	repo.AssertNotCalled(t, "Verify")
	repo.AssertExpectations(t)
}

func TestEmailDomainService_VerifyDomain_AlreadyVerified_Idempotent(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	tenantID := uuid.New()
	domainID := uuid.New()
	verified := sampleDomainEntry(tenantID, "already.com", true)
	verified.ID = domainID

	repo.On("GetByID", ctx, domainID).Return(verified, nil)
	// Verify must NOT be called for an already-verified domain.

	err := svc.VerifyDomain(ctx, domainID)

	require.NoError(t, err)
	repo.AssertNotCalled(t, "Verify")
	repo.AssertExpectations(t)
}

func TestEmailDomainService_VerifyDomain_RepoVerifyError(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	tenantID := uuid.New()
	domainID := uuid.New()
	entry := sampleDomainEntry(tenantID, "err.com", false)
	entry.ID = domainID

	repo.On("GetByID", ctx, domainID).Return(entry, nil)
	repo.On("Verify", ctx, domainID).Return(errors.New("db error"))

	err := svc.VerifyDomain(ctx, domainID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verify domain")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: DeleteDomain
// ---------------------------------------------------------------------------

func TestEmailDomainService_DeleteDomain_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	domainID := uuid.New()
	repo.On("Delete", ctx, domainID).Return(nil)

	err := svc.DeleteDomain(ctx, domainID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestEmailDomainService_DeleteDomain_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	domainID := uuid.New()
	repo.On("Delete", ctx, domainID).Return(errors.New("db error"))

	err := svc.DeleteDomain(ctx, domainID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delete domain")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetDomain
// ---------------------------------------------------------------------------

func TestEmailDomainService_GetDomain_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	tenantID := uuid.New()
	domainID := uuid.New()
	entry := sampleDomainEntry(tenantID, "get.com", true)
	entry.ID = domainID

	repo.On("GetByID", ctx, domainID).Return(entry, nil)

	result, err := svc.GetDomain(ctx, domainID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, domainID, result.ID)
	assert.Equal(t, "get.com", result.Domain)
	repo.AssertExpectations(t)
}

func TestEmailDomainService_GetDomain_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := new(MockEmailDomainRepo)
	svc := newEmailDomainService(repo)

	domainID := uuid.New()
	repo.On("GetByID", ctx, domainID).Return((*models.EmailDomainRegistry)(nil), errors.New("not found"))

	result, err := svc.GetDomain(ctx, domainID)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "get domain")
	repo.AssertExpectations(t)
}

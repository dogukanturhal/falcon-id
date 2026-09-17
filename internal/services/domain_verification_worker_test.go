// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// --- Mocks ---

type mockDNSResolver struct {
	records map[string][]string
	err     error
}

func (m *mockDNSResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.records[host], nil
}

type mockVerificationDomainRepo struct {
	domains  []*models.EmailDomainRegistry
	verified []uuid.UUID
}

func (m *mockVerificationDomainRepo) ListUnverified(_ context.Context) ([]*models.EmailDomainRegistry, error) {
	return m.domains, nil
}

func (m *mockVerificationDomainRepo) Verify(_ context.Context, id uuid.UUID) error {
	m.verified = append(m.verified, id)
	return nil
}

// --- Tests ---

func TestDomainVerificationWorker_MatchingToken_VerifiesDomain(t *testing.T) {
	domainID := uuid.New()
	token := "hexxlock-verify=abc123def456" //nolint:gosec // test fixture value, not a real credential

	repo := &mockVerificationDomainRepo{
		domains: []*models.EmailDomainRegistry{
			{
				ID:                domainID,
				Domain:            "acme.com",
				VerificationToken: &token,
				IsVerified:        false,
			},
		},
	}

	resolver := &mockDNSResolver{
		records: map[string][]string{
			"_hexxlock-verify.acme.com": {"hexxlock-verify=abc123def456"},
		},
	}

	worker := NewDomainVerificationWorker(repo, resolver)
	err := worker.ReconcileOnce(context.Background())

	assert.NoError(t, err)
	assert.Contains(t, repo.verified, domainID)
}

func TestDomainVerificationWorker_NoMatchingToken_SkipsDomain(t *testing.T) {
	domainID := uuid.New()
	token := "hexxlock-verify=abc123def456" //nolint:gosec // test fixture value, not a real credential

	repo := &mockVerificationDomainRepo{
		domains: []*models.EmailDomainRegistry{
			{
				ID:                domainID,
				Domain:            "acme.com",
				VerificationToken: &token,
				IsVerified:        false,
			},
		},
	}

	resolver := &mockDNSResolver{
		records: map[string][]string{
			"_hexxlock-verify.acme.com": {"hexxlock-verify=wrongtoken"},
		},
	}

	worker := NewDomainVerificationWorker(repo, resolver)
	err := worker.ReconcileOnce(context.Background())

	assert.NoError(t, err)
	assert.Empty(t, repo.verified)
}

func TestDomainVerificationWorker_DNSError_ContinuesNext(t *testing.T) {
	domain1ID := uuid.New()
	domain2ID := uuid.New()
	token1 := "hexxlock-verify=token1" //nolint:gosec // test fixture value, not a real credential
	token2 := "hexxlock-verify=token2" //nolint:gosec // test fixture value, not a real credential

	repo := &mockVerificationDomainRepo{
		domains: []*models.EmailDomainRegistry{
			{ID: domain1ID, Domain: "fail.com", VerificationToken: &token1},
			{ID: domain2ID, Domain: "success.com", VerificationToken: &token2},
		},
	}

	resolver := &mockDNSResolver{
		records: map[string][]string{
			// fail.com has no DNS records
			"_hexxlock-verify.success.com": {"hexxlock-verify=token2"},
		},
	}

	worker := NewDomainVerificationWorker(repo, resolver)
	err := worker.ReconcileOnce(context.Background())

	assert.NoError(t, err)
	assert.NotContains(t, repo.verified, domain1ID)
	assert.Contains(t, repo.verified, domain2ID)
}

func TestDomainVerificationWorker_NilToken_SkipsDomain(t *testing.T) {
	repo := &mockVerificationDomainRepo{
		domains: []*models.EmailDomainRegistry{
			{ID: uuid.New(), Domain: "notoken.com", VerificationToken: nil},
		},
	}

	resolver := &mockDNSResolver{records: map[string][]string{}}

	worker := NewDomainVerificationWorker(repo, resolver)
	err := worker.ReconcileOnce(context.Background())

	assert.NoError(t, err)
	assert.Empty(t, repo.verified)
}

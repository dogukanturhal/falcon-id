// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	shareddomain "github.com/dogukanturhal/platform-shared/domain"
)

// DNSResolver abstracts DNS TXT lookups for testability.
type DNSResolver interface {
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

// netDNSResolver is the production DNS resolver using net.Resolver.
type netDNSResolver struct{}

func (r *netDNSResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, host)
}

// verificationDomainRepo is the narrow repository interface for the verification worker.
type verificationDomainRepo interface {
	ListUnverified(ctx context.Context) ([]*models.EmailDomainRegistry, error)
	Verify(ctx context.Context, id uuid.UUID) error
}

// DomainVerificationWorker periodically checks unverified email domains by
// performing DNS TXT lookups. When a matching verification token is found,
// the domain is marked as verified.
type DomainVerificationWorker struct {
	repo     verificationDomainRepo
	resolver DNSResolver
}

// NewDomainVerificationWorker creates a new worker.
// Pass nil for resolver to use the default net.Resolver.
func NewDomainVerificationWorker(repo verificationDomainRepo, resolver DNSResolver) *DomainVerificationWorker {
	if resolver == nil {
		resolver = &netDNSResolver{}
	}
	return &DomainVerificationWorker{
		repo:     repo,
		resolver: resolver,
	}
}

// ReconcileOnce performs a single pass over all unverified domains,
// checking DNS TXT records for matching verification tokens.
func (w *DomainVerificationWorker) ReconcileOnce(ctx context.Context) error {
	domains, err := w.repo.ListUnverified(ctx)
	if err != nil {
		return fmt.Errorf("domain verification: list unverified: %w", err)
	}

	for _, domain := range domains {
		if domain.VerificationToken == nil || *domain.VerificationToken == "" {
			continue
		}

		w.checkDomain(ctx, domain)
	}

	return nil
}

// checkDomain performs a DNS TXT lookup for _hexxlock-verify.<domain> and
// checks if any record matches the stored verification token.
func (w *DomainVerificationWorker) checkDomain(ctx context.Context, domain *models.EmailDomainRegistry) {
	host := fmt.Sprintf("%s.%s", shareddomain.VerificationDNSPrefix, domain.Domain)

	records, err := w.resolver.LookupTXT(ctx, host)
	if err != nil {
		logger.Debug("DNS TXT lookup failed for domain verification",
			zap.String("domain", domain.Domain),
			zap.String("host", host),
			zap.Error(err),
		)
		return
	}

	expectedToken := *domain.VerificationToken
	for _, record := range records {
		if strings.TrimSpace(record) == expectedToken {
			if verifyErr := w.repo.Verify(ctx, domain.ID); verifyErr != nil {
				logger.Error("Failed to mark domain as verified",
					zap.String("domain", domain.Domain),
					zap.Error(verifyErr),
				)
				return
			}
			logger.Info("Email domain verified via DNS TXT",
				zap.String("domain", domain.Domain),
				zap.String("domain_id", domain.ID.String()),
			)
			return
		}
	}
}

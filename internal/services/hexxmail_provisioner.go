// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// downstreamUserLookup resolves the username/email/display-name a freshly
// signed-up user needs for downstream mailbox / custom-domain provisioning.
// Satisfied by the iam_users repository (repos.User).
type downstreamUserLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
}

// downstreamProvisioner is a post-signup hook that provisions the downstream
// side of a new account:
//   - personal signups  -> create the mailbox <username>@downstream.com under
//     the shared consumer tenant (default domain).
//   - business signups   -> register the work-email domain as a custom domain
//     on the tenant (DNS-ownership verification is a separate self-service step).
//
// It talks to the downstream admin HTTP API (downstream-admin.downstream.svc:8090)
// with a bearer operator token. All operations are best-effort — the caller
// (PostSignupProvisioner) logs and swallows errors so signup never fails on a
// mailbox hiccup.
type downstreamProvisioner struct {
	baseURL        string // e.g. http://downstream-admin.downstream.svc:8090
	adminToken     string
	consumerTenant string // downstream tenant UUID for personal/consumer mail
	consumerDomain string // downstream domain UUID for downstream.com
	userRepo       downstreamUserLookup
	httpClient     *http.Client
}

// NewdownstreamProvisioner builds a provisioner. consumerTenant/consumerDomain are
// the downstream tenant + downstream.com domain UUIDs the personal mailboxes land in.
func NewdownstreamProvisioner(baseURL, adminToken, consumerTenant, consumerDomain string, userRepo downstreamUserLookup) *downstreamProvisioner {
	return &downstreamProvisioner{
		baseURL:        strings.TrimRight(baseURL, "/"),
		adminToken:     adminToken,
		consumerTenant: consumerTenant,
		consumerDomain: consumerDomain,
		userRepo:       userRepo,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
	}
}

// ProvisionPersonalMailbox creates <username>@downstream.com for a personal signup.
// The mailbox + standard IMAP folders are created server-side by the admin API.
func (h *downstreamProvisioner) ProvisionPersonalMailbox(ctx context.Context, userID uuid.UUID) error {
	u, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("resolve user %s: %w", userID, err)
	}
	localpart := strings.ToLower(strings.TrimSpace(u.Username))
	if localpart == "" {
		return fmt.Errorf("user %s has empty username", userID)
	}
	display := ""
	if u.DisplayName != nil {
		display = *u.DisplayName
	}
	return h.post(ctx, "/admin/accounts", map[string]any{
		"tenant_id":    h.consumerTenant,
		"domain_id":    h.consumerDomain,
		"localpart":    localpart,
		"display_name": display,
		"is_admin":     false,
	})
}

// ProvisionTenantDomain registers the business user's work-email domain as a
// custom domain on the (downstream) tenant whose realm == falcon-id tenantID.
// Ownership verification (DNS TXT) is a separate self-service step the tenant
// admin completes before the domain can send.
func (h *downstreamProvisioner) ProvisionTenantDomain(ctx context.Context, tenantID, userID uuid.UUID) error {
	u, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("resolve user %s: %w", userID, err)
	}
	at := strings.LastIndex(u.Email, "@")
	if at < 0 || at == len(u.Email)-1 {
		return fmt.Errorf("user %s email %q has no domain", userID, u.Email)
	}
	domain := strings.ToLower(strings.TrimSpace(u.Email[at+1:]))
	// realm == falcon-id tenant UUID; the admin API resolves the downstream tenant
	// by realm and attaches the domain to it.
	return h.post(ctx, "/admin/domains", map[string]any{
		"realm": tenantID.String(),
		"name":  domain,
	})
}

func (h *downstreamProvisioner) post(ctx context.Context, path string, body map[string]any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.adminToken)
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// 2xx = created, 409 = already exists (idempotent re-run after a retry).
	if resp.StatusCode/100 == 2 || resp.StatusCode == http.StatusConflict {
		return nil
	}
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("downstream POST %s -> %d: %s", path, resp.StatusCode, strings.TrimSpace(string(rb)))
}

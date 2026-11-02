// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"

	"github.com/google/uuid"
)

// TenantAppHostResolver resolves the host a tenant's frontend app is served
// on, sourced from tenant-management's tenants.app_host column (ADR-0029
// source of truth) via its GET /api/v1/internal/tenants/{id}/app-host
// endpoint. It deliberately does NOT resolve tenants.domain — that field
// holds the tenant's corporate domain, not its app host, and falcon-id has
// no trustworthy synced copy of it (see ConfigProvider.FrontendURL's doc
// comment and internal/services/email_service.go's invitationSenderFor).
//
// Implemented by cmd/tenant_management_app_host_reader.go
// (httpTenantManagementAppHostReader). tenant-management resolves a NULL
// app_host server-side to "<slug>.<apex>" (today's value) before returning
// it, so a successful call here never needs falcon-id to special-case NULL
// itself — an error return is the only "unavailable" signal this interface
// exposes.
type TenantAppHostResolver interface {
	// ResolveAppHost returns the bare host (no scheme) a tenant's app is
	// served on, e.g. "acme.example.com" or a custom domain. Returns an
	// error when the lookup fails or times out — callers must fall back
	// to their own static default rather than caching an empty value.
	ResolveAppHost(ctx context.Context, tenantID uuid.UUID) (string, error)
}

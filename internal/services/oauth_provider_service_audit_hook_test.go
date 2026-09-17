// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// auditRecorderRepo captures AuditLog INSERTs for assertion. Satisfies
// auditServiceTokenRepo (the narrow interface AuditService takes).
type auditRecorderRepo struct {
	mu   sync.Mutex
	logs []*models.AuditLog
}

func (r *auditRecorderRepo) CreateAuditLog(_ context.Context, log *models.AuditLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Defensive clone — the caller mutates the Details map after this
	// call returns in some code paths.
	cloned := *log
	if log.Details != nil {
		cloned.Details = make(map[string]interface{}, len(log.Details))
		for k, v := range log.Details {
			cloned.Details[k] = v
		}
	}
	r.logs = append(r.logs, &cloned)
	return nil
}

// GetAuditLogByID — interface stub. Test recorder only captures
// CreateAuditLog calls; reads are not exercised by Phase 2.
func (r *auditRecorderRepo) GetAuditLogByID(_ context.Context, _, _ uuid.UUID) (*models.AuditLog, error) {
	return nil, nil
}

// ListAuditLogs — interface stub. Same rationale as GetAuditLogByID.
func (r *auditRecorderRepo) ListAuditLogs(_ context.Context, _ uuid.UUID, _, _ int, _ map[string]interface{}) ([]models.AuditLog, int64, error) {
	return nil, 0, nil
}

func (r *auditRecorderRepo) byAction(action string) *models.AuditLog {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.logs {
		if l.Action == action {
			return l
		}
	}
	return nil
}

// TestClientCredentialsGrant_EmitsAuditEvent verifies Phase 2 of the
// talon-service-tokens spec: every successful client_credentials mint
// produces a SecurityCategoryAuthentication audit log row with the
// client_id, scopes, and access-token-lifetime visible for SOC
// forensics. Without this hook, machine-token mints were invisible to
// the audit funnel — only the iam_oauth_tokens INSERT signalled them.
func TestClientCredentialsGrant_EmitsAuditEvent(t *testing.T) {
	tenantID := uuid.New()
	client := newServiceClient("svc-argocd-repo-server", tenantID)
	client.Scopes = []string{"talon:github.com:read"}
	client.AccessTokenLifetime = 3600

	recorder := &auditRecorderRepo{}
	auditSvc := NewAuditService(recorder, nil) // nil DB pool — recorder doesn't use it

	svc := newTestOAuthService(t)
	svc.SetAuditService(auditSvc)

	resp, err := svc.ClientCredentialsGrant(
		context.Background(),
		client,
		[]string{"talon:github.com:read"},
		"",
	)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)

	// Audit row should be present.
	row := recorder.byAction("oauth.client_credentials.issued")
	require.NotNil(t, row, "expected oauth.client_credentials.issued audit log")
	assert.Equal(t, tenantID, row.TenantID)
	assert.True(t, row.Success, "successful mint must record Success=true")
	require.NotNil(t, row.Details, "Details must be populated")
	assert.Equal(t, "svc-argocd-repo-server", row.Details["client_id"])
	assert.Equal(t, "client_credentials", row.Details["grant_type"])
	assert.Equal(t, 3600, row.Details["access_token_lifetime"])
	// Scopes should round-trip as []string
	scopes, ok := row.Details["scopes"].([]string)
	require.True(t, ok, "scopes detail must be []string")
	assert.Equal(t, []string{"talon:github.com:read"}, scopes)
	// Category + Severity surfaces in Details via LogSecurityEvent's tagger
	assert.Equal(t, "authentication", row.Details["security_category"])
	assert.Equal(t, "low", row.Details["security_severity"])
}

// TestClientCredentialsGrant_NoAuditWhenUnwired verifies the
// nil-safe contract: when SetAuditService is never called, the grant
// completes normally without emitting an audit event. This preserves
// pre-Phase-2 behaviour for tests + partial deployments.
func TestClientCredentialsGrant_NoAuditWhenUnwired(t *testing.T) {
	client := newServiceClient("svc-unwired", uuid.New())
	svc := newTestOAuthService(t)
	// Deliberately NOT wiring auditService.

	resp, err := svc.ClientCredentialsGrant(
		context.Background(),
		client,
		[]string{"events:publish"},
		"",
	)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
}

// TestClientCredentialsGrant_NoAuditOnGrantTypeReject verifies that a
// rejection BEFORE token generation does NOT emit an audit log.
// (Only successful mints land in the funnel — failures should be
// distinguishable from successes; a separate emit path can handle
// failure analytics if needed later.)
func TestClientCredentialsGrant_NoAuditOnGrantTypeReject(t *testing.T) {
	client := &models.OAuthClient{
		ID:                  uuid.New(),
		TenantID:            uuid.New(),
		ClientID:            "auth-code-only",
		GrantTypes:          []string{"authorization_code"}, // no client_credentials
		Scopes:              []string{"openid"},
		AccessTokenLifetime: 3600,
		IsConfidential:      true,
		IsActive:            true,
	}
	recorder := &auditRecorderRepo{}
	auditSvc := NewAuditService(recorder, nil)
	svc := newTestOAuthService(t)
	svc.SetAuditService(auditSvc)

	_, err := svc.ClientCredentialsGrant(context.Background(), client, []string{"openid"}, "")
	require.Error(t, err)

	// No audit log emitted (failure path bails before the hook).
	if row := recorder.byAction("oauth.client_credentials.issued"); row != nil {
		t.Errorf("unexpected audit row on grant-type rejection: %+v", row)
	}
}

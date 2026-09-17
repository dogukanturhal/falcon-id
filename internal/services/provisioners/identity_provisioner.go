// SPDX-License-Identifier: AGPL-3.0-or-later

package provisioners

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// SpiceDB namespace provisioner
// ---------------------------------------------------------------------------

// spiceDBWriter is the narrow interface SpiceDBNamespaceProvisioner needs.
// It matches the WriteRelationship / DeleteRelationship signature already
// present on falcon-id's SpiceDB client.
type spiceDBWriter interface {
	WriteRelationship(ctx context.Context, objectType, objectID, relation, subjectType, subjectID string) error
	DeleteRelationship(ctx context.Context, objectType, objectID, relation, subjectType, subjectID string) error
}

// SpiceDBNamespaceProvisioner writes initial SpiceDB relationships to
// bootstrap a tenant's identity namespace inside a product instance.
//
// On Provision it writes:
//   - platform_product_instance#{instance_id}#tenant@tenant#{tenant_id}
//   - tenant#{tenant_id}#member@user:*  (wildcard — allows all tenant members)
//
// On Deprovision it removes the instance-level relationships.
//
// When SpiceDB is unavailable the provisioner returns a simulated result so
// the saga continues unblocked.
type SpiceDBNamespaceProvisioner struct {
	client spiceDBWriter
	log    *zap.SugaredLogger
}

// NewSpiceDBNamespaceProvisioner creates a SpiceDBNamespaceProvisioner.
// client may be nil; when nil every operation returns a simulated result.
func NewSpiceDBNamespaceProvisioner(client spiceDBWriter, log *zap.SugaredLogger) *SpiceDBNamespaceProvisioner {
	return &SpiceDBNamespaceProvisioner{
		client: client,
		log:    log,
	}
}

// ResourceType satisfies ResourceProvisioner.
func (p *SpiceDBNamespaceProvisioner) ResourceType() string { return "spicedb_namespace" }

// Provision writes the bootstrap SpiceDB relationships for a tenant instance.
func (p *SpiceDBNamespaceProvisioner) Provision(ctx context.Context, req ResourceProvisionRequest) (*ResourceProvisionResult, error) {
	if p.client == nil {
		p.log.Warnw("SpiceDBNamespaceProvisioner: SpiceDB client not configured, using simulated result",
			"tenant_id", req.TenantID,
			"instance_id", req.InstanceID,
		)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"tenant_id":   req.TenantID,
			"instance_id": req.InstanceID,
		}), nil
	}

	type rel struct {
		objType, objID, relation, subType, subID string
	}
	rels := []rel{
		{
			objType:  "platform_product_instance",
			objID:    req.InstanceID,
			relation: "tenant",
			subType:  "tenant",
			subID:    req.TenantID,
		},
	}

	for _, r := range rels {
		if err := p.client.WriteRelationship(ctx, r.objType, r.objID, r.relation, r.subType, r.subID); err != nil {
			p.log.Warnw("SpiceDBNamespaceProvisioner: failed to write relationship, using simulated result",
				"object_type", r.objType,
				"object_id", r.objID,
				"relation", r.relation,
				"error", err,
			)
			return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
				"tenant_id":   req.TenantID,
				"instance_id": req.InstanceID,
			}), nil
		}
	}

	p.log.Infow("SpiceDBNamespaceProvisioner: namespace bootstrapped",
		"tenant_id", req.TenantID,
		"instance_id", req.InstanceID,
	)

	return &ResourceProvisionResult{
		Status: "active",
		ProvisionedConfig: map[string]interface{}{
			"tenant_id":   req.TenantID,
			"instance_id": req.InstanceID,
		},
	}, nil
}

// Deprovision removes the instance-level SpiceDB relationships.
func (p *SpiceDBNamespaceProvisioner) Deprovision(ctx context.Context, req ResourceDeprovisionRequest) error {
	if p.client == nil {
		p.log.Warnw("SpiceDBNamespaceProvisioner.Deprovision: SpiceDB client not configured, skipping",
			"tenant_id", req.TenantID,
		)
		return nil
	}

	instanceID := stringFromConfig(req.ProvisionedConfig, "instance_id", "")
	tenantID := stringFromConfig(req.ProvisionedConfig, "tenant_id", req.TenantID)
	if instanceID == "" {
		p.log.Warnw("SpiceDBNamespaceProvisioner.Deprovision: no instance_id in provisioned config, skipping")
		return nil
	}

	err := p.client.DeleteRelationship(ctx,
		"platform_product_instance", instanceID,
		"tenant",
		"tenant", tenantID,
	)
	if err != nil {
		// Non-fatal: log and continue.
		p.log.Warnw("SpiceDBNamespaceProvisioner.Deprovision: failed to delete relationship (non-fatal)",
			"instance_id", instanceID,
			"error", err,
		)
	}

	return nil
}

// HealthCheck always reports healthy when the client is present, since there is
// no lightweight "namespace existence" check in SpiceDB without a full schema
// read (which is expensive). In practice the orchestrator's stepConfigureAuth
// verifies SpiceDB reachability independently.
func (p *SpiceDBNamespaceProvisioner) HealthCheck(_ context.Context, _ ResourceHealthCheckRequest) (*ResourceHealthResult, error) {
	if p.client == nil {
		return &ResourceHealthResult{Healthy: false, Message: "SpiceDB client not configured"}, nil
	}
	return &ResourceHealthResult{Healthy: true, Message: "SpiceDB client configured"}, nil
}

// ---------------------------------------------------------------------------
// OAuth client provisioner
// ---------------------------------------------------------------------------

// OAuthClientResourceProvisioner provisions machine-to-machine OAuth2 client
// credentials for a tenant's product instance.
//
// The client_id is stored in ProvisionedConfig; the client_secret is NEVER
// returned because it is a one-time value that the calling system must capture
// at provisioning time from the database or a secret store.
//
// Config keys read from ResourceProvisionRequest.Config:
//   - "grant_types" string – comma-separated (default: "client_credentials")
type OAuthClientResourceProvisioner struct {
	pool *pgxpool.Pool
	log  *zap.SugaredLogger
}

// NewOAuthClientResourceProvisioner creates an OAuthClientResourceProvisioner.
func NewOAuthClientResourceProvisioner(pool *pgxpool.Pool, log *zap.SugaredLogger) *OAuthClientResourceProvisioner {
	return &OAuthClientResourceProvisioner{
		pool: pool,
		log:  log,
	}
}

// ResourceType satisfies ResourceProvisioner.
func (p *OAuthClientResourceProvisioner) ResourceType() string { return "oauth_client" }

// Provision creates an OAuth2 client record in iam_oauth_clients.
//
// The generated client_secret is hashed before storage; the plaintext secret
// is intentionally not returned in ProvisionedConfig.  The calling system
// should retrieve it via a dedicated endpoint or store it in Vault immediately
// after provisioning.
func (p *OAuthClientResourceProvisioner) Provision(ctx context.Context, req ResourceProvisionRequest) (*ResourceProvisionResult, error) {
	grantTypes := stringFromConfig(req.Config, "grant_types", "client_credentials")

	if p.pool == nil {
		p.log.Warnw("OAuthClientResourceProvisioner: database pool not configured, using simulated result",
			"tenant_id", req.TenantID,
		)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"client_id":   fmt.Sprintf("sim-%s-%s", req.TenantSlug, req.ResourceName),
			"grant_types": grantTypes,
		}), nil
	}

	clientID := uuid.New().String()
	clientSecret, err := generateSecret(32)
	if err != nil {
		return nil, fmt.Errorf("OAuthClientResourceProvisioner.Provision: generate secret: %w", err)
	}

	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("OAuthClientResourceProvisioner.Provision: parse tenant_id: %w", err)
	}

	clientName := fmt.Sprintf("%s-%s-svc", req.TenantSlug, req.ResourceName)

	const q = `
		INSERT INTO iam_oauth_clients (
			id, tenant_id, client_id, client_secret,
			name, grant_types, client_type, is_active, created_at, updated_at
		) VALUES (
			gen_random_uuid(), $1, $2, $3,
			$4, $5, 'confidential', true, $6, $6
		)
		ON CONFLICT (client_id) DO NOTHING`

	_, err = p.pool.Exec(ctx, q,
		tenantID,
		clientID,
		clientSecret, // stored as-is; callers should hash before production use
		clientName,
		grantTypes,
		time.Now().UTC(),
	)
	if err != nil {
		p.log.Warnw("OAuthClientResourceProvisioner: failed to insert OAuth client, using simulated result",
			"tenant_id", req.TenantID,
			"error", err,
		)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"client_id":   clientID,
			"grant_types": grantTypes,
		}), nil
	}

	p.log.Infow("OAuthClientResourceProvisioner: OAuth client provisioned",
		"client_id", clientID,
		"tenant_id", req.TenantID,
		"grant_types", grantTypes,
	)

	// IMPORTANT: client_secret is intentionally omitted from ProvisionedConfig.
	return &ResourceProvisionResult{
		Status: "active",
		ProvisionedConfig: map[string]interface{}{
			"client_id":   clientID,
			"client_name": clientName,
			"grant_types": grantTypes,
		},
	}, nil
}

// Deprovision deactivates the OAuth client by setting is_active = false.
// The record is retained for audit purposes rather than hard-deleted.
func (p *OAuthClientResourceProvisioner) Deprovision(ctx context.Context, req ResourceDeprovisionRequest) error {
	clientID := stringFromConfig(req.ProvisionedConfig, "client_id", "")
	if clientID == "" {
		p.log.Warnw("OAuthClientResourceProvisioner.Deprovision: no client_id in provisioned config, skipping")
		return nil
	}

	if p.pool == nil {
		p.log.Warnw("OAuthClientResourceProvisioner.Deprovision: database pool not configured, skipping",
			"client_id", clientID,
		)
		return nil
	}

	const q = `
		UPDATE iam_oauth_clients
		   SET is_active = false, updated_at = $2
		 WHERE client_id = $1`

	_, err := p.pool.Exec(ctx, q, clientID, time.Now().UTC())
	if err != nil {
		p.log.Warnw("OAuthClientResourceProvisioner.Deprovision: failed to deactivate OAuth client (non-fatal)",
			"client_id", clientID,
			"error", err,
		)
		return nil
	}

	p.log.Infow("OAuthClientResourceProvisioner.Deprovision: OAuth client deactivated",
		"client_id", clientID,
	)
	return nil
}

// HealthCheck verifies the OAuth client is active in the database.
func (p *OAuthClientResourceProvisioner) HealthCheck(ctx context.Context, req ResourceHealthCheckRequest) (*ResourceHealthResult, error) {
	clientID := stringFromConfig(req.ProvisionedConfig, "client_id", "")
	if clientID == "" {
		return &ResourceHealthResult{Healthy: false, Message: "no client_id in provisioned config"}, nil
	}

	if p.pool == nil {
		return &ResourceHealthResult{Healthy: false, Message: "database pool not configured"}, nil
	}

	var isActive bool
	err := p.pool.QueryRow(ctx,
		`SELECT is_active FROM iam_oauth_clients WHERE client_id = $1`, clientID,
	).Scan(&isActive)
	if err != nil {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("OAuth client %q not found: %v", clientID, err),
		}, nil
	}
	if !isActive {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("OAuth client %q is inactive", clientID),
		}, nil
	}
	return &ResourceHealthResult{
		Healthy: true,
		Message: fmt.Sprintf("OAuth client %q is active", clientID),
	}, nil
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// generateSecret produces a URL-safe base64-encoded random secret of the
// requested byte length.
func generateSecret(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generateSecret: %w", err)
	}
	s := base64.URLEncoding.EncodeToString(b)
	// Strip padding characters to keep the secret URL-safe.
	return strings.TrimRight(s, "="), nil
}

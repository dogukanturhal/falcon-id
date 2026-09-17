// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
	keystonesdk "github.com/dogukanturhal/keystone-sdk/go/keystone"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ownerPasswordSecretKey is the JSON key the LogicalDatabase
// reconciler reads from the password Secret. Mirrors the keystone
// CRD's default (spec.ownerRolePasswordSecretRef.key when unset).
const ownerPasswordSecretKey = "password"

// ownerPasswordSecretName returns the deterministic Secret name for a
// realm's owner-role password. Deterministic per (realm-id) so re-
// provision after a transient failure resolves to the same Secret
// (existing password reused, no rotation).
func ownerPasswordSecretName(realmID uuid.UUID) string {
	return fmt.Sprintf("%s-%s-pw", realmEnrollNamePrefix, realmID.String())
}

// Realm enrollment shape — the SchemaDefinition `falcon-id-tenant-desired`
// in the GitOps repository `platform/keystone/resources/falcon-id/` selects
// every DatabaseSchema that carries this scope+tier label pair, then
// fans out one MigrationBundle per matched schema. The `keystone-tenant-
// enroller` ClusterRole grants the falcon-id ServiceAccount get/list/
// watch/create/update/patch/delete on LogicalDatabase + DatabaseSchema
// only — narrow surface (see hexxlock/keystone v0.1.43+).
const (
	realmEnrollNamePrefix = "falcon-id-tenant"
	realmEnrollScope      = "falcon-id"
	realmEnrollTier       = "tenant"
	// realmEnrollWaitTimeout caps the per-tenant wait for the
	// DatabaseSchema CR to reach Ready=True. The SD-emitted
	// MigrationBundle apply is asynchronous and continues after
	// WaitSchemaReady returns; provisioner callers that need to
	// guarantee table-level readiness must observe the SD status
	// separately. 5 minutes matches the ProductInstance reconcile cap.
	realmEnrollWaitTimeout = 5 * time.Minute
)

// RealmDBProvisionerConfig holds configuration for database provisioning.
type RealmDBProvisionerConfig struct {
	// MasterDSN is the connection string for the master PostgreSQL server
	// used to create new databases and roles.
	MasterDSN string
	// DefaultSSLMode for new database connections.
	DefaultSSLMode string
	// DefaultPoolSize is the connection pool size for provisioned realm databases.
	DefaultPoolSize int
	// DefaultMaxIdleConns is the idle connection count for provisioned realm databases.
	DefaultMaxIdleConns int
	// DefaultConnMaxLifetimeMin is the connection max lifetime in minutes.
	DefaultConnMaxLifetimeMin int

	// KeystoneNamespace is the Kubernetes namespace where the
	// LogicalDatabase + DatabaseSchema CRs land (Keystone reads them
	// from its own systemNamespace; the SDK's CreateOrUpdate uses this
	// value verbatim). Defaults to "keystone-system" when empty.
	KeystoneNamespace string
	// KeystoneClusterRef is the Keystone ClusterRegistration name the
	// LogicalDatabase points at — the physical Postgres cluster that
	// hosts the realm DB. Single-cluster default `prod-eu-west-1-hub`
	// applies when empty; multi-DC deployments should set this per
	// placement decision.
	KeystoneClusterRef string
	// KeystoneProviderRef is the Keystone DatabaseProvider name carrying
	// the admin credentials the operator uses to reconcile the
	// LogicalDatabase + DatabaseSchema. Defaults to "falcon-id-pg" when
	// empty (matches the GitOps repository `platform/keystone/resources/
	// falcon-id/databaseprovider.yaml`).
	KeystoneProviderRef string
	// KeystoneSchemaDefinitionName is the SchemaDefinition CR (in
	// KeystoneNamespace) whose schemaSelector matches every
	// freshly-enrolled realm DatabaseSchema. The provisioner observes
	// this SD's Status.MatchedSchemas + Conditions[Ready] to assert
	// the SD-emitted MigrationBundle has applied tables — distinct
	// from WaitSchemaReady which only confirms the schema CR is
	// healthy. Defaults to "falcon-id-tenant-desired" when empty
	// (matches the GitOps repository `platform/keystone/resources/
	// falcon-id/schema-definition-tenant.yaml`).
	KeystoneSchemaDefinitionName string
}

// RealmDatabaseRepository is the interface for realm database CRUD operations.
// It is implemented by the concrete repository in internal/repositories.
type RealmDatabaseRepository interface {
	GetByRealmID(ctx context.Context, realmID uuid.UUID) (*models.RealmDatabase, error)
	Create(ctx context.Context, rd *models.RealmDatabase) error
	UpdateStatus(ctx context.Context, realmID uuid.UUID, status string) error
	UpdateHealthCheck(ctx context.Context, realmID uuid.UUID, status string, message string) error
}

// DatabaseHostRepository is the interface used by RealmDBProvisioner to update
// host capacity counters after a placement decision. The concrete implementation
// is repositories.DatabaseHostRepository.
type DatabaseHostRepository interface {
	IncrementDatabaseCount(ctx context.Context, id uuid.UUID) error
	DecrementDatabaseCount(ctx context.Context, id uuid.UUID) error
}

// RealmDBProvisioner handles creating, migrating, and decommissioning
// dedicated PostgreSQL databases for enterprise-tier realm isolation.
type RealmDBProvisioner struct {
	masterPool       *pgxpool.Pool // data-plane: CREATE DATABASE, realm_databases table
	controlPlanePool *pgxpool.Pool // control-plane: realms table (may be same as masterPool)
	encryption       *crypto.EncryptionService
	realmDBRepo      RealmDatabaseRepository
	config           RealmDBProvisionerConfig

	// Multi-host placement (optional). When placementEngine is non-nil and a
	// preferredRegion is supplied to ProvisionDatabase, a remote host is
	// selected and the database is created there instead of on masterPool.
	placementEngine *PlacementEngine
	hostRepo        DatabaseHostRepository

	// connRouter is the optional connection routing cache. When set,
	// InvalidateRealm is called after successful provision and decommission so
	// that subsequent lookups fetch fresh connection info from the database.
	connRouter *ConnectionRouter

	// keystoneClient is the controller-runtime client wired to the
	// in-cluster Kubernetes API. Constructed at process startup via
	// pkg/keystoneclient.New(); ownership is held here for the lifetime
	// of the provisioner. nil means realm provisioning is disabled —
	// the constructor refuses to build a provisioner without it.
	keystoneClient client.Client
}

// SetControlPlanePool is an exported identifier.
// NewRealmDBProvisioner is an exported identifier.
// NewRealmDBProvisioner is an exported identifier.
// NewRealmDBProvisioner creates a new RealmDBProvisioner with sensible defaults.
// SetControlPlanePool sets the pool used for control-plane operations (updating
// the realms table). When not set, the masterPool is used as fallback.
func (p *RealmDBProvisioner) SetControlPlanePool(pool *pgxpool.Pool) {
	p.controlPlanePool = pool
}

// SetPlacementEngine wires multi-host provisioning support. When both pe and
// hostRepo are non-nil, ProvisionDatabase will delegate host selection to the
// placement engine for requests that supply a preferredRegion.
func (p *RealmDBProvisioner) SetPlacementEngine(pe *PlacementEngine, hostRepo DatabaseHostRepository) {
	p.placementEngine = pe
	p.hostRepo = hostRepo
}

// SetConnectionRouter wires the Redis connection routing cache. When set,
// InvalidateRealm is called on the router after every successful
// ProvisionDatabase and DecommissionDatabase so stale cached entries are
// evicted immediately.
func (p *RealmDBProvisioner) SetConnectionRouter(router *ConnectionRouter) {
	p.connRouter = router
}

// realmPool returns the pool to use for realms table operations.
func (p *RealmDBProvisioner) realmPool() *pgxpool.Pool {
	if p.controlPlanePool != nil {
		return p.controlPlanePool
	}
	return p.masterPool
}

// NewRealmDBProvisioner is an exported function. keystoneClient is the
// controller-runtime client used to enroll per-tenant LogicalDatabase +
// DatabaseSchema CRs with Keystone (replaces the embedded golang-migrate
// path retired in phase-2b MR4). Pass nil only in test contexts that
// stub `ProvisionDatabase` end-to-end; production code must pass a live
// in-cluster client (build via pkg/keystoneclient.New).
func NewRealmDBProvisioner(
	masterPool *pgxpool.Pool,
	encryption *crypto.EncryptionService,
	realmDBRepo RealmDatabaseRepository,
	keystoneClient client.Client,
	config RealmDBProvisionerConfig,
) *RealmDBProvisioner {
	if config.DefaultSSLMode == "" {
		config.DefaultSSLMode = resolveDefaultSSLMode(masterPool)
	}
	if config.DefaultPoolSize == 0 {
		config.DefaultPoolSize = 20
	}
	if config.DefaultMaxIdleConns == 0 {
		config.DefaultMaxIdleConns = 5
	}
	if config.DefaultConnMaxLifetimeMin == 0 {
		config.DefaultConnMaxLifetimeMin = 30
	}
	if config.KeystoneNamespace == "" {
		config.KeystoneNamespace = "keystone-system"
	}
	if config.KeystoneClusterRef == "" {
		config.KeystoneClusterRef = "prod-eu-west-1-hub"
	}
	if config.KeystoneProviderRef == "" {
		config.KeystoneProviderRef = "falcon-id-pg"
	}
	if config.KeystoneSchemaDefinitionName == "" {
		config.KeystoneSchemaDefinitionName = "falcon-id-tenant-desired"
	}
	return &RealmDBProvisioner{
		masterPool:     masterPool,
		encryption:     encryption,
		realmDBRepo:    realmDBRepo,
		keystoneClient: keystoneClient,
		config:         config,
	}
}

// upsertOwnerPasswordSecret creates or returns the existing password
// Secret for the given realm. The Secret name is deterministic
// (ownerPasswordSecretName) so re-provision after a transient failure
// reuses the same password — no unintended rotation.
//
// Returns the password (plaintext) for use in the realm_databases
// row's PasswordEncrypted column. The password is stored at
// .data[ownerPasswordSecretKey] inside the Secret; the Keystone
// LogicalDatabaseReconciler reads the same key on every reconcile to
// detect rotation.
//
// Lives in p.config.KeystoneNamespace (where the LogicalDatabase
// itself lives). The keystone-tenant-enroller ClusterRole grants
// secrets/get + create + update + delete on this namespace via the
// RoleBinding scoped to keystone-system.
func (p *RealmDBProvisioner) upsertOwnerPasswordSecret(ctx context.Context, realmID uuid.UUID) (string, error) {
	name := ownerPasswordSecretName(realmID)
	ns := p.config.KeystoneNamespace

	// Read-back path: existing Secret → reuse password (idempotent
	// re-provision, no unintended rotation).
	var existing corev1.Secret
	if err := p.keystoneClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &existing); err == nil {
		if pw, ok := existing.Data[ownerPasswordSecretKey]; ok && len(pw) > 0 {
			return string(pw), nil
		}
		// Secret exists but is malformed (key missing or empty) — overwrite.
	} else if !apierrors.IsNotFound(err) {
		return "", fmt.Errorf("get existing password Secret %s/%s: %w", ns, name, err)
	}

	// Create path: generate a fresh password and write the Secret.
	password, err := generateSecurePassword(32)
	if err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Labels: map[string]string{
				"keystone.hexxlock.io/scope":     realmEnrollScope,
				"keystone.hexxlock.io/tier":      realmEnrollTier,
				"keystone.hexxlock.io/tenant-id": realmID.String(),
				"app.kubernetes.io/managed-by":   "falcon-id-realm-db-provisioner",
			},
			Annotations: map[string]string{
				"keystone.hexxlock.io/risk-tier": "high",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{ownerPasswordSecretKey: []byte(password)},
	}
	if err := p.keystoneClient.Create(ctx, sec); err != nil {
		// Race: another reconcile/concurrent provision may have just
		// created it. Re-read and use whatever's there.
		if apierrors.IsAlreadyExists(err) {
			if rerr := p.keystoneClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, sec); rerr == nil {
				if pw, ok := sec.Data[ownerPasswordSecretKey]; ok && len(pw) > 0 {
					return string(pw), nil
				}
			}
		}
		return "", fmt.Errorf("create password Secret %s/%s: %w", ns, name, err)
	}
	return password, nil
}

// deleteOwnerPasswordSecret removes the password Secret for the given
// realm. NotFound is treated as success — the caller invokes this on
// rollback (where the Secret may not exist) and on Decommission (where
// idempotent deletion is the contract).
func (p *RealmDBProvisioner) deleteOwnerPasswordSecret(ctx context.Context, realmID uuid.UUID) {
	name := ownerPasswordSecretName(realmID)
	ns := p.config.KeystoneNamespace
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	if err := p.keystoneClient.Delete(ctx, sec); err != nil && !apierrors.IsNotFound(err) {
		logger.Log.Warn("Failed to delete owner-role password Secret",
			zap.String("namespace", ns),
			zap.String("name", name),
			zap.Error(err),
		)
	}
}

// resolveDefaultSSLMode infers the SSL mode from the master pool's TLS config.
// Returns "disable" when TLS is not configured, "require" otherwise.
func resolveDefaultSSLMode(masterPool *pgxpool.Pool) string {
	if masterPool != nil {
		if masterCfg := masterPool.Config(); masterCfg != nil {
			if masterCfg.ConnConfig.TLSConfig == nil {
				return sslModeDisable
			}
			return "require"
		}
	}
	return "require"
}

// ProvisionDatabase creates a dedicated PostgreSQL database for the given realm.
//
// Phase-2c (keystone v0.1.54+, falcon-id 2026-05-04): role + database
// creation is fully delegated to Keystone's LogicalDatabaseReconciler
// via the SDK. Falcon-id's only direct-Postgres responsibility on the
// hot path is now the realm_databases bookkeeping insert (control-
// plane), and (optionally) the placement-engine host capacity update.
//
// Steps:
//  1. Check whether the realm already has an active database record.
//  2. Resolve placement (if PlacementEngine + preferredRegion are set)
//     to pick which Keystone DatabaseProvider to enroll against. The
//     placement engine runs READ-ONLY against the host catalog; it
//     does NOT open a Postgres admin connection.
//  3. Generate (or reuse) the cryptographically secure password and
//     write it to a Kubernetes Secret in the Keystone namespace. The
//     LogicalDatabaseReconciler reads this Secret on first CREATE to
//     issue CREATE ROLE LOGIN PASSWORD '<value>', and re-reads on
//     every reconcile to detect rotation (ALTER ROLE PASSWORD).
//  4. EnrollSchema — creates the LogicalDatabase + DatabaseSchema CR
//     pair. The LogicalDatabaseReconciler then runs (as
//     keystone_admin, with CREATEROLE+CREATEDB) and:
//        - EnsureRole(name, password) — CREATE ROLE LOGIN PASSWORD
//        - EnsureDatabase(name, owner) — CREATE DATABASE … OWNER
//        - EnsureExtension — uuid-ossp, pgcrypto (per LD spec)
//        - DatabaseSchema reconciler ensures `public` schema +
//          GRANTS to the new role
//     Falcon-id never opens an admin connection to the new database.
//  5. WaitSchemaReady — DatabaseSchema reports Ready=True.
//  6. WaitSchemaFingerprint — per-schema LastAppliedFingerprint
//     matches SD.Status.Fingerprint (the SD-emitted MigrationBundle
//     for the canonical realm table set has applied).
//  7. Encrypt the plaintext password and persist the RealmDatabase
//     record (control-plane bookkeeping; downstream connection
//     routing reads from this).
//  8. (Multi-host path) Increment the host's current_databases counter.
//
// Idempotency: re-provision of the same realm reuses the existing
// password Secret (read-back path) — the Keystone reconciler's
// rotation detector compares hashes and no-ops when content is
// unchanged. Failures after step 4 leave the LogicalDatabase CR in
// place; deletion-policy=Delete on the LD ensures DropDatabase runs
// when the CR is later removed (see DecommissionDatabase).
//
// Returns the persisted RealmDatabase record on success.
func (p *RealmDBProvisioner) ProvisionDatabase(ctx context.Context, realmID uuid.UUID, realmSlug string, preferredRegion string) (*models.RealmDatabase, error) {
	logger.Log.Info("Provisioning dedicated database for realm",
		zap.String("realm_id", realmID.String()),
		zap.String("realm_slug", realmSlug),
		zap.String("preferred_region", preferredRegion),
	)

	// Guard: reject if realm already has an active dedicated database.
	existing, err := p.realmDBRepo.GetByRealmID(ctx, realmID)
	if err == nil && existing != nil {
		if existing.Status == string(models.RealmDatabaseStatusActive) {
			return existing, fmt.Errorf("realm %s already has an active database", realmID)
		}
	}

	safe := sanitizeSlug(realmSlug)
	dbName := "hexxlock_realm_" + safe
	username := "realm_" + safe

	// Step 2: Placement (if engine + region set). Determines target
	// host endpoint for the realm_databases bookkeeping row. With
	// Keystone-managed provisioning, placement also chooses which
	// DatabaseProvider CR Keystone enrolls against — this requires
	// a placement→DatabaseProvider mapping (placement engine returns
	// the providerRef as well as host info). Until that mapping is
	// wired (follow-up MR), the configured KeystoneProviderRef is
	// used for all enrollments and placement only affects the
	// recorded host metadata.
	targetHost := p.masterPool.Config().ConnConfig.Host
	targetPort := int(p.masterPool.Config().ConnConfig.Port)
	targetSSL := p.config.DefaultSSLMode

	var placedHostID *uuid.UUID
	var placedHostAlias *string

	if p.placementEngine != nil && preferredRegion != "" {
		rp, h, portStr, sslMode, hostID, alias := p.selectRemoteHost(ctx, preferredRegion)
		if rp != nil {
			// Pool returned for placement-side capacity probing only;
			// no DDL runs on it. Close immediately.
			rp.Close()
			targetHost = h
			targetPort = portStr
			targetSSL = sslMode
			placedHostID = hostID
			placedHostAlias = alias
		}
	}

	// Step 3: Resolve / persist the password Secret. The Secret name
	// is deterministic per (realm_id) so re-provision after a
	// transient failure reuses the same password rather than
	// triggering an unintended rotation.
	password, err := p.upsertOwnerPasswordSecret(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("upsert owner-role password Secret: %w", err)
	}
	passwordSecretName := ownerPasswordSecretName(realmID)

	// Step 4: Enroll the schema with Keystone. This creates a
	// LogicalDatabase + DatabaseSchema CR pair in keystone-system.
	// The LogicalDatabaseReconciler reads the password Secret
	// (same namespace as the LD), then runs:
	//   - EnsureRole(username, password) — CREATE ROLE … LOGIN PASSWORD '...'
	//   - EnsureDatabase — CREATE DATABASE … OWNER
	//   - EnsureExtension — uuid-ossp, pgcrypto
	// Falcon-id never opens an admin Postgres connection to the new
	// database — Keystone owns DDL.
	//
	// Wait phases (ordered):
	//   a) WaitSchemaReady — DatabaseSchema CR reports Ready=True
	//      (schema present + ownership reconciled).
	//   b) WaitSchemaFingerprint — per-schema LastAppliedFingerprint
	//      matches SD.Status.Fingerprint. Identity-based, race-free
	//      (keystone v0.1.49+ ships the fingerprint feedback loop).
	//      Without this second phase, callers can return after
	//      WaitSchemaReady and find tables missing on first query —
	//      the 2026-05-04 phase-2b gap.
	sdRef := types.NamespacedName{
		Namespace: p.config.KeystoneNamespace,
		Name:      p.config.KeystoneSchemaDefinitionName,
	}

	enrollResult, err := keystonesdk.EnrollSchema(ctx, p.keystoneClient, keystonesdk.EnrollSchemaOpts{
		Namespace:  p.config.KeystoneNamespace,
		NamePrefix: realmEnrollNamePrefix,
		TenantID:   realmID.String(),
		Scope:      realmEnrollScope,
		Tier:       realmEnrollTier,
		LogicalDatabase: keystonev1alpha1.LogicalDatabaseSpec{
			Name:        dbName,
			ClusterRef:  p.config.KeystoneClusterRef,
			ProviderRef: p.config.KeystoneProviderRef,
			OwnerRole:   username,
			Extensions:  []string{"uuid-ossp", "pgcrypto"},
			OwnerRolePasswordSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: passwordSecretName},
				Key:                  ownerPasswordSecretKey,
			},
		},
		Schemas: []keystonev1alpha1.DatabaseSchemaSpec{{
			Name:      "public",
			OwnerRole: username,
		}},
		Annotations: map[string]string{
			"keystone.hexxlock.io/author":    "system:falcon-id-realm-db-provisioner",
			"keystone.hexxlock.io/risk-tier": "medium",
		},
	})
	if err != nil {
		// Rollback: delete the Secret we just wrote. The LogicalDatabase
		// CR creation failed, so no role/database side-effect to undo.
		p.deleteOwnerPasswordSecret(ctx, realmID)
		return nil, fmt.Errorf("enroll realm schema with keystone: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, realmEnrollWaitTimeout)
	defer cancel()
	if err := keystonesdk.WaitSchemaReady(waitCtx, p.keystoneClient, enrollResult.SchemaRefs); err != nil {
		// Past CR-create — leave the LD/Secret in place; the next
		// reconcile (or operator intervention) will resolve. Returning
		// error here surfaces the timeout to the caller; cleanup is
		// the caller's choice via DecommissionDatabase.
		return nil, fmt.Errorf("wait realm schema ready: %w", err)
	}

	if err := keystonesdk.WaitSchemaFingerprint(waitCtx, p.keystoneClient, sdRef, enrollResult.SchemaRefs); err != nil {
		return nil, fmt.Errorf("wait realm schema fingerprint match with %s: %w", sdRef, err)
	}

	logger.Log.Info("Realm schema enrolled and converged via Keystone",
		zap.String("database", dbName),
		zap.String("host", targetHost),
		zap.String("logical_database_ref", enrollResult.LogicalDatabaseRef.String()),
		zap.String("schema_definition", sdRef.String()),
	)

	// Step 7: Encrypt password and persist the realm database record.
	// password came from the Secret upsert above (either freshly generated
	// or read back on re-provision retries); the encryption guard mirrors
	// realm_databases.password_encrypted's column constraint.
	encryptedPassword := password
	if p.encryption != nil {
		encryptedPassword, err = p.encryption.Encrypt(password)
		if err != nil {
			// LD CR + Secret already exist; downstream connection routing
			// would still resolve via the Secret. Log + return the error
			// for the caller to retry / decommission.
			return nil, fmt.Errorf("encrypt database password: %w", err)
		}
	}

	now := time.Now().UTC()
	rd := &models.RealmDatabase{
		ID:                 uuid.New(),
		RealmID:            realmID,
		ConnectionName:     fmt.Sprintf("realm-%s", safe),
		Host:               targetHost,
		Port:               targetPort,
		DatabaseName:       dbName,
		Username:           username,
		PasswordEncrypted:  encryptedPassword,
		SSLMode:            targetSSL,
		PoolSize:           p.config.DefaultPoolSize,
		MaxIdleConns:       p.config.DefaultMaxIdleConns,
		ConnMaxLifetimeMin: p.config.DefaultConnMaxLifetimeMin,
		Status:             string(models.RealmDatabaseStatusActive),
		HostID:             placedHostID,
		HostAlias:          placedHostAlias,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	if err := p.realmDBRepo.Create(ctx, rd); err != nil {
		return nil, fmt.Errorf("store realm database record: %w", err)
	}

	// Step 5 (multi-host): update the host's capacity counter.
	if placedHostID != nil && p.hostRepo != nil {
		if incErr := p.hostRepo.IncrementDatabaseCount(ctx, *placedHostID); incErr != nil {
			// Non-fatal: the database is already created. Log and continue.
			logger.Log.Warn("Failed to increment host database count",
				zap.String("host_id", placedHostID.String()),
				zap.Error(incErr),
			)
		}
	}

	// Link the realm record to its dedicated database (realms live on the control plane).
	_, err = p.realmPool().Exec(ctx,
		"UPDATE realms SET database_connection_id = $1, updated_at = NOW() WHERE id = $2",
		rd.ID, realmID,
	)
	if err != nil {
		logger.Log.Error("Failed to link realm to database record — database is provisioned but realm.database_connection_id is not set",
			zap.String("realm_id", realmID.String()),
			zap.String("database_id", rd.ID.String()),
			zap.Error(err),
		)
		// Non-fatal: the database exists and is recorded in realm_databases.
		// An admin can fix the linkage manually. We do NOT rollback the entire
		// provisioning for a metadata-only failure.
	}

	// Invalidate cached connection info so the next lookup fetches the newly
	// provisioned database record from L3.
	if p.connRouter != nil {
		p.connRouter.InvalidateRealm(ctx, realmID)
	}

	logger.Log.Info("Realm database provisioned successfully",
		zap.String("realm_id", realmID.String()),
		zap.String("database", dbName),
		zap.String("host", targetHost),
		zap.Int("pool_size", p.config.DefaultPoolSize),
	)

	return rd, nil
}

// parseConnStrHostPort extracts host, port, and sslmode from a Postgres DSN.
// It supports both URL form (postgres://…) and key=value form.
// Returns (host, port-as-int, sslmode, error).
func parseConnStrHostPort(dsn string) (string, int, string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", 0, "", fmt.Errorf("parse DSN URL: %w", err)
	}
	host := u.Hostname()
	portStr := u.Port()
	port := 5432
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, "", fmt.Errorf("parse port %q: %w", portStr, err)
		}
		port = p
	}
	sslMode := u.Query().Get("sslmode")
	if sslMode == "" {
		sslMode = sslModeDisable
	}
	return host, port, sslMode, nil
}

// DecommissionDatabase marks a realm database record as decommissioned.
//
// This method does NOT drop the actual PostgreSQL database or role — that
// action requires explicit administrator intervention to prevent accidental
// data loss. The status change signals that the database should no longer
// be used for new connections.
func (p *RealmDBProvisioner) DecommissionDatabase(ctx context.Context, realmID uuid.UUID) error {
	logger.Log.Info("Decommissioning realm database",
		zap.String("realm_id", realmID.String()),
	)

	if err := p.realmDBRepo.UpdateStatus(ctx, realmID, string(models.RealmDatabaseStatusDecommission)); err != nil {
		return err
	}

	// Clear the database_connection_id on the realm so it falls back to shared pool.
	// Skip if no pool is configured (e.g., in tests or when pool is unavailable).
	if pool := p.realmPool(); pool != nil {
		if _, err := pool.Exec(ctx,
			"UPDATE realms SET database_connection_id = NULL, updated_at = NOW() WHERE id = $1",
			realmID,
		); err != nil {
			logger.Log.Error("Failed to clear realm database_connection_id",
				zap.String("realm_id", realmID.String()),
				zap.Error(err),
			)
		}
	}

	// Invalidate the connection routing cache so the next lookup does not serve
	// stale data for a realm that is now using the shared pool.
	if p.connRouter != nil {
		p.connRouter.InvalidateRealm(ctx, realmID)
	}

	return nil
}

// GetDatabaseHealth returns the health status for a realm's dedicated database.
// When no database record exists the realm is using the shared pool and health
// is reported as "shared_pool".
func (p *RealmDBProvisioner) GetDatabaseHealth(ctx context.Context, realmID uuid.UUID) (*models.RealmDatabase, error) {
	rd, err := p.realmDBRepo.GetByRealmID(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("GetDatabaseHealth: %w", err)
	}
	if rd == nil {
		// Realm uses the shared pool — synthesize a minimal record.
		return &models.RealmDatabase{
			RealmID: realmID,
			Status:  "shared_pool",
		}, nil
	}
	return rd, nil
}

// rollbackProvisionOn attempts to drop the database and role created during a
// failed ProvisionDatabase call on the given pool. Errors during rollback are
// logged but not returned — the caller's original error takes precedence.
//
// selectRemoteHost tries to select and connect to a remote host via the placement engine.
// On any failure it logs a warning and returns all nils (caller falls back to master pool).
func (p *RealmDBProvisioner) selectRemoteHost(ctx context.Context, preferredRegion string) (pool *pgxpool.Pool, host string, port int, sslMode string, hostID *uuid.UUID, hostAlias *string) {
	placement, err := p.placementEngine.SelectHost(ctx, PlacementRequest{PreferredRegion: preferredRegion})
	if err != nil {
		logger.Log.Warn("Placement engine failed, falling back to master pool",
			zap.String("preferred_region", preferredRegion),
			zap.Error(err),
		)
		return nil, "", 0, "", nil, nil
	}
	h, portStr, ssl, parseErr := parseConnStrHostPort(placement.PlaintextConnStr)
	if parseErr != nil {
		logger.Log.Warn("Cannot parse placement DSN, falling back to master pool",
			zap.String("host_alias", placement.Host.HostAlias),
			zap.Error(parseErr),
		)
		return nil, "", 0, "", nil, nil
	}
	cfg, poolErr := pgxpool.ParseConfig(placement.PlaintextConnStr)
	if poolErr != nil {
		logger.Log.Warn("Cannot parse placement DSN config, falling back to master pool", zap.Error(poolErr))
		return nil, "", 0, "", nil, nil
	}
	cfg.MaxConns = 3
	rp, poolErr := pgxpool.NewWithConfig(ctx, cfg)
	if poolErr != nil {
		logger.Log.Warn("Cannot connect to remote host, falling back to master pool",
			zap.String("host_alias", placement.Host.HostAlias),
			zap.Error(poolErr),
		)
		return nil, "", 0, "", nil, nil
	}
	logger.Log.Info("Using remote host for realm database provisioning",
		zap.String("host_alias", placement.Host.HostAlias),
		zap.String("host", h),
	)
	id := placement.Host.ID
	alias := placement.Host.HostAlias
	return rp, h, portStr, ssl, &id, &alias
}

// An empty dbName skips the DROP DATABASE step (used when the role was
// created but the database creation itself failed).
func (p *RealmDBProvisioner) rollbackProvisionOn(ctx context.Context, pool *pgxpool.Pool, dbName, username string) {
	logger.Log.Warn("Rolling back failed database provisioning",
		zap.String("database", dbName),
		zap.String("username", username),
	)

	if dbName != "" {
		// Force-terminate any stale connections before dropping the database.
		_, _ = pool.Exec(ctx,
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1",
			dbName,
		)
		if _, err := pool.Exec(ctx,
			fmt.Sprintf("DROP DATABASE IF EXISTS %s", quoteIdent(dbName)),
		); err != nil {
			logger.Log.Error("Rollback: failed to drop database",
				zap.String("database", dbName),
				zap.Error(err),
			)
		}
	}

	if _, err := pool.Exec(ctx,
		fmt.Sprintf("DROP ROLE IF EXISTS %s", quoteIdent(username)),
	); err != nil {
		logger.Log.Error("Rollback: failed to drop role",
			zap.String("username", username),
			zap.Error(err),
		)
	}
}

// generateSecurePassword creates a cryptographically secure random password
// returned as a lowercase hex string of length 2*byteLen.
func generateSecurePassword(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generateSecurePassword: rand.Read: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// sanitizeSlug converts an arbitrary realm slug into a string that is safe
// for use as a PostgreSQL database name or role name component.
//
//   - Uppercase letters are lowercased.
//   - Hyphens are converted to underscores.
//   - Any character that is not [a-z0-9_] is dropped.
//   - The result is truncated to 50 characters to stay within PostgreSQL's
//     63-byte identifier limit when combined with the "hexxlock_realm_" prefix.
func sanitizeSlug(slug string) string {
	result := make([]byte, 0, len(slug))
	for i := 0; i < len(slug); i++ {
		c := slug[i]
		switch {
		case c >= 'a' && c <= 'z':
			result = append(result, c)
		case c >= 'A' && c <= 'Z':
			result = append(result, c+32) // to lowercase
		case c >= '0' && c <= '9':
			result = append(result, c)
		case c == '_':
			result = append(result, c)
		case c == '-':
			result = append(result, '_')
			// All other characters are silently dropped.
		}
	}
	if len(result) > 50 {
		result = result[:50]
	}
	return string(result)
}

// quoteIdent wraps a PostgreSQL identifier in double-quotes and escapes any
// embedded double-quote characters by doubling them (SQL standard). This
// prevents SQL injection through identifier names.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

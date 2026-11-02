// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tenantpurge wires falcon-id into the tenant purge saga
// (platform-shared/tenantpurge). Off unless TENANT_PURGE_PARTICIPANT_ENABLED=true.
//
// falcon-id owns two databases: the main one (hexxlock_falcon_id) and the control
// plane one (hexxlock_falcon_id_control). A purge command sweeps both, plus the
// tenant's SpiceDB relationships:
//
//   - quiesce ends every session and revokes every OAuth token of the tenant;
//   - erase deletes home users that belong to no other tenant, re-homes home users
//     that also belong to a surviving tenant (the account is kept), releases the
//     memberships of visiting users, then runs the catalog sweep and the widened
//     user-reference sweep, removes the SpiceDB relationships and finally the
//     iam_tenants row.
//
// Security audit rows are retained; their actor and network fields are anonymised.
// Protected tenant ids are refused by the shared library (acked blocked).
//
// Append-only triggers (platform_admin_audit_log, iam_jit_elevation_transitions)
// must allow deletes when app.tenant_purge='on'; that is a Keystone bundle in
// the GitOps repository. Without it an erase that cascades into them fails loudly.
package tenantpurge

import (
	"fmt"
	"os"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	sharedconfig "github.com/dogukanturhal/platform-shared/config"
	sharedpurge "github.com/dogukanturhal/platform-shared/tenantpurge"
)

// EnvEnabled turns the participant on. Default off.
const EnvEnabled = "TENANT_PURGE_PARTICIPANT_ENABLED"

// ServiceName is the name tenant-management waits for. The consumer group is
// "<ServiceName>-tenant-purge" (falcon-id-tenant-purge), which the KafkaUser ACLs allow.
const ServiceName = "falcon-id"

// controlServiceName labels the control-plane sweep in logs only; it sends no acks.
const controlServiceName = "falcon-id-control"

// Enabled reports whether the participant flag is set.
func Enabled() bool { return os.Getenv(EnvEnabled) == "true" }

// IsProtectedTenant reports whether id is one of the tenants no purge may touch.
func IsProtectedTenant(id string) bool { return sharedpurge.IsProtected(id) }

// Options are the dependencies of New.
type Options struct {
	// Pool is the main (data plane) database.
	Pool *pgxpool.Pool
	// ControlPool is the control plane database; nil or equal to Pool skips the
	// separate control sweep (the main sweep already covers a shared database).
	ControlPool *pgxpool.Pool
	SpiceDB     SpiceDBCleaner
	Brokers     []string
	SASL        sharedconfig.KafkaSASLConfig
	Logger      *zap.Logger
}

// retained lists the rows kept after an erase.
func retained() []sharedpurge.Retain {
	r := []sharedpurge.Retain{
		{Table: "platform_admin_audit_log", Basis: "operator audit trail, append-only"},
	}
	for _, t := range retainedAudit {
		r = append(r, sharedpurge.Retain{Table: t, Basis: "security audit log, retained with actor PII anonymised"})
	}
	// iam_tenants is deleted last, by AfterErase, once the sweep has emptied every
	// child; the shared value sweep must not count the row as residue before that.
	r = append(r, sharedpurge.Retain{Table: "iam_tenants", Basis: "tenant registry row, removed in the finalize step after the sweep"})
	return r
}

// New builds the participant.
func New(o Options) (*sharedpurge.Participant, error) {
	if o.Pool == nil {
		return nil, fmt.Errorf("tenantpurge: falcon-id needs a database")
	}
	if o.SpiceDB == nil {
		return nil, fmt.Errorf("tenantpurge: falcon-id needs a spicedb client")
	}
	if o.Logger == nil {
		o.Logger = zap.NewNop()
	}
	h := &hooks{db: sharedpurge.NewPgxDB(o.Pool), pool: o.Pool, spicedb: o.SpiceDB, log: o.Logger, deleted: map[string][]string{}}
	if o.ControlPool != nil && o.ControlPool != o.Pool {
		ctl, err := sharedpurge.New(sharedpurge.Config{
			Service: controlServiceName,
			DB:      sharedpurge.NewPgxDB(o.ControlPool),
			Logger:  o.Logger,
		})
		if err != nil {
			return nil, err
		}
		h.control = ctl
	}
	return sharedpurge.New(sharedpurge.Config{
		Service: ServiceName,
		DB:      h.db,
		// iam_jit_elevations.tenant_scope scopes a platform elevation to a tenant.
		ExtraTenantColumns: []string{"tenant_scope"},
		Retain:             retained(),
		Hooks:              h,
		Brokers:            o.Brokers,
		SASL:               o.SASL,
		Logger:             o.Logger,
	})
}

type hooks struct {
	sharedpurge.NopHooks
	db      sharedpurge.DB
	pool    *pgxpool.Pool
	spicedb SpiceDBCleaner
	control *sharedpurge.Participant
	log     *zap.Logger

	mu      sync.Mutex
	deleted map[string][]string // run+tenant -> accounts deleted by EraseTx, for AfterErase
}

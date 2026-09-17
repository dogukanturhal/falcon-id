// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// placementHostRepo is a narrow interface over DatabaseHostRepository that the
// PlacementEngine requires. Using a minimal interface keeps the placement engine
// decoupled from the full concrete repository type.
type placementHostRepo interface {
	ListActiveByRegion(ctx context.Context, region string) ([]models.RealmDatabaseHost, error)
}

// PlacementRequest carries the constraints used to select a target host.
type PlacementRequest struct {
	// PreferredRegion selects hosts whose region field matches. An empty string
	// means "any region" and returns all active healthy hosts sorted by load.
	PreferredRegion string

	// DataResidencyZone, when set, further filters by zone after region filtering.
	// Leave empty to skip zone filtering.
	DataResidencyZone string
}

// PlacementResult contains the selected host and a ready-to-use plaintext DSN
// that can be passed directly to pgxpool.ParseConfig.
type PlacementResult struct {
	Host             models.RealmDatabaseHost
	PlaintextConnStr string // decrypted (or plaintext dev) connection string
}

// PlacementEngine selects the best target PostgreSQL host for a new realm
// database based on region preference, health, and current load.
//
// The engine follows the "accept interfaces" principle: it depends only on the
// narrow placementHostRepo interface so it can be easily tested in isolation.
type PlacementEngine struct {
	hostRepo   placementHostRepo
	encryption *crypto.EncryptionService
}

// NewPlacementEngine creates a PlacementEngine with the given host repository
// and optional encryption service. When encryption is nil the connection strings
// stored in the DB are treated as plaintext (dev mode).
func NewPlacementEngine(hostRepo placementHostRepo, encryption *crypto.EncryptionService) *PlacementEngine {
	return &PlacementEngine{
		hostRepo:   hostRepo,
		encryption: encryption,
	}
}

// SelectHost finds the least-loaded active healthy host that satisfies the
// placement request constraints and returns it together with its decrypted
// connection string.
//
// Selection algorithm:
//  1. Query hosts filtered by PreferredRegion (empty = any).
//  2. When DataResidencyZone is set, retain only hosts whose zone matches.
//  3. Retain only hosts that report HasCapacity().
//  4. The repository returns hosts sorted by current_databases ASC, so the
//     first remaining candidate is the least loaded.
//  5. Decrypt the connection string; if decryption fails, fall back to the
//     raw value (plaintext dev seeds are not encrypted).
//
// Returns ErrNoHostsAvailable when no suitable host can be found.
func (e *PlacementEngine) SelectHost(ctx context.Context, req PlacementRequest) (*PlacementResult, error) {
	hosts, err := e.hostRepo.ListActiveByRegion(ctx, req.PreferredRegion)
	if err != nil {
		return nil, fmt.Errorf("PlacementEngine.SelectHost: list hosts: %w", err)
	}

	// Apply residency zone filter when requested.
	candidates := hosts
	if req.DataResidencyZone != "" {
		candidates = filterByZone(hosts, req.DataResidencyZone)
	}

	// Keep only hosts that have capacity remaining.
	candidates = filterByCapacity(candidates)

	if len(candidates) == 0 {
		return nil, ErrNoHostsAvailable
	}

	// The repository already orders by current_databases ASC; take the first.
	selected := candidates[0]

	connStr, err := e.decryptConnStr(selected.ConnectionStringEnc)
	if err != nil {
		return nil, fmt.Errorf("PlacementEngine.SelectHost: decrypt connection string for host %s: %w",
			selected.HostAlias, err)
	}

	logger.Log.Info("Placement engine selected host",
		zap.String("host_alias", selected.HostAlias),
		zap.String("region", safeStr(selected.Region)),
		zap.Int("current_databases", selected.CurrentDatabases),
		zap.Int("max_databases", selected.MaxDatabases),
	)

	return &PlacementResult{
		Host:             selected,
		PlaintextConnStr: connStr,
	}, nil
}

// decryptConnStr attempts to decrypt the stored connection string. If the
// encryption service is nil or the decryption fails, the raw value is returned
// as-is. This allows dev seeds that store plaintext DSNs to work without an
// encryption key.
func (e *PlacementEngine) decryptConnStr(raw string) (string, error) {
	if e.encryption == nil {
		return raw, nil
	}
	// Only attempt decryption if the value carries the encrypted prefix; otherwise
	// treat it as plaintext (migration seeds store unencrypted DSNs for dev).
	if !crypto.IsEncrypted(raw) {
		return raw, nil
	}
	decrypted, err := e.encryption.Decrypt(raw)
	if err != nil {
		return "", err
	}
	return decrypted, nil
}

// ErrNoHostsAvailable is returned when SelectHost cannot find any candidate.
var ErrNoHostsAvailable = fmt.Errorf("no active healthy database hosts with available capacity")

// filterByZone returns hosts whose DataResidencyZone matches the given zone.
func filterByZone(hosts []models.RealmDatabaseHost, zone string) []models.RealmDatabaseHost {
	out := make([]models.RealmDatabaseHost, 0, len(hosts))
	for _, h := range hosts {
		if h.DataResidencyZone == zone {
			out = append(out, h)
		}
	}
	return out
}

// filterByCapacity returns hosts that have remaining capacity.
func filterByCapacity(hosts []models.RealmDatabaseHost) []models.RealmDatabaseHost {
	out := make([]models.RealmDatabaseHost, 0, len(hosts))
	for _, h := range hosts {
		if h.HasCapacity() {
			out = append(out, h)
		}
	}
	return out
}

// safeStr dereferences a *string pointer or returns "<nil>".
func safeStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

// ImmutableAuditEntry is a single record in the tamper-evident audit chain.
// Each entry carries a hash of its content plus the previous entry's hash,
// forming an append-only hash chain.
type ImmutableAuditEntry struct {
	// ID uniquely identifies this entry (UUID string).
	ID string `json:"id"`

	// TenantID scopes the entry to a tenant.
	TenantID string `json:"tenant_id"`

	// PrevHash is the EntryHash of the immediately preceding entry.
	// Empty for the genesis (first) entry of a chain.
	PrevHash string `json:"prev_hash"`

	// EntryHash is the SHA-256 of (prevHash|timestamp|actor|action|resource|resourceID|data).
	EntryHash string `json:"entry_hash"`

	// Timestamp is when the action occurred (UTC).
	Timestamp time.Time `json:"timestamp"`

	// Actor identifies the subject performing the action (user ID, service name).
	Actor string `json:"actor"`

	// ActorType classifies the actor: "user", "service", or "system".
	ActorType string `json:"actor_type"`

	// Action describes the operation, e.g. "CREATE_USER", "REVOKE_ROLE".
	Action string `json:"action"`

	// Resource is the affected entity type, e.g. "user", "role".
	Resource string `json:"resource"`

	// ResourceID is the identifier of the affected entity.
	ResourceID string `json:"resource_id"`

	// Data holds JSON-serialised supplementary context for the entry.
	Data string `json:"data"`

	// Severity is the operational impact level: "info", "warning", "critical".
	Severity string `json:"severity"`
}

// ComputeImmutableEntryHash produces a deterministic SHA-256 digest using the
// pipe-separated concatenation of the entry's immutable fields.
func ComputeImmutableEntryHash(prevHash string, timestamp time.Time, actor, action, resource, resourceID, data string) string {
	raw := prevHash +
		"|" + timestamp.UTC().Format(time.RFC3339Nano) +
		"|" + actor +
		"|" + action +
		"|" + resource +
		"|" + resourceID +
		"|" + data

	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Store interface
// ---------------------------------------------------------------------------

// ImmutableAuditStore is the persistence contract for the append-only log.
// Implementations must guarantee that committed entries are never modified.
type ImmutableAuditStore interface {
	// Append adds a new entry to the tenant's chain. The implementation must
	// fetch the last entry's hash, set PrevHash, compute EntryHash, and
	// persist the result atomically. It returns the fully-populated entry.
	Append(ctx context.Context, entry ImmutableAuditEntry) (*ImmutableAuditEntry, error)

	// GetChain retrieves all entries for tenantID with Timestamp in [from, to],
	// ordered by Timestamp ascending.
	GetChain(ctx context.Context, tenantID string, from, to time.Time) ([]ImmutableAuditEntry, error)

	// GetLastEntry returns the most recent entry for tenantID.
	// Returns (nil, nil) when the chain is empty.
	GetLastEntry(ctx context.Context, tenantID string) (*ImmutableAuditEntry, error)
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// ImmutableAuditService wraps an ImmutableAuditStore and exposes append and
// chain-integrity verification operations.
type ImmutableAuditService struct {
	store  ImmutableAuditStore
	logger *zap.Logger
}

// NewImmutableAuditService creates a new ImmutableAuditService.
func NewImmutableAuditService(store ImmutableAuditStore, logger *zap.Logger) *ImmutableAuditService {
	return &ImmutableAuditService{
		store:  store,
		logger: logger,
	}
}

// AppendImmutable adds an entry to the tenant's hash chain.
// The store implementation is responsible for linking the chain atomically.
func (s *ImmutableAuditService) AppendImmutable(ctx context.Context, entry ImmutableAuditEntry) (*ImmutableAuditEntry, error) {
	if entry.TenantID == "" {
		return nil, fmt.Errorf("AppendImmutable: tenant_id is required")
	}
	if entry.Actor == "" {
		return nil, fmt.Errorf("AppendImmutable: actor is required")
	}
	if entry.Action == "" {
		return nil, fmt.Errorf("AppendImmutable: action is required")
	}

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	if entry.ActorType == "" {
		entry.ActorType = auditResourceTypeUser
	}
	if entry.Severity == "" {
		entry.Severity = "info"
	}

	stored, err := s.store.Append(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("ImmutableAuditService.AppendImmutable: %w", err)
	}

	s.logger.Info("Immutable audit entry appended",
		zap.String("entry_id", stored.ID),
		zap.String("tenant_id", stored.TenantID),
		zap.String("action", stored.Action),
		zap.String("entry_hash", stored.EntryHash),
	)

	return stored, nil
}

// VerifyChainIntegrity retrieves all entries in the given time window for a
// tenant and verifies the hash chain is intact. Returns (true, nil) if valid,
// or (false, err) with the first violation encountered.
func (s *ImmutableAuditService) VerifyChainIntegrity(ctx context.Context, tenantID string, from, to time.Time) (bool, error) {
	if tenantID == "" {
		return false, fmt.Errorf("VerifyChainIntegrity: tenant_id is required")
	}

	entries, err := s.store.GetChain(ctx, tenantID, from, to)
	if err != nil {
		return false, fmt.Errorf("ImmutableAuditService.VerifyChainIntegrity get chain: %w", err)
	}

	ok, err := verifyImmutableChain(entries)
	if err != nil {
		s.logger.Warn("Immutable audit chain integrity violation",
			zap.String("tenant_id", tenantID),
			zap.Error(err),
		)
		return false, err
	}

	s.logger.Info("Immutable audit chain integrity verified",
		zap.String("tenant_id", tenantID),
		zap.Int("entries_checked", len(entries)),
		zap.Bool("ok", ok),
	)

	return ok, nil
}

// verifyImmutableChain is the pure chain-verification logic operating on a
// slice of entries sorted by Timestamp ascending.
func verifyImmutableChain(entries []ImmutableAuditEntry) (bool, error) {
	for i, entry := range entries {
		// Genesis rule: the first entry must have an empty PrevHash.
		if i == 0 {
			if entry.PrevHash != "" {
				return false, fmt.Errorf(
					"chain integrity violation at index %d (id=%s): genesis entry must have empty prev_hash, got %q",
					i, entry.ID, entry.PrevHash,
				)
			}
		} else {
			// Linkage rule: this entry's PrevHash must equal the previous entry's EntryHash.
			prev := entries[i-1] //nolint:gosec // index is bounds-checked by preceding if len() > 0 check
			if entry.PrevHash != prev.EntryHash {
				return false, fmt.Errorf(
					"chain integrity violation at index %d (id=%s): prev_hash %q does not match preceding entry_hash %q",
					i, entry.ID, entry.PrevHash, prev.EntryHash,
				)
			}
		}

		// Self-hash rule: recompute and compare.
		expected := ComputeImmutableEntryHash(
			entry.PrevHash,
			entry.Timestamp,
			entry.Actor,
			entry.Action,
			entry.Resource,
			entry.ResourceID,
			entry.Data,
		)
		if entry.EntryHash != expected {
			return false, fmt.Errorf(
				"chain integrity violation at index %d (id=%s): entry_hash %q does not match computed hash %q",
				i, entry.ID, entry.EntryHash, expected,
			)
		}
	}

	return true, nil
}

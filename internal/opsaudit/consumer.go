// SPDX-License-Identifier: AGPL-3.0-or-later

// Package opsaudit consumes the operator audit stream (Kafka topic
// platform.ops-audit.v1, published by every service through
// platform-shared/operatorauth) into platform_admin_audit_log, the
// INSERT-only, hash-chained sink created by migration 0035.
//
// Delivery is at-least-once: event_id is the idempotency key (unique index),
// so a redelivered event is a no-op and never extends the chain twice.
package opsaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Topic is the single topic this consumer reads.
const Topic = "platform.ops-audit.v1"

// DB is the slice of the pool the consumer needs (repositories.DBPool
// satisfies it).
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Event is the wire format emitted by operatorauth. Keep in sync with
// platform-shared/operatorauth/audit.go (AuditEvent).
type Event struct {
	EventID       uuid.UUID       `json:"event_id"`
	OccurredAt    time.Time       `json:"occurred_at"`
	SourceService string          `json:"source_service"`
	ActorUserID   uuid.UUID       `json:"actor_user_id"`
	ActorEmail    string          `json:"actor_email,omitempty"`
	ElevationID   string          `json:"elevation_id,omitempty"`
	ApprovalID    string          `json:"approval_id,omitempty"`
	Action        string          `json:"action"`
	TenantID      string          `json:"tenant_id,omitempty"`
	Resource      string          `json:"resource,omitempty"`
	ReasonCode    string          `json:"reason_code,omitempty"`
	Reason        string          `json:"reason,omitempty"`
	RequestID     string          `json:"request_id,omitempty"`
	BeforeHash    string          `json:"before_hash,omitempty"`
	AfterHash     string          `json:"after_hash,omitempty"`
	Success       bool            `json:"success"`
	IPAddress     string          `json:"ip_address,omitempty"`
	UserAgent     string          `json:"user_agent,omitempty"`
	Details       json.RawMessage `json:"details,omitempty"`
	// ApprovalMode is "four_eyes" or "platform_admin_bypass". It is stored in
	// details (not a hash input, so the v1 chain is unchanged).
	ApprovalMode string `json:"approval_mode,omitempty"`
}

// withApprovalMode merges approval_mode into a JSON-object details blob. An
// existing details.approval_mode wins; a non-object blob is left untouched.
func withApprovalMode(details []byte, mode string) []byte {
	if mode == "" {
		return details
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(details, &m); err != nil || m == nil {
		return details
	}
	if _, ok := m["approval_mode"]; ok {
		return details
	}
	v, err := json.Marshal(mode)
	if err != nil {
		return details
	}
	m["approval_mode"] = v
	out, err := json.Marshal(m)
	if err != nil {
		return details
	}
	return out
}

// permanentError marks a failure that retrying cannot fix (goes to the DLQ).
type permanentError struct{ err error }

func (p permanentError) Error() string { return p.err.Error() }
func (p permanentError) Unwrap() error { return p.err }

// chainLockKey serialises chain appends across replicas (pg advisory lock).
const chainLockKey = "platform_admin_audit_log_chain"

// Consumer validates events and appends them to the audit table.
type Consumer struct {
	db DB
}

// NewConsumer builds a consumer over db.
func NewConsumer(db DB) *Consumer { return &Consumer{db: db} }

func optUUID(s string) (*uuid.UUID, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func uuidText(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// HashInput is the canonical field set of one audit row. It is the ONLY place
// the row-content hash is defined; both the writer (Handle) and the integrity
// verifier (Verify) build their input through it.
//
// Canonicalisation (v1), documented in docs/ops-audit-hash-chain.md:
//
//	entry_hash = hex(sha256( prev_hash + "|" + JSON(fields) ))
//	fields     = JSON array, in this exact order, all elements strings except
//	             the last (bool):
//	  event_id, occurred_at, source_service, actor_user_id, admin_username,
//	  elevation_id, approval_id, action, tenant_id, resource, reason_code,
//	  reason, request_id, before_hash, after_hash, success
//
// UUIDs are lower-case canonical text ("" when NULL); occurred_at is UTC
// RFC3339Nano truncated to microseconds (what Postgres stores); NULL text is "".
// prev_hash is the previous row's entry_hash in chain order ("" for the first).
type HashInput struct {
	EventID       string
	OccurredAt    time.Time
	SourceService string
	ActorUserID   string
	AdminUsername string
	ElevationID   string
	ApprovalID    string
	Action        string
	TenantID      string
	Resource      string
	ReasonCode    string
	Reason        string
	RequestID     string
	BeforeHash    string
	AfterHash     string
	Success       bool
}

// EntryHashOf is the chain hash of one row (see HashInput for the definition).
func EntryHashOf(prev string, in HashInput) string {
	canon, _ := json.Marshal([]any{
		in.EventID, in.OccurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano), in.SourceService,
		in.ActorUserID, in.AdminUsername, in.ElevationID, in.ApprovalID, in.Action,
		in.TenantID, in.Resource, in.ReasonCode, in.Reason, in.RequestID, in.BeforeHash, in.AfterHash, in.Success,
	})
	sum := sha256.Sum256(append([]byte(prev+"|"), canon...))
	return hex.EncodeToString(sum[:])
}

// EntryHash is the chain hash of an event about to be written.
func EntryHash(prev string, e Event, adminUsername string) string {
	return EntryHashOf(prev, HashInput{
		EventID: e.EventID.String(), OccurredAt: e.OccurredAt, SourceService: e.SourceService,
		ActorUserID: e.ActorUserID.String(), AdminUsername: adminUsername,
		ElevationID: e.ElevationID, ApprovalID: e.ApprovalID, Action: e.Action,
		TenantID: e.TenantID, Resource: e.Resource, ReasonCode: e.ReasonCode, Reason: e.Reason,
		RequestID: e.RequestID, BeforeHash: e.BeforeHash, AfterHash: e.AfterHash, Success: e.Success,
	})
}

// SourceFalconID is the source_service stamped on events falcon-id records
// for its own operator-plane mutations.
const SourceFalconID = "falcon-id"

// Record appends an event produced by falcon-id itself (it is the sink, so no
// Kafka round trip). Same chain, same dedupe key, same validation as Handle.
func (c *Consumer) Record(ctx context.Context, e Event) error {
	if e.EventID == uuid.Nil {
		e.EventID = uuid.New()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	e.SourceService = SourceFalconID
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("opsaudit: marshal: %w", err)
	}
	return c.Handle(ctx, raw)
}

// Handle decodes and stores one raw message value. nil = fully dealt with
// (stored or duplicate); permanentError = send to the DLQ; any other error is
// retryable.
func (c *Consumer) Handle(ctx context.Context, value []byte) error {
	var e Event
	if err := json.Unmarshal(value, &e); err != nil {
		return permanentError{fmt.Errorf("bad ops-audit event: %w", err)}
	}
	if e.EventID == uuid.Nil {
		return permanentError{errors.New("ops-audit event missing event_id")}
	}
	if e.ActorUserID == uuid.Nil {
		return permanentError{errors.New("ops-audit event missing actor_user_id")}
	}
	if strings.TrimSpace(e.Action) == "" {
		return permanentError{errors.New("ops-audit event missing action")}
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	// Postgres stores microseconds: hash the value the row will hold so the
	// chain can be recomputed from the table.
	e.OccurredAt = e.OccurredAt.Truncate(time.Microsecond)
	tenantID, err := optUUID(e.TenantID)
	if err != nil {
		return permanentError{fmt.Errorf("ops-audit event bad tenant_id: %w", err)}
	}
	elevID, err := optUUID(e.ElevationID)
	if err != nil {
		return permanentError{fmt.Errorf("ops-audit event bad elevation_id: %w", err)}
	}
	apprID, err := optUUID(e.ApprovalID)
	if err != nil {
		return permanentError{fmt.Errorf("ops-audit event bad approval_id: %w", err)}
	}
	// Hash the canonical (lower-case) text of the parsed UUIDs, i.e. what the
	// verifier reads back from the uuid columns.
	e.ElevationID, e.ApprovalID, e.TenantID = uuidText(elevID), uuidText(apprID), uuidText(tenantID)
	adminUsername := e.ActorEmail
	if adminUsername == "" {
		adminUsername = e.ActorUserID.String()
	}
	details := []byte(e.Details)
	if len(details) == 0 || !json.Valid(details) {
		details = []byte("{}")
	}
	details = withApprovalMode(details, e.ApprovalMode)

	tx, err := c.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("opsaudit: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, chainLockKey); err != nil {
		return fmt.Errorf("opsaudit: chain lock: %w", err)
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM platform_admin_audit_log WHERE event_id = $1)`, e.EventID).Scan(&exists); err != nil {
		return fmt.Errorf("opsaudit: dedupe check: %w", err)
	}
	if exists {
		return nil
	}
	// The chain head is the row with the highest chain_seq (assigned below under
	// the advisory lock, so it is strictly commit-ordered). Rows written before
	// migration 0037 have no chain_seq: they sort after every sequenced row in
	// the DESC scan and are ordered among themselves by created_at.
	var prev string
	var headSeq int64
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE((SELECT entry_hash FROM platform_admin_audit_log
		                  WHERE entry_hash IS NOT NULL
		                  ORDER BY chain_seq DESC NULLS LAST, created_at DESC, id DESC LIMIT 1), ''),
		       COALESCE((SELECT max(chain_seq) FROM platform_admin_audit_log), 0)`).Scan(&prev, &headSeq); err != nil {
		return fmt.Errorf("opsaudit: read chain head: %w", err)
	}
	entry := EntryHash(prev, e, adminUsername)

	_, err = tx.Exec(ctx, `
		INSERT INTO platform_admin_audit_log (
			admin_user_id, admin_username, target_tenant_id, action, action_category,
			details, ip_address, user_agent, request_id, success,
			event_id, source_service, elevation_id, approval_id, reason_code, reason,
			resource, before_hash, after_hash, occurred_at, prev_hash, entry_hash, chain_seq
		) VALUES ($1,$2,$3,$4,'operator',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
		ON CONFLICT (event_id) WHERE event_id IS NOT NULL DO NOTHING`,
		e.ActorUserID, adminUsername, tenantID, e.Action,
		details, nullable(e.IPAddress), nullable(e.UserAgent), nullable(e.RequestID), e.Success,
		e.EventID, nullable(e.SourceService), elevID, apprID, nullable(e.ReasonCode), nullable(e.Reason),
		nullable(e.Resource), nullable(e.BeforeHash), nullable(e.AfterHash), e.OccurredAt, prev, entry, headSeq+1,
	)
	if err != nil {
		return fmt.Errorf("opsaudit: insert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("opsaudit: commit: %w", err)
	}
	return nil
}

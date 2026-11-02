// SPDX-License-Identifier: AGPL-3.0-or-later

package opsaudit

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Querier is the read slice of the pool Verify needs.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Report is the outcome of a chain verification.
type Report struct {
	OK       bool
	Checked  int
	FirstBad string // id of the first broken row, "" when OK
	// Reason is "link" (prev_hash != previous entry_hash) or "content"
	// (entry_hash != hash recomputed from the row's own fields).
	Reason   string
	HeadHash string
	// Unsequenced counts rows in the window written before chain_seq existed:
	// their linkage is checked, their content hash is not (they were hashed
	// with a timestamp precision Postgres cannot reproduce).
	Unsequenced int
}

// Verify checks the newest `limit` hash-chained rows: for every row the
// linkage (prev_hash equals the previous row's entry_hash) and, for rows with a
// chain_seq, the content (entry_hash equals EntryHashOf recomputed from the
// stored fields; see HashInput). The oldest row of the window has no
// predecessor in view, so only its content is checked.
func Verify(ctx context.Context, db Querier, limit int) (*Report, error) {
	rows, err := db.Query(ctx, `
		SELECT id::text, chain_seq IS NOT NULL,
		       COALESCE(prev_hash, ''), COALESCE(entry_hash, ''),
		       COALESCE(event_id::text, ''), occurred_at, COALESCE(source_service, ''),
		       COALESCE(admin_user_id::text, ''), COALESCE(admin_username, ''),
		       COALESCE(elevation_id::text, ''), COALESCE(approval_id::text, ''), action,
		       COALESCE(target_tenant_id::text, ''), COALESCE(resource, ''),
		       COALESCE(reason_code, ''), COALESCE(reason, ''), COALESCE(request_id, ''),
		       COALESCE(before_hash, ''), COALESCE(after_hash, ''), COALESCE(success, false)
		  FROM platform_admin_audit_log
		 WHERE entry_hash IS NOT NULL
		 ORDER BY chain_seq DESC NULLS LAST, created_at DESC, id DESC
		 LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("opsaudit: verify query: %w", err)
	}
	defer rows.Close()

	type rec struct {
		id, prev, entry string
		sequenced       bool
		in              HashInput
	}
	var window []rec // newest first
	for rows.Next() {
		var r rec
		var occurred *time.Time
		if err := rows.Scan(&r.id, &r.sequenced, &r.prev, &r.entry,
			&r.in.EventID, &occurred, &r.in.SourceService,
			&r.in.ActorUserID, &r.in.AdminUsername,
			&r.in.ElevationID, &r.in.ApprovalID, &r.in.Action,
			&r.in.TenantID, &r.in.Resource,
			&r.in.ReasonCode, &r.in.Reason, &r.in.RequestID,
			&r.in.BeforeHash, &r.in.AfterHash, &r.in.Success); err != nil {
			return nil, fmt.Errorf("opsaudit: verify scan: %w", err)
		}
		if occurred != nil {
			r.in.OccurredAt = *occurred
		}
		window = append(window, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("opsaudit: verify rows: %w", err)
	}

	rep := &Report{OK: true, Checked: len(window)}
	if len(window) > 0 {
		rep.HeadHash = window[0].entry
	}
	// Walk oldest -> newest so FirstBad is the earliest break.
	for i := len(window) - 1; i >= 0; i-- {
		r := window[i]
		if !r.sequenced {
			rep.Unsequenced++
		}
		bad := ""
		if i < len(window)-1 && r.prev != window[i+1].entry {
			bad = "link"
		} else if r.sequenced && EntryHashOf(r.prev, r.in) != r.entry {
			bad = "content"
		}
		if bad != "" && rep.OK {
			rep.OK, rep.FirstBad, rep.Reason = false, r.id, bad
		}
	}
	return rep, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sessionsweep ends iam_sessions rows and, when the end is EXPLICIT,
// revokes the refresh tokens bound to them in the same SQL statement.
//
// One data-modifying CTE does both, so a session can never be ended without its
// tokens being swept (or the reverse), whichever path ends it: user/admin
// revoke, logout, SAML SLO, inbound back-channel logout, password change,
// deactivation, tenant suspension. Idle/absolute expiry (non-explicit reasons,
// see models.IsExplicitSessionEnd) only flips the session row.
package sessionsweep

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// Executor is the subset of pgx pools/transactions the sweep needs.
type Executor interface {
	Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}

// NonExplicitReasons lists the end_reason values that do not terminate tokens;
// SQL fragments that upgrade an already-lapsed session use it.
const NonExplicitReasons = `'` + models.SessionEndReasonExpired + `', '` +
	models.SessionEndReasonInactivityTimeout + `', '` +
	models.SessionEndReasonRegenerated + `', '` +
	models.SessionEndReasonRegeneratedOnLogin + `'`

// tokenSweepSQL revokes every live token of the ended sessions' users that is
// bound to one of the ended sessions (session_id or idp_session_id) or belongs
// to a rotation family containing such a token. Same predicate as
// OAuthClientRepository.RevokeTokensBySession.
//
// Shape matters for the 100k-1M row token table: ids/users/families are
// aggregated into arrays once (init-plan parameters), so each OR branch is a
// plain `col = ANY($param)` the planner can bitmap-OR over the existing
// session_id / idp_session_id / token_family_id / user_id indexes instead of
// re-running correlated IN-subplans as sequential scans.
const tokenSweepSQL = `agg AS (
	SELECT array_agg(id) AS sids, array_agg(DISTINCT user_id) AS uids FROM ids
), fam AS (
	SELECT array_agg(DISTINCT f.token_family_id) AS fids FROM iam_oauth_tokens f
	WHERE f.token_family_id IS NOT NULL
	  AND f.user_id = ANY((SELECT uids FROM agg)::uuid[])
	  AND (f.session_id = ANY((SELECT sids FROM agg)::uuid[])
	       OR f.idp_session_id = ANY((SELECT sids FROM agg)::uuid[]))
), swept AS (
	UPDATE iam_oauth_tokens t
	SET is_revoked = true, revoked_at = NOW(), updated_at = NOW()
	WHERE t.is_revoked = false
	  AND t.user_id = ANY((SELECT uids FROM agg)::uuid[])
	  AND (t.session_id = ANY((SELECT sids FROM agg)::uuid[])
	       OR t.idp_session_id = ANY((SELECT sids FROM agg)::uuid[])
	       OR t.token_family_id = ANY((SELECT fids FROM fam)::uuid[]))
)`

// Statement builds the combined statement. updateSessions is a full
// `UPDATE iam_sessions ... RETURNING <alias>.id, <alias>.user_id` statement;
// extraSessionParam, when non-empty (e.g. "$1"), names a uuid parameter holding
// a session id whose tokens are swept even if the row was already ended
// (idempotent re-end). Tokens are only swept for the ended sessions' own users.
// It selects the number of session rows ended. Exposed for tests.
func Statement(updateSessions, reason, extraSessionParam string) string {
	if !models.IsExplicitSessionEnd(reason) {
		return fmt.Sprintf(`WITH ended AS (%s) SELECT count(*) FROM ended`, updateSessions)
	}
	ids := `SELECT id, user_id FROM ended`
	if extraSessionParam != "" {
		ids += ` UNION SELECT id, user_id FROM iam_sessions WHERE id = ` + extraSessionParam + `::uuid`
	}
	return fmt.Sprintf(`WITH ended AS (%s), ids AS (%s), %s SELECT count(*) FROM ended`,
		updateSessions, ids, tokenSweepSQL)
}

// End runs the statement and returns how many session rows were ended.
func End(ctx context.Context, db Executor, updateSessions, reason, extraSessionParam string, args ...interface{}) (int64, error) {
	var n int64
	if err := db.QueryRow(ctx, Statement(updateSessions, reason, extraSessionParam), args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

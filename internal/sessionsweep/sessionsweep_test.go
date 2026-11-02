// SPDX-License-Identifier: AGPL-3.0-or-later

package sessionsweep

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const upd = `UPDATE iam_sessions SET is_active = false WHERE user_id = $1 RETURNING id, user_id`

func TestStatement_ExplicitReasonSweepsTokens(t *testing.T) {
	// logout, SAML SLO ("saml_slo"), inbound back-channel logout, deactivation...
	for _, reason := range []string{"logout", "revoked", "saml_slo", "backchannel_logout", "password_change", "user_deactivated", "tenant_suspended"} {
		q := Statement(upd, reason, "")
		assert.Contains(t, q, "UPDATE iam_oauth_tokens t", reason)
		assert.Contains(t, q, "t.session_id = ANY((SELECT sids FROM agg)::uuid[])", reason)
		assert.Contains(t, q, "t.idp_session_id = ANY((SELECT sids FROM agg)::uuid[])", reason)
		assert.Contains(t, q, "t.token_family_id = ANY((SELECT fids FROM fam)::uuid[])", reason)
		assert.Contains(t, q, "t.user_id = ANY((SELECT uids FROM agg)::uuid[])", reason)
	}
}

func TestStatement_NonExplicitReasonDoesNotTouchTokens(t *testing.T) {
	for _, reason := range []string{"expired", "inactivity_timeout", "session_regenerated", "session_regenerated_on_login"} {
		q := Statement(upd, reason, "")
		assert.False(t, strings.Contains(q, "iam_oauth_tokens"), reason)
	}
}

func TestStatement_ExtraIDSweepsEvenIfAlreadyEnded(t *testing.T) {
	q := Statement(upd, "logout", "$1")
	assert.Contains(t, q, "SELECT id, user_id FROM ended UNION SELECT id, user_id FROM iam_sessions WHERE id = $1::uuid")
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package opsconsole

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/platform-shared/operatorauth"
)

func mustJSON(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

// parseReasonBody extracts and validates reason_code / reason.
func parseReasonBody(raw []byte) (operatorauth.Reason, bool) {
	var body struct {
		ReasonCode string `json:"reason_code"`
		Reason     string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return operatorauth.Reason{}, false
	}
	r, err := operatorauth.ParseReason(body.ReasonCode, body.Reason)
	if err != nil {
		return operatorauth.Reason{}, false
	}
	return r, true
}

func reasonFrom(c *gin.Context) operatorauth.Reason {
	if v, ok := c.Get(ctxReason); ok {
		if r, ok := v.(operatorauth.Reason); ok {
			return r
		}
	}
	return operatorauth.Reason{}
}

func actorOf(c *gin.Context) *operatorauth.Actor { return operatorauth.ActorFrom(c) }

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

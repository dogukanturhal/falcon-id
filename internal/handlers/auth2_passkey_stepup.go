// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"github.com/google/uuid"
	"time"
)

type passkeyStepUpSessionRepository interface {
	AppendAuthMethod(context.Context, uuid.UUID, string) (bool, error)
	RefreshAuthenticatedAt(context.Context, uuid.UUID) error
}
type passkeyStepUpRecorder interface {
	RecordVerification(context.Context, uuid.UUID, uuid.UUID, string, string, time.Duration) error
}

// Used only after a verified passkey assertion. All persistence must succeed
// before the handler reports success, otherwise OAuth freshness would loop.
func recordPasskeyStepUp(ctx context.Context, sessions passkeyStepUpSessionRepository, recorder passkeyStepUpRecorder, sid, userID uuid.UUID) error {
	for _, method := range []string{"mfa", "hwk"} {
		if _, err := sessions.AppendAuthMethod(ctx, sid, method); err != nil {
			return err
		}
	}
	if err := sessions.RefreshAuthenticatedAt(ctx, sid); err != nil {
		return err
	}
	return recorder.RecordVerification(ctx, sid, userID, "oauth_step_up", "webauthn", 5*time.Minute)
}

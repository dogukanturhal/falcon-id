// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"github.com/google/uuid"
)

// VerifyMFACodeForMethod never tries a different factor than the one selected
// for this challenge. Empty method preserves in-flight pre-deploy challenges.
func (s *MFAService) VerifyMFACodeForMethod(ctx context.Context, userID uuid.UUID, code, method string) (bool, error) {
	if method == "" {
		return s.VerifyMFACode(ctx, userID, code)
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("load MFA factor: %w", err)
	}
	if user == nil || !user.MFAEnabled {
		return false, nil
	}
	switch method {
	case "totp":
		if !user.MFATOTPEnabled {
			return false, nil
		}
		return s.VerifyTOTPCode(ctx, userID, code)
	case "email":
		if !user.MFAEmailEnabled {
			return false, nil
		}
		return s.VerifyEmailMFACode(ctx, userID, code)
	case "backup_code":
		return s.VerifyBackupCode(ctx, userID, code)
	default:
		return false, nil
	}
}

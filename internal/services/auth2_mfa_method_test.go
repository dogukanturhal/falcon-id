// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type auth2MFAUser struct {
	mfaUserRepository
	user *models.User
}

func (s auth2MFAUser) GetByID(context.Context, uuid.UUID) (*models.User, error) { return s.user, nil }
func (s auth2MFAUser) HasActiveWebAuthnCredential(context.Context, uuid.UUID) (bool, error) {
	return true, nil
}

func TestAuth2MFASelectedMethod_EmailDoesNotFallBackToAuthenticator(t *testing.T) {
	user := &models.User{ID: uuid.New(), MFAEnabled: true, MFATOTPEnabled: true, MFAEmailEnabled: false}
	s := NewMFAService(newAuthCfg(), auth2MFAUser{user: user}, nil, nil, nil)
	valid, err := s.VerifyMFACodeForMethod(context.Background(), user.ID, "123456", "email")
	require.NoError(t, err)
	require.False(t, valid)
}

func TestAuth2MFASelectedMethod_EmailValidAndInvalidCodes(t *testing.T) {
	user := &models.User{ID: uuid.New(), MFAEnabled: true, MFAEmailEnabled: true}
	repo := new(MockMFARepository)
	s := NewMFAService(newAuthCfg(), auth2MFAUser{user: user}, repo, nil, nil)
	code := &repositories.MFAEmailCode{ID: uuid.New(), CodeHash: s.hashCode("123456")}
	repo.On("GetActiveMFAEmailCode", mock.Anything, user.ID).Return(code, nil).Twice()
	repo.On("MarkMFAEmailCodeUsed", mock.Anything, code.ID).Return(nil).Once()
	valid, err := s.VerifyMFACodeForMethod(context.Background(), user.ID, "654321", "email")
	require.NoError(t, err)
	require.False(t, valid)
	valid, err = s.VerifyMFACodeForMethod(context.Background(), user.ID, "123456", "email")
	require.NoError(t, err)
	require.True(t, valid)
	repo.AssertExpectations(t)
}

func TestAuth2MFAStatus_MaskedDeliveryAndPasskeyAvailability(t *testing.T) {
	user := &models.User{ID: uuid.New(), Email: "member@example.test", MFAEnabled: true, MFAEmailEnabled: true}
	repo := new(MockMFARepository)
	repo.On("GetUnusedRecoveryCodesCount", mock.Anything, user.ID).Return(2, nil).Once()
	cfg := newAuthCfg()
	cfg.MFAEmailCodeTTL = 5 * time.Minute
	s := NewMFAService(cfg, auth2MFAUser{user: user}, repo, nil, nil)
	status, err := s.GetMFAStatus(context.Background(), user.ID)
	require.NoError(t, err)
	require.Equal(t, "m***@example.test", status.MaskedEmail)
	require.Equal(t, int64(300), status.EmailCodeTTL)
	require.True(t, status.PasskeyAvailable)
	require.Equal(t, []string{"email"}, status.AvailableMethods)
}

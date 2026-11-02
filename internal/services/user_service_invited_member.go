// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// PrepareInvitedMemberUser builds, without persisting, the global account of a
// person who accepts a team invitation before they have any falcon-id account.
//
// The invitation token proves possession of the invited mailbox, so the email
// is stored as verified. The password goes through the same self-service
// policy and breach check as signup (PrepareSignupCredential), and the realm
// is resolved fail-closed from the inviting tenant exactly like create().
// The caller persists the returned user inside the transaction that also
// grants roles, writes the membership and consumes the invitation, so a
// failure can never leave a half-onboarded account behind.
func (s *UserService) PrepareInvitedMemberUser(ctx context.Context, tenantID uuid.UUID, email, fullName, password string) (*models.User, error) {
	credential, err := s.PrepareSignupCredential(ctx, password)
	if err != nil {
		return nil, err
	}
	if s.realmResolver == nil {
		return nil, fmt.Errorf("PrepareInvitedMemberUser: realm resolver is not configured")
	}
	realm, err := s.realmResolver.GetTenantRealm(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("PrepareInvitedMemberUser: resolve realm: %w", err)
	}
	if realm == nil || realm.ID == uuid.Nil {
		return nil, fmt.Errorf("PrepareInvitedMemberUser: realm resolution failed for tenant %s", tenantID)
	}

	canonical := models.CanonicalInvitationEmail(email)
	first, last := splitPersonName(fullName)
	display := strings.TrimSpace(fullName)
	hash := credential.passwordHash
	user := &models.User{
		TenantID:        tenantID,
		RealmID:         realm.ID,
		Username:        canonical,
		Email:           canonical,
		PasswordHash:    &hash,
		FirstName:       &first,
		LastName:        &last,
		IsActive:        true,
		IsEmailVerified: true,
	}
	if display != "" {
		user.DisplayName = &display
	}
	return user, nil
}

// splitPersonName splits "Ada Lovelace King" into ("Ada", "Lovelace King").
func splitPersonName(full string) (string, string) {
	full = strings.Join(strings.Fields(full), " ")
	first, last, _ := strings.Cut(full, " ")
	return first, last
}

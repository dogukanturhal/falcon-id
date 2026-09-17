// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// Repository interfaces for SocialAuthService.
//
// These exist so the social-auth path can be exercised in a test. The service
// previously held concrete *repositories.UserRepository and
// *repositories.FederatedAccountRepository values, and the pgxmock
// constructors live in _test.go files INSIDE the repositories package, so they
// are unreachable from a services test. The practical consequence was that
// t-052's account-takeover fix — the refusal branch in
// resolveUserForFederation — could only ever be verified by READING it.
//
// That matters beyond one fix: the team's standard proof technique is now a
// negative control, where you break the fix in a simulation and confirm the
// test catches it. A service whose collaborators cannot be substituted is a
// service where that technique does not work at all.
//
// The interfaces are deliberately narrow — exactly the methods
// SocialAuthService calls, no more — so they document the service's real
// dependency surface rather than mirroring the repositories. The concrete
// repository types satisfy them structurally, so no constructor or call site
// changes.

// socialAuthUserRepo is the subset of *repositories.UserRepository used by
// SocialAuthService.
type socialAuthUserRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error)
	Create(ctx context.Context, user *models.User) error
	Update(ctx context.Context, user *models.User) error
	AssignRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error)
	HasAnyMFAFactor(ctx context.Context, userID uuid.UUID) (bool, error)
}

// socialAuthFedAccountRepo is the subset of
// *repositories.FederatedAccountRepository used by SocialAuthService.
//
// GetByProviderUserID is the load-bearing one: t-052's fix resolves identity
// by PROVIDER SUBJECT through this method, and only a hit here may return a
// pre-existing account.
type socialAuthFedAccountRepo interface {
	Create(ctx context.Context, account *models.FederatedAccount) error
	Update(ctx context.Context, account *models.FederatedAccount) error
	GetByProviderUserID(ctx context.Context, providerID uuid.UUID, providerUserID string) (*models.FederatedAccount, error)
	GetByUser(ctx context.Context, userID uuid.UUID) ([]models.FederatedAccount, error)
	GetByUserAndProvider(ctx context.Context, userID, providerID uuid.UUID) (*models.FederatedAccount, error)
	DeleteByUserAndProvider(ctx context.Context, userID, providerID uuid.UUID) error
}

// socialAuthRoleRepo is the subset of *repositories.RoleRepository used by
// SocialAuthService.
type socialAuthRoleRepo interface {
	GetDefaultRoles(ctx context.Context, tenantID uuid.UUID) ([]models.Role, error)
}

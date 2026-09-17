// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// Executes t-052's account-takeover fix in BOTH directions.
//
// Until the repository interfaces were extracted (social_auth_repos.go) this
// could only be verified by reading: SocialAuthService held concrete
// repository types, and the pgxmock constructors live in _test.go files inside
// the repositories package, unreachable from here. Both directions were
// recorded as "READ, not executed".
//
// Direction 1 is the security property: a social identity asserting an
// address that already belongs to somebody must be REFUSED, not handed the
// account. Direction 2 is the property that proves the fix did not simply
// break login: a returning user whose PROVIDER SUBJECT is already linked must
// still resolve. A fix that satisfies only Direction 1 is indistinguishable
// from one that blocks everything.

type fakeUserRepo struct {
	byEmail map[string]*models.User
	byID    map[uuid.UUID]*models.User
	created []*models.User
}

func (f *fakeUserRepo) GetByID(_ context.Context, id uuid.UUID) (*models.User, error) {
	return f.byID[id], nil
}
func (f *fakeUserRepo) GetByEmail(_ context.Context, _ uuid.UUID, email string) (*models.User, error) {
	return f.byEmail[email], nil
}
func (f *fakeUserRepo) Create(_ context.Context, u *models.User) error {
	f.created = append(f.created, u)
	return nil
}
func (f *fakeUserRepo) Update(_ context.Context, _ *models.User) error { return nil }
func (f *fakeUserRepo) AssignRoles(_ context.Context, _ uuid.UUID, _ []uuid.UUID, _ *uuid.UUID) error {
	return nil
}
func (f *fakeUserRepo) GetUserRoles(_ context.Context, _ uuid.UUID) ([]models.Role, error) {
	return nil, nil
}
func (f *fakeUserRepo) GetUserPermissions(_ context.Context, _ uuid.UUID) ([]models.Permission, error) {
	return nil, nil
}
func (f *fakeUserRepo) HasAnyMFAFactor(_ context.Context, _ uuid.UUID) (bool, error) {
	return false, nil
}

type fakeRoleRepo struct{}

func (fakeRoleRepo) GetDefaultRoles(_ context.Context, _ uuid.UUID) ([]models.Role, error) {
	return nil, nil
}

func googleProvider(tenantID uuid.UUID) *models.IdentityProvider {
	return &models.IdentityProvider{
		ID:       uuid.New(),
		TenantID: tenantID,
		Name:     "google",
		Type:     "google",
	}
}

// DIRECTION 1 — an identity asserting a pre-existing address must be refused.
func TestResolveUserForFederation_RefusesImplicitLinkToExistingAccount(t *testing.T) {
	tenantID := uuid.New()
	victim := &models.User{ID: uuid.New(), TenantID: tenantID, Email: "victim@company.com"}

	users := &fakeUserRepo{
		byEmail: map[string]*models.User{"victim@company.com": victim},
		byID:    map[uuid.UUID]*models.User{victim.ID: victim},
	}
	svc := &SocialAuthService{userRepo: users, roleRepo: fakeRoleRepo{}}

	got, err := svc.resolveUserForFederation(
		context.Background(),
		googleProvider(tenantID),
		map[string]interface{}{"email": "victim@company.com", "sub": "attacker-subject-999"},
		nil, // no linked federated account — first-time federation
	)

	if !errors.Is(err, ErrSocialAccountExists) {
		t.Fatalf("expected ErrSocialAccountExists, got user=%v err=%v", got, err)
	}
	if got != nil {
		t.Fatalf("ACCOUNT TAKEOVER: returned an existing account %q for an unlinked identity", got.Email)
	}
	if len(users.created) != 0 {
		t.Fatalf("expected no user creation on refusal, created %d", len(users.created))
	}
}

// DIRECTION 2 — a returning user linked by provider subject must still sign in.
func TestResolveUserForFederation_LinkedSubjectStillResolves(t *testing.T) {
	tenantID := uuid.New()
	returning := &models.User{ID: uuid.New(), TenantID: tenantID, Email: "returning@company.com"}

	users := &fakeUserRepo{
		byEmail: map[string]*models.User{"returning@company.com": returning},
		byID:    map[uuid.UUID]*models.User{returning.ID: returning},
	}
	svc := &SocialAuthService{userRepo: users, roleRepo: fakeRoleRepo{}}

	fed := &models.FederatedAccount{UserID: returning.ID}

	got, err := svc.resolveUserForFederation(
		context.Background(),
		googleProvider(tenantID),
		map[string]interface{}{"email": "returning@company.com", "sub": "known-subject-123"},
		fed,
	)

	if err != nil {
		t.Fatalf("returning federated user must still sign in, got err=%v", err)
	}
	if got == nil || got.ID != returning.ID {
		t.Fatalf("expected the linked user %v, got %v", returning.ID, got)
	}
}

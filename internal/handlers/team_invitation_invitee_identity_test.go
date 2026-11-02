// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

type fakeAccountReader struct{ user *models.User }

func (f fakeAccountReader) GetByID(context.Context, uuid.UUID) (*models.User, error) {
	return f.user, nil
}

type fakeProof struct {
	has   bool
	calls int
}

func (f *fakeProof) HasCompletedSignupForUser(context.Context, uuid.UUID, string) (bool, error) {
	f.calls++
	return f.has, nil
}

type fakeOwners struct{ n int }

func (f fakeOwners) CountAccountsByEmail(context.Context, string) (int, error) { return f.n, nil }

func identityFor(u *models.User, proof *fakeProof, owners int) repositoryInviteeIdentity {
	return repositoryInviteeIdentity{repo: fakeAccountReader{user: u}, proof: proof, owner: fakeOwners{n: owners}}
}

func verifiedUser() *models.User {
	return &models.User{ID: uuid.New(), Email: "Jane@Example.test", IsEmailVerified: true}
}

// The signed-in "my invitations" flow trusts a mailbox only with first-party
// proof; is_email_verified alone is written by admins and external IdPs too.
func TestInviteeIdentity_VerifiedEmailRequiresFirstPartyProof(t *testing.T) {
	ctx := context.Background()
	ldap := "ldap"
	empty := ""

	t.Run("completed self-service signup, single owner", func(t *testing.T) {
		u := verifiedUser()
		_, ok, err := identityFor(u, &fakeProof{has: true}, 1).VerifiedEmail(ctx, u.ID)
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("flag set by a tenant admin (force verify): no signup proof", func(t *testing.T) {
		u := verifiedUser()
		_, ok, err := identityFor(u, &fakeProof{has: false}, 1).VerifiedEmail(ctx, u.ID)
		require.NoError(t, err)
		assert.False(t, ok)
	})
	t.Run("federated account (LDAP/SAML/social asserted the flag)", func(t *testing.T) {
		u := verifiedUser()
		u.FederationType = &ldap
		proof := &fakeProof{has: true}
		_, ok, err := identityFor(u, proof, 1).VerifiedEmail(ctx, u.ID)
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Zero(t, proof.calls, "refused before looking for proof")
	})
	t.Run("empty federation type counts as local", func(t *testing.T) {
		u := verifiedUser()
		u.FederationType = &empty
		_, ok, err := identityFor(u, &fakeProof{has: true}, 1).VerifiedEmail(ctx, u.ID)
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("same email in another tenant", func(t *testing.T) {
		u := verifiedUser()
		_, ok, err := identityFor(u, &fakeProof{has: true}, 2).VerifiedEmail(ctx, u.ID)
		require.NoError(t, err)
		assert.False(t, ok)
	})
	t.Run("flag not set", func(t *testing.T) {
		u := verifiedUser()
		u.IsEmailVerified = false
		_, ok, err := identityFor(u, &fakeProof{has: true}, 1).VerifiedEmail(ctx, u.ID)
		require.NoError(t, err)
		assert.False(t, ok)
	})
	t.Run("proof source not wired fails closed", func(t *testing.T) {
		u := verifiedUser()
		id := repositoryInviteeIdentity{repo: fakeAccountReader{user: u}}
		_, ok, err := id.VerifiedEmail(ctx, u.ID)
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

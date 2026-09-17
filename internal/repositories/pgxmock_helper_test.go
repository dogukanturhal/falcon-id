// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

// pgxmock_helper_test.go provides test constructor functions that inject a
// pgxmock.PgxPoolIface instead of a real *pgxpool.Pool.
//
// Since the repository structs now use the DBTX interface (defined in dbtx.go),
// and pgxmock.PgxPoolIface satisfies DBTX, we can assign the mock directly
// to the unexported field from within the same package.

import (
	"github.com/pashagolub/pgxmock/v4"
)

// anyArgs returns n AnyArg() matchers, useful for ExpectExec/ExpectQuery
// where we don't want to pin exact argument values.
func anyArgs(n int) []interface{} {
	args := make([]interface{}, n)
	for i := range args {
		args[i] = pgxmock.AnyArg()
	}
	return args
}

// newDeviceRepositoryWithMock creates a DeviceRepository backed by a pgxmock pool.
func newDeviceRepositoryWithMock(mock pgxmock.PgxPoolIface) *DeviceRepository {
	return &DeviceRepository{db: mock}
}

// newImpersonationRepositoryWithMock creates an ImpersonationRepository backed by a pgxmock pool.
func newImpersonationRepositoryWithMock(mock pgxmock.PgxPoolIface) *ImpersonationRepository {
	return &ImpersonationRepository{db: mock}
}

// newDelegationRepositoryWithMock creates a DelegationRepository backed by a pgxmock pool.
func newDelegationRepositoryWithMock(mock pgxmock.PgxPoolIface) *DelegationRepository {
	return &DelegationRepository{db: mock}
}

// newWebhookRepositoryWithMock creates a WebhookRepository backed by a pgxmock pool.
func newWebhookRepositoryWithMock(mock pgxmock.PgxPoolIface) *WebhookRepository {
	return &WebhookRepository{pool: mock}
}

// newMagicLinkRepositoryWithMock creates a MagicLinkRepository backed by a pgxmock pool.
func newMagicLinkRepositoryWithMock(mock pgxmock.PgxPoolIface) *MagicLinkRepository {
	return &MagicLinkRepository{db: mock}
}

// newAPIKeyRepositoryWithMock creates an APIKeyRepository backed by a pgxmock pool.
func newAPIKeyRepositoryWithMock(mock pgxmock.PgxPoolIface) *APIKeyRepository {
	return &APIKeyRepository{pool: mock}
}

// newServiceAccountRepositoryWithMock creates a ServiceAccountRepository backed by a pgxmock pool.
func newServiceAccountRepositoryWithMock(mock pgxmock.PgxPoolIface) *ServiceAccountRepository {
	return &ServiceAccountRepository{pool: mock}
}

// newRealmRepositoryWithMock creates a RealmRepository backed by a pgxmock pool.
func newRealmRepositoryWithMock(mock pgxmock.PgxPoolIface) *RealmRepository {
	return &RealmRepository{db: mock}
}

// newOrganizationRepositoryWithMock creates an OrganizationRepository backed by a pgxmock pool.
func newOrganizationRepositoryWithMock(mock pgxmock.PgxPoolIface) *OrganizationRepository {
	return &OrganizationRepository{pool: mock}
}

// newIPRuleRepositoryWithMock creates an IPRuleRepository backed by a pgxmock pool.
func newIPRuleRepositoryWithMock(mock pgxmock.PgxPoolIface) *IPRuleRepository {
	return &IPRuleRepository{pool: mock}
}

// newPasswordPolicyRepositoryWithMock creates a PasswordPolicyRepository backed by a pgxmock pool.
func newPasswordPolicyRepositoryWithMock(mock pgxmock.PgxPoolIface) *PasswordPolicyRepository {
	return &PasswordPolicyRepository{db: mock}
}

// newMFARepositoryWithMock creates an MFARepository backed by a pgxmock pool.
func newMFARepositoryWithMock(mock pgxmock.PgxPoolIface) *MFARepository {
	return &MFARepository{db: mock}
}

// newPermissionRepositoryWithMock creates a PermissionRepository backed by a pgxmock pool.
func newPermissionRepositoryWithMock(mock pgxmock.PgxPoolIface) *PermissionRepository {
	return &PermissionRepository{db: mock}
}

// newOAuthClientRepositoryWithMock creates an OAuthClientRepository backed by a pgxmock pool.
func newOAuthClientRepositoryWithMock(mock pgxmock.PgxPoolIface) *OAuthClientRepository {
	return &OAuthClientRepository{pool: mock}
}

// newApplicationRepositoryWithMock creates an ApplicationRepository backed by a pgxmock pool.
func newApplicationRepositoryWithMock(mock pgxmock.PgxPoolIface) *ApplicationRepository {
	return &ApplicationRepository{pool: mock}
}

// newIdentityProviderRepositoryWithMock creates an IdentityProviderRepository backed by a pgxmock pool.
func newIdentityProviderRepositoryWithMock(mock pgxmock.PgxPoolIface) *IdentityProviderRepository {
	return &IdentityProviderRepository{db: mock}
}

// newFederatedAccountRepositoryWithMock creates a FederatedAccountRepository backed by a pgxmock pool.
func newFederatedAccountRepositoryWithMock(mock pgxmock.PgxPoolIface) *FederatedAccountRepository {
	return &FederatedAccountRepository{db: mock}
}


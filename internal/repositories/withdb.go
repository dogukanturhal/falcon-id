// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import "github.com/jackc/pgx/v5/pgxpool"

// This file adds WithDB / WithDBPool cloning methods to every repository type
// so that a caller can swap the underlying database connection at runtime —
// for example to route a request to a dedicated realm database.
//
// Naming convention:
//   - WithDB(pool DBTX)         – for repositories whose db/pool field is of
//                                  type DBPool (= DBTX interface).
//   - WithDBPool(pool *pgxpool.Pool) – for repositories whose field holds the
//                                       concrete *pgxpool.Pool type.
//
// All methods return a shallow clone so the original repository is untouched.

// ---------------------------------------------------------------------------
// Repositories with db DBPool field
// ---------------------------------------------------------------------------

// WithDB returns a shallow clone of UserRepository using the given pool.
func (r *UserRepository) WithDB(pool DBTX) *UserRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of RoleRepository using the given pool.
func (r *RoleRepository) WithDB(pool DBTX) *RoleRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDBPool returns a shallow clone of SessionRepository using the given pool.
func (r *SessionRepository) WithDBPool(pool *pgxpool.Pool) *SessionRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of TokenRepository using the given pool.
func (r *TokenRepository) WithDB(pool DBTX) *TokenRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of TenantRepository using the given pool.
func (r *TenantRepository) WithDB(pool DBTX) *TenantRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of RealmRepository using the given pool.
func (r *RealmRepository) WithDB(pool DBTX) *RealmRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of ConsentRepository using the given pool.
func (r *ConsentRepository) WithDB(pool DBTX) *ConsentRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of DelegationRepository using the given pool.
func (r *DelegationRepository) WithDB(pool DBTX) *DelegationRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of DeviceRepository using the given pool.
func (r *DeviceRepository) WithDB(pool DBTX) *DeviceRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of ImpersonationRepository using the given pool.
func (r *ImpersonationRepository) WithDB(pool DBTX) *ImpersonationRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of InvitationRepository using the given pool.
func (r *InvitationRepository) WithDB(pool DBTX) *InvitationRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of MagicLinkRepository using the given pool.
func (r *MagicLinkRepository) WithDB(pool DBTX) *MagicLinkRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of MFARepository using the given pool.
func (r *MFARepository) WithDB(pool DBTX) *MFARepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of PasswordPolicyRepository using the given pool.
func (r *PasswordPolicyRepository) WithDB(pool DBTX) *PasswordPolicyRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of PermissionRepository using the given pool.
func (r *PermissionRepository) WithDB(pool DBTX) *PermissionRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// ---------------------------------------------------------------------------
// Repositories with pool DBPool field
// ---------------------------------------------------------------------------

// WithDB returns a shallow clone of APIKeyRepository using the given pool.
func (r *APIKeyRepository) WithDB(pool DBTX) *APIKeyRepository {
	clone := *r
	clone.pool = pool
	return &clone
}

// WithDB returns a shallow clone of GroupRepository using the given pool.
func (r *GroupRepository) WithDB(pool DBTX) *GroupRepository {
	clone := *r
	clone.pool = pool
	return &clone
}

// WithDB returns a shallow clone of IPRuleRepository using the given pool.
func (r *IPRuleRepository) WithDB(pool DBTX) *IPRuleRepository {
	clone := *r
	clone.pool = pool
	return &clone
}

// WithDB returns a shallow clone of OrganizationRepository using the given pool.
func (r *OrganizationRepository) WithDB(pool DBTX) *OrganizationRepository {
	clone := *r
	clone.pool = pool
	return &clone
}

// WithDB returns a shallow clone of ServiceAccountRepository using the given pool.
func (r *ServiceAccountRepository) WithDB(pool DBTX) *ServiceAccountRepository {
	clone := *r
	clone.pool = pool
	return &clone
}

// WithDB returns a shallow clone of WebhookRepository using the given pool.
func (r *WebhookRepository) WithDB(pool DBTX) *WebhookRepository {
	clone := *r
	clone.pool = pool
	return &clone
}

// ---------------------------------------------------------------------------
// Repositories with concrete *pgxpool.Pool field
// ---------------------------------------------------------------------------

// WithDBPool returns a shallow clone of SettingsRepository using the given pool.
func (r *SettingsRepository) WithDBPool(pool *pgxpool.Pool) *SettingsRepository {
	clone := *r
	clone.pool = pool
	return &clone
}

// WithDBPool returns a shallow clone of LicenseRepository using the given pool.
func (r *LicenseRepository) WithDBPool(pool *pgxpool.Pool) *LicenseRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDBPool returns a shallow clone of ProductRepository using the given pool.
func (r *ProductRepository) WithDBPool(pool *pgxpool.Pool) *ProductRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDBPool returns a shallow clone of AppRegistrationRepository using the given pool.
func (r *AppRegistrationRepository) WithDBPool(pool *pgxpool.Pool) *AppRegistrationRepository {
	clone := *r
	clone.db = pool
	return &clone
}

// WithDB returns a shallow clone of IAMDevicesRepository using the given pool.
func (r *IAMDevicesRepository) WithDB(pool DBTX) *IAMDevicesRepository {
	clone := *r
	clone.pool = pool
	return &clone
}

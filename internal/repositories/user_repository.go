// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/authorization"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/sessionsweep"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const msgFailedDecryptPII = "failed to decrypt PII: %w"

// Explicit session end reasons written by deactivation paths.
const (
	sessionEndUserDeactivated       = "user_deactivated"
	sessionEndEmployeeAccessExpired = "employee_access_expired"
)

// revokeUserOAuthTokensTx revokes every live OAuth token of the user inside tx.
func revokeUserOAuthTokensTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE iam_oauth_tokens SET is_revoked = true, revoked_at = NOW(), updated_at = NOW()
		WHERE user_id = $1 AND is_revoked = false`, userID)
	return err
}

var (
	ErrTeamTargetNotFound    = errors.New("team target not found")
	ErrTeamActorNotActive    = errors.New("team actor is not active in tenant")
	ErrTeamTargetPriority    = errors.New("target has equal or higher role priority")
	ErrTeamLastAdministrator = errors.New("cannot remove the last active tenant administrator")
	ErrTeamSelfDeactivation  = errors.New("cannot deactivate yourself")
)

// UserRepository is an exported type.
type UserRepository struct {
	db                DBPool
	encryptionService *crypto.EncryptionService
	realmID           *uuid.UUID
}

// WithRealmID returns a shallow clone of UserRepository scoped to the given realm.
func (r *UserRepository) WithRealmID(realmID uuid.UUID) *UserRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// userColumns defines the standard column list for user queries
const userColumns = `id, tenant_id, realm_id, username, email, email_hash, password_hash, first_name, last_name, display_name, phone, department, title, avatar_url,
	federation_type, federation_id, federation_source,
	is_active, is_email_verified, is_locked, lock_reason, locked_at, locked_until,
	mfa_enabled, mfa_secret, mfa_type, mfa_totp_enabled, mfa_email_enabled, mfa_preferred_method,
	mfa_enrollment_first_prompted_at, mfa_enrollment_deadline, mfa_enrollment_skip_count,
	password_changed_at, must_change_password, failed_login_attempts, last_failed_login_at,
	last_login_at, last_login_ip, created_at, updated_at, created_by, updated_by`

// NewUserRepository is an exported function.
func NewUserRepository(db DBPool) *UserRepository {
	return &UserRepository{
		db:                db,
		encryptionService: nil,
	}
}

// scanUser scans a database row into a User struct
func scanUser(row pgx.Row) (*models.User, error) {
	user := &models.User{}
	err := row.Scan(
		&user.ID, &user.TenantID, &user.RealmID, &user.Username, &user.Email, &user.EmailHash, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.DisplayName, &user.Phone, &user.Department, &user.Title, &user.AvatarURL,
		&user.FederationType, &user.FederationID, &user.FederationSource,
		&user.IsActive, &user.IsEmailVerified, &user.IsLocked, &user.LockReason, &user.LockedAt, &user.LockedUntil,
		&user.MFAEnabled, &user.MFASecret, &user.MFAType, &user.MFATOTPEnabled, &user.MFAEmailEnabled, &user.MFAPreferredMethod,
		&user.MFAEnrollmentFirstPromptedAt, &user.MFAEnrollmentDeadline, &user.MFAEnrollmentSkipCount,
		&user.PasswordChangedAt, &user.MustChangePassword, &user.FailedLoginAttempts, &user.LastFailedLoginAt,
		&user.LastLoginAt, &user.LastLoginIP, &user.CreatedAt, &user.UpdatedAt, &user.CreatedBy, &user.UpdatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("scanUser: %w", err)
	}
	return user, nil
}

// scanUserRow is a helper for scanning a row from pgx.Rows
func (r *UserRepository) scanUserRow(rows pgx.Rows) (*models.User, error) {
	user := &models.User{}
	err := rows.Scan(
		&user.ID, &user.TenantID, &user.RealmID, &user.Username, &user.Email, &user.EmailHash, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.DisplayName, &user.Phone, &user.Department, &user.Title, &user.AvatarURL,
		&user.FederationType, &user.FederationID, &user.FederationSource,
		&user.IsActive, &user.IsEmailVerified, &user.IsLocked, &user.LockReason, &user.LockedAt, &user.LockedUntil,
		&user.MFAEnabled, &user.MFASecret, &user.MFAType, &user.MFATOTPEnabled, &user.MFAEmailEnabled, &user.MFAPreferredMethod,
		&user.MFAEnrollmentFirstPromptedAt, &user.MFAEnrollmentDeadline, &user.MFAEnrollmentSkipCount,
		&user.PasswordChangedAt, &user.MustChangePassword, &user.FailedLoginAttempts, &user.LastFailedLoginAt,
		&user.LastLoginAt, &user.LastLoginIP, &user.CreatedAt, &user.UpdatedAt, &user.CreatedBy, &user.UpdatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("scanUserRow: %w", err)
	}
	return user, nil
}

// SetEncryptionService wires the encryption service for PII encryption
func (r *UserRepository) SetEncryptionService(encryptionService *crypto.EncryptionService) {
	r.encryptionService = encryptionService
}

// emailHashKey is the HMAC key used for computing email hashes.
// It must be initialized via SetEmailHashKey before the service starts.
// There is no default: an empty key is rejected by RequireEmailHashKey so
// that misconfigured deployments fail fast rather than silently hashing with
// a weak, well-known value.
var emailHashKey []byte

// SetEmailHashKey configures the HMAC key for email hashing.
// Call this at startup with a key loaded from Vault or the config.
// NOTE: Changing the key will invalidate existing email_hash values in the database.
func SetEmailHashKey(key string) {
	emailHashKey = []byte(key)
}

// RequireEmailHashKey validates that the email hash key has been configured.
// Returns an error if the key is empty (not set via SetEmailHashKey).
// Call this during startup to enforce fail-fast in production.
func RequireEmailHashKey() error {
	if len(emailHashKey) == 0 {
		return fmt.Errorf("EMAIL_HASH_KEY is required but not configured — call SetEmailHashKey() before starting the service")
	}
	return nil
}

// EmailLookupHash is the exported form of computeEmailHash, for operator
// search by exact email (iam_users.email_hash is the only indexed email key).
func EmailLookupHash(email string) string { return computeEmailHash(email) }

// computeEmailHash computes a deterministic HMAC-SHA256 hash of the normalized email.
// HMAC is used instead of bare SHA-256 to prevent rainbow-table attacks.
// The email is normalized (lowercased and trimmed) before hashing to ensure
// case-insensitive matching.
func computeEmailHash(email string) string {
	normalized := strings.ToLower(strings.TrimSpace(email))
	mac := hmac.New(sha256.New, emailHashKey)
	mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil))
}

// Create is an exported function.
func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO iam_users (
			id, tenant_id, realm_id, username, email, email_hash, password_hash, first_name, last_name, display_name, phone, department, title,
			federation_type, federation_id, federation_source, is_active, mfa_enabled, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
		) RETURNING created_at, updated_at`

	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}

	if user.RealmID == uuid.Nil {
		return fmt.Errorf("realm_id is required: resolve tenant realm before creating user")
	}

	// Compute email hash before encryption for efficient lookups
	user.EmailHash = computeEmailHash(user.Email)

	// GDPR Article 32: Encrypt PII before storing
	if err := r.encryptPII(user); err != nil {
		return fmt.Errorf("failed to encrypt PII: %w", err)
	}

	if err := r.db.QueryRow(ctx, query,
		user.ID, user.TenantID, user.RealmID, user.Username, user.Email, user.EmailHash, user.PasswordHash,
		user.FirstName, user.LastName, user.DisplayName, user.Phone, user.Department, user.Title,
		user.FederationType, user.FederationID, user.FederationSource,
		user.IsActive, user.MFAEnabled, user.CreatedBy,
	).Scan(&user.CreatedAt, &user.UpdatedAt); err != nil {
		return err
	}

	// Decrypt PII back so the caller always receives plaintext fields.
	// encryptPII mutates the struct in-place; without this the caller
	// (e.g. LDAP findOrCreateUser) would return encrypted ciphertext
	// all the way up to the API response.
	return r.decryptPII(user)
}

// GetByID is an exported function.
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := fmt.Sprintf("SELECT %s FROM iam_users WHERE id = $1", userColumns)

	user, err := scanUser(r.db.QueryRow(ctx, query, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}

	// GDPR Article 32: Decrypt PII after reading from database
	if err := r.decryptPII(user); err != nil {
		return nil, fmt.Errorf(msgFailedDecryptPII, err)
	}

	return user, nil
}

// GetByIDInTenant reads a user on a transaction with the tenant RLS GUC set.
// Internal S2S routes derive their tenant from a path parameter after the
// request-level RLS transaction has been opened, so their repository work must
// establish its own scoped transaction.
func (r *UserRepository) GetByIDInTenant(ctx context.Context, tenantID, userID uuid.UUID) (*models.User, error) {
	var user *models.User
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		var err error
		user, err = r.WithDB(tx).GetByID(ctx, userID)
		if err != nil || user == nil {
			return err
		}
		if user.TenantID != tenantID {
			user = nil
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("GetByIDInTenant: %w", err)
	}
	return user, nil
}

// GetByUsername is an exported function.
func (r *UserRepository) GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error) {
	query := fmt.Sprintf("SELECT %s FROM iam_users WHERE tenant_id = $1 AND username = $2", userColumns)

	user, err := scanUser(r.db.QueryRow(ctx, query, tenantID, username))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByUsername: %w", err)
	}

	// Decrypt PII after reading
	if err := r.decryptPII(user); err != nil {
		return nil, fmt.Errorf(msgFailedDecryptPII, err)
	}

	return user, nil
}

// GetByEmail is an exported function.
func (r *UserRepository) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error) {
	// Use email_hash for efficient lookup instead of scanning all users.
	// This provides O(1) lookup via index instead of O(n) table scan with decryption.
	emailHash := computeEmailHash(email)

	query := fmt.Sprintf("SELECT %s FROM iam_users WHERE tenant_id = $1 AND email_hash = $2", userColumns)

	user, err := scanUser(r.db.QueryRow(ctx, query, tenantID, emailHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByEmail: %w", err)
	}

	// Decrypt PII after reading from database
	if err := r.decryptPII(user); err != nil {
		return nil, fmt.Errorf(msgFailedDecryptPII, err)
	}

	// Verify the decrypted email matches (defense in depth against hash collisions)
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	decryptedNormalized := strings.ToLower(strings.TrimSpace(user.Email))
	if decryptedNormalized != normalizedEmail {
		return nil, nil
	}

	return user, nil
}

// GetByEmailInTenant is the RLS-scoped equivalent for S2S callers that do not
// carry an X-Tenant-ID header through request middleware.
func (r *UserRepository) GetByEmailInTenant(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error) {
	var user *models.User
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		var err error
		user, err = r.WithDB(tx).GetByEmail(ctx, tenantID, email)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("GetByEmailInTenant: %w", err)
	}
	return user, nil
}

// GetByEmailGlobal finds a user by email across all tenants (for login without tenant context).
//
// The query intentionally does NOT filter on is_active. The caller (typically
// DiscoverService) inspects user.IsActive and decides how to route the
// response — an inactive but real user receives auth_method=contact_admin
// from the login UI rather than the misleading "user not found / signup"
// flow that filtering here would produce. See discover_service.go.
func (r *UserRepository) GetByEmailGlobal(ctx context.Context, email string) (*models.User, error) {
	// Use email_hash for efficient lookup across all tenants.
	// This provides O(1) lookup via index instead of O(n) table scan with decryption.
	emailHash := computeEmailHash(email)

	query := fmt.Sprintf("SELECT %s FROM iam_users WHERE email_hash = $1 LIMIT 1", userColumns)

	user, err := scanUser(r.db.QueryRow(ctx, query, emailHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByEmailGlobal: %w", err)
	}

	// Decrypt PII after reading from database
	if err := r.decryptPII(user); err != nil {
		return nil, fmt.Errorf(msgFailedDecryptPII, err)
	}

	// Verify the decrypted email matches (defense in depth against hash collisions)
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	decryptedNormalized := strings.ToLower(strings.TrimSpace(user.Email))
	if decryptedNormalized != normalizedEmail {
		return nil, nil
	}

	return user, nil
}

// GetByFederationID is an exported function.
func (r *UserRepository) GetByFederationID(ctx context.Context, federationType, federationID string) (*models.User, error) {
	query := fmt.Sprintf("SELECT %s FROM iam_users WHERE federation_type = $1 AND federation_id = $2", userColumns)

	user, err := scanUser(r.db.QueryRow(ctx, query, federationType, federationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByFederationID: %w", err)
	}

	// Decrypt PII
	if err := r.decryptPII(user); err != nil {
		return nil, fmt.Errorf(msgFailedDecryptPII, err)
	}

	return user, nil
}

// GetByFederationSource returns all active users federated from a specific source
func (r *UserRepository) GetByFederationSource(ctx context.Context, federationType, federationSource string) ([]models.User, error) {
	query := fmt.Sprintf("SELECT %s FROM iam_users WHERE federation_type = $1 AND federation_source = $2 AND is_active = true", userColumns)

	rows, err := r.db.Query(ctx, query, federationType, federationSource)
	if err != nil {
		return nil, fmt.Errorf("GetByFederationSource: %w", err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		user, err := r.scanUserRow(rows)
		if err != nil {
			return nil, fmt.Errorf("GetByFederationSource: scanUserRow failed: %w", err)
		}

		// Decrypt PII for each user
		if err := r.decryptPII(user); err != nil {
			return nil, fmt.Errorf("failed to decrypt PII for user %s: %w", user.ID, err)
		}

		users = append(users, *user)
	}
	return users, rows.Err()
}

// Update is an exported function.
func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	// Defensive SQL-level guard against partial-struct wipes.
	//
	// `Update` is a write-all-columns SQL — every column listed below is
	// unconditionally set from the inbound struct. Historically this has
	// caused two production data-corruption incidents:
	//
	//   - 2026-05-12: a partial *models.User (only ID/TenantID/Username)
	//     passed by a mfa-flip caller wiped the row's Email + computed
	//     a constant email_hash from "".
	//   - 2026-05-23: webauthn FinishRegistration passed a *models.User
	//     built from JWT context (only ID/TenantID/Username/Email) and
	//     wiped IsActive + IsEmailVerified + PasswordHash, locking the
	//     user out via the discover-flow "Restricted access" branch.
	//
	// Both were caller-side mistakes; both fixes landed at the call
	// site. This guard is the durable repository-layer defense so the
	// class of bug cannot recur regardless of future caller patterns.
	//
	// Sentinel: an empty `user.Email` ('') means "the caller didn't
	// carry the full row — preserve PII-and-auth-state columns". A
	// caller that genuinely wants to ERASE a user's email (GDPR Article
	// 17 right-to-be-forgotten) MUST use the dedicated EraseUserPII
	// method (TODO: add when needed); piggybacking erasure on Update
	// would re-introduce the ambiguity this guard closes.
	//
	// Boolean fields (is_active, is_email_verified, password_hash) are
	// tied to the same empty-email sentinel because boolean Go zero
	// values (false) are indistinguishable from "caller meant false".
	// The empty-email check is a proxy for "caller passed a partial
	// struct" — when it fires, every column that would surprise a user
	// to find wiped is preserved.
	query := `
		UPDATE iam_users SET
			email             = CASE WHEN $2::text  = '' THEN email             ELSE $2  END,
			email_hash        = CASE WHEN $2::text  = '' THEN email_hash        ELSE $3  END,
			first_name        = CASE WHEN $2::text  = '' THEN first_name        ELSE $4  END,
			last_name         = CASE WHEN $2::text  = '' THEN last_name         ELSE $5  END,
			display_name      = CASE WHEN $2::text  = '' THEN display_name      ELSE $6  END,
			phone             = CASE WHEN $2::text  = '' THEN phone             ELSE $7  END,
			department = $8, title = $9, avatar_url = $10,
			is_active         = CASE WHEN $2::text  = '' THEN is_active         ELSE $11 END,
			is_email_verified = CASE WHEN $2::text  = '' THEN is_email_verified ELSE $12 END,
			is_locked = $13, lock_reason = $14, locked_at = $15, locked_until = $16,
			mfa_enabled = $17, mfa_secret = $18, mfa_type = $19, mfa_totp_enabled = $20, mfa_email_enabled = $21, mfa_preferred_method = $22,
			password_hash         = CASE WHEN $2::text = '' THEN password_hash         ELSE $23 END,
			password_changed_at   = CASE WHEN $2::text = '' THEN password_changed_at   ELSE $24 END,
			must_change_password  = CASE WHEN $2::text = '' THEN must_change_password  ELSE $25 END,
			failed_login_attempts = $26, last_failed_login_at = $27,
			last_login_at = $28, last_login_ip = $29, updated_by = $30
		WHERE id = $1
		RETURNING updated_at`

	// Compute email hash before encryption for efficient lookups.
	//
	// CRITICAL: skip the recomputation when user.Email is empty.
	//
	// Why: callers (mfa_enrollment_service, webauthn_service finish-registration,
	// mfa_service factor flips, etc.) routinely load a user, flip an
	// unrelated boolean like MFAEnabled, and call Update — they don't
	// touch user.Email. If the in-memory user.Email is empty at that point
	// (because scanUser returned an empty value, or because PII decryption
	// silently zeroed it out, or because the field was never populated by
	// the caller's intermediate code path), the unguarded call
	// `user.EmailHash = computeEmailHash(user.Email)` rewrites the stored
	// hash to HMAC-SHA256(emailHashKey, "") — a deterministic constant
	// shared by EVERY user that hits this path. The user's row then
	// becomes unfindable by their actual email (UserRepository.GetByEmail
	// and GetByEmailGlobal both look up by email_hash), so the login
	// discover flow returns "email_known: false" and the login UI shows
	// "no account found" even though the row exists. Live regression
	// signature: row with email='' and email_hash equal to
	// b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad
	// (= HMAC-SHA256(empty key, empty input)).
	//
	// The guard keeps the existing hash when the caller isn't carrying
	// the email. The "real" email-change path (UserService.Update with a
	// non-empty new email, or admin email-change endpoints) sets
	// user.Email to the new value BEFORE invoking this method, so the
	// recomputation fires correctly for those flows.
	if user.Email != "" {
		user.EmailHash = computeEmailHash(user.Email)
	}

	// GDPR Article 32: Encrypt PII before updating
	if err := r.encryptPII(user); err != nil {
		return fmt.Errorf("failed to encrypt PII: %w", err)
	}

	if err := r.db.QueryRow(ctx, query,
		user.ID, user.Email, user.EmailHash, user.FirstName, user.LastName, user.DisplayName, user.Phone, user.Department, user.Title, user.AvatarURL,
		user.IsActive, user.IsEmailVerified, user.IsLocked, user.LockReason, user.LockedAt, user.LockedUntil,
		user.MFAEnabled, user.MFASecret, user.MFAType, user.MFATOTPEnabled, user.MFAEmailEnabled, user.MFAPreferredMethod,
		user.PasswordHash, user.PasswordChangedAt, user.MustChangePassword,
		user.FailedLoginAttempts, user.LastFailedLoginAt,
		user.LastLoginAt, user.LastLoginIP, user.UpdatedBy,
	).Scan(&user.UpdatedAt); err != nil {
		return err
	}

	// Decrypt PII back so the caller always receives plaintext fields.
	// encryptPII mutates the struct in-place; without this the caller
	// (e.g. LDAP findOrCreateUser, updateUserLoginInfo) would hold
	// encrypted ciphertext that leaks into API responses.
	return r.decryptPII(user)
}

// MigrateRealm reassigns a user's realm_id from fromRealmID to toRealmID
// atomically. Used by the cmd/migrate-user-realm CLI for one-off operator-
// driven realm migrations — e.g. Sprint-1 #5 (FI!135 created the bootstrap
// admin in WellKnownRealmShared instead of WellKnownRealmPlatform).
//
// Why a dedicated method (and not Update + struct mutation):
//
//   - Update() deliberately omits realm_id from its column list because
//     realm migration is a security-relevant scope change that should
//     happen through an explicit, auditable code path — not as a side
//     effect of a generic profile edit.
//   - This method's atomic WHERE-clause guards (tenant_id + from_realm_id)
//     defend against concurrent edits and against running the migration
//     twice (RowsAffected=0 on second run is a deterministic signal).
//   - The dedicated SQL keeps `realm_id` updates limited to this method
//     so future audit hooks (separate MR) can wire to it directly without
//     adding fan-out detection in Update().
//
// Validation responsibilities:
//
//   - Caller MUST verify the target realm exists (repos.Realm.GetByID)
//     before calling. The underlying FK constraint would catch a missing
//     realm but the application error surfaces clearer with a pre-check.
//   - Caller is responsible for emitting an audit log entry through the
//     audit service. This method handles the data change only.
//
// Returns:
//
//   - nil when exactly one row was updated.
//   - error when zero rows match (user not found in the from-realm —
//     could mean the migration already ran, the user is in a different
//     realm, or the user-tenant pair doesn't exist).
//   - error when >1 rows match (would indicate a primary-key uniqueness
//     violation — should never happen and is a hard fail).
func (r *UserRepository) MigrateRealm(
	ctx context.Context,
	userID uuid.UUID,
	tenantID uuid.UUID,
	fromRealmID uuid.UUID,
	toRealmID uuid.UUID,
	migratedBy *uuid.UUID,
) error {
	result, err := r.db.Exec(ctx,
		`UPDATE iam_users
		 SET realm_id = $4, updated_by = $5, updated_at = NOW()
		 WHERE id = $1 AND tenant_id = $2 AND realm_id = $3`,
		userID, tenantID, fromRealmID, toRealmID, migratedBy,
	)
	if err != nil {
		return fmt.Errorf("MigrateRealm: %w", err)
	}
	rows := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf(
			"MigrateRealm: no rows updated — user %s not found in tenant %s with realm %s (migration may have already run, or user is in a different realm)",
			userID, tenantID, fromRealmID,
		)
	}
	if rows > 1 {
		return fmt.Errorf(
			"MigrateRealm: unexpected RowsAffected=%d for user %s — primary-key uniqueness violated, refusing to continue",
			rows, userID,
		)
	}
	return nil
}

// LinkFederation sets the federation fields on an existing user without touching other columns.
// It only links users that are not already federated (federation_type IS NULL or empty),
// preventing accidental overwrites of existing federation bindings.
func (r *UserRepository) LinkFederation(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, federationType, federationID, federationSource string) error {
	result, err := r.db.Exec(ctx,
		`UPDATE iam_users
		 SET federation_type = $2, federation_id = $3, federation_source = $4, updated_at = NOW()
		 WHERE id = $1 AND tenant_id = $5
		   AND (federation_type IS NULL OR federation_type = '')`,
		userID, federationType, federationID, federationSource, tenantID,
	)
	if err != nil {
		return fmt.Errorf("LinkFederation: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("LinkFederation: user %s not found or already federated", userID)
	}
	return nil
}

// Delete is an exported function.
func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("Delete: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit makes rollback a no-op
	if err := r.releaseMembershipsTx(ctx, tx, id); err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM iam_users WHERE id = $1", id); err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("Delete: commit: %w", err)
	}
	return nil
}

// releaseMembershipsTx removes the user's membership rows inside tx, freeing the seat of an active member-class
// one (UserMembershipRepository.Delete). iam_user_memberships has no ON DELETE CASCADE, so the rows must go
// before the iam_users row, and the tenant is read from the user row itself.
func (r *UserRepository) releaseMembershipsTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	var tenantID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT tenant_id FROM iam_users WHERE id = $1`, userID).Scan(&tenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("lookup tenant: %w", err)
	}
	if _, err := (&UserMembershipRepository{db: tx}).Delete(ctx, tenantID, userID); err != nil {
		return fmt.Errorf("release membership: %w", err)
	}
	return nil
}

// List is an exported function.
func (r *UserRepository) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]models.User, int64, error) {
	return r.listFiltered(ctx, tenantID, page, pageSize, search, "")
}

// ListTenantHumans applies identity/status filters before both COUNT and
// pagination. "all" preserves the team management/reactivation inventory;
// "active" is the active-human view, and "inactive" is the recovery view.
// svc- is Falcon's canonical legacy service username convention (migration
// 0013 and IsSeatFree), not an email/display-name heuristic. Membership
// classification also excludes service identities with ordinary usernames.
func (r *UserRepository) ListTenantHumans(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search, status string) (users []models.User, total int64, err error) {
	if status != "all" && status != "active" && status != "inactive" {
		return nil, 0, fmt.Errorf("invalid member status")
	}
	filter := ` AND username NOT ILIKE 'svc-%'
		AND NOT EXISTS (SELECT 1 FROM iam_user_memberships m
			WHERE m.tenant_id = $1 AND m.user_id = iam_users.id AND m.seat_class = 'service')`
	active := `is_active = true AND deletion_scheduled_at IS NULL
		AND NOT EXISTS (SELECT 1 FROM iam_user_memberships m
			WHERE m.tenant_id = $1 AND m.user_id = iam_users.id AND m.status = 'deactivated')`
	if status == "active" {
		filter += " AND (" + active + ")"
	} else if status == "inactive" {
		filter += " AND NOT (" + active + ")"
	}
	err = WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		var readErr error
		users, total, readErr = r.WithDB(tx).listFiltered(ctx, tenantID, page, pageSize, search, filter)
		return readErr
	})
	return
}

func (r *UserRepository) listFiltered(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search, filter string) ([]models.User, int64, error) {
	offset := (page - 1) * pageSize

	// Count total. Excludes soft-deleted users (both the self-service
	// pending_deletion state and the admin-triggered admin_deleted state)
	// — soft-deleted users must vanish from every list/read path, per the
	// admin lifecycle requirement. Restore (cancel-deletion / admin
	// restore) flips activation_status back to "active", which is the
	// only way a user reappears here.
	const excludeDeletedClause = ` AND (activation_status IS NULL OR activation_status NOT IN ('pending_deletion', 'admin_deleted'))`
	countQuery := `SELECT COUNT(*) FROM iam_users WHERE tenant_id = $1` + excludeDeletedClause + filter
	args := []interface{}{tenantID}

	// NOTE: email, first_name, last_name are encrypted at rest (PII).
	// ILIKE cannot match against ciphertext. Only search username (plaintext)
	// and email_hash (for exact email matches).
	if search != "" {
		emailHash := computeEmailHash(search)
		countQuery += ` AND (username ILIKE $2 OR email_hash = $3)`
		args = append(args, "%"+search+"%", emailHash)
	}

	var total int64
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("List: %w", err)
	}

	// Get users — LIMIT and OFFSET are bound as parameters to prevent injection.
	query := "SELECT " + userColumns + " FROM iam_users WHERE tenant_id = $1" + excludeDeletedClause + filter

	if search != "" {
		query += ` AND (username ILIKE $2 OR email_hash = $3) ORDER BY created_at DESC LIMIT $4 OFFSET $5`
		args = append(args, pageSize, offset)
	} else {
		query += ` ORDER BY created_at DESC LIMIT $2 OFFSET $3`
		args = append(args, pageSize, offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("List: %w", err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		user, err := r.scanUserRow(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("List: scanUserRow failed: %w", err)
		}

		// Decrypt PII for each user
		if err := r.decryptPII(user); err != nil {
			return nil, 0, fmt.Errorf("failed to decrypt PII for user %s: %w", user.ID, err)
		}

		users = append(users, *user)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("List: rows iteration: %w", err)
	}

	return users, total, nil
}

// AssignRoles atomically replaces all roles for a user within a single transaction.
// SECURITY: Without a transaction, a crash between DELETE and INSERT would leave the
// user with zero roles, potentially locking them out or escalating privileges on retry.
func (r *UserRepository) AssignRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("AssignRoles: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Delete existing roles — EXCEPT a row that is a live, still-active
	// TIME-BOXED grant (expires_at in the future). Those rows are JIT/PIM
	// activations (see JITAccessService.applyRoleGrant); this bulk-replace
	// path is not JIT-aware, and previously deleted+reinserted such a row
	// WITHOUT its expires_at, silently converting a time-boxed elevation
	// into a permanent one. A JIT grant must be revoked/expired through its
	// own path (JITAccessService.RevokeGrant / ExpireGrants), never
	// incidentally by an unrelated role edit.
	if _, err := tx.Exec(ctx, "SELECT id FROM iam_users WHERE id = $1 FOR UPDATE", userID); err != nil {
		return fmt.Errorf("AssignRoles: user lock: %w", err)
	}
	err = deleteRolesWithOutbox(ctx, tx,
		"DELETE FROM iam_user_roles ur WHERE user_id = $1 AND (expires_at IS NULL OR expires_at <= NOW())",
		[]interface{}{userID}, roleIDs)
	if err != nil {
		return fmt.Errorf("AssignRoles: delete: %w", err)
	}

	// Insert new roles. ON CONFLICT DO NOTHING: a roleID that survived the
	// delete above (a live time-boxed grant) is already present — leave its
	// expires_at untouched rather than erroring or overwriting it.
	for _, roleID := range roleIDs {
		_, err := tx.Exec(ctx,
			"INSERT INTO iam_user_roles (user_id, role_id, assigned_by) VALUES ($1, $2, $3) ON CONFLICT (user_id, role_id) DO NOTHING",
			userID, roleID, assignedBy,
		)
		if err != nil {
			return fmt.Errorf("AssignRoles: insert: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("AssignRoles: commit: %w", err)
	}

	return nil
}

// ErrRoleAlreadyPermanent is returned by AddTimeBoundRole when the user already
// holds the role as a PERMANENT assignment (expires_at IS NULL). A JIT
// activation must never shorten or clobber a standing grant.
var ErrRoleAlreadyPermanent = errors.New("role already permanently assigned")

// AddTimeBoundRole additively grants a single TIME-BOXED role assignment, used
// by JIT/PIM activation (JITAccessService.applyRoleGrant). Unlike AssignRoles
// (which replaces ALL of a user's roles), this inserts one row with an
// expires_at. This row is NOT the authorization boundary — SpiceDB's
// role#member relationship is what AuthorizationEngine.CheckPermission
// actually consults — but it keeps the grant visible to the team/role picker,
// audit queries, and admin priority checks that already filter on
// iam_user_roles.expires_at. Returns the assignment id. If the user already
// holds the role permanently (expires_at IS NULL), the row is left untouched
// and ErrRoleAlreadyPermanent is returned.
func (r *UserRepository) AddTimeBoundRole(ctx context.Context, userID, roleID, assignedBy uuid.UUID, expiresAt time.Time) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx,
		`INSERT INTO iam_user_roles (user_id, role_id, assigned_by, expires_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (user_id, role_id) DO UPDATE
		   SET expires_at = EXCLUDED.expires_at, assigned_by = EXCLUDED.assigned_by
		   WHERE iam_user_roles.expires_at IS NOT NULL
		 RETURNING id`,
		userID, roleID, assignedBy, expiresAt,
	).Scan(&id)
	// A conflict where the existing row is permanent makes the DO UPDATE WHERE
	// false → no row updated → RETURNING yields nothing → ErrNoRows.
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrRoleAlreadyPermanent
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("AddTimeBoundRole: %w", err)
	}
	return id, nil
}

// RemoveTimeBoundRole deletes a user's TIME-BOXED assignment of a role (a JIT
// grant being revoked or expired). The `expires_at IS NOT NULL` guard
// guarantees a permanent assignment is never removed by this call. Idempotent
// (no error if the row is already gone).
func (r *UserRepository) RemoveTimeBoundRole(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM iam_user_roles
		 WHERE user_id = $1 AND role_id = $2 AND expires_at IS NOT NULL`,
		userID, roleID,
	)
	if err != nil {
		return fmt.Errorf("RemoveTimeBoundRole: %w", err)
	}
	return nil
}

// SoonestActiveRoleExpiry returns the earliest expires_at among the user's
// CURRENTLY-ACTIVE time-boxed role assignments (JIT/PIM grants), or nil when
// the user holds no live time-boxed roles. Used to cap an elevated access
// token's expiry to the grant that conferred the role — the token must never
// outlive it. The (user_id, role_id, expires_at) index covers this lookup.
func (r *UserRepository) SoonestActiveRoleExpiry(ctx context.Context, userID uuid.UUID) (*time.Time, error) {
	var soonest *time.Time
	err := r.db.QueryRow(ctx,
		`SELECT MIN(expires_at) FROM iam_user_roles
		 WHERE user_id = $1 AND expires_at IS NOT NULL AND expires_at > NOW()`,
		userID,
	).Scan(&soonest)
	if err != nil {
		return nil, fmt.Errorf("SoonestActiveRoleExpiry: %w", err)
	}
	return soonest, nil
}

// RequiresInvitedAdminMFA reports whether userID joined tenantID through a team
// invitation and currently holds an owner or admin role there. Those members
// must enrol a second factor at first sign-in (operator decision 2026-10-13:
// MFA is required for owner/admin, optional for everyone else). Scoped to the
// invitation path on purpose: it does not retroactively force founders and
// admins who were never invited; that policy belongs to the tenant MFA policy.
func (r *UserRepository) RequiresInvitedAdminMFA(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	var required bool
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM iam_user_memberships m
				WHERE m.tenant_id = $2 AND m.user_id = $1
					AND m.status = 'active' AND m.invitation_id IS NOT NULL
					AND EXISTS (
						SELECT 1 FROM iam_user_roles ur
						INNER JOIN iam_roles ro ON ro.id = ur.role_id
						WHERE ur.user_id = $1 AND ro.tenant_id = $2
							AND lower(ro.name) IN ('owner', 'admin')
							AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
					)
			)`, userID, tenantID).Scan(&required)
	})
	if err != nil {
		return false, fmt.Errorf("RequiresInvitedAdminMFA: %w", err)
	}
	return required, nil
}

// CountAccountsByEmail counts accounts in every tenant that share the email
// (matched on the email hash). Emails are unique per tenant only, so more than
// one means the address does not identify a single person.
func (r *UserRepository) CountAccountsByEmail(ctx context.Context, email string) (int, error) {
	var n int
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM iam_users WHERE email_hash = $1`, computeEmailHash(email)).Scan(&n); err != nil {
		return 0, fmt.Errorf("CountAccountsByEmail: %w", err)
	}
	return n, nil
}

// MarkEmailVerified records that the user proved possession of their mailbox
// (an invitation token, for people onboarded from a team invitation).
func (r *UserRepository) MarkEmailVerified(ctx context.Context, userID uuid.UUID) error {
	if _, err := r.db.Exec(ctx, `UPDATE iam_users SET is_email_verified = true, password_changed_at = COALESCE(password_changed_at, now()), updated_at = now() WHERE id = $1`, userID); err != nil {
		return fmt.Errorf("MarkEmailVerified: %w", err)
	}
	return nil
}

// GetHomeTenantID returns the user's home tenant (iam_users.tenant_id) and
// false when the user does not exist.
func (r *UserRepository) GetHomeTenantID(ctx context.Context, userID uuid.UUID) (uuid.UUID, bool, error) {
	var tenantID uuid.UUID
	err := r.db.QueryRow(ctx, `SELECT tenant_id FROM iam_users WHERE id = $1`, userID).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("GetHomeTenantID: %w", err)
	}
	return tenantID, true, nil
}

// RevokeTenantRoles removes every role grant the user holds in tenantID and
// leaves grants in any other tenant untouched. Used when an external
// (seat-free) member's access to a client tenant is revoked: the member's
// home-tenant roles must survive.
func (r *UserRepository) RevokeTenantRoles(ctx context.Context, userID, tenantID uuid.UUID) error {
	if _, err := r.db.Exec(ctx, `
		DELETE FROM iam_user_roles ur
		USING iam_roles role
		WHERE ur.role_id = role.id AND ur.user_id = $1 AND role.tenant_id = $2`,
		userID, tenantID); err != nil {
		return fmt.Errorf("RevokeTenantRoles: %w", err)
	}
	return nil
}

// GrantRoles adds role grants without replacing existing grants. It is used by
// invitation acceptance, where replacing roles would discard independently
// managed or locked grants.
func (r *UserRepository) GrantRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	for _, roleID := range roleIDs {
		if _, err := r.db.Exec(ctx, `INSERT INTO iam_user_roles (user_id, role_id, assigned_by)
			VALUES ($1, $2, $3) ON CONFLICT (user_id, role_id) DO NOTHING`, userID, roleID, assignedBy); err != nil {
			return fmt.Errorf("GrantRoles: insert: %w", err)
		}
	}
	return nil
}

// AssignRolesInTenant replaces a user's role assignments, but ONLY within
// the intersection of tenantID and allowedRoleIDs:
//
//   - allowedRoleIDs is the set of role IDs the self-service picker
//     (GET /api/v1/roles → RoleService.ListSelfService /
//     SelfServiceVisibleRoleIDs) would currently show for this tenant —
//     i.e. roles whose permissions fall in an entitled product module, or
//     roles with no permissions at all. Roles in THIS tenant that the
//     tenant isn't entitled to (e.g. a role belonging to a product module
//     never provisioned here) are NOT in this set.
//   - tenantID additionally bounds the DELETE by r.tenant_id, as defence
//     in depth in case allowedRoleIDs is ever computed for the wrong
//     tenant.
//
// Any role the user holds outside that intersection — another tenant's
// role, or a same-tenant role the picker doesn't offer because of module
// entitlement — is left untouched. Plain AssignRoles must NOT be used for
// this endpoint: its DELETE has no such scoping and would silently drop
// any such grant.
//
// roleIDs (the requested new assignment) not present in allowedRoleIDs are
// rejected outright rather than silently ignored, so a caller cannot be
// confused about what was applied.
func (r *UserRepository) AssignRolesInTenant(ctx context.Context, userID, tenantID uuid.UUID, allowedRoleIDs, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	allowed := make(map[uuid.UUID]bool, len(allowedRoleIDs))
	for _, id := range allowedRoleIDs {
		allowed[id] = true
	}
	for _, id := range roleIDs {
		if !allowed[id] {
			return fmt.Errorf("AssignRolesInTenant: role id %s is not assignable in this context", id)
		}
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("AssignRolesInTenant: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Delete only roles that are BOTH in this tenant AND in the
	// caller-supplied allow-list (self-service-visible roles); everything
	// else the user holds — cross-tenant or unentitled-module grants — is
	// preserved. Also excluded: a live, still-active TIME-BOXED grant
	// (expires_at in the future) — that is a JIT/PIM activation, and this
	// self-service path is not JIT-aware. Without the guard, a role the
	// picker happens to offer would be deleted and reinserted WITHOUT its
	// expires_at, silently converting a time-boxed elevation into a
	// permanent one. Such a grant is only revoked/expired via
	// JITAccessService.RevokeGrant / ExpireGrants.
	if _, err := tx.Exec(ctx, "SELECT id FROM iam_users WHERE id = $1 FOR UPDATE", userID); err != nil {
		return fmt.Errorf("AssignRolesInTenant: user lock: %w", err)
	}
	err = deleteRolesWithOutbox(ctx, tx,
		`DELETE FROM iam_user_roles ur
		 USING iam_roles r
		 WHERE ur.role_id = r.id AND ur.user_id = $1 AND r.tenant_id = $2 AND r.id = ANY($3)
		   AND (ur.expires_at IS NULL OR ur.expires_at <= NOW())`,
		[]interface{}{userID, tenantID, allowedRoleIDs}, roleIDs,
	)
	if err != nil {
		return fmt.Errorf("AssignRolesInTenant: delete: %w", err)
	}

	// ON CONFLICT DO NOTHING: a roleID that survived the delete above (a
	// live time-boxed grant) is already present — leave its expires_at
	// untouched rather than erroring or overwriting it.
	for _, roleID := range roleIDs {
		_, err := tx.Exec(ctx,
			"INSERT INTO iam_user_roles (user_id, role_id, assigned_by) VALUES ($1, $2, $3) ON CONFLICT (user_id, role_id) DO NOTHING",
			userID, roleID, assignedBy,
		)
		if err != nil {
			return fmt.Errorf("AssignRolesInTenant: insert: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("AssignRolesInTenant: commit: %w", err)
	}

	return nil
}

// ReplaceTeamRoles serializes tenant administration changes, retaining grants
// outside editableRoleIDs and refusing to remove the final active tenant administrator.
func (r *UserRepository) ReplaceTeamRoles(ctx context.Context, tenantID, actorID, targetID uuid.UUID, editableRoleIDs, requestedRoleIDs []uuid.UUID, audit *models.AuditLog, entitlementModules ...[]string) error {
	adminRoleNames := authorization.TenantAdministratorRoleNames()
	// Treat role sets as sets. This prevents duplicate inserts and gives one
	// unambiguous grant/audit result for an otherwise equivalent request.
	editableRoleIDs = uniqueUUIDs(editableRoleIDs)
	requestedRoleIDs = uniqueUUIDs(requestedRoleIDs)
	allowed := make(map[uuid.UUID]bool, len(editableRoleIDs))
	for _, id := range editableRoleIDs {
		allowed[id] = true
	}
	for _, id := range requestedRoleIDs {
		if !allowed[id] {
			return fmt.Errorf("ReplaceTeamRoles: role is not assignable")
		}
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("ReplaceTeamRoles: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Lock order is invariant across team mutations: tenant advisory lock,
	// actor row, target row, then role catalogue rows in UUID order. This keeps
	// authorization facts stable without a broad table lock or lock inversion.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, tenantID); err != nil {
		return fmt.Errorf("ReplaceTeamRoles: tenant lock: %w", err)
	}
	var actorActive bool
	if err := tx.QueryRow(ctx, `SELECT is_active FROM iam_users WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, actorID, tenantID).Scan(&actorActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTeamActorNotActive
		}
		return fmt.Errorf("ReplaceTeamRoles: actor: %w", err)
	}
	if !actorActive {
		return ErrTeamActorNotActive
	}
	var targetActive bool
	if err := tx.QueryRow(ctx, `SELECT is_active FROM iam_users WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, targetID, tenantID).Scan(&targetActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTeamTargetNotFound
		}
		return fmt.Errorf("ReplaceTeamRoles: target: %w", err)
	}
	// Role catalogue rows used by current grants and requested assignments must
	// not change tenant/system/priority while this transaction authorizes them.
	if _, err := tx.Exec(ctx, `SELECT r.id FROM iam_roles r WHERE r.tenant_id=$1 AND (
		r.id=ANY($2) OR r.id=ANY($3) OR EXISTS (SELECT 1 FROM iam_user_roles ur WHERE ur.role_id=r.id AND ur.user_id=ANY($4))
	) ORDER BY r.id FOR UPDATE`, tenantID, requestedRoleIDs, editableRoleIDs, []uuid.UUID{actorID, targetID}); err != nil {
		return fmt.Errorf("ReplaceTeamRoles: role catalogue lock: %w", err)
	}
	priorityQuery := `SELECT COALESCE(MAX(r.priority),0) FROM iam_roles r JOIN iam_user_roles ur ON ur.role_id=r.id WHERE ur.user_id=$1 AND r.tenant_id=$2 AND (ur.expires_at IS NULL OR ur.expires_at>NOW())`
	var actorPriority, targetPriority int
	if err := tx.QueryRow(ctx, priorityQuery, actorID, tenantID).Scan(&actorPriority); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, priorityQuery, targetID, tenantID).Scan(&targetPriority); err != nil {
		return err
	}
	if actorPriority <= targetPriority {
		return ErrTeamTargetPriority
	}
	// The handler's editable IDs are only a preflight candidate. The locked
	// catalogue is authoritative: RoleService exposes only non-system roles
	// whose priority is below the actor's effective priority.
	var candidateCount int
	var candidateLocked, candidateTooHigh bool
	if err := tx.QueryRow(ctx, `SELECT COUNT(*), COALESCE(bool_or(is_system),false), COALESCE(bool_or(priority >= $3),false)
		FROM iam_roles WHERE id=ANY($1) AND tenant_id=$2`, editableRoleIDs, tenantID, actorPriority).Scan(&candidateCount, &candidateLocked, &candidateTooHigh); err != nil {
		return err
	}
	if candidateCount != len(editableRoleIDs) || candidateLocked || candidateTooHigh {
		return fmt.Errorf("ReplaceTeamRoles: editable role candidate changed or is no longer manageable")
	}
	var requestedCount int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM iam_roles WHERE id = ANY($1) AND tenant_id = $2`, requestedRoleIDs, tenantID).Scan(&requestedCount); err != nil {
		return err
	}
	if requestedCount != len(requestedRoleIDs) {
		return fmt.Errorf("ReplaceTeamRoles: requested role does not belong to tenant")
	}
	var requestedTooHigh bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam_roles WHERE id = ANY($1) AND tenant_id=$2 AND priority >= $3)`, requestedRoleIDs, tenantID, actorPriority).Scan(&requestedTooHigh); err != nil {
		return err
	}
	if requestedTooHigh {
		return ErrTeamTargetPriority
	}
	if len(entitlementModules) > 0 {
		if _, err := tx.Exec(ctx, "LOCK TABLE iam_permissions, iam_role_permissions IN SHARE MODE"); err != nil {
			return fmt.Errorf("ReplaceTeamRoles: lock permission catalogue: %w", err)
		}
		var includesUnentitled bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM iam_role_permissions rp JOIN iam_permissions p ON p.id = rp.permission_id
			WHERE rp.role_id = ANY($1) AND NOT (p.module = ANY($2))
		)`, requestedRoleIDs, entitlementModules[0]).Scan(&includesUnentitled); err != nil {
			return fmt.Errorf("ReplaceTeamRoles: entitlement check: %w", err)
		}
		if includesUnentitled {
			return fmt.Errorf("ReplaceTeamRoles: requested role is outside tenant module entitlement")
		}
	}
	// Account for preserved grants (outside editableRoleIDs) plus proposed grants.
	var postAdmin bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam_user_roles ur JOIN iam_roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND r.tenant_id=$2 AND lower(r.name)=ANY($3) AND (ur.expires_at IS NULL OR ur.expires_at>NOW()) AND NOT (r.id = ANY($4)) UNION SELECT 1 FROM iam_roles r WHERE r.id=ANY($5) AND r.tenant_id=$2 AND lower(r.name)=ANY($3))`, targetID, tenantID, adminRoleNames, editableRoleIDs, requestedRoleIDs).Scan(&postAdmin); err != nil {
		return err
	}
	if targetActive && !postAdmin {
		var admins int
		if err := tx.QueryRow(ctx, `SELECT COUNT(DISTINCT u.id) FROM iam_users u JOIN iam_user_roles ur ON ur.user_id=u.id JOIN iam_roles r ON r.id=ur.role_id WHERE u.tenant_id=$1 AND u.is_active AND r.tenant_id=$1 AND lower(r.name)=ANY($2) AND (ur.expires_at IS NULL OR ur.expires_at>NOW())`, tenantID, adminRoleNames).Scan(&admins); err != nil {
			return err
		}
		var wasAdmin bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam_user_roles ur JOIN iam_roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND r.tenant_id=$2 AND lower(r.name)=ANY($3) AND (ur.expires_at IS NULL OR ur.expires_at>NOW()))`, targetID, tenantID, adminRoleNames).Scan(&wasAdmin); err != nil {
			return err
		}
		if wasAdmin && admins <= 1 {
			return ErrTeamLastAdministrator
		}
	}
	// Exclude a live, still-active TIME-BOXED grant (expires_at in the
	// future) from both the delete and the reinsert below — it is a
	// JIT/PIM activation, and this admin team-edit path is not JIT-aware.
	// Without the guard, an editable role the target happens to hold via an
	// active JIT grant would be deleted and reinserted WITHOUT its
	// expires_at, silently converting a time-boxed elevation into a
	// permanent one. Such a grant is only revoked/expired via
	// JITAccessService.RevokeGrant / ExpireGrants.
	if err := deleteRolesWithOutbox(ctx, tx, `DELETE FROM iam_user_roles ur USING iam_roles r WHERE ur.role_id=r.id AND ur.user_id=$1 AND r.tenant_id=$2 AND r.id=ANY($3) AND (ur.expires_at IS NULL OR ur.expires_at<=NOW())`, []interface{}{targetID, tenantID, editableRoleIDs}, requestedRoleIDs); err != nil {
		return err
	}
	for _, roleID := range requestedRoleIDs {
		// ON CONFLICT DO NOTHING: a roleID that survived the delete above
		// (a live time-boxed grant) is already present — leave its
		// expires_at untouched.
		if _, err := tx.Exec(ctx, `INSERT INTO iam_user_roles (user_id,role_id,assigned_by) VALUES ($1,$2,$3) ON CONFLICT (user_id, role_id) DO NOTHING`, targetID, roleID, &actorID); err != nil {
			return err
		}
	}
	if audit != nil {
		if err := CreateAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("ReplaceTeamRoles: audit: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func uniqueUUIDs(ids []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(ids))
	result := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result
}

// GetUserRoles is an exported function.
func (r *UserRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	query := `
		SELECT r.id, r.tenant_id, r.name, r.display_name, r.description, r.is_system, r.is_default, r.priority,
			   r.created_at, r.updated_at, r.created_by, r.updated_by
		FROM iam_roles r
		INNER JOIN iam_user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
		  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("GetUserRoles: %w", err)
	}
	defer rows.Close()

	var roles []models.Role
	for rows.Next() {
		var role models.Role
		err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name, &role.DisplayName, &role.Description,
			&role.IsSystem, &role.IsDefault, &role.Priority,
			&role.CreatedAt, &role.UpdatedAt, &role.CreatedBy, &role.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("GetUserRoles: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserRoles: rows iteration: %w", err)
	}

	return roles, nil
}

// GetUserPermissions is an exported function.
func (r *UserRepository) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error) {
	query := `
		SELECT DISTINCT p.id, p.module, p.resource, p.action, p.name, p.display_name, p.description, p.is_system, p.created_at
		FROM iam_permissions p
		INNER JOIN iam_role_permissions rp ON p.id = rp.permission_id
		INNER JOIN iam_user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = $1
		  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("GetUserPermissions: %w", err)
	}
	defer rows.Close()

	var permissions []models.Permission
	for rows.Next() {
		var perm models.Permission
		err := rows.Scan(
			&perm.ID, &perm.Module, &perm.Resource, &perm.Action, &perm.Name,
			&perm.DisplayName, &perm.Description, &perm.IsSystem, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetUserPermissions: %w", err)
		}
		permissions = append(permissions, perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserPermissions: rows iteration: %w", err)
	}

	return permissions, nil
}

// IncrementFailedAttempts atomically increments the failed login counter and returns the new count.
// SECURITY: Uses RETURNING to get the authoritative count from the database in a single atomic
// operation, preventing race conditions where concurrent requests could bypass lockout thresholds.
func (r *UserRepository) IncrementFailedAttempts(ctx context.Context, userID uuid.UUID) (int, error) {
	var newCount int
	err := r.db.QueryRow(ctx,
		`UPDATE iam_users SET failed_login_attempts = failed_login_attempts + 1, last_failed_login_at = NOW() WHERE id = $1 RETURNING failed_login_attempts`,
		userID,
	).Scan(&newCount)
	if err != nil {
		return 0, fmt.Errorf("IncrementFailedAttempts: %w", err)
	}
	return newCount, nil
}

// ResetFailedAttempts is an exported function.
func (r *UserRepository) ResetFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_users SET failed_login_attempts = 0, last_failed_login_at = NULL WHERE id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("ResetFailedAttempts: %w", err)
	}
	return nil
}

// UpdateLoginInfo records a successful login's timestamp/IP with a
// targeted, single-purpose UPDATE — deliberately NOT routed through the
// write-all-columns Update() method above.
//
// Root cause this exists to close (2026-09-18 incident: every
// self-service signup's password silently wiped ~1s after creation):
// AuthService.IssueSessionForNewUser (auth_signup_session.go) hands
// updateUserLoginInfo a *models.User assembled by
// signupUserCreatorAdapter.CreateForSignup from a *models.UserResponse —
// a response DTO that never carries PasswordHash (correctly: it's not
// meant to leave the process as a secret). That partial user has a
// non-empty Email (needed for the JWT), so Update()'s partial-struct
// guard — which keys off `email == ”` as a proxy for "caller doesn't
// carry the full row" — does not fire, and Update() unconditionally
// overwrote password_hash with the zero value from the partial struct,
// nulling out the credential CreatePreparedForSignup had just persisted.
// The same partial-struct risk applies to every other column Update()
// writes unconditionally (is_email_verified, mfa_*, lock state, etc.) —
// this method sidesteps the whole class of risk for the login-timestamp
// case by touching only the three columns it actually means to change.
func (r *UserRepository) UpdateLoginInfo(ctx context.Context, userID uuid.UUID, loginAt time.Time, ipAddress string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_users SET last_login_at = $2, last_login_ip = $3, failed_login_attempts = 0, updated_at = NOW() WHERE id = $1`,
		userID, loginAt, ipAddress,
	)
	if err != nil {
		return fmt.Errorf("UpdateLoginInfo: %w", err)
	}
	return nil
}

// LockUser is an exported function.
func (r *UserRepository) LockUser(ctx context.Context, userID uuid.UUID, reason string, until *time.Time) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_users SET is_locked = true, lock_reason = $2, locked_at = NOW(), locked_until = $3 WHERE id = $1`,
		userID, reason, until,
	)
	if err != nil {
		return fmt.Errorf("LockUser: %w", err)
	}
	return nil
}

// UnlockUser is an exported function.
func (r *UserRepository) UnlockUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_users SET is_locked = false, lock_reason = NULL, locked_at = NULL, locked_until = NULL, failed_login_attempts = 0 WHERE id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("UnlockUser: %w", err)
	}
	return nil
}

// FlagForAdminReview marks a user as requiring admin review (t-431, d-169
// Q3): visible (requires_admin_review + reason queryable/returned on the
// existing admin-facing User endpoints), reversible (ClearAdminReviewFlag),
// and audited (callers are expected to also write an audit-log entry — see
// AuthService.Login's local_auth_disabled gate, the only caller today).
// Idempotent: re-flagging an already-flagged user overwrites the reason and
// timestamp rather than erroring, since repeated trigger events are
// expected (every rejected login attempt re-evaluates the gate).
func (r *UserRepository) FlagForAdminReview(ctx context.Context, userID uuid.UUID, reason string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_users SET requires_admin_review = true, admin_review_reason = $2, admin_review_flagged_at = NOW() WHERE id = $1`,
		userID, reason,
	)
	if err != nil {
		return fmt.Errorf("FlagForAdminReview: %w", err)
	}
	return nil
}

// ClearAdminReviewFlag reverses FlagForAdminReview once an admin has
// resolved the flagged account (t-431, d-169 Q3's "reversible" requirement).
func (r *UserRepository) ClearAdminReviewFlag(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_users SET requires_admin_review = false, admin_review_reason = NULL, admin_review_flagged_at = NULL WHERE id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("ClearAdminReviewFlag: %w", err)
	}
	return nil
}

// CountByTenant returns the count of users for a specific tenant
func (r *UserRepository) CountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM iam_users WHERE tenant_id = $1", tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("CountByTenant: %w", err)
	}
	return count, nil
}

// CountActiveByTenant counts the tenant's occupied seats: active users that
// are not in a pending-deletion grace period. Unlike CountByTenant (which
// counts every row regardless of state), this is the seat-usage-accurate
// count backing GET /internal/v1/tenants/:id/users/count — a user with
// deletion_scheduled_at set has already relinquished their seat even though
// the row still exists during the grace window, and an inactive
// (deactivated) user is not occupying a seat either. Employee-class (ESS) and kiosk-class users are seat-free and excluded.
func (r *UserRepository) CountActiveByTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var count int
	// Employee-class (ESS) users never occupy a seat. iam_user_memberships has FORCE RLS, so the
	// NOT EXISTS runs under the tenant's scope (WithTenantScope).
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM iam_users u
			 WHERE u.tenant_id = $1 AND u.is_active = true AND u.deletion_scheduled_at IS NULL
			   AND u.username NOT ILIKE 'svc-%'
			   AND NOT EXISTS (SELECT 1 FROM iam_user_memberships m
			                   WHERE m.tenant_id = $1 AND m.user_id = u.id AND m.status = 'deactivated')
			   AND NOT EXISTS (SELECT 1 FROM iam_user_memberships m
			                   WHERE m.tenant_id = $1 AND m.user_id = u.id AND m.seat_class IN ('employee', 'kiosk', 'service', 'external'))`,
			tenantID,
		).Scan(&count)
	})
	if err != nil {
		return 0, fmt.Errorf("CountActiveByTenant: %w", err)
	}
	return count, nil
}

// GetMemberActiveState reports whether userID belongs to tenantID (found) and, if so,
// whether it currently occupies an active seat (is_active and not in the deletion grace
// period). It backs GET /internal/v1/tenants/:id/members/:userId and deliberately returns
// nothing but these two booleans — no row, no PII.
func (r *UserRepository) GetMemberActiveState(ctx context.Context, tenantID, userID uuid.UUID) (found, active bool, err error) {
	err = r.db.QueryRow(ctx,
		`SELECT (is_active AND deletion_scheduled_at IS NULL) FROM iam_users WHERE tenant_id = $1 AND id = $2`,
		tenantID, userID,
	).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("GetMemberActiveState: %w", err)
	}
	return true, active, nil
}

// UpdateActivationStatus updates the activation status of a user
func (r *UserRepository) UpdateActivationStatus(ctx context.Context, userID uuid.UUID, status string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_users SET activation_status = $1, updated_at = NOW() WHERE id = $2`,
		status, userID,
	)
	if err != nil {
		return fmt.Errorf("UpdateActivationStatus: %w", err)
	}
	return nil
}

// StampMFAEnrollmentFirstPrompt sets first_prompted_at + deadline iff
// first_prompted_at IS NULL — i.e. fires exactly once per enrollment
// cycle, on the user's first encounter with the interrupt under the
// current realm policy. The "IS NULL" guard is the canonical idempotency
// pattern (Entra/Okta both implement it this way) so concurrent login
// attempts can't double-stamp.
//
// Returns (stamped=true) when this call performed the write, (false)
// when the columns were already populated. Callers should re-fetch the
// user to read the authoritative deadline value.
func (r *UserRepository) StampMFAEnrollmentFirstPrompt(ctx context.Context, userID uuid.UUID, deadline time.Time) (bool, error) {
	cmd, err := r.db.Exec(ctx, `
		UPDATE iam_users
		SET mfa_enrollment_first_prompted_at = NOW(),
		    mfa_enrollment_deadline = $2,
		    updated_at = NOW()
		WHERE id = $1
		  AND mfa_enrollment_first_prompted_at IS NULL`,
		userID, deadline,
	)
	if err != nil {
		return false, fmt.Errorf("StampMFAEnrollmentFirstPrompt: %w", err)
	}
	return cmd.RowsAffected() == 1, nil
}

// IncrementMFAEnrollmentSkipCount atomically increments skip_count for
// the given user, but only when the user hasn't already enrolled and
// the deadline (if set) hasn't passed. Returns the new count after the
// increment, or 0 when the row was not updated (already enrolled,
// deadline elapsed, or user not found — caller distinguishes by
// re-reading state).
//
// The atomic RETURNING avoids the read-modify-write race two parallel
// logins would otherwise hit; Postgres serializes the UPDATE under
// row-level locks.
func (r *UserRepository) IncrementMFAEnrollmentSkipCount(ctx context.Context, userID uuid.UUID, now time.Time) (int, error) {
	var newCount int
	err := r.db.QueryRow(ctx, `
		UPDATE iam_users
		SET mfa_enrollment_skip_count = mfa_enrollment_skip_count + 1,
		    updated_at = NOW()
		WHERE id = $1
		  AND mfa_enabled = false
		  AND (mfa_enrollment_deadline IS NULL OR mfa_enrollment_deadline > $2)
		RETURNING mfa_enrollment_skip_count`,
		userID, now,
	).Scan(&newCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("IncrementMFAEnrollmentSkipCount: %w", err)
	}
	return newCount, nil
}

// ResetMFAEnrollmentGraceTracking clears skip_count after a successful
// enrollment. first_prompted_at + deadline are left intact so audit
// history of "how long did this user take to enroll" remains queryable.
// Idempotent (always executes — no row count check needed; the success-
// path caller will already have set mfa_enabled = true via Update).
func (r *UserRepository) ResetMFAEnrollmentGraceTracking(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_users SET mfa_enrollment_skip_count = 0, updated_at = NOW() WHERE id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("ResetMFAEnrollmentGraceTracking: %w", err)
	}
	return nil
}

// HasActiveWebAuthnCredential returns true when the user has at least
// one non-revoked WebAuthn credential. Source-of-truth for the
// WebAuthn-as-MFA path in createMFAChallenge — when the user has a
// passkey enrolled and no other code-based factor, the login MFA
// challenge surface includes "webauthn" so the frontend can drive
// a navigator.credentials.get() ceremony instead of falling back to
// the (since-removed 2026-05-26) silent email path.
//
// Distinct from HasNonPrimaryMFAFactor: that also matches push-device
// rows. This one is specifically passkey-vs-no-passkey for the MFA
// method enumeration.
func (r *UserRepository) HasActiveWebAuthnCredential(ctx context.Context, userID uuid.UUID) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM iam_webauthn_credentials wc
			WHERE wc.user_id = $1 AND wc.revoked_at IS NULL
		)`
	var has bool
	err := r.db.QueryRow(ctx, query, userID).Scan(&has)
	if err != nil {
		return false, fmt.Errorf("HasActiveWebAuthnCredential: %w", err)
	}
	return has, nil
}

// HasNonPrimaryMFAFactor returns true when the user has at least one
// active MFA factor OUTSIDE the iam_users row — i.e. a non-revoked
// WebAuthn credential or a push device. Companion to HasAnyMFAFactor
// for DisableMFA-style flows that clear TOTP/email columns in iam_users
// and need to know whether the consolidated mfa_enabled flag should
// stay true because residual factors persist. Reading from iam_users
// here would race the in-flight UPDATE; querying only the sibling
// tables is what makes the derived flag computable BEFORE the write.
func (r *UserRepository) HasNonPrimaryMFAFactor(ctx context.Context, userID uuid.UUID) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM iam_webauthn_credentials wc
			WHERE wc.user_id = $1 AND wc.revoked_at IS NULL
		) OR EXISTS (
			SELECT 1 FROM iam_push_mfa_devices pd
			WHERE pd.user_id = $1
		)`
	var has bool
	err := r.db.QueryRow(ctx, query, userID).Scan(&has)
	if err != nil {
		return false, fmt.Errorf("HasNonPrimaryMFAFactor: %w", err)
	}
	return has, nil
}

// HasAnyMFAFactor returns true when the user has at least one active
// MFA factor across all supported types: TOTP, email, WebAuthn passkey,
// or push device. Single round-trip via two EXISTS sub-queries against
// indexed columns. Returns (false, nil) when the user row itself is
// absent.
//
// Source-of-truth check used by the OAuth /authorize ACR step-up gate
// (oauth_provider_handler.go) so step-up routing is no longer subject
// to denormalization drift on iam_users.mfa_enabled. Previously a user
// with mfa_enabled=false and a webauthn credential (live repro
// 2026-05-12: WebAuthn FinishRegistration did not flip the flag) got
// routed to /auth/mfa/enrollment despite having a phishing-resistant
// factor. Reading from the factor tables directly closes that gap;
// the denormalized flag stays for compliance dashboard queries but
// is no longer load-bearing on the auth flow.
func (r *UserRepository) HasAnyMFAFactor(ctx context.Context, userID uuid.UUID) (bool, error) {
	const query = `
		SELECT
			u.mfa_totp_enabled
			OR u.mfa_email_enabled
			OR EXISTS (
				SELECT 1 FROM iam_webauthn_credentials wc
				WHERE wc.user_id = u.id AND wc.revoked_at IS NULL
			)
			OR EXISTS (
				SELECT 1 FROM iam_push_mfa_devices pd
				WHERE pd.user_id = u.id
			)
		FROM iam_users u
		WHERE u.id = $1`
	var hasFactor bool
	err := r.db.QueryRow(ctx, query, userID).Scan(&hasFactor)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("HasAnyMFAFactor: %w", err)
	}
	return hasFactor, nil
}

// encryptPII encrypts PII fields before storing in the database.
//
// Per-tenant DEK derivation (added 2026-05-25 P0): each tenant's PII is
// encrypted under an HKDF-derived key tied to user.TenantID, not the
// shared master key. A compromised key has tenant-bounded blast radius
// rather than exposing every tenant's PII at once — required by SOC 2
// CC6.1 / ISO 27018 §8.2.4 / GDPR Art. 32(1)(a) "appropriate technical
// measures".
//
// Ciphertext gains the `enc:v2:` framing prefix to distinguish v2
// (tenant-DEK) from v1 (master-key, legacy). Decryption auto-detects
// the prefix and routes accordingly — old v1 rows continue to decrypt
// with the master key, new writes use the tenant DEK. Migration is
// LAZY: any UPDATE on an existing user row promotes that row's PII to
// v2 framing on the next write. No big-bang migration required.
func (r *UserRepository) encryptPII(user *models.User) error {
	if r.encryptionService == nil {
		return fmt.Errorf("encryption service not configured - cannot encrypt PII")
	}

	// Derive once per call so every field encrypts under the same DEK
	// without re-running HKDF for each value (HKDF is cheap, but
	// per-field calls would still be wasteful).
	tenantEnc, err := r.encryptionService.DeriveTenantKey(user.TenantID)
	if err != nil {
		return fmt.Errorf("encryptPII: derive tenant key for %s: %w", user.TenantID, err)
	}

	// Encrypt email (non-pointer) with v2 framing.
	if user.Email != "" {
		encrypted, err := r.encryptionService.EncryptForTenant(user.TenantID, user.Email)
		if err != nil {
			return fmt.Errorf("failed to encrypt email: %w", err)
		}
		user.Email = encrypted
	}

	// Encrypt pointer PII fields using the tenant-scoped service.
	// The string-ptr helper accepts any Encrypt(string) → (string, error)
	// shape; passing tenantEnc routes to v1 framing internally, so we
	// wrap with a v2 marker by using EncryptForTenant directly.
	for _, f := range []struct {
		field **string
		name  string
	}{
		{&user.FirstName, "first_name"},
		{&user.LastName, "last_name"},
		{&user.DisplayName, "display_name"},
		{&user.Phone, "phone"},
		// SECURITY: MFA TOTP secret — high-value target for account takeover
		{&user.MFASecret, "mfa_secret"},
	} {
		if *f.field == nil || **f.field == "" {
			continue
		}
		encrypted, err := r.encryptionService.EncryptForTenant(user.TenantID, **f.field)
		if err != nil {
			return fmt.Errorf("failed to encrypt %s: %w", f.name, err)
		}
		*f.field = &encrypted
	}

	// Silence the unused-variable check; tenantEnc is documented above
	// as the "compute once" intent and may be reused in future PII paths.
	_ = tenantEnc
	return nil
}

// decryptPII decrypts PII fields after reading from the database.
//
// Uses DecryptForTenant which auto-detects ciphertext framing:
//
//   - v2 prefix → derive tenant DEK, decrypt with it (post-2026-05-25 writes)
//   - v1 prefix → master-key decrypt (legacy writes)
//   - no prefix → master-key decrypt (pre-encryption-migration data)
//
// Single code path handles all three, so v1 → v2 migration can happen
// gradually as users get touched by normal traffic.
func (r *UserRepository) decryptPII(user *models.User) error {
	if r.encryptionService == nil {
		return fmt.Errorf("encryption service not configured - cannot decrypt PII")
	}

	// Decrypt email (non-pointer)
	if user.Email != "" {
		decrypted, err := r.encryptionService.DecryptForTenant(user.TenantID, user.Email)
		if err != nil {
			return fmt.Errorf("failed to decrypt email: %w", err)
		}
		user.Email = decrypted
	}

	// Decrypt standard pointer PII fields with v1/v2 auto-detect.
	for _, f := range []struct {
		field **string
		name  string
	}{
		{&user.FirstName, "first_name"},
		{&user.LastName, "last_name"},
		{&user.DisplayName, "display_name"},
		{&user.Phone, "phone"},
	} {
		if *f.field == nil || **f.field == "" {
			continue
		}
		decrypted, err := r.encryptionService.DecryptForTenant(user.TenantID, **f.field)
		if err != nil {
			return fmt.Errorf("failed to decrypt %s: %w", f.name, err)
		}
		*f.field = &decrypted
	}

	// SECURITY: Decrypt MFA TOTP secret with backward-compatibility fallback.
	// If decryption fails the secret may be stored in plaintext (pre-migration);
	// log a warning and leave the raw value so TOTP verification can still proceed.
	if user.MFASecret != nil && *user.MFASecret != "" {
		decrypted, err := r.encryptionService.DecryptForTenant(user.TenantID, *user.MFASecret)
		if err != nil {
			logger.Warn("MFA secret decryption failed, using raw value (pre-migration?)",
				zap.String("user_id", user.ID.String()),
				zap.Error(err),
			)
		} else {
			user.MFASecret = &decrypted
		}
	}

	return nil
}

// Deactivate sets is_active = false for a user (soft-delete).
// The row is retained for cross-tenant audit retention. Callers must
// separately revoke sessions / tokens; this method only flips the column.
func (r *UserRepository) Deactivate(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE iam_users SET is_active = false, updated_at = NOW() WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("Deactivate: %w", err)
	}
	return nil
}

// Reactivate restores a human tenant member. OAuth clients and dedicated
// service accounts do not use iam_users and are intentionally outside this API.
func (r *UserRepository) Reactivate(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, "UPDATE iam_users SET is_active = true, updated_at = NOW() WHERE id = $1", userID)
	if err != nil {
		return fmt.Errorf("Reactivate: %w", err)
	}
	return nil
}

// SetTeamMemberActive applies a tenant member lifecycle change under one
// transaction. The advisory lock is tenant-scoped, which makes the aggregate
// last-admin check serializable even though PostgreSQL cannot FOR UPDATE lock
// an aggregate result. Deactivation also terminates all active sessions before
// the user row can become inactive.
func (r *UserRepository) SetTeamMemberActive(ctx context.Context, tenantID, actorID, targetID uuid.UUID, active bool, audit ...*models.AuditLog) error {
	adminRoleNames := authorization.TenantAdministratorRoleNames()
	if actorID == targetID && !active {
		return ErrTeamSelfDeactivation
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("SetTeamMemberActive: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, tenantID); err != nil {
		return fmt.Errorf("SetTeamMemberActive: tenant lock: %w", err)
	}
	var actorActive bool
	if err := tx.QueryRow(ctx, `SELECT is_active FROM iam_users WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, actorID, tenantID).Scan(&actorActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTeamActorNotActive
		}
		return fmt.Errorf("SetTeamMemberActive: lock actor: %w", err)
	}
	if !actorActive {
		return ErrTeamActorNotActive
	}
	var targetActive bool
	if err := tx.QueryRow(ctx, `SELECT is_active FROM iam_users WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, targetID, tenantID).Scan(&targetActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTeamTargetNotFound
		}
		return fmt.Errorf("SetTeamMemberActive: lock target: %w", err)
	}
	// Match ReplaceTeamRoles' lock order. This stable UUID-ordered FOR UPDATE
	// read pins every catalogue row that can affect actor/target priority or the
	// tenant-administrator invariant before the aggregate reads below are authorized.
	if _, err := tx.Exec(ctx, `SELECT r.id FROM iam_roles r
		JOIN iam_user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = ANY($1) AND r.tenant_id = $2
		ORDER BY r.id FOR UPDATE`, []uuid.UUID{actorID, targetID}, tenantID); err != nil {
		return fmt.Errorf("SetTeamMemberActive: role catalogue lock: %w", err)
	}
	var actorPriority, targetPriority int
	priorityQuery := `SELECT COALESCE(MAX(r.priority), 0) FROM iam_roles r JOIN iam_user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1 AND r.tenant_id = $2 AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`
	if err := tx.QueryRow(ctx, priorityQuery, actorID, tenantID).Scan(&actorPriority); err != nil {
		return fmt.Errorf("SetTeamMemberActive: actor priority: %w", err)
	}
	if err := tx.QueryRow(ctx, priorityQuery, targetID, tenantID).Scan(&targetPriority); err != nil {
		return fmt.Errorf("SetTeamMemberActive: target priority: %w", err)
	}
	if actorPriority <= targetPriority {
		return ErrTeamTargetPriority
	}
	if !active && targetActive {
		var remaining, remainingOwners int
		if err := tx.QueryRow(ctx, `SELECT COUNT(DISTINCT u.id),
			COUNT(DISTINCT u.id) FILTER (WHERE lower(r.name) = 'owner') FROM iam_users u
			JOIN iam_user_roles ur ON ur.user_id = u.id JOIN iam_roles r ON r.id = ur.role_id
			WHERE u.tenant_id = $1 AND u.is_active AND r.tenant_id = $1 AND lower(r.name)=ANY($2)
			AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`, tenantID, adminRoleNames).Scan(&remaining, &remainingOwners); err != nil {
			return fmt.Errorf("SetTeamMemberActive: count administrators: %w", err)
		}
		var targetAdmin, targetOwner bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam_user_roles ur JOIN iam_roles r ON r.id = ur.role_id
			WHERE ur.user_id = $1 AND r.tenant_id = $2 AND lower(r.name)=ANY($3)
			AND (ur.expires_at IS NULL OR ur.expires_at > NOW())),
			EXISTS(SELECT 1 FROM iam_user_roles ur JOIN iam_roles r ON r.id = ur.role_id
			WHERE ur.user_id = $1 AND r.tenant_id = $2 AND lower(r.name) = 'owner'
			AND (ur.expires_at IS NULL OR ur.expires_at > NOW()))`, targetID, tenantID, adminRoleNames).Scan(&targetAdmin, &targetOwner); err != nil {
			return fmt.Errorf("SetTeamMemberActive: target administrator: %w", err)
		}
		// An active admin is not a replacement owner. Preserve the literal
		// last-owner invariant as well as the broader last-administrator one.
		if (targetAdmin && remaining <= 1) || (targetOwner && remainingOwners <= 1) {
			return ErrTeamLastAdministrator
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE iam_users SET is_active = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3`, active, targetID, tenantID); err != nil {
		return fmt.Errorf("SetTeamMemberActive: update user: %w", err)
	}
	// Seat ledger moves with the user in this same transaction: deactivation frees the member seat once,
	// reactivation re-occupies one under the seat limit (ErrSeatLimitReached rolls the whole change back).
	memberships := &UserMembershipRepository{db: tx}
	if !active {
		if _, err := memberships.Deactivate(ctx, tenantID, targetID); err != nil {
			return fmt.Errorf("SetTeamMemberActive: release seat: %w", err)
		}
	} else if !targetActive {
		if _, err := memberships.Reactivate(ctx, tenantID, targetID); err != nil {
			if errors.Is(err, ErrSeatLimitReached) {
				return ErrSeatLimitReached
			}
			return fmt.Errorf("SetTeamMemberActive: occupy seat: %w", err)
		}
	}
	if !active {
		if _, err := sessionsweep.End(ctx, tx, `UPDATE iam_sessions SET is_active = false, ended_at = NOW(), end_reason = $2
			WHERE user_id = $1 AND is_active = true RETURNING id, user_id`, sessionEndUserDeactivated, "", targetID, sessionEndUserDeactivated); err != nil {
			return fmt.Errorf("SetTeamMemberActive: revoke sessions: %w", err)
		}
		// The sessions above are ended user-wide, so sweep the user's tokens
		// user-wide too. Not by tenant: a token's tenant_id is its client's
		// tenant, not the member's, and legacy tokens carry no session binding.
		if err := revokeUserOAuthTokensTx(ctx, tx, targetID); err != nil {
			return fmt.Errorf("SetTeamMemberActive: revoke oauth tokens: %w", err)
		}
	}
	if len(audit) > 0 && audit[0] != nil {
		if err := CreateAuditLogTx(ctx, tx, audit[0]); err != nil {
			return fmt.Errorf("SetTeamMemberActive: audit: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("SetTeamMemberActive: commit: %w", err)
	}
	return nil
}

// ErrLastOwner is returned by admin soft/hard-delete when the target user
// is the tenant's only holder of the "owner" role — the task's explicit
// "refuse to delete the last owner of a tenant" guard. Deliberately
// scoped to the literal role name "owner" (not the broader
// authorization.TenantAdministratorRoleNames() set SetTeamMemberActive
// uses for deactivation/role-removal) because that is what was asked for;
// a tenant that has admins but no "owner" role at all is not blocked by
// this guard.
var ErrLastOwner = errors.New("cannot delete the last owner of the tenant")

// CountActiveOwners returns how many non-deleted, active users in
// tenantID hold a role literally named "owner" (case-insensitive).
// AdminSoftDelete/AdminHardDeleteUser call this before touching a user
// who holds that role; if the count is 1 and the target is that one
// owner, the operation is refused with ErrLastOwner.
func (r *UserRepository) CountActiveOwners(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(DISTINCT u.id)
		FROM iam_users u
		JOIN iam_user_roles ur ON ur.user_id = u.id
		JOIN iam_roles r ON r.id = ur.role_id
		WHERE u.tenant_id = $1
		  AND lower(r.name) = 'owner'
		  AND u.is_active
		  AND u.activation_status <> 'pending_deletion'
		  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
	`, tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("CountActiveOwners: %w", err)
	}
	return count, nil
}

// HasRole reports whether userID currently holds a role literally named
// roleName (case-insensitive), ignoring expired assignments.
func (r *UserRepository) HasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	var has bool
	err := r.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM iam_user_roles ur
			JOIN iam_roles ro ON ro.id = ur.role_id
			WHERE ur.user_id = $1 AND lower(ro.name) = lower($2)
			  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
		)
	`, userID, roleName).Scan(&has)
	if err != nil {
		return false, fmt.Errorf("HasRole: %w", err)
	}
	return has, nil
}

// SetDeletionState persists the activation_status/deletion_* lifecycle
// columns directly via a targeted UPDATE, instead of going through
// Update().
//
// BUG FOUND while building the admin lifecycle endpoints (2026-09-19):
// UserRepository.Update's write-all-columns SQL never lists
// activation_status, deletion_scheduled_at, deletion_grace_period_ends_at
// or deletion_reason (see Update's query above — those four columns are
// simply absent from the SET list). ScheduleAccountDeletion and
// CancelAccountDeletion (auth_account_deletion_service.go) set those
// fields on the in-memory *models.User and then called Update(), which
// silently discarded the write: self-service account deletion has never
// actually persisted past the in-memory struct returned to the caller.
// The columns DO exist in the schema (the GitOps repository
// falcon-id/schema-definition-main.yaml declares them, with a partial
// index on deletion_grace_period_ends_at scoped to
// activation_status='pending_deletion' — clearly intended to back a
// purge-candidate query that was never built). Both the self-service
// flow and the new admin lifecycle now route every write of these four
// columns through this one method so there is exactly one write path,
// and it demonstrably persists (see repository/service tests).
func (r *UserRepository) SetDeletionState(ctx context.Context, userID uuid.UUID, activationStatus string, deletionScheduledAt, deletionGracePeriodEndsAt *time.Time, deletionReason *string) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE iam_users
		SET activation_status = $2,
		    deletion_scheduled_at = $3,
		    deletion_grace_period_ends_at = $4,
		    deletion_reason = $5,
		    updated_at = NOW()
		WHERE id = $1
	`, userID, activationStatus, deletionScheduledAt, deletionGracePeriodEndsAt, deletionReason)
	if err != nil {
		return fmt.Errorf("SetDeletionState: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("SetDeletionState: user %s not found", userID)
	}
	return nil
}

// HardDeleteUserTx performs the real, irreversible row delete plus a
// best-effort cleanup of the user-scoped child rows this repository knows
// about, all inside the caller's transaction. It is named *Tx (unlike the
// pre-existing Delete, which is the RAW, ungated single-statement DELETE
// still used by the legacy /api/users/:id and
// /api/platform/tenants/:tenant_id/users/:user_id DELETE routes) so the
// two call paths stay visibly distinct: existing callers are UNCHANGED,
// and the new admin hard-delete path is the only caller of this method.
//
// Child tables cleaned explicitly (FK-cascade walk): iam_user_roles
// (role_id-keyed elsewhere, but user_id here), iam_sessions,
// iam_user_recovery_methods. iam_audit_log rows referencing this user as
// actor_id/target_user_id are intentionally NOT deleted — audit history
// must outlive the actor per this task's own audit requirement; the
// residual reference is a UUID with no PII attached (LogUserAction never
// stores the user's decrypted PII in the log row).
func (r *UserRepository) HardDeleteUserTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	for _, stmt := range []string{
		`DELETE FROM iam_user_roles WHERE user_id = $1`,
		`DELETE FROM iam_sessions WHERE user_id = $1`,
		`DELETE FROM iam_user_recovery_methods WHERE user_id = $1`,
	} {
		if _, err := tx.Exec(ctx, stmt, userID); err != nil {
			return fmt.Errorf("HardDeleteUserTx: %s: %w", stmt, err)
		}
	}
	if err := r.releaseMembershipsTx(ctx, tx, userID); err != nil {
		return fmt.Errorf("HardDeleteUserTx: %w", err)
	}
	tag, err := tx.Exec(ctx, `DELETE FROM iam_users WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("HardDeleteUserTx: delete iam_users: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("HardDeleteUserTx: user %s not found", userID)
	}
	return nil
}

// CountResidualRowsTx is the value-sweep half of hard-delete completeness
// verification (the task's "value sweep" — finding rows scoped by
// unconventional column names, not just FK-cascade children). It is
// called AFTER HardDeleteUserTx inside the same transaction and asserts
// that no row anywhere in the tables this repository knows carry a
// user_id-shaped column pointing at the deleted user. A non-empty result
// means the transaction must be rolled back rather than report success.
//
// This is a best-effort, DISCLOSED enumeration of the tables this
// repository package is aware of — it does NOT sweep tables owned by
// other services/repositories in the same falcon-id database (e.g.
// device/webauthn/mfa-enrollment repositories not touched by this
// change). See the MR report for the explicit list of tables NOT swept.
func (r *UserRepository) CountResidualRowsTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (map[string]int, error) {
	tables := map[string]string{
		"iam_user_roles":            `SELECT COUNT(*) FROM iam_user_roles WHERE user_id = $1`,
		"iam_sessions":              `SELECT COUNT(*) FROM iam_sessions WHERE user_id = $1`,
		"iam_user_recovery_methods": `SELECT COUNT(*) FROM iam_user_recovery_methods WHERE user_id = $1`,
	}
	counts := make(map[string]int, len(tables))
	for name, q := range tables {
		var n int
		if err := tx.QueryRow(ctx, q, userID).Scan(&n); err != nil {
			return nil, fmt.Errorf("CountResidualRowsTx: %s: %w", name, err)
		}
		counts[name] = n
	}
	return counts, nil
}

// HardDeleteUser is the single entry point admin_user_lifecycle.go calls
// for irreversible user erasure. It wraps HardDeleteUserTx in a
// transaction and, before committing, re-runs CountResidualRowsTx as the
// completeness check: any nonzero residual count rolls the whole
// transaction back instead of reporting success, so a partial delete is
// never silently accepted as complete.
func (r *UserRepository) HardDeleteUser(ctx context.Context, userID uuid.UUID) (residual map[string]int, err error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("HardDeleteUser: begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	if err = r.HardDeleteUserTx(ctx, tx, userID); err != nil {
		return nil, err
	}

	counts, cErr := r.CountResidualRowsTx(ctx, tx, userID)
	if cErr != nil {
		err = cErr
		return nil, err
	}
	for table, n := range counts {
		if n != 0 {
			err = fmt.Errorf("HardDeleteUser: residual rows remain in %s (count=%d) for user %s, aborting", table, n, userID)
			return nil, err
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("HardDeleteUser: commit: %w", err)
	}
	return counts, nil
}

// DeactivateEmployeeUser switches an employee-class (ESS) user off: is_active=false, live sessions ended, one audit row,
// all in one transaction. Unlike SetTeamMemberActive it needs no acting administrator (the expiry worker and the S2S
// endpoint act as the system) and skips the last-administrator guard: employee seats never carry an administrator role.
func (r *UserRepository) DeactivateEmployeeUser(ctx context.Context, tenantID, targetID uuid.UUID, audit *models.AuditLog) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("DeactivateEmployeeUser: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `UPDATE iam_users SET is_active = false, updated_at = NOW() WHERE id = $1 AND tenant_id = $2`, targetID, tenantID)
	if err != nil {
		return fmt.Errorf("DeactivateEmployeeUser: update user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrTeamTargetNotFound
	}
	if _, err := sessionsweep.End(ctx, tx, `UPDATE iam_sessions SET is_active = false, ended_at = NOW(), end_reason = $2
		WHERE user_id = $1 AND is_active = true RETURNING id, user_id`, sessionEndEmployeeAccessExpired, "", targetID, sessionEndEmployeeAccessExpired); err != nil {
		return fmt.Errorf("DeactivateEmployeeUser: revoke sessions: %w", err)
	}
	if err := revokeUserOAuthTokensTx(ctx, tx, targetID); err != nil {
		return fmt.Errorf("DeactivateEmployeeUser: revoke oauth tokens: %w", err)
	}
	if audit != nil {
		if err := CreateAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("DeactivateEmployeeUser: audit: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("DeactivateEmployeeUser: commit: %w", err)
	}
	return nil
}

// GetMFATOTPEnabledAt returns when the user's TOTP factor was last enabled
// (maintained by a trigger on iam_users). NULL — legacy rows enrolled before
// the column existed — is returned as nil.
func (r *UserRepository) GetMFATOTPEnabledAt(ctx context.Context, userID uuid.UUID) (*time.Time, error) {
	var at *time.Time
	err := r.db.QueryRow(ctx, `SELECT mfa_totp_enabled_at FROM iam_users WHERE id = $1`, userID).Scan(&at)
	if err != nil {
		return nil, fmt.Errorf("GetMFATOTPEnabledAt: %w", err)
	}
	return at, nil
}

// StampMFATOTPEnabledAt sets mfa_totp_enabled_at to now. Called whenever a TOTP
// secret is (re-)enrolled so the witness age gate restarts.
func (r *UserRepository) StampMFATOTPEnabledAt(ctx context.Context, userID uuid.UUID) error {
	if _, err := r.db.Exec(ctx, `UPDATE iam_users SET mfa_totp_enabled_at = NOW() WHERE id = $1`, userID); err != nil {
		return fmt.Errorf("StampMFATOTPEnabledAt: %w", err)
	}
	return nil
}

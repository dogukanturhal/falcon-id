// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

const msgFailedUnmarshalProfileData = "failed to unmarshal profile data: %w"

// FederatedAccountRepository is an exported type.
type FederatedAccountRepository struct {
	db                DBTX
	encryptionService *crypto.EncryptionService
}

// NewFederatedAccountRepository is an exported function.
func NewFederatedAccountRepository(db *pgxpool.Pool) *FederatedAccountRepository {
	return &FederatedAccountRepository{db: db}
}

// SetEncryptionService wires the encryption service for token encryption
func (r *FederatedAccountRepository) SetEncryptionService(es *crypto.EncryptionService) {
	r.encryptionService = es
}

// encryptTokens encrypts OAuth access/refresh tokens before storage
func (r *FederatedAccountRepository) encryptTokens(account *models.FederatedAccount) error {
	if r.encryptionService == nil {
		return fmt.Errorf("encryption service not configured: cannot store OAuth tokens without encryption")
	}
	if account.AccessToken != nil && *account.AccessToken != "" {
		encrypted, err := r.encryptionService.Encrypt(*account.AccessToken)
		if err != nil {
			return fmt.Errorf("failed to encrypt access_token: %w", err)
		}
		account.AccessToken = &encrypted
	}
	if account.RefreshToken != nil && *account.RefreshToken != "" {
		encrypted, err := r.encryptionService.Encrypt(*account.RefreshToken)
		if err != nil {
			return fmt.Errorf("failed to encrypt refresh_token: %w", err)
		}
		account.RefreshToken = &encrypted
	}
	return nil
}

// decryptTokens decrypts OAuth access/refresh tokens after reading from DB
func (r *FederatedAccountRepository) decryptTokens(account *models.FederatedAccount) {
	if r.encryptionService == nil {
		return
	}
	if account.AccessToken != nil && *account.AccessToken != "" {
		decrypted, err := r.encryptionService.Decrypt(*account.AccessToken)
		if err == nil {
			account.AccessToken = &decrypted
		}
		// If decryption fails, token may be plaintext (pre-migration) — leave as-is
	}
	if account.RefreshToken != nil && *account.RefreshToken != "" {
		decrypted, err := r.encryptionService.Decrypt(*account.RefreshToken)
		if err == nil {
			account.RefreshToken = &decrypted
		}
	}
}

// Create creates a new federated account
func (r *FederatedAccountRepository) Create(ctx context.Context, account *models.FederatedAccount) error {
	profileDataJSON, err := json.Marshal(account.ProfileData)
	if err != nil {
		return fmt.Errorf("failed to marshal profile data: %w", err)
	}

	// SECURITY: Encrypt OAuth tokens before storage
	if err := r.encryptTokens(account); err != nil {
		return fmt.Errorf("Create: %w", err)
	}

	query := `
		INSERT INTO iam_federated_accounts (
			id, user_id, provider_id, provider_user_id, provider_username, provider_email,
			access_token, refresh_token, token_expires_at, profile_data, first_linked_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		) RETURNING created_at, updated_at`

	if account.ID == uuid.Nil {
		account.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		account.ID, account.UserID, account.ProviderID, account.ProviderUserID,
		account.ProviderUsername, account.ProviderEmail,
		account.AccessToken, account.RefreshToken, account.TokenExpiresAt,
		profileDataJSON, account.FirstLinkedAt,
	).Scan(&account.CreatedAt, &account.UpdatedAt)
}

// GetByID retrieves a federated account by ID
func (r *FederatedAccountRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.FederatedAccount, error) {
	account := &models.FederatedAccount{}
	var profileDataJSON []byte

	query := `
		SELECT id, user_id, provider_id, provider_user_id, provider_username, provider_email,
			   access_token, refresh_token, token_expires_at, profile_data,
			   first_linked_at, last_used_at, created_at, updated_at
		FROM iam_federated_accounts WHERE id = $1`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&account.ID, &account.UserID, &account.ProviderID, &account.ProviderUserID,
		&account.ProviderUsername, &account.ProviderEmail,
		&account.AccessToken, &account.RefreshToken, &account.TokenExpiresAt,
		&profileDataJSON, &account.FirstLinkedAt, &account.LastUsedAt,
		&account.CreatedAt, &account.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}

	if len(profileDataJSON) > 0 {
		if err := json.Unmarshal(profileDataJSON, &account.ProfileData); err != nil {
			return nil, fmt.Errorf(msgFailedUnmarshalProfileData, err)
		}
	}

	r.decryptTokens(account)
	return account, nil
}

// GetByUserAndProvider retrieves a federated account by user ID and provider ID
func (r *FederatedAccountRepository) GetByUserAndProvider(ctx context.Context, userID, providerID uuid.UUID) (*models.FederatedAccount, error) {
	account := &models.FederatedAccount{}
	var profileDataJSON []byte

	query := `
		SELECT id, user_id, provider_id, provider_user_id, provider_username, provider_email,
			   access_token, refresh_token, token_expires_at, profile_data,
			   first_linked_at, last_used_at, created_at, updated_at
		FROM iam_federated_accounts
		WHERE user_id = $1 AND provider_id = $2`

	err := r.db.QueryRow(ctx, query, userID, providerID).Scan(
		&account.ID, &account.UserID, &account.ProviderID, &account.ProviderUserID,
		&account.ProviderUsername, &account.ProviderEmail,
		&account.AccessToken, &account.RefreshToken, &account.TokenExpiresAt,
		&profileDataJSON, &account.FirstLinkedAt, &account.LastUsedAt,
		&account.CreatedAt, &account.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByUserAndProvider: %w", err)
	}

	if len(profileDataJSON) > 0 {
		if err := json.Unmarshal(profileDataJSON, &account.ProfileData); err != nil {
			return nil, fmt.Errorf(msgFailedUnmarshalProfileData, err)
		}
	}

	r.decryptTokens(account)
	return account, nil
}

// GetByProviderUserID retrieves a federated account by provider and provider user ID
func (r *FederatedAccountRepository) GetByProviderUserID(ctx context.Context, providerID uuid.UUID, providerUserID string) (*models.FederatedAccount, error) {
	account := &models.FederatedAccount{}
	var profileDataJSON []byte

	query := `
		SELECT id, user_id, provider_id, provider_user_id, provider_username, provider_email,
			   access_token, refresh_token, token_expires_at, profile_data,
			   first_linked_at, last_used_at, created_at, updated_at
		FROM iam_federated_accounts
		WHERE provider_id = $1 AND provider_user_id = $2`

	err := r.db.QueryRow(ctx, query, providerID, providerUserID).Scan(
		&account.ID, &account.UserID, &account.ProviderID, &account.ProviderUserID,
		&account.ProviderUsername, &account.ProviderEmail,
		&account.AccessToken, &account.RefreshToken, &account.TokenExpiresAt,
		&profileDataJSON, &account.FirstLinkedAt, &account.LastUsedAt,
		&account.CreatedAt, &account.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByProviderUserID: %w", err)
	}

	if len(profileDataJSON) > 0 {
		if err := json.Unmarshal(profileDataJSON, &account.ProfileData); err != nil {
			return nil, fmt.Errorf(msgFailedUnmarshalProfileData, err)
		}
	}

	r.decryptTokens(account)
	return account, nil
}

// GetByUser retrieves all federated accounts for a user
func (r *FederatedAccountRepository) GetByUser(ctx context.Context, userID uuid.UUID) ([]models.FederatedAccount, error) {
	query := `
		SELECT id, user_id, provider_id, provider_user_id, provider_username, provider_email,
			   access_token, refresh_token, token_expires_at, profile_data,
			   first_linked_at, last_used_at, created_at, updated_at
		FROM iam_federated_accounts
		WHERE user_id = $1
		ORDER BY first_linked_at DESC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("GetByUser: %w", err)
	}
	defer rows.Close()

	var accounts []models.FederatedAccount
	for rows.Next() {
		account := models.FederatedAccount{}
		var profileDataJSON []byte

		err := rows.Scan(
			&account.ID, &account.UserID, &account.ProviderID, &account.ProviderUserID,
			&account.ProviderUsername, &account.ProviderEmail,
			&account.AccessToken, &account.RefreshToken, &account.TokenExpiresAt,
			&profileDataJSON, &account.FirstLinkedAt, &account.LastUsedAt,
			&account.CreatedAt, &account.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetByUser: %w", err)
		}

		if len(profileDataJSON) > 0 {
			if err := json.Unmarshal(profileDataJSON, &account.ProfileData); err != nil {
				return nil, fmt.Errorf(msgFailedUnmarshalProfileData, err)
			}
		}

		r.decryptTokens(&account)
		accounts = append(accounts, account)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetByUser: rows iteration: %w", err)
	}

	return accounts, nil
}

// Update updates a federated account
func (r *FederatedAccountRepository) Update(ctx context.Context, account *models.FederatedAccount) error {
	profileDataJSON, err := json.Marshal(account.ProfileData)
	if err != nil {
		return fmt.Errorf("failed to marshal profile data: %w", err)
	}

	// SECURITY: Encrypt OAuth tokens before storage
	if err := r.encryptTokens(account); err != nil {
		return fmt.Errorf("Update: %w", err)
	}

	query := `
		UPDATE iam_federated_accounts SET
			provider_username = $2, provider_email = $3, access_token = $4,
			refresh_token = $5, token_expires_at = $6, profile_data = $7, last_used_at = $8
		WHERE id = $1
		RETURNING updated_at`

	return r.db.QueryRow(ctx, query,
		account.ID, account.ProviderUsername, account.ProviderEmail,
		account.AccessToken, account.RefreshToken, account.TokenExpiresAt,
		profileDataJSON, account.LastUsedAt,
	).Scan(&account.UpdatedAt)
}

// UpdateLastUsed updates the last used timestamp
func (r *FederatedAccountRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		"UPDATE iam_federated_accounts SET last_used_at = NOW() WHERE id = $1",
		id,
	)
	if err != nil {
		return fmt.Errorf("UpdateLastUsed: %w", err)
	}
	return nil
}

// Delete removes a federated account
func (r *FederatedAccountRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, "DELETE FROM iam_federated_accounts WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	return nil
}

// DeleteByUserAndProvider removes a federated account by user and provider
func (r *FederatedAccountRepository) DeleteByUserAndProvider(ctx context.Context, userID, providerID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		"DELETE FROM iam_federated_accounts WHERE user_id = $1 AND provider_id = $2",
		userID, providerID,
	)
	if err != nil {
		return fmt.Errorf("DeleteByUserAndProvider: %w", err)
	}
	return nil
}

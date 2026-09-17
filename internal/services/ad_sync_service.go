// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// adSyncServiceSyncRepo defines the AD sync repository methods needed by ADSyncService.
type adSyncServiceSyncRepo interface {
	UpsertSyncState(ctx context.Context, state *models.ADSyncState) error
	GetPendingConflicts(ctx context.Context, tenantID, providerID uuid.UUID) ([]models.ADSyncConflict, error)
	GetSyncStatsByTenant(ctx context.Context, tenantID uuid.UUID) (map[string]interface{}, error)
	GetConflictTenantID(ctx context.Context, conflictID uuid.UUID) (uuid.UUID, error)
	ResolveConflict(ctx context.Context, conflictID uuid.UUID, resolution string, details map[string]interface{}, resolvedBy uuid.UUID) error
}

// adSyncServiceHistoryRepo defines the LDAP sync history repository methods needed by ADSyncService.
type adSyncServiceHistoryRepo interface {
	Create(ctx context.Context, history *models.LDAPSyncHistory) error
	Update(ctx context.Context, history *models.LDAPSyncHistory) error
	GetLatestByProviderID(ctx context.Context, providerID uuid.UUID) (*models.LDAPSyncHistory, error)
	GetByProviderID(ctx context.Context, providerID uuid.UUID, limit, offset int) ([]*models.LDAPSyncHistory, int, error)
	DeleteOlderThan(ctx context.Context, olderThan time.Duration) (int64, error)
}

// adSyncServiceIDPRepo defines the identity provider repository methods needed by ADSyncService.
type adSyncServiceIDPRepo interface {
	GetAllByType(ctx context.Context, providerType string) ([]*models.IdentityProvider, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.IdentityProvider, error)
}

const msgADSyncProviderNotFound = "provider not found"

// ADSyncService handles AD synchronization scheduling and orchestration
type ADSyncService struct {
	config       *config.Config
	ldapService  *LDAPService
	syncRepo     adSyncServiceSyncRepo
	historyRepo  adSyncServiceHistoryRepo
	idpRepo      adSyncServiceIDPRepo
	auditService *AuditService

	syncMutex sync.Mutex
	isRunning atomic.Bool
	stopChan  chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
}

// SyncStatusResponse represents the current sync status for a provider
type SyncStatusResponse struct {
	ProviderID       uuid.UUID  `json:"provider_id"`
	ProviderName     string     `json:"provider_name"`
	IsRunning        bool       `json:"is_running"`
	LastSyncAt       *time.Time `json:"last_sync_at,omitempty"`
	LastSyncStatus   string     `json:"last_sync_status,omitempty"`
	LastSyncMessage  string     `json:"last_sync_message,omitempty"`
	NextSyncAt       *time.Time `json:"next_sync_at,omitempty"`
	SyncEnabled      bool       `json:"sync_enabled"`
	SyncInterval     string     `json:"sync_interval,omitempty"`
	UsersTotal       int        `json:"users_total"`
	GroupsTotal      int        `json:"groups_total"`
	PendingConflicts int        `json:"pending_conflicts"`
}

// SyncHistoryResponse represents paginated sync history
type SyncHistoryResponse struct {
	History []*models.LDAPSyncHistory `json:"history"`
	Total   int                       `json:"total"`
	Page    int                       `json:"page"`
	Limit   int                       `json:"limit"`
}

// TriggerSyncRequest represents a manual sync trigger request
type TriggerSyncRequest struct {
	ProviderID  uuid.UUID  `json:"provider_id" binding:"required"`
	FullSync    bool       `json:"full_sync"`
	SyncGroups  bool       `json:"sync_groups"`
	TriggeredBy *uuid.UUID `json:"triggered_by,omitempty"`
}

// TriggerSyncResponse represents the response from a sync trigger
type TriggerSyncResponse struct {
	SyncID     uuid.UUID `json:"sync_id"`
	Status     string    `json:"status"`
	Message    string    `json:"message"`
	ProviderID uuid.UUID `json:"provider_id"`
}

// NewADSyncService creates a new AD sync service
func NewADSyncService(
	cfg *config.Config,
	ldapService *LDAPService,
	syncRepo adSyncServiceSyncRepo,
	historyRepo adSyncServiceHistoryRepo,
	idpRepo adSyncServiceIDPRepo,
) *ADSyncService {
	return &ADSyncService{
		config:      cfg,
		ldapService: ldapService,
		syncRepo:    syncRepo,
		historyRepo: historyRepo,
		idpRepo:     idpRepo,
		stopChan:    make(chan struct{}),
	}
}

// SetAuditService sets the audit service for logging sync events
func (s *ADSyncService) SetAuditService(auditService *AuditService) {
	s.auditService = auditService
}

// StartScheduler starts the background sync scheduler
func (s *ADSyncService) StartScheduler(ctx context.Context) {
	if !s.config.ADSyncEnabled {
		logger.Info("AD sync scheduler disabled by configuration")
		return
	}

	interval := s.config.ADSyncDefaultInterval
	if interval <= 0 {
		interval = 1 * time.Hour // Default to 1 hour
	}

	logger.Info("Starting AD sync scheduler",
		zap.Duration("interval", interval),
	)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		// Run initial sync after a short delay
		initialDelay := 30 * time.Second
		select {
		case <-time.After(initialDelay):
			s.runScheduledSync(ctx)
		case <-s.stopChan:
			return
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.runScheduledSync(ctx)
			case <-s.stopChan:
				logger.Info("AD sync scheduler stopped")
				return
			case <-ctx.Done():
				logger.Info("AD sync scheduler context cancelled")
				return
			}
		}
	}()
}

// StopScheduler gracefully stops the background scheduler
func (s *ADSyncService) StopScheduler() {
	s.stopOnce.Do(func() {
		close(s.stopChan)
	})
	s.wg.Wait()
	logger.Info("AD sync scheduler shutdown complete")
}

// runScheduledSync runs sync for all enabled providers
func (s *ADSyncService) runScheduledSync(ctx context.Context) {
	logger.Info("Running scheduled AD sync")

	providers, err := s.idpRepo.GetAllByType(ctx, federationTypeLDAP)
	if err != nil {
		logger.Error("Failed to get LDAP providers for scheduled sync", zap.Error(err))
		return
	}

	for _, provider := range providers {
		if s.isProviderSyncDue(ctx, *provider) {
			s.triggerProviderSync(ctx, *provider)
		}
	}
}

// isProviderSyncDue returns true when the given provider is enabled, sync is
// configured, and enough time has elapsed since the last successful sync.
func (s *ADSyncService) isProviderSyncDue(ctx context.Context, provider models.IdentityProvider) bool {
	if !provider.IsEnabled {
		return false
	}
	if provider.LDAPConfig == nil || !provider.LDAPConfig.SyncEnabled {
		return false
	}
	if provider.LDAPConfig.SyncInterval <= 0 {
		return true
	}
	lastSync, _ := s.historyRepo.GetLatestByProviderID(ctx, provider.ID)
	if lastSync == nil || lastSync.CompletedAt == nil {
		return true
	}
	nextSync := lastSync.CompletedAt.Add(time.Duration(provider.LDAPConfig.SyncInterval) * time.Minute)
	return !time.Now().Before(nextSync)
}

// triggerProviderSync triggers an incremental sync for a single provider and
// logs the outcome.
func (s *ADSyncService) triggerProviderSync(ctx context.Context, provider models.IdentityProvider) {
	logger.Info("Triggering scheduled sync for provider",
		zap.String("provider", provider.Name),
		zap.String("provider_id", provider.ID.String()),
	)
	_, err := s.TriggerSync(ctx, TriggerSyncRequest{
		ProviderID:  provider.ID,
		FullSync:    false,
		SyncGroups:  provider.LDAPConfig.SyncGroups,
		TriggeredBy: nil,
	})
	if err != nil {
		logger.Error("Scheduled sync failed for provider",
			zap.String("provider", provider.Name),
			zap.Error(err),
		)
	}
}

// TriggerSync manually triggers a sync for a specific provider
func (s *ADSyncService) TriggerSync(ctx context.Context, req TriggerSyncRequest) (*TriggerSyncResponse, error) {
	// Try to acquire the sync lock
	if !s.syncMutex.TryLock() {
		return nil, fmt.Errorf("another sync is already in progress")
	}
	defer s.syncMutex.Unlock()

	// Get the provider
	provider, err := s.idpRepo.GetByID(ctx, req.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}
	if provider == nil {
		return nil, errors.New(msgADSyncProviderNotFound)
	}
	if !provider.IsEnabled {
		return nil, fmt.Errorf("provider is disabled")
	}

	// Create sync history record
	syncID := uuid.New()
	syncType := "manual"
	if req.FullSync {
		syncType = "full"
	}

	history := &models.LDAPSyncHistory{
		ID:           syncID,
		TenantID:     provider.TenantID,
		ProviderID:   provider.ID,
		ProviderName: provider.Name,
		SyncType:     syncType,
		Status:       "running",
		StartedAt:    time.Now(),
		TriggeredBy:  req.TriggeredBy,
	}

	if err := s.historyRepo.Create(ctx, history); err != nil {
		return nil, fmt.Errorf("failed to create sync history: %w", err)
	}

	s.isRunning.Store(true)

	// Run sync
	result, syncErr := s.runSync(ctx, provider, req.FullSync, req.SyncGroups)

	s.isRunning.Store(false)

	// Update history with results
	now := time.Now()
	history.CompletedAt = &now
	history.DurationMs = now.Sub(history.StartedAt).Milliseconds()

	if syncErr != nil {
		history.Status = DeletionOverallFailed
		history.Message = syncErr.Error()
		history.Errors = append(history.Errors, syncErr.Error())
	} else {
		history.Status = DeletionOverallCompleted
		history.UsersFound = result.UsersFound
		history.UsersCreated = result.UsersCreated
		history.UsersUpdated = result.UsersUpdated
		history.UsersDisabled = result.UsersDisabled
		history.Errors = result.Errors
		history.Message = result.Message
	}

	if err := s.historyRepo.Update(ctx, history); err != nil {
		logger.Error("Failed to update sync history", zap.Error(err))
	}

	// Log audit event
	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, provider.TenantID, req.TriggeredBy, nil, "ad_sync_completed", history.Status == DeletionOverallCompleted, map[string]interface{}{
			"provider_id":    provider.ID.String(),
			"provider_name":  provider.Name,
			"sync_type":      syncType,
			"status":         history.Status,
			"users_found":    history.UsersFound,
			"users_created":  history.UsersCreated,
			"users_updated":  history.UsersUpdated,
			"users_disabled": history.UsersDisabled,
			"duration_ms":    history.DurationMs,
		})
	}

	response := &TriggerSyncResponse{
		SyncID:     syncID,
		ProviderID: provider.ID,
	}

	if syncErr != nil {
		response.Status = DeletionOverallFailed
		response.Message = syncErr.Error()
		return response, nil // Return response even on failure
	}

	response.Status = DeletionOverallCompleted
	response.Message = history.Message
	return response, nil
}

// runSync executes the actual sync using LDAPService
func (s *ADSyncService) runSync(ctx context.Context, provider *models.IdentityProvider, fullSync, syncGroups bool) (*models.LDAPSyncResult, error) {
	logger.Info("Starting AD sync",
		zap.String("provider", provider.Name),
		zap.Bool("full_sync", fullSync),
		zap.Bool("sync_groups", syncGroups),
	)

	// Update sync state to running
	syncState := &models.ADSyncState{
		TenantID:         provider.TenantID,
		ProviderID:       provider.ID,
		DomainController: provider.LDAPConfig.Host,
		SyncStatus:       models.SyncStatusSyncing,
	}
	_ = s.syncRepo.UpsertSyncState(ctx, syncState)

	// Run user sync using existing LDAPService
	result, err := s.ldapService.SyncUsers(ctx, provider.ID, fullSync)
	if err != nil {
		// Update sync state to error
		errMsg := err.Error()
		syncState.SyncStatus = models.SyncStatusError
		syncState.ErrorMessage = &errMsg
		_ = s.syncRepo.UpsertSyncState(ctx, syncState)
		return nil, fmt.Errorf("runSync: %w", err)
	}

	// Sync groups if requested
	if syncGroups && provider.LDAPConfig.SyncGroups {
		groupsCreated, groupsUpdated, groupErr := s.ldapService.SyncGroups(ctx, provider.ID, provider.TenantID)
		if groupErr != nil {
			logger.Error("Group sync failed", zap.Error(groupErr))
			result.Errors = append(result.Errors, fmt.Sprintf("Group sync failed: %v", groupErr))
		} else {
			logger.Info("Group sync completed",
				zap.Int("created", groupsCreated),
				zap.Int("updated", groupsUpdated),
			)
		}
	}

	// Update sync state to complete
	now := time.Now()
	syncState.SyncStatus = models.SyncStatusComplete
	syncState.LastSyncAt = &now
	if fullSync {
		syncState.LastFullSyncAt = &now
	}
	syncState.ErrorMessage = nil
	_ = s.syncRepo.UpsertSyncState(ctx, syncState)

	logger.Info("AD sync completed",
		zap.String("provider", provider.Name),
		zap.Int("users_found", result.UsersFound),
		zap.Int("users_created", result.UsersCreated),
		zap.Int("users_updated", result.UsersUpdated),
		zap.Int("users_disabled", result.UsersDisabled),
		zap.String("duration", result.Duration),
	)

	return result, nil
}

// GetSyncStatus returns the current sync status for a provider
func (s *ADSyncService) GetSyncStatus(ctx context.Context, providerID uuid.UUID) (*SyncStatusResponse, error) {
	provider, err := s.idpRepo.GetByID(ctx, providerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}
	if provider == nil {
		return nil, errors.New(msgADSyncProviderNotFound)
	}

	response := &SyncStatusResponse{
		ProviderID:   provider.ID,
		ProviderName: provider.Name,
		IsRunning:    s.isRunning.Load(),
		SyncEnabled:  provider.LDAPConfig != nil && provider.LDAPConfig.SyncEnabled,
	}

	if provider.LDAPConfig != nil && provider.LDAPConfig.SyncInterval > 0 {
		syncInterval := time.Duration(provider.LDAPConfig.SyncInterval) * time.Minute
		response.SyncInterval = syncInterval.String()
	}

	// Get latest sync history
	lastSync, err := s.historyRepo.GetLatestByProviderID(ctx, providerID)
	if err == nil && lastSync != nil {
		response.LastSyncAt = &lastSync.StartedAt
		response.LastSyncStatus = lastSync.Status
		response.LastSyncMessage = lastSync.Message
		response.UsersTotal = lastSync.UsersFound
		response.GroupsTotal = lastSync.GroupsFound

		// Calculate next sync time
		if provider.LDAPConfig != nil && provider.LDAPConfig.SyncInterval > 0 && lastSync.CompletedAt != nil {
			syncInterval := time.Duration(provider.LDAPConfig.SyncInterval) * time.Minute
			nextSync := lastSync.CompletedAt.Add(syncInterval)
			response.NextSyncAt = &nextSync
		}
	}

	// Get pending conflicts count
	conflicts, err := s.syncRepo.GetPendingConflicts(ctx, provider.TenantID, providerID)
	if err == nil {
		response.PendingConflicts = len(conflicts)
	}

	return response, nil
}

// GetSyncHistory returns paginated sync history for a provider
func (s *ADSyncService) GetSyncHistory(ctx context.Context, providerID uuid.UUID, page, limit int) (*SyncHistoryResponse, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit

	history, total, err := s.historyRepo.GetByProviderID(ctx, providerID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get sync history: %w", err)
	}

	return &SyncHistoryResponse{
		History: history,
		Total:   total,
		Page:    page,
		Limit:   limit,
	}, nil
}

// GetSyncStats returns sync statistics for a tenant
func (s *ADSyncService) GetSyncStats(ctx context.Context, tenantID uuid.UUID) (map[string]interface{}, error) {
	return s.syncRepo.GetSyncStatsByTenant(ctx, tenantID)
}

// GetPendingConflicts returns unresolved sync conflicts
func (s *ADSyncService) GetPendingConflicts(ctx context.Context, tenantID, providerID uuid.UUID) ([]models.ADSyncConflict, error) {
	return s.syncRepo.GetPendingConflicts(ctx, tenantID, providerID)
}

// ValidateProviderTenant checks that the given identity provider belongs to the given tenant.
func (s *ADSyncService) ValidateProviderTenant(ctx context.Context, providerID, tenantID uuid.UUID) error {
	provider, err := s.idpRepo.GetByID(ctx, providerID)
	if err != nil {
		return errors.New(msgADSyncProviderNotFound)
	}
	if provider == nil {
		return errors.New(msgADSyncProviderNotFound)
	}
	if provider.TenantID != tenantID {
		return errors.New(msgADSyncProviderNotFound)
	}
	return nil
}

// GetConflictTenantID retrieves the tenant ID for a sync conflict via its provider.
func (s *ADSyncService) GetConflictTenantID(ctx context.Context, conflictID uuid.UUID) (uuid.UUID, error) {
	return s.syncRepo.GetConflictTenantID(ctx, conflictID)
}

// ResolveConflict resolves a sync conflict
func (s *ADSyncService) ResolveConflict(ctx context.Context, conflictID uuid.UUID, resolution string, details map[string]interface{}, resolvedBy uuid.UUID) error {
	return s.syncRepo.ResolveConflict(ctx, conflictID, resolution, details, resolvedBy)
}

// CleanupOldHistory removes sync history older than the retention period
func (s *ADSyncService) CleanupOldHistory(ctx context.Context, retention time.Duration) (int64, error) {
	return s.historyRepo.DeleteOlderThan(ctx, retention)
}

// IsRunning returns whether a sync is currently in progress
func (s *ADSyncService) IsRunning() bool {
	return s.isRunning.Load()
}

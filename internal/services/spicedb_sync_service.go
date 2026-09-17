// SPDX-License-Identifier: AGPL-3.0-or-later

// Package services provides the SpiceDB synchronization service.
// This service keeps SpiceDB relationships in sync with the database
// when users, roles, or permissions change.
package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

// SpiceDBSyncService handles synchronization of authorization relationships to SpiceDB.
// It implements a dual-write pattern where changes are written to both the database
// and SpiceDB to maintain consistency.
type SpiceDBSyncService struct {
	client *spicedb.Client

	// Async write queue for non-blocking operations
	writeQueue chan *syncOperation
	wg         sync.WaitGroup
	stopCh     chan struct{}
	stopOnce   sync.Once

	// Metrics
	mu           sync.RWMutex
	syncCount    int64
	errorCount   int64
	lastSyncTime time.Time
}

type syncOperation struct {
	opType    string
	tenantID  uuid.UUID
	userID    uuid.UUID
	roleID    uuid.UUID
	retries   int
	createdAt time.Time
}

// NewSpiceDBSyncService creates a new sync service
func NewSpiceDBSyncService(client *spicedb.Client) *SpiceDBSyncService {
	s := &SpiceDBSyncService{
		client:     client,
		writeQueue: make(chan *syncOperation, 1000),
		stopCh:     make(chan struct{}),
	}

	// Start background worker
	s.wg.Add(1)
	go s.worker()

	return s
}

// Stop gracefully shuts down the sync service
func (s *SpiceDBSyncService) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
	s.wg.Wait()
}

// worker processes sync operations from the queue
func (s *SpiceDBSyncService) worker() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopCh:
			s.drainWithDeadline()
			return

		case op := <-s.writeQueue:
			s.processOperation(op)
		}
	}
}

// drainWithDeadline processes remaining queue items on shutdown with a 30-second deadline.
func (s *SpiceDBSyncService) drainWithDeadline() {
	deadline := time.Now().Add(30 * time.Second)
	for {
		if time.Now().After(deadline) {
			remaining := len(s.writeQueue)
			if remaining > 0 {
				logger.Log.Warn("SpiceDB sync shutdown drain timed out", zap.Int("dropped_operations", remaining))
			}
			return
		}
		select {
		case op := <-s.writeQueue:
			s.processOperation(op)
		default:
			return
		}
	}
}

func (s *SpiceDBSyncService) processOperation(op *syncOperation) {
	// Always use a fresh context with timeout - never reuse the stored context
	// which may have been cancelled (especially during shutdown drain or retries)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error

	switch op.opType {
	case "user_role_add":
		_, err = s.client.WriteUserRole(ctx, op.tenantID, op.userID, op.roleID)
	case "user_role_remove":
		_, err = s.client.DeleteUserRole(ctx, op.tenantID, op.userID, op.roleID)
	case "user_tenant_add":
		_, err = s.client.WriteUserTenant(ctx, op.tenantID, op.userID, "member")
	case "user_tenant_admin":
		_, err = s.client.WriteUserTenant(ctx, op.tenantID, op.userID, "admin")
	default:
		logger.Log.Warn("Unknown sync operation type", zap.String("type", op.opType))
		return
	}

	s.mu.Lock()
	if err != nil {
		s.errorCount++
		logger.Log.Error("SpiceDB sync operation failed",
			zap.String("operation", op.opType),
			zap.String("tenant_id", op.tenantID.String()),
			zap.String("user_id", op.userID.String()),
			zap.Int("retry", op.retries),
			zap.Error(err),
		)

		// Retry logic with limit
		if op.retries < 3 {
			op.retries++
			select {
			case s.writeQueue <- op:
			default:
				logger.Log.Error("SpiceDB sync queue full, dropping retry",
					zap.String("operation", op.opType),
					zap.String("user_id", op.userID.String()),
				)
			}
		} else {
			logger.Log.Error("SpiceDB sync operation exhausted retries",
				zap.String("operation", op.opType),
				zap.String("tenant_id", op.tenantID.String()),
				zap.String("user_id", op.userID.String()),
			)
		}
	} else {
		s.syncCount++
		s.lastSyncTime = time.Now()
	}
	s.mu.Unlock()
}

// SyncUserRoleAssignment syncs a user-role assignment to SpiceDB.
// Returns the ZedToken from the write for use with AtLeastAsFresh consistency.
func (s *SpiceDBSyncService) SyncUserRoleAssignment(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error) {
	if s.client == nil {
		return "", fmt.Errorf("SpiceDB client not initialized")
	}

	// Synchronous write for immediate consistency
	token, err := s.client.WriteUserRole(ctx, tenantID, userID, roleID)
	if err != nil {
		logger.Log.Error("Failed to sync user role assignment to SpiceDB",
			zap.String("tenant_id", tenantID.String()),
			zap.String("user_id", userID.String()),
			zap.String("role_id", roleID.String()),
			zap.Error(err),
		)
		return "", fmt.Errorf("SyncUserRoleAssignment: %w", err)
	}

	s.mu.Lock()
	s.syncCount++
	s.lastSyncTime = time.Now()
	s.mu.Unlock()

	logger.Log.Info("Synced user role assignment to SpiceDB",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.String("role_id", roleID.String()),
		zap.Bool("has_zed_token", token != ""),
	)
	return token, nil
}

// SyncUserRoleRemoval syncs a user-role removal to SpiceDB.
// Returns the ZedToken from the delete for use with AtLeastAsFresh consistency.
func (s *SpiceDBSyncService) SyncUserRoleRemoval(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error) {
	if s.client == nil {
		return "", fmt.Errorf("SpiceDB client not initialized")
	}

	token, err := s.client.DeleteUserRole(ctx, tenantID, userID, roleID)
	if err != nil {
		logger.Log.Error("Failed to sync user role removal to SpiceDB",
			zap.String("tenant_id", tenantID.String()),
			zap.String("user_id", userID.String()),
			zap.String("role_id", roleID.String()),
			zap.Error(err),
		)
		return "", fmt.Errorf("SyncUserRoleRemoval: %w", err)
	}

	s.mu.Lock()
	s.syncCount++
	s.lastSyncTime = time.Now()
	s.mu.Unlock()

	logger.Log.Info("Synced user role removal to SpiceDB",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.String("role_id", roleID.String()),
		zap.Bool("has_zed_token", token != ""),
	)
	return token, nil
}

// SyncUserTenantMembership syncs a user's tenant membership to SpiceDB.
// Returns the ZedToken from the write for use with AtLeastAsFresh consistency.
func (s *SpiceDBSyncService) SyncUserTenantMembership(ctx context.Context, tenantID, userID uuid.UUID, isAdmin bool) (string, error) {
	if s.client == nil {
		return "", fmt.Errorf("SpiceDB client not initialized")
	}

	relation := "member"
	if isAdmin {
		relation = "admin"
	}

	token, err := s.client.WriteUserTenant(ctx, tenantID, userID, relation)
	if err != nil {
		logger.Log.Error("Failed to sync user tenant membership to SpiceDB",
			zap.String("tenant_id", tenantID.String()),
			zap.String("user_id", userID.String()),
			zap.String("relation", relation),
			zap.Error(err),
		)
		return "", fmt.Errorf("SyncUserTenantMembership: %w", err)
	}

	s.mu.Lock()
	s.syncCount++
	s.lastSyncTime = time.Now()
	s.mu.Unlock()

	return token, nil
}

// SyncUserRoleAssignmentAsync queues a user-role assignment for async sync
func (s *SpiceDBSyncService) SyncUserRoleAssignmentAsync(_ context.Context, tenantID, userID, roleID uuid.UUID) {
	select {
	case s.writeQueue <- &syncOperation{
		opType:    "user_role_add",
		tenantID:  tenantID,
		userID:    userID,
		roleID:    roleID,
		createdAt: time.Now(),
	}:
	default:
		logger.Log.Warn("SpiceDB sync queue full, dropping operation",
			zap.String("operation", "user_role_add"),
			zap.String("user_id", userID.String()),
		)
	}
}

// SyncUserRoleRemovalAsync queues a user-role removal for async sync
func (s *SpiceDBSyncService) SyncUserRoleRemovalAsync(_ context.Context, tenantID, userID, roleID uuid.UUID) {
	select {
	case s.writeQueue <- &syncOperation{
		opType:    "user_role_remove",
		tenantID:  tenantID,
		userID:    userID,
		roleID:    roleID,
		createdAt: time.Now(),
	}:
	default:
		logger.Log.Warn("SpiceDB sync queue full, dropping operation",
			zap.String("operation", "user_role_remove"),
			zap.String("user_id", userID.String()),
		)
	}
}

// CheckPermission checks if a user has a permission via SpiceDB
func (s *SpiceDBSyncService) CheckPermission(ctx context.Context, tenantID, userID uuid.UUID, permission string) (bool, error) {
	if s.client == nil {
		return false, fmt.Errorf("SpiceDB client not initialized")
	}

	return s.client.CheckPermission(ctx, tenantID, userID, "permission", permission, "check")
}

// CheckRole checks if a user has a role via SpiceDB
func (s *SpiceDBSyncService) CheckRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (bool, error) {
	if s.client == nil {
		return false, fmt.Errorf("SpiceDB client not initialized")
	}

	return s.client.CheckPermission(ctx, tenantID, userID, "role", roleID.String(), "view")
}

// GetUserRoles returns all roles for a user from SpiceDB
func (s *SpiceDBSyncService) GetUserRoles(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	if s.client == nil {
		return nil, fmt.Errorf("SpiceDB client not initialized")
	}

	return s.client.LookupUserRoles(ctx, tenantID, userID)
}

// Metrics returns sync service metrics
func (s *SpiceDBSyncService) Metrics() SyncMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return SyncMetrics{
		SyncCount:    s.syncCount,
		ErrorCount:   s.errorCount,
		LastSyncTime: s.lastSyncTime,
		QueueSize:    len(s.writeQueue),
	}
}

// SyncMetrics contains sync service metrics
type SyncMetrics struct {
	SyncCount    int64
	ErrorCount   int64
	LastSyncTime time.Time
	QueueSize    int
}

// SyncApplicationOwnership syncs an application's owner tenant relationship to SpiceDB.
func (s *SpiceDBSyncService) SyncApplicationOwnership(ctx context.Context, appID, ownerTenantID uuid.UUID) error {
	if s.client == nil {
		return fmt.Errorf("SpiceDB client not initialized")
	}

	_, err := s.client.WriteRelationship(ctx, "application", appID.String(), "owner", "tenant", ownerTenantID.String())
	if err != nil {
		logger.Log.Error("Failed to sync application ownership to SpiceDB",
			zap.String("app_id", appID.String()),
			zap.String("owner_tenant_id", ownerTenantID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("SyncApplicationOwnership: %w", err)
	}

	s.mu.Lock()
	s.syncCount++
	s.lastSyncTime = time.Now()
	s.mu.Unlock()

	return nil
}

// SyncApplicationConsent syncs an application consent (tenant granted admin consent) to SpiceDB.
func (s *SpiceDBSyncService) SyncApplicationConsent(ctx context.Context, appID, tenantID uuid.UUID) error {
	if s.client == nil {
		return fmt.Errorf("SpiceDB client not initialized")
	}

	_, err := s.client.WriteRelationship(ctx, "application", appID.String(), "consented_tenant", "tenant", tenantID.String())
	if err != nil {
		logger.Log.Error("Failed to sync application consent to SpiceDB",
			zap.String("app_id", appID.String()),
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("SyncApplicationConsent: %w", err)
	}

	s.mu.Lock()
	s.syncCount++
	s.lastSyncTime = time.Now()
	s.mu.Unlock()

	return nil
}

// SyncApplicationConsentRemoval removes an application consent relationship from SpiceDB.
func (s *SpiceDBSyncService) SyncApplicationConsentRemoval(ctx context.Context, appID, tenantID uuid.UUID) error {
	if s.client == nil {
		return fmt.Errorf("SpiceDB client not initialized")
	}

	err := s.client.DeleteRelationship(ctx, "application", appID.String(), "consented_tenant", "tenant", tenantID.String())
	if err != nil {
		logger.Log.Error("Failed to remove application consent from SpiceDB",
			zap.String("app_id", appID.String()),
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("SyncApplicationConsentRemoval: %w", err)
	}

	s.mu.Lock()
	s.syncCount++
	s.lastSyncTime = time.Now()
	s.mu.Unlock()

	return nil
}

// SyncServicePrincipal syncs a service principal's relationships to SpiceDB.
func (s *SpiceDBSyncService) SyncServicePrincipal(ctx context.Context, spID, appID, tenantID, ownerUserID uuid.UUID) error {
	if s.client == nil {
		return fmt.Errorf("SpiceDB client not initialized")
	}

	// Write application relationship
	_, err := s.client.WriteRelationship(ctx, "service_principal", spID.String(), "application", "application", appID.String())
	if err != nil {
		logger.Log.Error("Failed to sync SP application relationship to SpiceDB",
			zap.String("sp_id", spID.String()),
			zap.String("app_id", appID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("SyncServicePrincipal (application): %w", err)
	}

	// Write tenant relationship
	_, err = s.client.WriteRelationship(ctx, "service_principal", spID.String(), "tenant", "tenant", tenantID.String())
	if err != nil {
		logger.Log.Error("Failed to sync SP tenant relationship to SpiceDB",
			zap.String("sp_id", spID.String()),
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("SyncServicePrincipal (tenant): %w", err)
	}

	// Write owner relationship
	if ownerUserID != uuid.Nil {
		_, err = s.client.WriteRelationship(ctx, "service_principal", spID.String(), "owner", "user", ownerUserID.String())
		if err != nil {
			logger.Log.Error("Failed to sync SP owner relationship to SpiceDB",
				zap.String("sp_id", spID.String()),
				zap.String("owner_id", ownerUserID.String()),
				zap.Error(err),
			)
			return fmt.Errorf("SyncServicePrincipal (owner): %w", err)
		}
	}

	s.mu.Lock()
	s.syncCount++
	s.lastSyncTime = time.Now()
	s.mu.Unlock()

	return nil
}

// SyncServicePrincipalRemoval removes a service principal's relationships from SpiceDB.
// Requires the known subject IDs so that individual delete calls can be made.
func (s *SpiceDBSyncService) SyncServicePrincipalRemoval(ctx context.Context, spID, appID, tenantID, ownerUserID uuid.UUID) error {
	if s.client == nil {
		return fmt.Errorf("SpiceDB client not initialized")
	}

	// Delete application relationship
	if err := s.client.DeleteRelationship(ctx, "service_principal", spID.String(), "application", "application", appID.String()); err != nil {
		logger.Log.Warn("Failed to remove SP→application from SpiceDB (non-fatal)",
			zap.String("sp_id", spID.String()),
			zap.Error(err),
		)
	}

	// Delete tenant relationship
	if err := s.client.DeleteRelationship(ctx, "service_principal", spID.String(), "tenant", "tenant", tenantID.String()); err != nil {
		logger.Log.Warn("Failed to remove SP→tenant from SpiceDB (non-fatal)",
			zap.String("sp_id", spID.String()),
			zap.Error(err),
		)
	}

	// Delete owner relationship
	if ownerUserID != uuid.Nil {
		if err := s.client.DeleteRelationship(ctx, "service_principal", spID.String(), "owner", "user", ownerUserID.String()); err != nil {
			logger.Log.Warn("Failed to remove SP→owner from SpiceDB (non-fatal)",
				zap.String("sp_id", spID.String()),
				zap.Error(err),
			)
		}
	}

	s.mu.Lock()
	s.syncCount++
	s.lastSyncTime = time.Now()
	s.mu.Unlock()

	return nil
}

// IsHealthy returns true if the sync service is functioning properly
func (s *SpiceDBSyncService) IsHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Unhealthy if error rate is too high
	if s.syncCount > 0 {
		errorRate := float64(s.errorCount) / float64(s.syncCount)
		if errorRate > 0.1 { // More than 10% errors
			return false
		}
	}

	// Unhealthy if queue is backing up
	if len(s.writeQueue) > 800 { // 80% of capacity
		return false
	}

	return true
}

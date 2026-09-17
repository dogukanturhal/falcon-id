// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// spSignInRepo is the repository interface consumed by SPSignInActivityService.
// Keeping it narrow lets callers supply any conforming type in tests.
type spSignInRepo interface {
	Record(ctx context.Context, a *models.SPSignInActivity) error
	ListBySP(ctx context.Context, spID uuid.UUID, limit int) ([]models.SPSignInActivity, error)
	ListByApp(ctx context.Context, appID uuid.UUID, limit int) ([]models.SPSignInActivity, error)
	GetLastSignIn(ctx context.Context, spID uuid.UUID) (*models.SPSignInActivity, error)
	CountByAppSince(ctx context.Context, appID uuid.UUID, since time.Time) (int, error)
}

// SPSignInActivityService records and queries service-principal authentication events.
type SPSignInActivityService struct {
	repo spSignInRepo
}

// NewSPSignInActivityService creates a new SPSignInActivityService.
func NewSPSignInActivityService(repo spSignInRepo) *SPSignInActivityService {
	return &SPSignInActivityService{repo: repo}
}

// RecordSignIn persists a sign-in event. SignedInAt is set to now if not provided.
func (s *SPSignInActivityService) RecordSignIn(ctx context.Context, activity *models.SPSignInActivity) error {
	if activity.SignedInAt.IsZero() {
		activity.SignedInAt = time.Now()
	}
	if err := s.repo.Record(ctx, activity); err != nil {
		return fmt.Errorf("SPSignInActivityService.RecordSignIn: %w", err)
	}
	return nil
}

// ListBySP returns recent sign-in events for a specific service principal.
func (s *SPSignInActivityService) ListBySP(ctx context.Context, spID uuid.UUID, limit int) ([]models.SPSignInActivity, error) {
	activities, err := s.repo.ListBySP(ctx, spID, limit)
	if err != nil {
		return nil, fmt.Errorf("SPSignInActivityService.ListBySP: %w", err)
	}
	return activities, nil
}

// ListByApp returns recent sign-in events across all SPs for an application.
func (s *SPSignInActivityService) ListByApp(ctx context.Context, appID uuid.UUID, limit int) ([]models.SPSignInActivity, error) {
	activities, err := s.repo.ListByApp(ctx, appID, limit)
	if err != nil {
		return nil, fmt.Errorf("SPSignInActivityService.ListByApp: %w", err)
	}
	return activities, nil
}

// GetLastSignIn returns the most recent successful sign-in for a service principal.
// Returns a wrapped pgx.ErrNoRows when no successful sign-in has been recorded.
func (s *SPSignInActivityService) GetLastSignIn(ctx context.Context, spID uuid.UUID) (*models.SPSignInActivity, error) {
	activity, err := s.repo.GetLastSignIn(ctx, spID)
	if err != nil {
		return nil, fmt.Errorf("SPSignInActivityService.GetLastSignIn: %w", err)
	}
	return activity, nil
}

// HasRecentActivity reports whether an application has had any sign-in events
// (success or failure) within the last n days.
func (s *SPSignInActivityService) HasRecentActivity(ctx context.Context, appID uuid.UUID, days int) (bool, error) {
	since := time.Now().AddDate(0, 0, -days)
	count, err := s.repo.CountByAppSince(ctx, appID, since)
	if err != nil {
		return false, fmt.Errorf("SPSignInActivityService.HasRecentActivity: %w", err)
	}
	return count > 0, nil
}

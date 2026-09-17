// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ===== ITDR Models (Agent 1D) =====

// ITDRThreat represents a detected identity threat event.
type ITDRThreat struct {
	ID          uuid.UUID         `json:"id"`
	TenantID    uuid.UUID         `json:"tenant_id"`
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Status      string            `json:"status"`
	Description string            `json:"description"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	DetectedAt  time.Time         `json:"detected_at"`
	AckedAt     *time.Time        `json:"acked_at,omitempty"`
	AckedBy     *uuid.UUID        `json:"acked_by,omitempty"`
}

// ITDRDetectionRule — canonical definition is in itdr.go
// SSFStreamStatus, SSFStream — canonical definitions are in ssf.go

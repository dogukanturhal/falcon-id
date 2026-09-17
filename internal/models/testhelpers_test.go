// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// Shared pointer-helper functions used across model test files.

func boolPtr(b bool) *bool           { return &b }
func strPtr(s string) *string        { return &s }
func timePtr(t time.Time) *time.Time { return &t }
func uuidPtr(u uuid.UUID) *uuid.UUID { return &u }

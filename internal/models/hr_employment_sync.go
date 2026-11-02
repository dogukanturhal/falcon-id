// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "github.com/google/uuid"

// HREmploymentDesiredState is the versioned, HR-owned employment projection. It intentionally has no job-title role mapping.
type HREmploymentDesiredState struct {
	EventID             uuid.UUID  `json:"eventId"`
	ContractVersion     int        `json:"contractVersion"`
	LegalEntityID       uuid.UUID  `json:"legalEntityId"`
	RelationshipVersion int64      `json:"relationshipVersion"`
	ScopeVersion        int64      `json:"scopeVersion"`
	DesiredState        string     `json:"desiredState"`
	DepartmentID        *uuid.UUID `json:"departmentId"`
	ManagerEmployeeID   *uuid.UUID `json:"managerEmployeeId"`
	WorkEmail           string     `json:"workEmail"`
	IAMUserID           *uuid.UUID `json:"iamUserId"`
	ConfirmedIAMUserID  *uuid.UUID `json:"confirmedIamUserId,omitempty"`
	ManualApproved      bool       `json:"manualApproved"`
	ManualReviewActorID *uuid.UUID `json:"manualReviewActorId,omitempty"`
	ManualReviewReason  string     `json:"manualReviewReason,omitempty"`
}

type HREmploymentSyncOutcome struct {
	Outcome            string     `json:"outcome"`
	LinkedIAMUserID    *uuid.UUID `json:"linkedIamUserId,omitempty"`
	CandidateIAMUserID *uuid.UUID `json:"candidateIamUserId,omitempty"`
	Reason             string     `json:"reason,omitempty"`
}

type HREmploymentScope struct { LegalEntityID uuid.UUID `json:"legalEntityId"`; Mode string `json:"mode"`; Enabled bool `json:"enabled"`; ScopeVersion int64 `json:"scopeVersion"` }

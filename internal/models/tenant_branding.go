// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// TenantBranding holds the visual customisation settings for a tenant's login experience.
// All colour fields are expected to be valid CSS hex colour strings (e.g. "#1A2B3C").
// Pointer fields are optional; omitting them keeps the platform defaults visible to end users.
type TenantBranding struct {
	ID                   uuid.UUID `json:"id" db:"id"`
	TenantID             uuid.UUID `json:"tenant_id" db:"tenant_id"`
	LogoURL              *string   `json:"logo_url,omitempty" db:"logo_url"`
	FaviconURL           *string   `json:"favicon_url,omitempty" db:"favicon_url"`
	PrimaryColor         string    `json:"primary_color" db:"primary_color"`
	BackgroundColor      string    `json:"background_color" db:"background_color"`
	AccentColor          *string   `json:"accent_color,omitempty" db:"accent_color"`
	CustomCSS            *string   `json:"custom_css,omitempty" db:"custom_css"`
	LoginTitle           *string   `json:"login_title,omitempty" db:"login_title"`
	LoginSubtitle        *string   `json:"login_subtitle,omitempty" db:"login_subtitle"`
	LoginMessage         *string   `json:"login_message,omitempty" db:"login_message"`
	SupportEmail         *string   `json:"support_email,omitempty" db:"support_email"`
	SupportURL           *string   `json:"support_url,omitempty" db:"support_url"`
	PrivacyPolicyURL     *string   `json:"privacy_policy_url,omitempty" db:"privacy_policy_url"`
	TermsOfServiceURL    *string   `json:"terms_of_service_url,omitempty" db:"terms_of_service_url"`
	HideHexxlockBranding bool      `json:"hide_hexxlock_branding" db:"hide_hexxlock_branding"`
	CreatedAt            time.Time `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time `json:"updated_at" db:"updated_at"`
}

// UpdateTenantBrandingRequest is the request body for updating tenant branding.
// All fields are optional; only the supplied fields will be applied.
// Colour fields are validated as CSS hex colour strings when present.
type UpdateTenantBrandingRequest struct {
	LogoURL              *string `json:"logo_url"`
	FaviconURL           *string `json:"favicon_url"`
	PrimaryColor         *string `json:"primary_color" binding:"omitempty,hexcolor"`
	BackgroundColor      *string `json:"background_color" binding:"omitempty,hexcolor"`
	AccentColor          *string `json:"accent_color" binding:"omitempty,hexcolor"`
	CustomCSS            *string `json:"custom_css"`
	LoginTitle           *string `json:"login_title" binding:"omitempty,max=255"`
	LoginSubtitle        *string `json:"login_subtitle" binding:"omitempty,max=500"`
	LoginMessage         *string `json:"login_message"`
	SupportEmail         *string `json:"support_email" binding:"omitempty,email"`
	SupportURL           *string `json:"support_url" binding:"omitempty,url"`
	PrivacyPolicyURL     *string `json:"privacy_policy_url" binding:"omitempty,url"`
	TermsOfServiceURL    *string `json:"terms_of_service_url" binding:"omitempty,url"`
	HideHexxlockBranding *bool   `json:"hide_hexxlock_branding"`
}

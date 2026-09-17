// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ApplicationStatus represents the lifecycle state of an Application Object.
type ApplicationStatus string

const (
	// ApplicationStatusActive is an exported identifier.
	ApplicationStatusActive ApplicationStatus = "active"
	// ApplicationStatusDisabled is an exported identifier.
	ApplicationStatusDisabled ApplicationStatus = "disabled"
	// ApplicationStatusArchived is an exported identifier.
	ApplicationStatusArchived ApplicationStatus = "archived"
)

// ApplicationAppType represents the client type of an application.
type ApplicationAppType string

const (
	// ApplicationAppTypeWeb is an exported identifier.
	ApplicationAppTypeWeb ApplicationAppType = "web"
	// ApplicationAppTypeSPA is an exported identifier.
	ApplicationAppTypeSPA ApplicationAppType = "spa"
	// ApplicationAppTypeNative is an exported identifier.
	ApplicationAppTypeNative ApplicationAppType = "native"
	// ApplicationAppTypeService is an exported identifier.
	ApplicationAppTypeService ApplicationAppType = "service"
	// ApplicationAppTypeDaemon is an exported identifier.
	ApplicationAppTypeDaemon ApplicationAppType = "daemon"
)

// ApplicationPublisherType represents who published the application.
type ApplicationPublisherType string

const (
	// ApplicationPublisherFirstParty is an exported identifier.
	ApplicationPublisherFirstParty ApplicationPublisherType = "first_party"
	// ApplicationPublisherThirdParty is an exported identifier.
	ApplicationPublisherThirdParty ApplicationPublisherType = "third_party"
	// ApplicationPublisherVerifiedPartner is an exported identifier.
	ApplicationPublisherVerifiedPartner ApplicationPublisherType = "verified_partner"
)

// Application represents a global application definition (Entra ID "App Object").
// One record per application, instantiated per-tenant via ServicePrincipals.
type Application struct {
	ID                   uuid.UUID                `json:"id" db:"id"`
	DisplayName          string                   `json:"display_name" db:"display_name"`
	Slug                 string                   `json:"slug" db:"slug"`
	Description          string                   `json:"description" db:"description"`
	LogoURL              *string                  `json:"logo_url,omitempty" db:"logo_url"`
	HomepageURL          *string                  `json:"homepage_url,omitempty" db:"homepage_url"`
	PrivacyPolicyURL     *string                  `json:"privacy_policy_url,omitempty" db:"privacy_policy_url"`
	TermsOfServiceURL    *string                  `json:"terms_of_service_url,omitempty" db:"terms_of_service_url"`
	AppType              ApplicationAppType       `json:"app_type" db:"app_type"`
	PublisherType        ApplicationPublisherType `json:"publisher_type" db:"publisher_type"`
	IsPlatformApp        bool                     `json:"is_platform_app" db:"is_platform_app"`
	SignInAudience       string                   `json:"sign_in_audience" db:"sign_in_audience"`
	RedirectURIs         []string                 `json:"redirect_uris" db:"redirect_uris"`
	PostLogoutURIs       []string                 `json:"post_logout_uris" db:"post_logout_uris"`
	AllowedGrantTypes    []string                 `json:"allowed_grant_types" db:"allowed_grant_types"`
	DefaultScopes        []string                 `json:"default_scopes" db:"default_scopes"`
	AccessTokenLifetime  int                      `json:"access_token_lifetime" db:"access_token_lifetime"`
	RefreshTokenLifetime int                      `json:"refresh_token_lifetime" db:"refresh_token_lifetime"`
	IDTokenLifetime      int                      `json:"id_token_lifetime" db:"id_token_lifetime"`
	IsPublic             bool                     `json:"is_public" db:"is_public"`
	RequirePKCE          bool                     `json:"require_pkce" db:"require_pkce"`
	Preauthorized        bool                     `json:"preauthorized" db:"preauthorized"`
	Status               ApplicationStatus        `json:"status" db:"status"`
	Tags                 []string                 `json:"tags" db:"tags"`
	Metadata             []byte                   `json:"metadata" db:"metadata"`
	PublisherVerified    bool                     `json:"publisher_verified" db:"publisher_verified"`
	PublisherVerifiedAt  *time.Time               `json:"publisher_verified_at,omitempty" db:"publisher_verified_at"`
	PublisherDomain      *string                  `json:"publisher_domain,omitempty" db:"publisher_domain"`
	CreatedBy            *uuid.UUID               `json:"created_by,omitempty" db:"created_by"`
	CreatedAt            time.Time                `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time                `json:"updated_at" db:"updated_at"`
	DeletedAt            *time.Time               `json:"deleted_at,omitempty" db:"deleted_at"`
	PurgeAfter           *time.Time               `json:"purge_after,omitempty" db:"purge_after"`
	StaleSince           *time.Time               `json:"stale_since,omitempty" db:"stale_since"`
	LastSignInAt         *time.Time               `json:"last_sign_in_at,omitempty" db:"last_sign_in_at"`
}

// IsFirstParty returns true if the application is owned by HexxLock.
func (a *Application) IsFirstParty() bool {
	return a.PublisherType == ApplicationPublisherFirstParty
}

// ==================== Request DTOs ====================

// CreateApplicationRequest is the payload for registering a new Application Object.
type CreateApplicationRequest struct {
	DisplayName          string                   `json:"display_name" binding:"required,min=2,max=255"`
	Slug                 string                   `json:"slug" binding:"required,min=2,max=100"`
	Description          string                   `json:"description"`
	LogoURL              *string                  `json:"logo_url" binding:"omitempty,url"`
	HomepageURL          *string                  `json:"homepage_url" binding:"omitempty,url"`
	PrivacyPolicyURL     *string                  `json:"privacy_policy_url" binding:"omitempty,url"`
	TermsOfServiceURL    *string                  `json:"terms_of_service_url" binding:"omitempty,url"`
	AppType              ApplicationAppType       `json:"app_type" binding:"required,oneof=web spa native service daemon"`
	PublisherType        ApplicationPublisherType `json:"publisher_type" binding:"omitempty,oneof=first_party third_party verified_partner"`
	SignInAudience       string                   `json:"sign_in_audience" binding:"omitempty,oneof=single_tenant multi_tenant personal_accounts"`
	RedirectURIs         []string                 `json:"redirect_uris"`
	PostLogoutURIs       []string                 `json:"post_logout_uris"`
	AllowedGrantTypes    []string                 `json:"allowed_grant_types"`
	DefaultScopes        []string                 `json:"default_scopes"`
	AccessTokenLifetime  *int                     `json:"access_token_lifetime"`
	RefreshTokenLifetime *int                     `json:"refresh_token_lifetime"`
	IDTokenLifetime      *int                     `json:"id_token_lifetime"`
	IsPublic             bool                     `json:"is_public"`
	RequirePKCE          bool                     `json:"require_pkce"`
	Preauthorized        bool                     `json:"preauthorized"`
	Tags                 []string                 `json:"tags"`
}

// UpdateApplicationRequest is the payload for updating an Application Object.
type UpdateApplicationRequest struct {
	DisplayName          *string                   `json:"display_name" binding:"omitempty,min=2,max=255"`
	Description          *string                   `json:"description"`
	LogoURL              *string                   `json:"logo_url" binding:"omitempty,url"`
	HomepageURL          *string                   `json:"homepage_url" binding:"omitempty,url"`
	PrivacyPolicyURL     *string                   `json:"privacy_policy_url" binding:"omitempty,url"`
	TermsOfServiceURL    *string                   `json:"terms_of_service_url" binding:"omitempty,url"`
	AppType              *ApplicationAppType       `json:"app_type" binding:"omitempty,oneof=web spa native service daemon"`
	PublisherType        *ApplicationPublisherType `json:"publisher_type" binding:"omitempty,oneof=first_party third_party verified_partner"`
	SignInAudience       *string                   `json:"sign_in_audience" binding:"omitempty,oneof=single_tenant multi_tenant personal_accounts"`
	RedirectURIs         []string                  `json:"redirect_uris"`
	PostLogoutURIs       []string                  `json:"post_logout_uris"`
	AllowedGrantTypes    []string                  `json:"allowed_grant_types"`
	DefaultScopes        []string                  `json:"default_scopes"`
	AccessTokenLifetime  *int                      `json:"access_token_lifetime"`
	RefreshTokenLifetime *int                      `json:"refresh_token_lifetime"`
	IDTokenLifetime      *int                      `json:"id_token_lifetime"`
	IsPublic             *bool                     `json:"is_public"`
	RequirePKCE          *bool                     `json:"require_pkce"`
	Preauthorized        *bool                     `json:"preauthorized"`
	Status               *ApplicationStatus        `json:"status" binding:"omitempty,oneof=active disabled archived"`
	Tags                 []string                  `json:"tags"`
}

// ==================== Response DTOs ====================

// ApplicationResponse is the API representation of an Application Object.
type ApplicationResponse struct {
	ID                    uuid.UUID                `json:"id"`
	DisplayName           string                   `json:"display_name"`
	Slug                  string                   `json:"slug"`
	Description           string                   `json:"description"`
	LogoURL               *string                  `json:"logo_url,omitempty"`
	HomepageURL           *string                  `json:"homepage_url,omitempty"`
	PrivacyPolicyURL      *string                  `json:"privacy_policy_url,omitempty"`
	TermsOfServiceURL     *string                  `json:"terms_of_service_url,omitempty"`
	AppType               ApplicationAppType       `json:"app_type"`
	PublisherType         ApplicationPublisherType `json:"publisher_type"`
	IsPlatformApp         bool                     `json:"is_platform_app"`
	SignInAudience        string                   `json:"sign_in_audience"`
	RedirectURIs          []string                 `json:"redirect_uris"`
	PostLogoutURIs        []string                 `json:"post_logout_uris"`
	AllowedGrantTypes     []string                 `json:"allowed_grant_types"`
	DefaultScopes         []string                 `json:"default_scopes"`
	AccessTokenLifetime   int                      `json:"access_token_lifetime"`
	RefreshTokenLifetime  int                      `json:"refresh_token_lifetime"`
	IDTokenLifetime       int                      `json:"id_token_lifetime"`
	IsPublic              bool                     `json:"is_public"`
	RequirePKCE           bool                     `json:"require_pkce"`
	Preauthorized         bool                     `json:"preauthorized"`
	Status                ApplicationStatus        `json:"status"`
	Tags                  []string                 `json:"tags"`
	PublisherVerified     bool                     `json:"publisher_verified"`
	PublisherVerifiedAt   *time.Time               `json:"publisher_verified_at,omitempty"`
	PublisherDomain       *string                  `json:"publisher_domain,omitempty"`
	ServicePrincipalCount int                      `json:"service_principal_count,omitempty"`
	CreatedBy             *uuid.UUID               `json:"created_by,omitempty"`
	CreatedAt             time.Time                `json:"created_at"`
	UpdatedAt             time.Time                `json:"updated_at"`
	DeletedAt             *time.Time               `json:"deleted_at,omitempty"`
	PurgeAfter            *time.Time               `json:"purge_after,omitempty"`
	StaleSince            *time.Time               `json:"stale_since,omitempty"`
	LastSignInAt          *time.Time               `json:"last_sign_in_at,omitempty"`
}

// ApplicationListResponse is the paginated list of applications.
type ApplicationListResponse struct {
	Applications []ApplicationResponse `json:"applications"`
	Total        int64                 `json:"total"`
	Page         int                   `json:"page"`
	PageSize     int                   `json:"page_size"`
	TotalPages   int                   `json:"total_pages"`
}

// ToResponse converts an Application to its API response form.
func (a *Application) ToResponse() *ApplicationResponse {
	return &ApplicationResponse{
		ID:                   a.ID,
		DisplayName:          a.DisplayName,
		Slug:                 a.Slug,
		Description:          a.Description,
		LogoURL:              a.LogoURL,
		HomepageURL:          a.HomepageURL,
		PrivacyPolicyURL:     a.PrivacyPolicyURL,
		TermsOfServiceURL:    a.TermsOfServiceURL,
		AppType:              a.AppType,
		PublisherType:        a.PublisherType,
		IsPlatformApp:        a.IsPlatformApp,
		SignInAudience:       a.SignInAudience,
		RedirectURIs:         a.RedirectURIs,
		PostLogoutURIs:       a.PostLogoutURIs,
		AllowedGrantTypes:    a.AllowedGrantTypes,
		DefaultScopes:        a.DefaultScopes,
		AccessTokenLifetime:  a.AccessTokenLifetime,
		RefreshTokenLifetime: a.RefreshTokenLifetime,
		IDTokenLifetime:      a.IDTokenLifetime,
		IsPublic:             a.IsPublic,
		RequirePKCE:          a.RequirePKCE,
		Preauthorized:        a.Preauthorized,
		Status:               a.Status,
		Tags:                 a.Tags,
		PublisherVerified:    a.PublisherVerified,
		PublisherVerifiedAt:  a.PublisherVerifiedAt,
		PublisherDomain:      a.PublisherDomain,
		CreatedBy:            a.CreatedBy,
		CreatedAt:            a.CreatedAt,
		UpdatedAt:            a.UpdatedAt,
		DeletedAt:            a.DeletedAt,
		PurgeAfter:           a.PurgeAfter,
		StaleSince:           a.StaleSince,
		LastSignInAt:         a.LastSignInAt,
	}
}

// ProvisionServicePrincipalRequest is the request to provision an SP from an Application Object.
type ProvisionServicePrincipalRequest struct {
	ApplicationID  uuid.UUID `json:"application_id" binding:"required"`
	TenantID       uuid.UUID `json:"tenant_id" binding:"required"`
	ScopeOverrides []string  `json:"scope_overrides,omitempty"`
}

// ProvisionServicePrincipalResponse includes the SP plus one-time credentials.
type ProvisionServicePrincipalResponse struct {
	ServicePrincipal ServicePrincipalResponse `json:"service_principal"`
	ClientID         string                   `json:"client_id,omitempty"`
	ClientSecret     string                   `json:"client_secret,omitempty"`
}

// BulkProvisionRequest is the request to provision SPs in multiple tenants.
type BulkProvisionRequest struct {
	TenantIDs []uuid.UUID `json:"tenant_ids" binding:"required,min=1"`
}

// BulkProvisionResult holds the result for each tenant in a bulk operation.
type BulkProvisionResult struct {
	TenantID uuid.UUID                          `json:"tenant_id"`
	Success  bool                               `json:"success"`
	SP       *ProvisionServicePrincipalResponse `json:"service_principal,omitempty"`
	Error    string                             `json:"error,omitempty"`
}

// VerifyPublisherRequest is the request for publisher domain verification.
type VerifyPublisherRequest struct {
	Domain string `json:"domain" binding:"required"`
}

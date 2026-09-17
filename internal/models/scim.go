// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ==================== SCIM Token ====================

// SCIMToken represents a SCIM API token for automated provisioning
type SCIMToken struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	TenantID    uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Name        string     `json:"name" db:"name"`
	Description *string    `json:"description,omitempty" db:"description"`
	TokenHash   string     `json:"-" db:"token_hash"`
	IsActive    bool       `json:"is_active" db:"is_active"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	LastUsedIP  *string    `json:"last_used_ip,omitempty" db:"last_used_ip"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" db:"expires_at"`
}

// SCIMTokenCreatedResponse includes the plain token (only shown once)
type SCIMTokenCreatedResponse struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	Token       string     `json:"token"` // Plain token, only shown at creation
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// CreateSCIMTokenRequest for creating a new SCIM token
type CreateSCIMTokenRequest struct {
	Name        string  `json:"name" binding:"required,min=2,max=100"`
	Description *string `json:"description"`
	ExpiresAt   *string `json:"expires_at"` // RFC3339 format
}

// UpdateSCIMTokenRequest for updating a SCIM token
type UpdateSCIMTokenRequest struct {
	Name        *string `json:"name" binding:"omitempty,min=2,max=100"`
	Description *string `json:"description"`
	IsActive    *bool   `json:"is_active"`
}

// SCIMTokenListResponse for list endpoints
type SCIMTokenListResponse struct {
	Tokens []SCIMToken `json:"tokens"`
	Total  int64       `json:"total"`
}

// ==================== SCIM 2.0 Schema Types ====================

// SCIMResource is the base type for all SCIM resources
type SCIMResource struct {
	Schemas []string  `json:"schemas"`
	ID      string    `json:"id"`
	Meta    *SCIMMeta `json:"meta,omitempty"`
}

// SCIMMeta contains resource metadata
type SCIMMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

// SCIMUser represents a SCIM 2.0 User resource
type SCIMUser struct {
	Schemas           []string            `json:"schemas"`
	ID                string              `json:"id"`
	ExternalID        string              `json:"externalId,omitempty"`
	UserName          string              `json:"userName"`
	Name              *SCIMName           `json:"name,omitempty"`
	DisplayName       string              `json:"displayName,omitempty"`
	NickName          string              `json:"nickName,omitempty"`
	ProfileURL        string              `json:"profileUrl,omitempty"`
	Title             string              `json:"title,omitempty"`
	UserType          string              `json:"userType,omitempty"`
	PreferredLanguage string              `json:"preferredLanguage,omitempty"`
	Locale            string              `json:"locale,omitempty"`
	Timezone          string              `json:"timezone,omitempty"`
	Active            bool                `json:"active"`
	Password          string              `json:"password,omitempty"`
	Emails            []SCIMEmail         `json:"emails,omitempty"`
	PhoneNumbers      []SCIMPhoneNumber   `json:"phoneNumbers,omitempty"`
	Groups            []SCIMGroupRef      `json:"groups,omitempty"`
	Roles             []SCIMRole          `json:"roles,omitempty"`
	EnterpriseUser    *SCIMEnterpriseUser `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Meta              *SCIMMeta           `json:"meta,omitempty"`
}

// SCIMName represents the name component
type SCIMName struct {
	Formatted       string `json:"formatted,omitempty"`
	FamilyName      string `json:"familyName,omitempty"`
	GivenName       string `json:"givenName,omitempty"`
	MiddleName      string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

// SCIMEmail represents an email address
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMPhoneNumber represents a phone number
type SCIMPhoneNumber struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMGroupRef is a reference to a group
type SCIMGroupRef struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
}

// SCIMRole represents a role assignment
type SCIMRole struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMEnterpriseUser represents enterprise user extension
type SCIMEnterpriseUser struct {
	EmployeeNumber string       `json:"employeeNumber,omitempty"`
	CostCenter     string       `json:"costCenter,omitempty"`
	Organization   string       `json:"organization,omitempty"`
	Division       string       `json:"division,omitempty"`
	Department     string       `json:"department,omitempty"`
	Manager        *SCIMManager `json:"manager,omitempty"`
}

// SCIMManager represents a manager reference
type SCIMManager struct {
	Value       string `json:"value,omitempty"`
	Ref         string `json:"$ref,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// SCIMGroup represents a SCIM 2.0 Group resource
type SCIMGroup struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id"`
	ExternalID  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName"`
	Members     []SCIMGroupMember `json:"members,omitempty"`
	Meta        *SCIMMeta         `json:"meta,omitempty"`
}

// SCIMGroupMember represents a group member
type SCIMGroupMember struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"` // User or Group
}

// SCIMListResponse is the standard list response format
type SCIMListResponse struct {
	Schemas      []string    `json:"schemas"`
	TotalResults int         `json:"totalResults"`
	StartIndex   int         `json:"startIndex"`
	ItemsPerPage int         `json:"itemsPerPage"`
	Resources    interface{} `json:"Resources"`
}

// SCIMError represents a SCIM error response
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail"`
}

// SCIMPatchOp represents a SCIM patch operation
type SCIMPatchOp struct {
	Schemas    []string             `json:"schemas"`
	Operations []SCIMPatchOperation `json:"Operations"`
}

// SCIMPatchOperation represents a single patch operation
type SCIMPatchOperation struct {
	Op    string      `json:"op"` // add, remove, replace
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

// SCIMServiceProviderConfig represents the service provider configuration
type SCIMServiceProviderConfig struct {
	Schemas               []string            `json:"schemas"`
	DocumentationURI      string              `json:"documentationUri,omitempty"`
	Patch                 SCIMSupported       `json:"patch"`
	Bulk                  SCIMBulkSupported   `json:"bulk"`
	Filter                SCIMFilterSupported `json:"filter"`
	ChangePassword        SCIMSupported       `json:"changePassword"`
	Sort                  SCIMSupported       `json:"sort"`
	ETag                  SCIMSupported       `json:"etag"`
	AuthenticationSchemes []SCIMAuthScheme    `json:"authenticationSchemes"`
	Meta                  *SCIMMeta           `json:"meta,omitempty"`
}

// SCIMSupported represents a supported feature
type SCIMSupported struct {
	Supported bool `json:"supported"`
}

// SCIMBulkSupported represents bulk operation support
type SCIMBulkSupported struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

// SCIMFilterSupported represents filter support
type SCIMFilterSupported struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// SCIMAuthScheme represents an authentication scheme
type SCIMAuthScheme struct {
	Type             string `json:"type"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	SpecURI          string `json:"specUri,omitempty"`
	DocumentationURI string `json:"documentationUri,omitempty"`
	Primary          bool   `json:"primary,omitempty"`
}

// SCIMSchema represents a SCIM schema definition
type SCIMSchema struct {
	Schemas     []string        `json:"schemas"`
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Attributes  []SCIMAttribute `json:"attributes,omitempty"`
	Meta        *SCIMMeta       `json:"meta,omitempty"`
}

// SCIMAttribute represents a schema attribute
type SCIMAttribute struct {
	Name            string          `json:"name"`
	Type            string          `json:"type"`
	MultiValued     bool            `json:"multiValued"`
	Description     string          `json:"description,omitempty"`
	Required        bool            `json:"required"`
	CaseExact       bool            `json:"caseExact,omitempty"`
	Mutability      string          `json:"mutability"`
	Returned        string          `json:"returned"`
	Uniqueness      string          `json:"uniqueness,omitempty"`
	SubAttributes   []SCIMAttribute `json:"subAttributes,omitempty"`
	CanonicalValues []string        `json:"canonicalValues,omitempty"`
}

// SCIMResourceType represents a resource type definition
type SCIMResourceType struct {
	Schemas          []string              `json:"schemas"`
	ID               string                `json:"id"`
	Name             string                `json:"name"`
	Description      string                `json:"description,omitempty"`
	Endpoint         string                `json:"endpoint"`
	Schema           string                `json:"schema"`
	SchemaExtensions []SCIMSchemaExtension `json:"schemaExtensions,omitempty"`
	Meta             *SCIMMeta             `json:"meta,omitempty"`
}

// SCIMSchemaExtension represents a schema extension
type SCIMSchemaExtension struct {
	Schema   string `json:"schema"`
	Required bool   `json:"required"`
}

// ==================== SCIM Schema URIs ====================

const (
	// SCIMSchemaCore is an exported identifier.
	SCIMSchemaCore = "urn:ietf:params:scim:schemas:core:2.0"
	// SCIMSchemaUser is an exported identifier.
	SCIMSchemaUser = "urn:ietf:params:scim:schemas:core:2.0:User"
	// SCIMSchemaGroup is an exported identifier.
	SCIMSchemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	// SCIMSchemaEnterpriseUser is an exported identifier.
	SCIMSchemaEnterpriseUser = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	// SCIMSchemaListResponse is an exported identifier.
	SCIMSchemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	// SCIMSchemaError is an exported identifier.
	SCIMSchemaError = "urn:ietf:params:scim:api:messages:2.0:Error"
	// SCIMSchemaPatchOp is an exported identifier.
	SCIMSchemaPatchOp = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	// SCIMSchemaServiceProvider is an exported identifier.
	SCIMSchemaServiceProvider = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	// SCIMSchemaSchema is an exported identifier.
	SCIMSchemaSchema = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	// SCIMSchemaResourceType is an exported identifier.
	SCIMSchemaResourceType = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	// SCIMSchemaBulkRequest is an exported identifier.
	SCIMSchemaBulkRequest = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	// SCIMSchemaBulkResponse is an exported identifier.
	SCIMSchemaBulkResponse = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"

	// SCIMMaxBulkOperations is the server-enforced maximum number of operations
	// accepted in a single Bulk request (RFC 7644 §3.7).
	SCIMMaxBulkOperations = 1000

	// SCIMMaxBulkPayloadBytes is the server-enforced maximum request body size
	// for Bulk requests (1 MiB).
	SCIMMaxBulkPayloadBytes = 1_048_576
)

// ==================== Bulk Operations (RFC 7644 §3.7) ====================

// SCIMBulkRequest is the body of POST /scim/v2/Bulk.
type SCIMBulkRequest struct {
	Schemas      []string            `json:"schemas"`
	FailOnErrors *int                `json:"failOnErrors,omitempty"`
	Operations   []SCIMBulkOperation `json:"Operations"`
}

// SCIMBulkOperation represents a single operation within a Bulk request.
type SCIMBulkOperation struct {
	// Method is one of "POST", "PUT", "PATCH", "DELETE".
	Method string `json:"method"`
	// Path is the resource-relative path, e.g. "/Users" or "/Users/<id>".
	Path string `json:"path"`
	// BulkID is the caller-supplied correlation identifier (required for POST).
	BulkID string `json:"bulkId,omitempty"`
	// Data holds the request body. For DELETE it is omitted.
	Data interface{} `json:"data,omitempty"`
}

// SCIMBulkResponse is the response body of POST /scim/v2/Bulk.
type SCIMBulkResponse struct {
	Schemas    []string                  `json:"schemas"`
	Operations []SCIMBulkOperationResult `json:"Operations"`
}

// SCIMBulkOperationResult describes the outcome of one Bulk operation.
type SCIMBulkOperationResult struct {
	// Method mirrors the method from the request.
	Method string `json:"method"`
	// BulkID mirrors the bulkId from the request (present when the operation had one).
	BulkID string `json:"bulkId,omitempty"`
	// Location is the canonical URL of the affected resource.
	Location string `json:"location,omitempty"`
	// Version is the ETag of the resource after the operation.
	Version string `json:"version,omitempty"`
	// Status is the HTTP status code as a string (e.g. "201").
	Status string `json:"status"`
	// Response holds the resource body for successful POST/PUT/PATCH operations.
	// Nil for DELETE and for failed operations (the Response field contains the
	// SCIM Error object in that case as per the spec).
	Response interface{} `json:"response,omitempty"`
}

// ==================== POST Search (RFC 7644 §3.4.3) ====================

// SCIMSearchRequest is the body of POST /scim/v2/.search.
type SCIMSearchRequest struct {
	Schemas            []string `json:"schemas"`
	Filter             string   `json:"filter,omitempty"`
	SortBy             string   `json:"sortBy,omitempty"`
	SortOrder          string   `json:"sortOrder,omitempty"`
	StartIndex         int      `json:"startIndex,omitempty"`
	Count              int      `json:"count,omitempty"`
	Attributes         []string `json:"attributes,omitempty"`
	ExcludedAttributes []string `json:"excludedAttributes,omitempty"`
}

// Helper functions for SCIM

// NewSCIMError creates a new SCIM error response
func NewSCIMError(status int, detail string, scimType string) *SCIMError {
	return &SCIMError{
		Schemas:  []string{SCIMSchemaError},
		Status:   string(rune(status)), //nolint:gosec // int value is bounded by string length, safe conversion
		ScimType: scimType,
		Detail:   detail,
	}
}

// buildSCIMName constructs the optional SCIMName struct from the user's
// first/last name pointer fields. Returns nil when both are absent.
func buildSCIMName(firstName, lastName *string) *SCIMName {
	if firstName == nil && lastName == nil {
		return nil
	}
	name := &SCIMName{}
	if firstName != nil {
		name.GivenName = *firstName
	}
	if lastName != nil {
		name.FamilyName = *lastName
	}
	if firstName != nil && lastName != nil {
		name.Formatted = *firstName + " " + *lastName
	}
	return name
}

// buildSCIMEnterpriseUser constructs the optional enterprise extension from
// department and title pointer fields. Returns nil when both are absent.
func buildSCIMEnterpriseUser(department *string) *SCIMEnterpriseUser {
	if department == nil {
		return nil
	}
	eu := &SCIMEnterpriseUser{}
	eu.Department = *department
	return eu
}

// ToSCIMUser converts an internal User to a SCIM User
func (u *User) ToSCIMUser(baseURL string) *SCIMUser {
	scimUser := &SCIMUser{
		Schemas:  []string{SCIMSchemaUser},
		ID:       u.ID.String(),
		UserName: u.Username,
		Active:   u.IsActive && !u.IsLocked,
		Meta: &SCIMMeta{
			ResourceType: "User",
			Created:      u.CreatedAt,
			LastModified: u.UpdatedAt,
			Location:     baseURL + "/scim/v2/Users/" + u.ID.String(),
		},
	}

	scimUser.Name = buildSCIMName(u.FirstName, u.LastName)

	if u.DisplayName != nil {
		scimUser.DisplayName = *u.DisplayName
	}

	scimUser.Emails = []SCIMEmail{
		{Value: u.Email, Type: "work", Primary: true},
	}

	if u.Phone != nil && *u.Phone != "" {
		scimUser.PhoneNumbers = []SCIMPhoneNumber{
			{Value: *u.Phone, Type: "work", Primary: true},
		}
	}

	scimUser.EnterpriseUser = buildSCIMEnterpriseUser(u.Department)

	if u.Title != nil {
		scimUser.Title = *u.Title
	}

	return scimUser
}

// ToSCIMGroup converts an internal Role to a SCIM Group
func (r *Role) ToSCIMGroup(baseURL string) *SCIMGroup {
	return &SCIMGroup{
		Schemas:     []string{SCIMSchemaGroup},
		ID:          r.ID.String(),
		DisplayName: r.DisplayName,
		Meta: &SCIMMeta{
			ResourceType: "Group",
			Created:      r.CreatedAt,
			LastModified: r.UpdatedAt,
			Location:     baseURL + "/scim/v2/Groups/" + r.ID.String(),
		},
	}
}

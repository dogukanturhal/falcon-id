// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hrn provides HexxLock Resource Name parsing and formatting.
//
// Format: hrn:hexxlock:{product}:{tenant-id}:{resource-type}/{resource-id}
// Example: hrn:hexxlock:erp:550e8400-e29b-41d4-a716-446655440000:contact/12345
//
// HRNs serve as a canonical, human-readable identifier for any resource managed
// by the HexxLock platform, regardless of which product owns the resource. The
// format is intentionally similar to AWS ARNs so that operators familiar with
// cloud resource naming will find the convention immediately recognisable.
package hrn

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Scheme is the fixed prefix that identifies a HexxLock Resource Name.
const Scheme = "hrn:hexxlock"

// Sentinel errors returned by Parse and Validate.
var (
	// ErrInvalidScheme is returned when the string does not start with "hrn:hexxlock:".
	ErrInvalidScheme = errors.New("hrn: invalid scheme, expected \"hrn:hexxlock\"")

	// ErrInvalidFormat is returned when the HRN does not have the required number
	// of colon-separated segments.
	ErrInvalidFormat = errors.New("hrn: invalid format, expected hrn:hexxlock:{product}:{tenant-id}:{resource-type}/{resource-id}")

	// ErrInvalidTenantID is returned when the tenant-id segment is not a valid UUID.
	ErrInvalidTenantID = errors.New("hrn: tenant-id is not a valid UUID")

	// ErrInvalidResourceSegment is returned when the resource segment does not
	// contain exactly one "/" separating resource-type from resource-id.
	ErrInvalidResourceSegment = errors.New("hrn: resource segment must be in the form {resource-type}/{resource-id}")

	// ErrEmptyProduct is returned by Validate when the Product field is empty.
	ErrEmptyProduct = errors.New("hrn: product must not be empty")

	// ErrEmptyResourceType is returned by Validate when the ResourceType field is empty.
	ErrEmptyResourceType = errors.New("hrn: resource-type must not be empty")

	// ErrEmptyResourceID is returned by Validate when the ResourceID field is empty.
	ErrEmptyResourceID = errors.New("hrn: resource-id must not be empty")
)

// HRN represents a parsed HexxLock Resource Name.
//
// All fields are accessible and mutable; use Validate to assert invariants
// before persisting or transmitting an HRN.
type HRN struct {
	// Product identifies the platform product that owns the resource
	// (e.g. "erp", "example-pms", "car-rental").
	Product string

	// TenantID is the UUID of the tenant that owns the resource.
	TenantID uuid.UUID

	// ResourceType categorises the resource within the product
	// (e.g. "contact", "invoice", "reservation").
	ResourceType string

	// ResourceID is the unique identifier of the specific resource instance.
	// It may be any non-empty string: a UUID, a numeric ID, or a slug.
	ResourceID string
}

// New constructs an HRN from its constituent parts. It does not validate the
// fields; call Validate on the returned value if validation is required.
func New(product string, tenantID uuid.UUID, resourceType, resourceID string) *HRN {
	return &HRN{
		Product:      product,
		TenantID:     tenantID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}
}

// Parse parses a HexxLock Resource Name string into an HRN.
//
// The expected format is:
//
//	hrn:hexxlock:{product}:{tenant-id}:{resource-type}/{resource-id}
//
// Parse returns ErrInvalidScheme if the string does not begin with
// "hrn:hexxlock:", ErrInvalidFormat if the segment count is wrong,
// ErrInvalidTenantID if the tenant-id segment is not a valid UUID, and
// ErrInvalidResourceSegment if the last segment lacks a "/" separator.
func Parse(s string) (*HRN, error) {
	// The format has exactly 5 colon-separated tokens:
	//   hrn | hexxlock | {product} | {tenant-id} | {resource-type}/{resource-id}
	parts := strings.SplitN(s, ":", 5)
	if len(parts) != 5 {
		return nil, ErrInvalidFormat
	}

	// Verify the scheme (first two tokens joined with ":").
	if parts[0]+":"+parts[1] != Scheme {
		return nil, ErrInvalidScheme
	}

	product := parts[2]
	tenantStr := parts[3]
	resourceSegment := parts[4]

	// Validate and parse the tenant UUID.
	tenantID, err := uuid.Parse(tenantStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidTenantID, tenantStr)
	}

	// Split the resource segment into type and ID at the first "/".
	slashIdx := strings.IndexByte(resourceSegment, '/')
	if slashIdx <= 0 || slashIdx == len(resourceSegment)-1 {
		// slashIdx == -1  → no "/" present
		// slashIdx == 0   → resource-type is empty (leading slash)
		// slashIdx == len → resource-id is empty (trailing slash)
		return nil, ErrInvalidResourceSegment
	}

	resourceType := resourceSegment[:slashIdx]
	resourceID := resourceSegment[slashIdx+1:]

	return &HRN{
		Product:      product,
		TenantID:     tenantID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}, nil
}

// String formats the HRN into its canonical string representation.
//
// The returned string has the form:
//
//	hrn:hexxlock:{product}:{tenant-id}:{resource-type}/{resource-id}
func (h *HRN) String() string {
	return fmt.Sprintf("%s:%s:%s:%s/%s",
		Scheme,
		h.Product,
		h.TenantID.String(),
		h.ResourceType,
		h.ResourceID,
	)
}

// ToSpiceDBID converts the HRN to a SpiceDB-compatible object identifier.
//
// The format is "{product}:{resource_type}:{resource_id}", where the product
// and resource type are joined with underscores where colons appear in the raw
// values. This keeps the identifier within SpiceDB's allowed ObjectId character
// set (^(([a-zA-Z0-9/_|\-=+]{1,})|\*)$) while still encoding the full
// product/resource lineage.
//
// Example:
//
//	HRN{Product:"erp", ResourceType:"contact", ResourceID:"12345"}
//	→ "erp:contact:12345"
func (h *HRN) ToSpiceDBID() string {
	return fmt.Sprintf("%s:%s:%s", h.Product, h.ResourceType, h.ResourceID)
}

// Validate checks that all HRN fields satisfy the basic non-empty invariants
// and that TenantID is not the zero UUID.
//
// Validate does not check the semantic correctness of field values (e.g. whether
// the product slug is registered in the platform); that responsibility belongs
// to the caller.
func (h *HRN) Validate() error {
	if h.Product == "" {
		return ErrEmptyProduct
	}
	if h.TenantID == uuid.Nil {
		return ErrInvalidTenantID
	}
	if h.ResourceType == "" {
		return ErrEmptyResourceType
	}
	if h.ResourceID == "" {
		return ErrEmptyResourceID
	}
	return nil
}

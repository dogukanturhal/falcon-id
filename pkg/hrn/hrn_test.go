// SPDX-License-Identifier: AGPL-3.0-or-later

package hrn

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// knownTenantID is a fixed UUID used throughout the test suite so that
// expected string values can be hard-coded rather than reconstructed at
// runtime from a randomly generated UUID.
var knownTenantID = uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

// ─── TestNew ──────────────────────────────────────────────────────────────────

func TestNew(t *testing.T) {
	tests := []struct {
		name         string
		product      string
		tenantID     uuid.UUID
		resourceType string
		resourceID   string
	}{
		{
			name:         "ERP contact resource",
			product:      "erp",
			tenantID:     knownTenantID,
			resourceType: "contact",
			resourceID:   "12345",
		},
		{
			name:         "Example PMS reservation resource",
			product:      "example-pms",
			tenantID:     knownTenantID,
			resourceType: "reservation",
			resourceID:   "res-9a2f",
		},
		{
			name:         "Car rental vehicle resource",
			product:      "car-rental",
			tenantID:     knownTenantID,
			resourceType: "vehicle",
			resourceID:   uuid.New().String(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := New(tt.product, tt.tenantID, tt.resourceType, tt.resourceID)

			require.NotNil(t, h)
			assert.Equal(t, tt.product, h.Product)
			assert.Equal(t, tt.tenantID, h.TenantID)
			assert.Equal(t, tt.resourceType, h.ResourceType)
			assert.Equal(t, tt.resourceID, h.ResourceID)
		})
	}
}

// ─── TestParse_Valid ──────────────────────────────────────────────────────────

func TestParse_Valid(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantProduct  string
		wantTenantID uuid.UUID
		wantResType  string
		wantResID    string
	}{
		{
			name:         "ERP contact",
			input:        "hrn:hexxlock:erp:550e8400-e29b-41d4-a716-446655440000:contact/12345",
			wantProduct:  "erp",
			wantTenantID: knownTenantID,
			wantResType:  "contact",
			wantResID:    "12345",
		},
		{
			name:         "Example PMS reservation with UUID resource ID",
			input:        "hrn:hexxlock:example-pms:550e8400-e29b-41d4-a716-446655440000:reservation/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			wantProduct:  "example-pms",
			wantTenantID: knownTenantID,
			wantResType:  "reservation",
			wantResID:    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		},
		{
			name:         "Car rental vehicle with hyphenated resource ID",
			input:        "hrn:hexxlock:car-rental:550e8400-e29b-41d4-a716-446655440000:vehicle/veh-9a2f",
			wantProduct:  "car-rental",
			wantTenantID: knownTenantID,
			wantResType:  "vehicle",
			wantResID:    "veh-9a2f",
		},
		{
			name:         "Resource ID containing forward slash is preserved",
			input:        "hrn:hexxlock:erp:550e8400-e29b-41d4-a716-446655440000:invoice/2026/INV-001",
			wantProduct:  "erp",
			wantTenantID: knownTenantID,
			wantResType:  "invoice",
			wantResID:    "2026/INV-001",
		},
		{
			name:         "Numeric resource ID",
			input:        "hrn:hexxlock:erp:550e8400-e29b-41d4-a716-446655440000:order/99",
			wantProduct:  "erp",
			wantTenantID: knownTenantID,
			wantResType:  "order",
			wantResID:    "99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := Parse(tt.input)

			require.NoError(t, err)
			require.NotNil(t, h)
			assert.Equal(t, tt.wantProduct, h.Product)
			assert.Equal(t, tt.wantTenantID, h.TenantID)
			assert.Equal(t, tt.wantResType, h.ResourceType)
			assert.Equal(t, tt.wantResID, h.ResourceID)
		})
	}
}

// ─── TestParse_InvalidFormat ──────────────────────────────────────────────────

func TestParse_InvalidFormat(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   error
		errSubstr string
	}{
		{
			// "arn:hexxlock:..." has 5 colon segments so the segment-count check
			// passes, but the scheme reconstruction ("arn:hexxlock") does not match
			// "hrn:hexxlock", so ErrInvalidScheme is returned.
			name:    "Wrong scheme prefix – arn instead of hrn",
			input:   "arn:hexxlock:erp:550e8400-e29b-41d4-a716-446655440000:contact/12345",
			wantErr: ErrInvalidScheme,
		},
		{
			name:    "Wrong authority – aws instead of hexxlock",
			input:   "hrn:aws:erp:550e8400-e29b-41d4-a716-446655440000:contact/12345",
			wantErr: ErrInvalidScheme,
		},
		{
			name:    "Too few segments – missing resource segment",
			input:   "hrn:hexxlock:erp:550e8400-e29b-41d4-a716-446655440000",
			wantErr: ErrInvalidFormat,
		},
		{
			name:    "Completely empty string",
			input:   "",
			wantErr: ErrInvalidFormat,
		},
		{
			name:    "Plain text – not an HRN at all",
			input:   "this-is-not-an-hrn",
			wantErr: ErrInvalidFormat,
		},
		{
			name:      "Invalid tenant UUID",
			input:     "hrn:hexxlock:erp:not-a-uuid:contact/12345",
			wantErr:   ErrInvalidTenantID,
			errSubstr: "not-a-uuid",
		},
		{
			name:    "Resource segment missing slash separator",
			input:   "hrn:hexxlock:erp:550e8400-e29b-41d4-a716-446655440000:contact",
			wantErr: ErrInvalidResourceSegment,
		},
		{
			name:    "Resource segment with leading slash – empty resource-type",
			input:   "hrn:hexxlock:erp:550e8400-e29b-41d4-a716-446655440000:/12345",
			wantErr: ErrInvalidResourceSegment,
		},
		{
			name:    "Resource segment with trailing slash – empty resource-id",
			input:   "hrn:hexxlock:erp:550e8400-e29b-41d4-a716-446655440000:contact/",
			wantErr: ErrInvalidResourceSegment,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := Parse(tt.input)

			require.Error(t, err)
			assert.Nil(t, h)
			assert.ErrorIs(t, err, tt.wantErr)

			if tt.errSubstr != "" {
				assert.Contains(t, err.Error(), tt.errSubstr)
			}
		})
	}
}

// ─── TestString_RoundTrip ─────────────────────────────────────────────────────

func TestString_RoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "ERP contact",
			input: "hrn:hexxlock:erp:550e8400-e29b-41d4-a716-446655440000:contact/12345",
		},
		{
			name:  "Example PMS reservation",
			input: "hrn:hexxlock:example-pms:550e8400-e29b-41d4-a716-446655440000:reservation/res-9a2f",
		},
		{
			name:  "Car rental vehicle with UUID resource ID",
			input: "hrn:hexxlock:car-rental:550e8400-e29b-41d4-a716-446655440000:vehicle/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		},
		{
			name:  "Numeric resource ID",
			input: "hrn:hexxlock:erp:550e8400-e29b-41d4-a716-446655440000:order/99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := Parse(tt.input)
			require.NoError(t, err)

			// String() must reproduce the original input exactly.
			assert.Equal(t, tt.input, h.String())
		})
	}
}

// TestString_Format verifies that String produces the correct shape even when
// the HRN is constructed via New rather than Parse.
func TestString_Format(t *testing.T) {
	h := New("erp", knownTenantID, "contact", "12345")
	want := "hrn:hexxlock:erp:550e8400-e29b-41d4-a716-446655440000:contact/12345"
	assert.Equal(t, want, h.String())
}

// ─── TestToSpiceDBID ──────────────────────────────────────────────────────────

func TestToSpiceDBID(t *testing.T) {
	tests := []struct {
		name         string
		product      string
		resourceType string
		resourceID   string
		want         string
	}{
		{
			name:         "ERP contact",
			product:      "erp",
			resourceType: "contact",
			resourceID:   "12345",
			want:         "erp:contact:12345",
		},
		{
			name:         "Example PMS reservation",
			product:      "example-pms",
			resourceType: "reservation",
			resourceID:   "res-9a2f",
			want:         "example-pms:reservation:res-9a2f",
		},
		{
			name:         "Car rental vehicle with UUID",
			product:      "car-rental",
			resourceType: "vehicle",
			resourceID:   "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			want:         "car-rental:vehicle:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		},
		{
			name:         "Travel agency booking",
			product:      "travel-agency",
			resourceType: "booking",
			resourceID:   "book-001",
			want:         "travel-agency:booking:book-001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := New(tt.product, knownTenantID, tt.resourceType, tt.resourceID)
			assert.Equal(t, tt.want, h.ToSpiceDBID())
		})
	}
}

// ─── TestValidate_Valid ───────────────────────────────────────────────────────

func TestValidate_Valid(t *testing.T) {
	tests := []struct {
		name string
		hrn  *HRN
	}{
		{
			name: "Fully populated ERP HRN",
			hrn:  New("erp", knownTenantID, "contact", "12345"),
		},
		{
			name: "Example PMS with UUID resource ID",
			hrn:  New("example-pms", uuid.New(), "reservation", uuid.New().String()),
		},
		{
			name: "Minimal valid HRN – single-char fields",
			hrn:  New("a", uuid.New(), "b", "c"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NoError(t, tt.hrn.Validate())
		})
	}
}

// ─── TestValidate_Invalid ─────────────────────────────────────────────────────

func TestValidate_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		hrn     *HRN
		wantErr error
	}{
		{
			name:    "Empty product",
			hrn:     New("", knownTenantID, "contact", "12345"),
			wantErr: ErrEmptyProduct,
		},
		{
			name:    "Zero UUID tenant",
			hrn:     New("erp", uuid.Nil, "contact", "12345"),
			wantErr: ErrInvalidTenantID,
		},
		{
			name:    "Empty resource type",
			hrn:     New("erp", knownTenantID, "", "12345"),
			wantErr: ErrEmptyResourceType,
		},
		{
			name:    "Empty resource ID",
			hrn:     New("erp", knownTenantID, "contact", ""),
			wantErr: ErrEmptyResourceID,
		},
		{
			name:    "All fields empty",
			hrn:     New("", uuid.Nil, "", ""),
			wantErr: ErrEmptyProduct,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.hrn.Validate()

			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// ─── TestParse_ThenValidate ───────────────────────────────────────────────────

// TestParse_ThenValidate ensures that any HRN successfully returned by Parse
// also passes Validate without additional checks by the caller.
func TestParse_ThenValidate(t *testing.T) {
	inputs := []string{
		"hrn:hexxlock:erp:550e8400-e29b-41d4-a716-446655440000:contact/12345",
		"hrn:hexxlock:example-pms:550e8400-e29b-41d4-a716-446655440000:reservation/res-9a2f",
		"hrn:hexxlock:car-rental:550e8400-e29b-41d4-a716-446655440000:vehicle/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			h, err := Parse(input)
			require.NoError(t, err)
			require.NotNil(t, h)
			assert.NoError(t, h.Validate())
		})
	}
}

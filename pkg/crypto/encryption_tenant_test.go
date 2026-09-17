// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestEncryptForTenant_RoundTrip — happy path with per-tenant DEK.
// The ciphertext carries the v2 framing prefix; DecryptForTenant
// recovers the original plaintext when called with the same tenantID.
func TestEncryptForTenant_RoundTrip(t *testing.T) {
	svc, err := NewEncryptionService("12345678901234567890123456789012") // 32-byte AES-256 key
	if err != nil {
		t.Fatalf("NewEncryptionService: %v", err)
	}
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000002")

	for _, plaintext := range []string{
		"user@example.com",
		"Düşünmek + 🔐 + 北京",
		strings.Repeat("a", 4096), // larger payload
		"",                        // empty roundtrips as empty
	} {
		ciphertext, err := svc.EncryptForTenant(tenantID, plaintext)
		if err != nil {
			t.Fatalf("EncryptForTenant(%q): %v", plaintext, err)
		}
		if plaintext == "" {
			if ciphertext != "" {
				t.Errorf("EncryptForTenant(empty) should yield empty, got %q", ciphertext)
			}
			continue
		}
		if !strings.HasPrefix(ciphertext, EncryptedPrefixV2) {
			t.Errorf("ciphertext missing v2 prefix: %q", ciphertext)
		}
		got, err := svc.DecryptForTenant(tenantID, ciphertext)
		if err != nil {
			t.Fatalf("DecryptForTenant: %v", err)
		}
		if got != plaintext {
			t.Errorf("roundtrip mismatch: got %q, want %q", got, plaintext)
		}
	}
}

// TestEncryptForTenant_TenantIsolation — the core SOC2/ISO27018 control.
// Tenant A's ciphertext MUST be unreadable with Tenant B's derivation.
// This is the property HKDF buys us.
func TestEncryptForTenant_TenantIsolation(t *testing.T) {
	svc, err := NewEncryptionService("12345678901234567890123456789012")
	if err != nil {
		t.Fatalf("NewEncryptionService: %v", err)
	}
	tenantA := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	tenantB := uuid.MustParse("00000000-0000-0000-0000-000000000003")

	ciphertext, err := svc.EncryptForTenant(tenantA, "secret-pii")
	if err != nil {
		t.Fatalf("EncryptForTenant(A): %v", err)
	}

	// Same tenant → succeeds
	got, err := svc.DecryptForTenant(tenantA, ciphertext)
	if err != nil {
		t.Fatalf("DecryptForTenant(A): %v", err)
	}
	if got != "secret-pii" {
		t.Errorf("tenant A roundtrip = %q, want secret-pii", got)
	}

	// Different tenant → fails with the canonical decryption error.
	// This is the load-bearing assertion: one tenant's DEK cannot read
	// another's ciphertext, so a compromised tenant key has bounded
	// blast radius.
	if _, err := svc.DecryptForTenant(tenantB, ciphertext); err == nil {
		t.Error("DecryptForTenant(B) on tenant-A ciphertext must FAIL — tenant isolation broken")
	}
}

// TestDecryptForTenant_BackwardCompat — auto-detect v1 (master-key) framing
// and route through legacy Decrypt. Required so that pre-migration data
// remains readable after we ship v2 writes. Lazy migration happens on the
// next legitimate UPDATE of the row.
func TestDecryptForTenant_BackwardCompat(t *testing.T) {
	svc, err := NewEncryptionService("12345678901234567890123456789012")
	if err != nil {
		t.Fatalf("NewEncryptionService: %v", err)
	}
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000002")

	// Pre-migration data: written by the legacy `Encrypt` with no
	// tenant derivation. v1 framing.
	v1ciphertext, err := svc.Encrypt("legacy-pii-value")
	if err != nil {
		t.Fatalf("Encrypt(v1): %v", err)
	}
	if !strings.HasPrefix(v1ciphertext, EncryptedPrefix) {
		t.Errorf("v1 ciphertext missing v1 prefix: %q", v1ciphertext)
	}

	// DecryptForTenant should auto-detect v1 and route to master-key
	// decryption — regardless of the tenantID passed (which is ignored
	// for v1 framing).
	got, err := svc.DecryptForTenant(tenantID, v1ciphertext)
	if err != nil {
		t.Fatalf("DecryptForTenant(v1): %v", err)
	}
	if got != "legacy-pii-value" {
		t.Errorf("v1 backward compat = %q, want legacy-pii-value", got)
	}

	// Also covers legacy un-prefixed data (pre-versioning). Pre-version
	// data is base64-bytes, not encrypted text — DecryptForTenant's
	// fallback requires base64 decoding which only works on printable
	// strings. We don't assert on outcome; both error and success are
	// acceptable since production always carries the v1 prefix.
	raw, _ := svc.EncryptBytes([]byte("super-legacy"))
	_, _ = svc.DecryptForTenant(tenantID, string(raw))
}

// TestEncryptForTenant_NilUUIDFallsBackToMaster — defensive: uuid.Nil
// (the documented "default realm" / "no tenant" sentinel) MUST not
// crash. It returns the master key per DeriveTenantKey's contract.
// Useful for service-account / system-user rows that lack a tenant
// scope.
func TestEncryptForTenant_NilUUIDFallsBackToMaster(t *testing.T) {
	svc, err := NewEncryptionService("12345678901234567890123456789012")
	if err != nil {
		t.Fatalf("NewEncryptionService: %v", err)
	}
	ciphertext, err := svc.EncryptForTenant(uuid.Nil, "system-account")
	if err != nil {
		t.Fatalf("EncryptForTenant(nil): %v", err)
	}
	// Still gets v2 prefix even though DEK == master.
	if !strings.HasPrefix(ciphertext, EncryptedPrefixV2) {
		t.Errorf("nil-tenant ciphertext should still carry v2 prefix: %q", ciphertext)
	}
	got, err := svc.DecryptForTenant(uuid.Nil, ciphertext)
	if err != nil {
		t.Fatalf("DecryptForTenant(nil): %v", err)
	}
	if got != "system-account" {
		t.Errorf("nil-tenant roundtrip = %q, want system-account", got)
	}
}

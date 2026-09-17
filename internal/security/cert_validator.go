// SPDX-License-Identifier: AGPL-3.0-or-later

// Package security provides security utilities.
package security

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// CertFingerprint returns the hex-encoded SHA-256 fingerprint of a certificate.
func CertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// ParsePEMOrDERCertificate accepts either PEM-encoded or raw base64 DER certificate.
func ParsePEMOrDERCertificate(input string) (*x509.Certificate, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, fmt.Errorf("empty certificate input")
	}

	// Try PEM first.
	if strings.HasPrefix(trimmed, "-----") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		return x509.ParseCertificate(block.Bytes)
	}

	// Try raw base64 DER.
	clean := strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(trimmed)
	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return x509.ParseCertificate(der)
}

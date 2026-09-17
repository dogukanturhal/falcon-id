// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// JWKS represents a JSON Web Key Set document.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key.
type JWK struct {
	KTY string `json:"kty"`           // Key type (RSA, EC)
	Use string `json:"use"`           // Key use (sig)
	KID string `json:"kid"`           // Key ID
	ALG string `json:"alg"`           // Algorithm
	N   string `json:"n,omitempty"`   // RSA modulus
	E   string `json:"e,omitempty"`   // RSA exponent
	CRV string `json:"crv,omitempty"` // EC curve
	X   string `json:"x,omitempty"`   // EC x coordinate
	Y   string `json:"y,omitempty"`   // EC y coordinate
}

// BuildJWKS constructs a JWKS document from a list of public keys.
// Only includes active and rotated keys; revoked keys are excluded.
func BuildJWKS(keys []PublicKeyInfo) (*JWKS, error) {
	jwks := &JWKS{Keys: make([]JWK, 0, len(keys))}

	for _, k := range keys {
		if k.Status == StatusRevoked {
			continue
		}

		jwk, err := publicKeyToJWK(k)
		if err != nil {
			return nil, fmt.Errorf("failed to convert key %s to JWK: %w", k.KeyID, err)
		}
		jwks.Keys = append(jwks.Keys, *jwk)
	}

	return jwks, nil
}

func publicKeyToJWK(info PublicKeyInfo) (*JWK, error) {
	switch pub := info.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsaPublicKeyToJWK(pub, info.KeyID, info.Algorithm)
	case *ecdsa.PublicKey:
		return ecdsaPublicKeyToJWK(pub, info.KeyID, info.Algorithm)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", info.PublicKey)
	}
}

func rsaPublicKeyToJWK(pub *rsa.PublicKey, kid, alg string) (*JWK, error) {
	return &JWK{
		KTY: "RSA",
		Use: "sig",
		KID: kid,
		ALG: alg,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}, nil
}

func ecdsaPublicKeyToJWK(pub *ecdsa.PublicKey, kid, alg string) (*JWK, error) {
	// Use ECDH() to obtain the uncompressed point bytes (0x04 || X || Y)
	// without accessing the deprecated pub.X / pub.Y fields (Go 1.26 SA1019).
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert EC key to ECDH form: %w", err)
	}
	// Uncompressed point: 0x04 prefix + X bytes + Y bytes.
	raw := ecdhPub.Bytes()
	coordLen := (len(raw) - 1) / 2
	xBytes := raw[1 : 1+coordLen]
	yBytes := raw[1+coordLen:]

	return &JWK{
		KTY: "EC",
		Use: "sig",
		KID: kid,
		ALG: alg,
		CRV: pub.Curve.Params().Name,
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
	}, nil
}

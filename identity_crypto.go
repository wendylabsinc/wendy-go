package wendy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
)

// GoSignatureVerifier verifies ES256 and pure ML-DSA-65 JWS signatures using
// Go's cryptography. Its zero value is ready for concurrent use. Core selects
// the JWK by token algorithm/key ID and validates claims after verification.
type GoSignatureVerifier struct{}

var _ SignatureVerifier = GoSignatureVerifier{}

// VerifySignature verifies exact message bytes, never a pre-hashed ML-DSA
// message. ES256 uses the JWS fixed-width R || S encoding, not ASN.1 DER.
// Cryptographic work is synchronous; cancellation is checked before and after.
func (GoSignatureVerifier) VerifySignature(ctx context.Context, jwk map[string]string, message, signature []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	valid := false
	switch jwk["alg"] {
	case "ES256":
		if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || len(signature) != 64 {
			break
		}
		xBytes, errX := base64.RawURLEncoding.DecodeString(jwk["x"])
		yBytes, errY := base64.RawURLEncoding.DecodeString(jwk["y"])
		if errX != nil || errY != nil {
			break
		}
		x, y := new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)
		if !elliptic.P256().IsOnCurve(x, y) {
			break
		}
		digest := sha256.Sum256(message)
		valid = ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:],
			new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
	case "ML-DSA-65":
		if jwk["kty"] != "AKP" {
			break
		}
		publicBytes, err := base64.RawURLEncoding.DecodeString(jwk["pub"])
		if err != nil {
			break
		}
		public, err := mldsa.NewPublicKey(mldsa.MLDSA65(), publicBytes)
		valid = err == nil && mldsa.Verify(public, message, signature, nil) == nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid or unsupported JWS signature")
	}
	return nil
}

// CryptoEntropy supplies secure random bytes from crypto/rand. Its zero value
// is ready for concurrent use.
type CryptoEntropy struct{}

var _ Entropy = CryptoEntropy{}

// RandomBytes returns exactly size caller-owned bytes. The random read cannot
// be interrupted; cancellation is checked before and after it.
func (CryptoEntropy) RandomBytes(ctx context.Context, size int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if size < 0 {
		return nil, errors.New("random byte count must not be negative")
	}
	result := make([]byte, size)
	if _, err := rand.Read(result); err != nil {
		return nil, errors.New("secure random generation failed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// Adapted from WendyOS enrollment proof primitives at 027e41342404 (Apache-2.0).
package wendy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// GoLegacyProofSigner signs the legacy Cloud ingress proof with a P-256 key.
// The key is parsed and retained by the host; Core receives only signatures.
// It is safe for concurrent use.
type GoLegacyProofSigner struct {
	key                 *ecdsa.PrivateKey
	identityURI, serial string
}

var _ LegacyProofSigner = (*GoLegacyProofSigner)(nil)

// NewLegacyProofSigner validates the CLI's PEM P-256 certificate/key pair and
// canonical serial. It accepts EC PRIVATE KEY and PKCS#8 PRIVATE KEY encodings.
// As in the CLI, identityURI is supplied by the caller; this checks key binding,
// not certificate trust, validity or authorization.
func NewLegacyProofSigner(identityURI, certificatePEM, privateKeyPEM string) (*GoLegacyProofSigner, error) {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("decode legacy certificate proof leaf certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse legacy certificate proof leaf certificate: %w", err)
	}
	block, _ = pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("decode legacy certificate proof private key")
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse legacy certificate proof EC private key: %w", err)
		}
	case "PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse legacy certificate proof PKCS#8 private key: %w", parseErr)
		}
		var ok bool
		key, ok = parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("legacy certificate proof private key is not ECDSA")
		}
	default:
		return nil, fmt.Errorf("unsupported legacy certificate proof private key PEM type %q", block.Type)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("legacy certificate proof private key must use ECDSA P-256")
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() || !publicKey.Equal(key.Public()) {
		return nil, fmt.Errorf("legacy certificate proof key does not match the P-256 certificate")
	}
	if certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 {
		return nil, fmt.Errorf("legacy certificate proof certificate serial must be positive")
	}
	serial := hex.EncodeToString(certificate.SerialNumber.Bytes())
	if len(serial) < 2 || len(serial) > 40 || len(serial)%2 != 0 || strings.HasPrefix(serial, "00") {
		return nil, fmt.Errorf("legacy certificate proof certificate serial is not canonical")
	}
	if identityURI == "" {
		return nil, fmt.Errorf("legacy certificate proof identity URI is empty")
	}
	return &GoLegacyProofSigner{key: key, identityURI: identityURI, serial: serial}, nil
}

// IdentityURI returns the caller-supplied legacy identity selector.
func (s *GoLegacyProofSigner) IdentityURI() string { return s.identityURI }

// CertificateSerial returns the canonical lowercase hexadecimal leaf serial.
func (s *GoLegacyProofSigner) CertificateSerial() string { return s.serial }

// SignLegacyProof hashes exact message bytes with SHA-256 and returns an ASN.1
// ECDSA signature, preserving the legacy ingress format (not JWS R || S).
func (s *GoLegacyProofSigner) SignLegacyProof(ctx context.Context, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return signature, err
}

// GoCompletionSigner signs device reset receipts with the caller's key.
// Key storage and certificate binding belong to the caller. Concurrent use is
// supported when the supplied crypto.Signer supports it.
type GoCompletionSigner struct{ key crypto.Signer }

var _ CompletionSigner = (*GoCompletionSigner)(nil)

// NewCompletionSigner accepts the CLI's ML-DSA, ECDSA and RSA device key types.
// It preserves pure ML-DSA or SHA-256 ECDSA/RSA PKCS#1 v1.5 encoding. Other key
// types are refused; no algorithm is silently substituted.
func NewCompletionSigner(key crypto.Signer) (*GoCompletionSigner, error) {
	if key == nil {
		return nil, fmt.Errorf("completion signer is required")
	}
	switch public := key.Public().(type) {
	case *mldsa.PublicKey:
		if public == nil {
			return nil, fmt.Errorf("unsupported completion key")
		}
	case *ecdsa.PublicKey:
		if public == nil {
			return nil, fmt.Errorf("unsupported completion key")
		}
	case *rsa.PublicKey:
		if public == nil {
			return nil, fmt.Errorf("unsupported completion key")
		}
	default:
		return nil, fmt.Errorf("unsupported completion key")
	}
	return &GoCompletionSigner{key: key}, nil
}

// SignCompletion checks cancellation before and after synchronous signing.
// ML-DSA signs body directly without a context string; ECDSA and RSA sign its
// SHA-256 digest, as in the existing device reset receipt.
func (s *GoCompletionSigner) SignCompletion(ctx context.Context, body []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	input, options := completionSigningInput(body, s.key.Public())
	signature, err := s.key.Sign(rand.Reader, input, options)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return signature, err
}

func completionSigningInput(body []byte, key crypto.PublicKey) ([]byte, crypto.SignerOpts) {
	if _, ok := key.(*mldsa.PublicKey); ok {
		return body, &mldsa.Options{}
	}
	digest := sha256.Sum256(body)
	return digest[:], crypto.SHA256
}

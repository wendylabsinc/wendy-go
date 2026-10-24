package wendy

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/x509"
	"errors"
)

// MLDSA65Signer signs exact message bytes with a Go ML-DSA-65 private key.
// It is safe for concurrent use. Key storage and certificate renewal belong to
// the caller; create a new signer after renewing the certificate chain.
type MLDSA65Signer struct {
	key   *mldsa.PrivateKey
	chain [][]byte
	spki  []byte
}

var _ Signer = (*MLDSA65Signer)(nil)

// NewMLDSA65Signer wraps the key type used by the CLI, including keys parsed by
// x509.ParsePKCS8PrivateKey. chain is optional, leaf-first DER; when present,
// its leaf must identify key. This checks key binding, not certificate trust,
// validity or authorization. chain is copied; the immutable key may be shared.
func NewMLDSA65Signer(key *mldsa.PrivateKey, chain [][]byte) (*MLDSA65Signer, error) {
	if key == nil || key.PublicKey().Parameters() != mldsa.MLDSA65() {
		return nil, errors.New("signer requires an ML-DSA-65 private key")
	}
	spki, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		return nil, errors.New("cannot encode signing public key")
	}
	if len(chain) > 0 {
		leaf, err := x509.ParseCertificate(chain[0])
		if err != nil {
			return nil, errors.New("invalid signing certificate")
		}
		if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, spki) {
			return nil, errors.New("signing certificate does not match key")
		}
	}
	return &MLDSA65Signer{key: key, chain: cloneChain(chain), spki: spki}, nil
}

// Algorithm returns MLDSA65.
func (*MLDSA65Signer) Algorithm() SignatureAlgorithm { return MLDSA65 }

// CertificateChain returns a caller-owned copy of the leaf-first DER chain.
func (s *MLDSA65Signer) CertificateChain(ctx context.Context) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return cloneChain(s.chain), nil
}

// PublicKey returns a caller-owned DER SubjectPublicKeyInfo for the signing key.
func (s *MLDSA65Signer) PublicKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return bytes.Clone(s.spki), nil
}

// Sign signs message without pre-hashing or an ML-DSA context string. The local
// cryptographic operation cannot be interrupted; cancellation is checked before
// and after it, and a canceled operation returns no signature.
func (s *MLDSA65Signer) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	signature, err := s.key.Sign(nil, message, &mldsa.Options{})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, errors.New("ML-DSA-65 signing failed")
	}
	return signature, nil
}

func cloneChain(chain [][]byte) [][]byte {
	if chain == nil {
		return nil
	}
	result := make([][]byte, len(chain))
	for i, cert := range chain {
		result[i] = bytes.Clone(cert)
	}
	return result
}

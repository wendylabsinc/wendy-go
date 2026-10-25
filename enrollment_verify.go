// Adapted from WendyOS enrollment proof primitives at 027e41342404 (Apache-2.0).
package wendy

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/wendylabsinc/wendy-go/internal/devicecerts"
)

// GoProofVerifier provides the CLI's certificate parsing and pure ML-DSA
// signature verification. Its zero value is ready for concurrent use. It never
// establishes certificate-chain trust or authority for a raw Cloud key.
type GoProofVerifier struct{}

var _ ProofVerifier = GoProofVerifier{}

// ParseProofCertificate returns public facts and the sole tenant SPIFFE URI.
// Missing or multiple tenant URIs leave Principal empty, as in the CLI. This
// neither verifies the certificate signature nor establishes trust or validity.
func (GoProofVerifier) ParseProofCertificate(ctx context.Context, der []byte) (ProofCertificate, error) {
	if err := ctx.Err(); err != nil {
		return ProofCertificate{}, err
	}
	leaf, err := x509.ParseCertificate(bytes.Clone(der))
	if err != nil {
		return ProofCertificate{}, err
	}
	principal, _ := devicecerts.TenantPrincipalFromCert(leaf)
	if err := ctx.Err(); err != nil {
		return ProofCertificate{}, err
	}
	return ProofCertificate{DER: leaf.Raw, Principal: principal, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
}

// VerifyMLDSA verifies exact message bytes with ML-DSA-65 or ML-DSA-87. key is
// raw public-key bytes, or a DER certificate when certificate is true. The
// requested algorithm must match the actual key; pre-hashed/context variants
// are never used. Cancellation is checked before and after cryptographic work.
func (GoProofVerifier) VerifyMLDSA(ctx context.Context, key, message, signature []byte, algorithm string, certificate bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var parameters mldsa.Parameters
	switch algorithm {
	case "ML-DSA-65":
		parameters = mldsa.MLDSA65()
	case "ML-DSA-87":
		parameters = mldsa.MLDSA87()
	default:
		return fmt.Errorf("unsupported ML-DSA proof algorithm")
	}
	var public *mldsa.PublicKey
	if certificate {
		leaf, err := x509.ParseCertificate(key)
		if err != nil {
			return err
		}
		var ok bool
		public, ok = leaf.PublicKey.(*mldsa.PublicKey)
		if !ok || public.Parameters() != parameters {
			return fmt.Errorf("ML-DSA proof key does not match algorithm")
		}
	} else {
		var err error
		public, err = mldsa.NewPublicKey(parameters, key)
		if err != nil {
			return err
		}
	}
	err := mldsa.Verify(public, message, signature, nil)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

// GoReceiptVerifier adds the CLI's reset signature, issuer and OCSP checks to
// GoProofVerifier. Its zero value is ready for concurrent use. Callers must
// independently anchor remote device chains and authenticate Cloud keys.
type GoReceiptVerifier struct{ GoProofVerifier }

var _ ReceiptVerifier = GoReceiptVerifier{}

// CertificateIssuer finds a supplied PEM certificate that signed this exact
// leaf. Embedded certificates are candidates only, never trusted roots. Like
// the CLI, unparsable/non-certificate PEM blocks are skipped.
func (GoReceiptVerifier) CertificateIssuer(ctx context.Context, der []byte, chain string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	candidates, _ := devicecerts.ParseCertsFromPEM([]byte(chain))
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if bytes.Equal(leaf.RawIssuer, candidate.RawSubject) && leaf.CheckSignatureFrom(candidate) == nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return candidate.Raw, nil
		}
	}
	return nil, fmt.Errorf("installed certificate issuer unavailable")
}

// VerifyCompletionSignature uses the certificate's actual ML-DSA, ECDSA or RSA
// key, retaining pure ML-DSA and SHA-256 ASN.1 ECDSA / RSA PKCS#1 v1.5 formats.
func (GoReceiptVerifier) VerifyCompletionSignature(ctx context.Context, der, body, signature []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	input, _ := completionSigningInput(body, leaf.PublicKey)
	switch key := leaf.PublicKey.(type) {
	case *mldsa.PublicKey:
		err = mldsa.Verify(key, body, signature, nil)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, input, signature) {
			err = fmt.Errorf("invalid completion signature")
		}
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(key, crypto.SHA256, input, signature)
	default:
		err = fmt.Errorf("unsupported completion key")
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

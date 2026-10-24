package wendy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"strings"
)

var _ IdentityKey = (*MLDSA65Signer)(nil)

// CertificateRequest creates a PEM PKCS#10 request using the CLI's clientAuth
// and digitalSignature extensions. subject becomes the common name; identity
// URI SANs are assigned by the issuing service, as in the CLI sign-in flow.
func (s *MLDSA65Signer) CertificateRequest(ctx context.Context, subject string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	usage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 1})
	if err != nil {
		return nil, errors.New("cannot encode CSR key usage")
	}
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 2}})
	if err != nil {
		return nil, errors.New("cannot encode CSR extended key usage")
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: subject},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: usage},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: eku},
		},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, s.key)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, errors.New("creating CSR failed")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// CheckCertificate normalizes a leaf-first PEM response, checks its leaf's key
// binding and extracts exactly one tenant SPIFFE URI. Core checks the URI's
// tenant, principal kind and subject. This checks neither chain trust nor
// certificate validity and does not update the signer's certificate chain.
func (s *MLDSA65Signer) CheckCertificate(ctx context.Context, chain []byte) (CertificateIdentity, error) {
	if err := ctx.Err(); err != nil {
		return CertificateIdentity{}, err
	}
	var leaf *x509.Certificate
	var leafPEM, chainPEM []byte
	for len(bytes.TrimSpace(chain)) > 0 {
		block, rest := pem.Decode(chain)
		if block == nil || block.Type != "CERTIFICATE" {
			return CertificateIdentity{}, errors.New("response contains non-certificate PEM data")
		}
		if leaf == nil {
			var err error
			leaf, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return CertificateIdentity{}, errors.New("invalid identity certificate")
			}
			leafPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
		} else {
			chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
		}
		chain = rest
	}
	if leaf == nil {
		return CertificateIdentity{}, errors.New("response contains no certificate")
	}
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, s.spki) {
		return CertificateIdentity{}, errors.New("pki-core returned a certificate for a different key")
	}
	var principal string
	for _, uri := range leaf.URIs {
		if strings.HasPrefix(uri.String(), "spiffe://wendy.sh/tenant/") {
			if principal != "" {
				return CertificateIdentity{}, errors.New("pki-core certificate must contain exactly one tenant SPIFFE principal")
			}
			principal = uri.String()
		}
	}
	if principal == "" {
		return CertificateIdentity{}, errors.New("pki-core certificate must contain exactly one tenant SPIFFE principal")
	}
	if err := ctx.Err(); err != nil {
		return CertificateIdentity{}, err
	}
	return CertificateIdentity{CertificatePEM: string(leafPEM), ChainPEM: string(chainPEM), PrincipalURI: principal}, nil
}

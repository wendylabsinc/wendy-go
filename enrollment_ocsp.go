// Adapted from WendyOS go/internal/shared/unenrollproof at 027e41342404 (Apache-2.0).
package wendy

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

type ocspCertID struct {
	Algorithm pkix.AlgorithmIdentifier
	NameHash  []byte
	KeyHash   []byte
	Serial    *big.Int
}
type ocspResponseData struct {
	Raw        asn1.RawContent
	Version    int `asn1:"optional,explicit,tag:0,default:0"`
	Responder  asn1.RawValue
	ProducedAt time.Time `asn1:"generalized"`
	Responses  []asn1.RawValue
	Extensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}
type ocspBasicResponse struct {
	Data         asn1.RawValue
	Algorithm    pkix.AlgorithmIdentifier
	Signature    asn1.BitString
	Certificates []asn1.RawValue `asn1:"optional,explicit,tag:0"`
}
type ocspResponseBytes struct {
	Type     asn1.ObjectIdentifier
	Response []byte
}
type ocspWireResponse struct {
	Status asn1.Enumerated
	Bytes  ocspResponseBytes `asn1:"optional,explicit,tag:0"`
}

// RevocationEvidence authenticates an issuer-signed OCSP answer for the exact
// leaf, including its CertID hashes and responder identity. Delegated responders
// are refused, as in the CLI. Core decides revoked status and freshness. No
// network access occurs and no supplied certificate becomes a trusted root.
func (GoReceiptVerifier) RevocationEvidence(ctx context.Context, raw, leafDER, issuerDER []byte) (RevocationEvidence, error) {
	if err := ctx.Err(); err != nil {
		return RevocationEvidence{}, err
	}
	if len(raw) == 0 || len(raw) > 256*1024 {
		return RevocationEvidence{}, fmt.Errorf("missing or oversized revocation evidence")
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return RevocationEvidence{}, err
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return RevocationEvidence{}, err
	}
	if leaf.CheckSignatureFrom(issuer) != nil {
		return RevocationEvidence{}, fmt.Errorf("invalid installed certificate issuer")
	}
	answer, err := ocsp.ParseResponseForCert(raw, leaf, nil)
	if err != nil {
		return RevocationEvidence{}, fmt.Errorf("invalid OCSP evidence: %w", err)
	}
	if answer.Certificate != nil || answer.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		return RevocationEvidence{}, fmt.Errorf("OCSP does not confirm installed-leaf revocation")
	}
	var outer ocspWireResponse
	rest, err := asn1.Unmarshal(raw, &outer)
	if err != nil || len(rest) != 0 || outer.Status != 0 || !outer.Bytes.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}) {
		return RevocationEvidence{}, fmt.Errorf("invalid OCSP envelope")
	}
	var basic ocspBasicResponse
	rest, err = asn1.Unmarshal(outer.Bytes.Response, &basic)
	if err != nil || len(rest) != 0 || len(basic.Certificates) != 0 {
		return RevocationEvidence{}, fmt.Errorf("unsupported OCSP signer")
	}
	alg := answer.SignatureAlgorithm
	switch basic.Algorithm.Algorithm.String() {
	case "2.16.840.1.101.3.4.3.17":
		alg = x509.MLDSA44
	case "2.16.840.1.101.3.4.3.18":
		alg = x509.MLDSA65
	case "2.16.840.1.101.3.4.3.19":
		alg = x509.MLDSA87
	}
	if err := issuer.CheckSignature(alg, answer.TBSResponseData, answer.Signature); err != nil {
		return RevocationEvidence{}, fmt.Errorf("invalid PKI revocation signature: %w", err)
	}
	var data ocspResponseData
	rest, err = asn1.Unmarshal(answer.TBSResponseData, &data)
	if err != nil || len(rest) != 0 || len(data.Responses) != 1 {
		return RevocationEvidence{}, fmt.Errorf("ambiguous OCSP response")
	}
	var id ocspCertID
	_, err = asn1.Unmarshal(data.Responses[0].Bytes, &id)
	if err != nil {
		return RevocationEvidence{}, fmt.Errorf("invalid OCSP certificate identity")
	}
	request, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: answer.IssuerHash})
	if err != nil {
		return RevocationEvidence{}, err
	}
	wanted, err := ocsp.ParseRequest(request)
	if err != nil || !bytes.Equal(id.NameHash, wanted.IssuerNameHash) || !bytes.Equal(id.KeyHash, wanted.IssuerKeyHash) {
		return RevocationEvidence{}, fmt.Errorf("OCSP issuer binding mismatch")
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return RevocationEvidence{}, err
	}
	keyHash := sha1.Sum(spki.Key.RightAlign())
	if len(answer.RawResponderName) != 0 {
		if !bytes.Equal(answer.RawResponderName, issuer.RawSubject) {
			return RevocationEvidence{}, fmt.Errorf("wrong OCSP responder")
		}
	} else if !bytes.Equal(answer.ResponderKeyHash, keyHash[:]) {
		return RevocationEvidence{}, fmt.Errorf("wrong OCSP responder key")
	}
	if err := ctx.Err(); err != nil {
		return RevocationEvidence{}, err
	}
	return RevocationEvidence{Revoked: answer.Status == ocsp.Revoked, Delegated: false, ThisUpdate: answer.ThisUpdate, ProducedAt: answer.ProducedAt, RevokedAt: answer.RevokedAt, NextUpdate: answer.NextUpdate}, nil
}

package devicecerts

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Exercise the CLI's custom verifier directly even when crypto/x509 supports
// the signature algorithm, so fallback chain checking remains covered.
func TestMLDSAChainVerifier(t *testing.T) {
	now := time.Now()
	rootKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	childKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	makeCert := func(template, parent *x509.Certificate, key *mldsa.PrivateKey) *x509.Certificate {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, template, parent, childKey.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ML-DSA root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	// A root must carry its own key, unlike the intermediate and leaf below.
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := *rootTemplate
	intermediateTemplate.SerialNumber = big.NewInt(2)
	intermediateTemplate.Subject = pkix.Name{CommonName: "ML-DSA intermediate"}
	intermediate := makeCert(&intermediateTemplate, root, rootKey)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leaf := makeCert(leafTemplate, intermediate, childKey)
	verify := func(cert *x509.Certificate, usage x509.ExtKeyUsage, at time.Time) error {
		return VerifyPeerCertificateChain(cert, []*x509.Certificate{intermediate}, []*x509.Certificate{root}, usage, at, at)
	}
	if err := verify(leaf, x509.ExtKeyUsageServerAuth, now); err != nil {
		t.Fatal(err)
	}
	if err := verify(leaf, x509.ExtKeyUsageClientAuth, now); err == nil {
		t.Fatal("accepted wrong usage")
	}
	if err := verify(leaf, x509.ExtKeyUsageServerAuth, now.Add(2*time.Minute)); err == nil {
		t.Fatal("accepted expired leaf")
	}
	corrupt := *leaf
	corrupt.Signature = append([]byte(nil), leaf.Signature...)
	corrupt.Signature[0] ^= 1
	if err := verify(&corrupt, x509.ExtKeyUsageServerAuth, now); err == nil {
		t.Fatal("accepted invalid ML-DSA signature")
	}
	if err := VerifyPeerCertificateChain(leaf, []*x509.Certificate{intermediate}, nil, x509.ExtKeyUsageServerAuth, now, now); err == nil {
		t.Fatal("peer intermediate became a trust anchor")
	}
}

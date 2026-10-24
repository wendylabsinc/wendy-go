package wendy_test

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	wendy "github.com/wendylabsinc/wendy-go"
)

func TestIdentityKeyCertificateRequest(t *testing.T) {
	key := signingKey(t)
	signer, err := wendy.NewMLDSA65Signer(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := signer.CertificateRequest(context.Background(), "operator subject")
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(request)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		t.Fatal("invalid PKCS#10 PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(csr.RawSubjectPublicKeyInfo, mustPublicKeyDER(t, key)) || csr.Subject.CommonName != "operator subject" || len(csr.URIs)+len(csr.DNSNames) != 0 {
		t.Fatal("CSR identity or key differs from CLI request")
	}
	var keyUsage, extendedKeyUsage bool
	for _, extension := range csr.Extensions {
		switch extension.Id.String() {
		case "2.5.29.15":
			var bits asn1.BitString
			rest, err := asn1.Unmarshal(extension.Value, &bits)
			keyUsage = err == nil && len(rest) == 0 && extension.Critical && bits.BitLength == 1 && bits.At(0) == 1
		case "2.5.29.37":
			var oids []asn1.ObjectIdentifier
			rest, err := asn1.Unmarshal(extension.Value, &oids)
			extendedKeyUsage = err == nil && len(rest) == 0 && !extension.Critical && len(oids) == 1 && oids[0].String() == "1.3.6.1.5.5.7.3.2"
		}
	}
	if !keyUsage || !extendedKeyUsage {
		t.Fatal("CSR lost CLI digitalSignature/clientAuth extensions")
	}
}

func mustPublicKeyDER(t *testing.T, key *mldsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func identityCertificate(t *testing.T, key *mldsa.PrivateKey, principals ...string) []byte {
	t.Helper()
	var uris []*url.URL
	for _, raw := range principals {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, u)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), URIs: uris}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.PublicKey(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestIdentityKeyChecksCertificateBindingAndSoleTenantPrincipal(t *testing.T) {
	const principal = "spiffe://wendy.sh/tenant/11111111-2222-4333-8444-555555555555/operator/test"
	key := signingKey(t)
	signer, err := wendy.NewMLDSA65Signer(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf := identityCertificate(t, key, principal, "urn:wendy:org:1:user:test")
	intermediate := identityCertificate(t, signingKey(t))
	chain := append(bytes.Clone(leaf), intermediate...)
	got, err := signer.CheckCertificate(context.Background(), chain)
	if err != nil || got.CertificatePEM != string(leaf) || got.ChainPEM != string(intermediate) || got.PrincipalURI != principal {
		t.Fatalf("certificate identity: %v", err)
	}
	if !bytes.Equal(chain, append(bytes.Clone(leaf), intermediate...)) {
		t.Fatal("borrowed chain mutated")
	}
	stored, err := signer.CertificateChain(context.Background())
	if err != nil || len(stored) != 0 {
		t.Fatal("checking a certificate changed signer state")
	}
	for _, invalid := range [][]byte{
		nil, []byte("garbage"), []byte("  \n"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}),
		append(bytes.Clone(leaf), []byte("trailing garbage")...),
		identityCertificate(t, signingKey(t), principal),
		identityCertificate(t, key), identityCertificate(t, key, "spiffe://untrusted.example/tenant/1/operator/test"),
		identityCertificate(t, key, principal, principal),
		identityCertificate(t, key, principal, "spiffe://wendy.sh/tenant/aaaaaaaa-2222-4333-8444-555555555555/operator/test"),
	} {
		if got, err := signer.CheckCertificate(context.Background(), invalid); got != (wendy.CertificateIdentity{}) || err == nil {
			t.Fatal("accepted invalid or ambiguous certificate")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := signer.CheckCertificate(ctx, chain); got != (wendy.CertificateIdentity{}) || !errors.Is(err, context.Canceled) {
		t.Fatalf("certificate cancellation: %v", err)
	}
	if got, err := signer.CertificateRequest(ctx, "test"); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("CSR cancellation: %v", err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := signer.CertificateRequest(context.Background(), "test"); err != nil {
				t.Error(err)
			}
			if _, err := signer.CheckCertificate(context.Background(), chain); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

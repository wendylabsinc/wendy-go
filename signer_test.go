package wendy_test

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/wendylabsinc/wendy-go"
)

func signingKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the CLI's PKCS#8 seed encoding and parsed key type.
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.(*mldsa.PrivateKey)
}

func signingCertificate(t *testing.T, key *mldsa.PrivateKey) []byte {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestMLDSA65Signer(t *testing.T) {
	key := signingKey(t)
	certificate := signingCertificate(t, key)
	chain := [][]byte{bytes.Clone(certificate), bytes.Clone(certificate)}
	signer, err := wendy.NewMLDSA65Signer(key, chain)
	if err != nil {
		t.Fatal(err)
	}
	var capability wendy.Signer = signer
	if capability.Algorithm() != wendy.MLDSA65 {
		t.Fatal("wrong signing algorithm")
	}
	chain[0][0] ^= 1
	chain[1][0] ^= 1
	for range 2 {
		got, err := signer.CertificateChain(context.Background())
		if err != nil || !bytes.Equal(got[0], certificate) || !bytes.Equal(got[1], certificate) {
			t.Fatalf("chain ownership: %v", err)
		}
		got[0][0] ^= 1
		got[1][0] ^= 1
	}
	for range 2 {
		spki, err := signer.PublicKey(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		public, err := x509.ParsePKIXPublicKey(spki)
		if err != nil || !key.PublicKey().Equal(public) {
			t.Fatalf("SPKI: %v", err)
		}
		spki[0] ^= 1
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for _, message := range [][]byte{nil, {}, []byte("exact\x00message\xff")} {
				original := bytes.Clone(message)
				signature, err := signer.Sign(context.Background(), message)
				if err != nil {
					t.Error(err)
					return
				}
				if err := mldsa.Verify(key.PublicKey(), message, signature, nil); err != nil {
					t.Error(err)
				}
				if !bytes.Equal(message, original) {
					t.Error("message modified")
				}
				if mldsa.Verify(key.PublicKey(), append(bytes.Clone(message), 1), signature, nil) == nil {
					t.Error("signature accepted changed message")
				}
			}
		})
	}
	wg.Wait()
}

func TestMLDSA65SignerValidationAndCancellation(t *testing.T) {
	key := signingKey(t)
	if _, err := wendy.NewMLDSA65Signer(nil, nil); err == nil {
		t.Fatal("accepted nil key")
	}
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA87()} {
		wrong, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wendy.NewMLDSA65Signer(wrong, nil); err == nil {
			t.Fatal("accepted another parameter set")
		}
	}
	for _, chain := range [][][]byte{{{}}, {signingCertificate(t, signingKey(t))}} {
		if _, err := wendy.NewMLDSA65Signer(key, chain); err == nil {
			t.Fatal("accepted invalid or mismatched certificate")
		}
	}
	signer, err := wendy.NewMLDSA65Signer(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if chain, err := signer.CertificateChain(context.Background()); err != nil || chain != nil {
		t.Fatalf("public-key-only chain: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for _, ctx := range []context.Context{canceled, expired} {
		if got, err := signer.Sign(ctx, []byte("secret")); got != nil || !errors.Is(err, ctx.Err()) {
			t.Fatalf("Sign cancellation: %v", err)
		}
		if got, err := signer.PublicKey(ctx); got != nil || !errors.Is(err, ctx.Err()) {
			t.Fatalf("PublicKey cancellation: %v", err)
		}
		if got, err := signer.CertificateChain(ctx); got != nil || !errors.Is(err, ctx.Err()) {
			t.Fatalf("CertificateChain cancellation: %v", err)
		}
	}
}

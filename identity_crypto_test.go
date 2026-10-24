package wendy_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"

	wendy "github.com/wendylabsinc/wendy-go"
)

func TestSignatureVerifierES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("header.payload\x00\xff")
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	jwk := map[string]string{"alg": "ES256", "kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}
	verifySignatureCases(t, jwk, message, signature, map[string][]string{
		"alg": {"", "ES384", "ML-DSA-65", "none"}, "kty": {"", "RSA", "AKP"},
		"crv": {"", "P-384"}, "x": {"", "%%", "AA"}, "y": {"", "%%", "AA"},
	})
	derSignature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := (wendy.GoSignatureVerifier{}).VerifySignature(context.Background(), jwk, message, derSignature); err == nil {
		t.Fatal("accepted DER instead of JWS R || S")
	}
}

func TestSignatureVerifierMLDSA65(t *testing.T) {
	key := signingKey(t)
	message := []byte("header.payload\x00\xff")
	signature, err := key.Sign(nil, message, &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]string{"alg": "ML-DSA-65", "kty": "AKP", "pub": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())}
	verifySignatureCases(t, jwk, message, signature, map[string][]string{
		"alg": {"", "ML-DSA-44", "ML-DSA-87", "ES256", "none"}, "kty": {"", "EC", "OKP"},
		"pub": {"", "%%", "AA", base64.RawURLEncoding.EncodeToString(signingKey(t).PublicKey().Bytes())},
	})
	digest := sha256.Sum256(message)
	if err := (wendy.GoSignatureVerifier{}).VerifySignature(context.Background(), jwk, digest[:], signature); err == nil {
		t.Fatal("accepted a pre-hashed ML-DSA message")
	}
}

func verifySignatureCases(t *testing.T, jwk map[string]string, message, signature []byte, invalidFields map[string][]string) {
	t.Helper()
	verifier := wendy.GoSignatureVerifier{}
	if err := verifier.VerifySignature(context.Background(), jwk, message, signature); err != nil {
		t.Fatal(err)
	}
	for name, values := range invalidFields {
		for _, value := range values {
			changed := maps.Clone(jwk)
			changed[name] = value
			if err := verifier.VerifySignature(context.Background(), changed, message, signature); err == nil {
				t.Fatalf("accepted invalid %s", name)
			}
		}
	}
	if err := verifier.VerifySignature(context.Background(), nil, message, signature); err == nil {
		t.Fatal("accepted missing JWK")
	}
	changed := bytes.Clone(signature)
	changed[0] ^= 1
	for _, sig := range [][]byte{nil, signature[:len(signature)-1], changed, make([]byte, len(signature))} {
		if err := verifier.VerifySignature(context.Background(), jwk, message, sig); err == nil {
			t.Fatal("accepted invalid signature")
		}
	}
	if err := verifier.VerifySignature(context.Background(), jwk, append(bytes.Clone(message), '!'), signature); err == nil {
		t.Fatal("accepted different message")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.VerifySignature(ctx, jwk, message, signature); !errors.Is(err, context.Canceled) {
		t.Fatalf("verification cancellation: %v", err)
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := verifier.VerifySignature(ctx, jwk, message, signature); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("verification deadline: %v", err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := verifier.VerifySignature(context.Background(), jwk, message, signature); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func TestCryptoEntropy(t *testing.T) {
	entropy := wendy.CryptoEntropy{}
	if data, err := entropy.RandomBytes(context.Background(), -1); data != nil || err == nil {
		t.Fatal("accepted negative size")
	}
	if data, err := entropy.RandomBytes(context.Background(), 0); len(data) != 0 || err != nil {
		t.Fatalf("empty entropy: %v", err)
	}
	var wg sync.WaitGroup
	results := make(chan []byte, 8)
	for range 8 {
		wg.Go(func() {
			data, err := entropy.RandomBytes(context.Background(), 32)
			if err != nil || len(data) != 32 {
				t.Errorf("random bytes: %v", err)
			}
			results <- data
		})
	}
	wg.Wait()
	close(results)
	seen := make(map[string]bool)
	for data := range results {
		if seen[string(data)] || bytes.Equal(data, make([]byte, 32)) {
			t.Fatal("random bytes repeated or all zero")
		}
		seen[string(data)] = true
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if data, err := entropy.RandomBytes(ctx, 32); data != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("entropy cancellation: %v", err)
	}
}

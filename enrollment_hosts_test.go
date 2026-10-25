package wendy_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"testing"
	"time"

	wendy "github.com/wendylabsinc/wendy-go"
	"github.com/wendylabsinc/wendy-go/enrollment"
	"golang.org/x/crypto/ocsp"
)

const proofPrincipal = "spiffe://wendy.sh/tenant/11111111-1111-4111-8111-111111111111/device/22222222-2222-4222-8222-222222222222"

func proofKey(t *testing.T, algorithm string) crypto.Signer {
	t.Helper()
	var key crypto.Signer
	var err error
	switch algorithm {
	case "ML-DSA-44":
		key, err = mldsa.GenerateKey(mldsa.MLDSA44())
	case "ML-DSA-65":
		key, err = mldsa.GenerateKey(mldsa.MLDSA65())
	case "ML-DSA-87":
		key, err = mldsa.GenerateKey(mldsa.MLDSA87())
	case "P256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "RSA":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "Ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("unknown key type: %s", algorithm)
	}
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func proofCert(t *testing.T, template, parent *x509.Certificate, public crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func proofFixture(t *testing.T, algorithm string) (leaf, issuer *x509.Certificate, key, caKey crypto.Signer) {
	t.Helper()
	caKey, key = proofKey(t, algorithm), proofKey(t, algorithm)
	now := time.Now().Truncate(time.Second)
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "Enrollment issuer"}, SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	issuer = proofCert(t, tmpl, tmpl, caKey.Public(), caKey)
	uri, err := url.Parse(proofPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	tmpl = &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature}
	leaf = proofCert(t, tmpl, issuer, key.Public(), caKey)
	return
}

func certPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func TestLegacyEnrollmentProofFormatsAndBinding(t *testing.T) {
	leaf, _, key, _ := proofFixture(t, "P256")
	ctx := context.Background()
	for _, encoding := range []string{"EC PRIVATE KEY", "PRIVATE KEY"} {
		t.Run(encoding, func(t *testing.T) {
			var der []byte
			var err error
			if encoding == "EC PRIVATE KEY" {
				der, err = x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
			} else {
				der, err = x509.MarshalPKCS8PrivateKey(key)
			}
			if err != nil {
				t.Fatal(err)
			}
			signer, err := wendy.NewLegacyProofSigner(proofPrincipal, certPEM(leaf), string(pem.EncodeToMemory(&pem.Block{Type: encoding, Bytes: der})))
			if err != nil {
				t.Fatal(err)
			}
			if signer.IdentityURI() != proofPrincipal || signer.CertificateSerial() != "2a" {
				t.Fatal("lost legacy identity/serial")
			}
			now := time.Unix(1700000000, 0)
			md, err := enrollment.LegacyMetadata(ctx, signer.IdentityURI(), signer.CertificateSerial(), "/legacy.Service/Enroll", wendy.CryptoEntropy{}, signer, now)
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]string{}
			for _, entry := range md {
				values[entry.Name] = string(entry.Value)
			}
			nonce, err := base64.RawURLEncoding.DecodeString(values[enrollment.NonceHeader])
			if err != nil || len(nonce) != 16 {
				t.Fatal("invalid nonce")
			}
			var canonical bytes.Buffer
			for _, component := range []string{"wendy-legacy-certificate-proof/v1", "legacy.Service/Enroll", proofPrincipal, "2a", "1700000000", values[enrollment.NonceHeader]} {
				if err := binary.Write(&canonical, binary.BigEndian, uint32(len(component))); err != nil {
					t.Fatal(err)
				}
				canonical.WriteString(component)
			}
			signature, err := base64.RawURLEncoding.DecodeString(values[enrollment.SignatureHeader])
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(canonical.Bytes())
			if !ecdsa.VerifyASN1(key.Public().(*ecdsa.PublicKey), digest[:], signature) {
				t.Fatal("legacy proof changed its signing input or encoding")
			}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if sig, err := signer.SignLegacyProof(canceled, canonical.Bytes()); !errors.Is(err, context.Canceled) || sig != nil {
				t.Fatal("canceled signing returned output")
			}
		})
	}
	wrong := proofKey(t, "P256")
	marshalKey := func(key crypto.Signer) string {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	for _, tc := range []struct{ name, cert, key, identity string }{
		{"mismatched key", certPEM(leaf), marshalKey(wrong), proofPrincipal},
		{"non P256", certPEM(leaf), marshalKey(proofKey(t, "P384")), proofPrincipal},
		{"non ECDSA", certPEM(leaf), marshalKey(proofKey(t, "Ed25519")), proofPrincipal},
		{"missing identity", certPEM(leaf), marshalKey(key), ""},
		{"malformed certificate", "bad", marshalKey(key), proofPrincipal},
		{"malformed key", certPEM(leaf), "bad", proofPrincipal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := wendy.NewLegacyProofSigner(tc.identity, tc.cert, tc.key); err == nil {
				t.Fatal("invalid pair accepted")
			}
		})
	}
}

func TestEnrollmentProofVerification(t *testing.T) {
	ctx := context.Background()
	verifier := wendy.GoProofVerifier{}
	for _, algorithm := range []string{"ML-DSA-65", "ML-DSA-87"} {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			leaf, _, key, _ := proofFixture(t, algorithm)
			message := []byte("header.exact-proof-body")
			signature, err := key.Sign(rand.Reader, message, &mldsa.Options{})
			if err != nil {
				t.Fatal(err)
			}
			for _, certificate := range []bool{false, true} {
				material := key.Public().(*mldsa.PublicKey).Bytes()
				if certificate {
					material = leaf.Raw
				}
				if err := verifier.VerifyMLDSA(ctx, material, message, signature, algorithm, certificate); err != nil {
					t.Fatal(err)
				}
				for _, tc := range []struct {
					name           string
					key, body, sig []byte
					alg            string
				}{
					{"body", material, []byte("changed"), signature, algorithm},
					{"signature", material, message, append([]byte{signature[0] ^ 1}, signature[1:]...), algorithm},
					{"algorithm", material, message, signature, map[string]string{"ML-DSA-65": "ML-DSA-87", "ML-DSA-87": "ML-DSA-65"}[algorithm]},
					{"unsupported", material, message, signature, "ML-DSA-44"},
					{"malformed", []byte("bad"), message, signature, algorithm},
				} {
					if err := verifier.VerifyMLDSA(ctx, tc.key, tc.body, tc.sig, tc.alg, certificate); err == nil {
						t.Fatalf("accepted changed %s (certificate=%v)", tc.name, certificate)
					}
				}
			}
			parsed, err := verifier.ParseProofCertificate(ctx, leaf.Raw)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Principal != proofPrincipal || !parsed.NotBefore.Equal(leaf.NotBefore) || !parsed.NotAfter.Equal(leaf.NotAfter) {
				t.Fatal("lost certificate facts")
			}
			parsed.DER[0] ^= 1
			if bytes.Equal(parsed.DER, leaf.Raw) {
				t.Fatal("certificate output aliases input")
			}
		})
	}
	leaf, issuer, key, caKey := proofFixture(t, "P256")
	if err := verifier.VerifyMLDSA(ctx, leaf.Raw, []byte("body"), nil, "ML-DSA-65", true); err == nil {
		t.Fatal("ECDSA key accepted as ML-DSA")
	}
	for _, uris := range [][]*url.URL{nil, {leaf.URIs[0], leaf.URIs[0]}} {
		template := *leaf
		template.URIs = uris
		cert := proofCert(t, &template, issuer, key.Public(), caKey)
		parsed, err := verifier.ParseProofCertificate(ctx, cert.Raw)
		if err != nil || parsed.Principal != "" {
			t.Fatal("missing/ambiguous tenant principal accepted", err)
		}
	}
	if _, err := verifier.ParseProofCertificate(ctx, []byte("bad")); err == nil {
		t.Fatal("malformed certificate accepted")
	}
}

func TestCompletionSigningAlgorithms(t *testing.T) {
	ctx := context.Background()
	verifier := wendy.GoReceiptVerifier{}
	for _, algorithm := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "P256", "P384", "RSA"} {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			leaf, _, key, _ := proofFixture(t, algorithm)
			signer, err := wendy.NewCompletionSigner(key)
			if err != nil {
				t.Fatal(err)
			}
			body := []byte(`{"receipt":"exact canonical body"}`)
			signature, err := signer.SignCompletion(ctx, body)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(body)
			switch public := key.Public().(type) {
			case *mldsa.PublicKey:
				err = mldsa.Verify(public, body, signature, nil)
			case *ecdsa.PublicKey:
				if !ecdsa.VerifyASN1(public, digest[:], signature) {
					t.Fatal("invalid ECDSA receipt")
				}
			case *rsa.PublicKey:
				err = rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := verifier.VerifyCompletionSignature(ctx, leaf.Raw, body, signature); err != nil {
				t.Fatal(err)
			}
			if err := verifier.VerifyCompletionSignature(ctx, leaf.Raw, []byte("changed"), signature); err == nil {
				t.Fatal("changed receipt accepted")
			}
			if err := verifier.VerifyCompletionSignature(ctx, leaf.Raw, body, signature[:len(signature)-1]); err == nil {
				t.Fatal("truncated signature accepted")
			}
		})
	}
	if _, err := wendy.NewCompletionSigner(nil); err == nil {
		t.Fatal("nil signer accepted")
	}
	if _, err := wendy.NewCompletionSigner(proofKey(t, "Ed25519")); err == nil {
		t.Fatal("unsupported key accepted")
	}
	leaf, _, _, _ := proofFixture(t, "Ed25519")
	if err := verifier.VerifyCompletionSignature(ctx, leaf.Raw, []byte("body"), nil); err == nil {
		t.Fatal("unsupported receipt key accepted")
	}
}

// Independent OCSP fixture encodings allow authenticated but misbound replies.
type testOCSPBytes struct {
	Type     asn1.ObjectIdentifier
	Response []byte
}
type testOCSPEnvelope struct {
	Status asn1.Enumerated
	Bytes  testOCSPBytes `asn1:"optional,explicit,tag:0"`
}
type testOCSPBasic struct {
	Data         asn1.RawValue
	Algorithm    pkix.AlgorithmIdentifier
	Signature    asn1.BitString
	Certificates []asn1.RawValue `asn1:"optional,explicit,tag:0"`
}
type testOCSPData struct {
	Raw        asn1.RawContent
	Version    int `asn1:"optional,explicit,tag:0,default:0"`
	Responder  asn1.RawValue
	ProducedAt time.Time `asn1:"generalized"`
	Responses  []asn1.RawValue
	Extensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

func mustASN1(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func decodeASN1(t *testing.T, raw []byte, value any) {
	t.Helper()
	rest, err := asn1.Unmarshal(raw, value)
	if err != nil || len(rest) != 0 {
		t.Fatal("invalid fixture ASN.1", err)
	}
}

func proofOCSP(t *testing.T, leaf, issuer *x509.Certificate, key crypto.Signer, status int, mutate func(*testOCSPBasic)) []byte {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	template := ocsp.Response{IssuerHash: crypto.SHA256, Status: status, SerialNumber: leaf.SerialNumber, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), RevokedAt: now.Add(-time.Minute)}
	signer := key
	if _, ok := key.Public().(*mldsa.PublicKey); ok {
		signer = proofKey(t, "P256")
	}
	raw, err := ocsp.CreateResponse(issuer, issuer, template, signer)
	if err != nil {
		t.Fatal(err)
	}
	var outer testOCSPEnvelope
	decodeASN1(t, raw, &outer)
	var basic testOCSPBasic
	decodeASN1(t, outer.Bytes.Response, &basic)
	if mutate != nil {
		mutate(&basic)
	}
	if public, ok := key.Public().(*mldsa.PublicKey); ok {
		switch public.Parameters() {
		case mldsa.MLDSA44():
			basic.Algorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
		case mldsa.MLDSA65():
			basic.Algorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
		case mldsa.MLDSA87():
			basic.Algorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
		}
		signature, err := key.Sign(rand.Reader, basic.Data.FullBytes, &mldsa.Options{})
		if err != nil {
			t.Fatal(err)
		}
		basic.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	} else {
		digest := sha256.Sum256(basic.Data.FullBytes)
		signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		basic.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	}
	outer.Bytes.Response = mustASN1(t, basic)
	return mustASN1(t, outer)
}

func TestEnrollmentOCSPAndReceiptRoundTrip(t *testing.T) {
	ctx := context.Background()
	verifier := wendy.GoReceiptVerifier{}
	for _, algorithm := range []string{"P256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "RSA"} {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			leaf, issuer, key, caKey := proofFixture(t, algorithm)
			evidence := proofOCSP(t, leaf, issuer, caKey, ocsp.Revoked, nil)
			facts, err := verifier.RevocationEvidence(ctx, evidence, leaf.Raw, issuer.Raw)
			if err != nil {
				t.Fatal(err)
			}
			if !facts.Revoked || facts.Delegated || facts.NextUpdate.IsZero() {
				t.Fatal("lost OCSP facts")
			}
			now := time.Now().Truncate(time.Second)
			if err := enrollment.VerifyRevocation(ctx, verifier, evidence, leaf.Raw, issuer.Raw, now); err != nil {
				t.Fatal(err)
			}
			if err := enrollment.VerifyRevocation(ctx, verifier, evidence, leaf.Raw, issuer.Raw, now.Add(2*time.Hour)); err == nil {
				t.Fatal("stale OCSP accepted")
			}
			if err := enrollment.VerifyRevocation(ctx, verifier, evidence, leaf.Raw, issuer.Raw, now.Add(-time.Hour)); err == nil {
				t.Fatal("future OCSP accepted")
			}
			good := proofOCSP(t, leaf, issuer, caKey, ocsp.Good, nil)
			if err := enrollment.VerifyRevocation(ctx, verifier, good, leaf.Raw, issuer.Raw, now); err == nil {
				t.Fatal("good status authorized reset")
			}
			digest := sha256.Sum256(leaf.Raw)
			record := enrollment.Completion{Principal: proofPrincipal, Cloud: "api.example:443", AssetID: "33333333-3333-4333-8333-333333333333", Fingerprint: hex.EncodeToString(digest[:]), AuthorizedAt: now.Unix(), Certificate: leaf.Raw, Chain: certPEM(issuer), Revocation: evidence}
			signer, err := wendy.NewCompletionSigner(key)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := enrollment.SignCompletion(ctx, record, signer)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := enrollment.ReadCompletion(ctx, verifier, receipt)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Principal != record.Principal || parsed.Fingerprint != record.Fingerprint || parsed.Version != 1 {
				t.Fatal("receipt round trip lost identity")
			}
			var envelope struct{ Body, Signature []byte }
			if err := json.Unmarshal(receipt, &envelope); err != nil {
				t.Fatal(err)
			}
			envelope.Body = append(envelope.Body, ' ')
			changed, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := enrollment.ReadCompletion(ctx, verifier, changed); err == nil {
				t.Fatal("tampered receipt accepted")
			}
			found, err := verifier.CertificateIssuer(ctx, leaf.Raw, "ignored text\n"+certPEM(leaf)+certPEM(issuer))
			if err != nil || !bytes.Equal(found, issuer.Raw) {
				t.Fatal("issuer selection failed", err)
			}
		})
	}
}

func TestEnrollmentOCSPRejectsMisboundEvidence(t *testing.T) {
	ctx := context.Background()
	verifier := wendy.GoReceiptVerifier{}
	leaf, issuer, _, caKey := proofFixture(t, "ML-DSA-65")
	_, foreign, _, _ := proofFixture(t, "ML-DSA-65")
	valid := proofOCSP(t, leaf, issuer, caKey, ocsp.Revoked, nil)
	mutateData := func(mutate func(*testOCSPData)) func(*testOCSPBasic) {
		return func(basic *testOCSPBasic) {
			var data testOCSPData
			decodeASN1(t, basic.Data.FullBytes, &data)
			data.Raw = nil
			mutate(&data)
			basic.Data = asn1.RawValue{FullBytes: mustASN1(t, data)}
		}
	}
	cases := []struct {
		name              string
		raw, leaf, issuer []byte
	}{
		{"malformed", []byte("bad"), leaf.Raw, issuer.Raw},
		{"missing", nil, leaf.Raw, issuer.Raw},
		{"oversized", make([]byte, enrollment.MaxProofBytes+1), leaf.Raw, issuer.Raw},
		{"different issuer", valid, leaf.Raw, foreign.Raw},
		{"invalid leaf", valid, []byte("bad"), issuer.Raw},
		{"invalid issuer", valid, leaf.Raw, []byte("bad")},
		{"trailing data", append(bytes.Clone(valid), 0), leaf.Raw, issuer.Raw},
		{"forged signature", append(bytes.Clone(valid[:len(valid)-1]), valid[len(valid)-1]^1), leaf.Raw, issuer.Raw},
		{"delegated", proofOCSP(t, leaf, issuer, caKey, ocsp.Revoked, func(b *testOCSPBasic) { b.Certificates = []asn1.RawValue{{FullBytes: issuer.Raw}} }), leaf.Raw, issuer.Raw},
		{"ambiguous", proofOCSP(t, leaf, issuer, caKey, ocsp.Revoked, mutateData(func(d *testOCSPData) { d.Responses = append(d.Responses, d.Responses[0]) })), leaf.Raw, issuer.Raw},
		{"responder", proofOCSP(t, leaf, issuer, caKey, ocsp.Revoked, mutateData(func(d *testOCSPData) {
			d.Responder = asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: mustASN1(t, pkix.Name{CommonName: "wrong responder"}.ToRDNSequence())}
		})), leaf.Raw, issuer.Raw},
		{"issuer hash", proofOCSP(t, leaf, issuer, caKey, ocsp.Revoked, mutateData(func(d *testOCSPData) {
			var id struct {
				Algorithm         pkix.AlgorithmIdentifier
				NameHash, KeyHash []byte
				Serial            *big.Int
			}
			_, err := asn1.Unmarshal(d.Responses[0].Bytes, &id)
			if err != nil {
				t.Fatal(err)
			}
			id.KeyHash[0] ^= 1
			// Replace only the CertID inside the signed SingleResponse.
			old := d.Responses[0].Bytes
			var original asn1.RawValue
			rest, err := asn1.Unmarshal(old, &original)
			if err != nil {
				t.Fatal(err)
			}
			contents := append(mustASN1(t, id), rest...)
			d.Responses[0] = asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: contents}
		})), leaf.Raw, issuer.Raw},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifier.RevocationEvidence(ctx, tc.raw, tc.leaf, tc.issuer); err == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
	if _, err := verifier.CertificateIssuer(ctx, leaf.Raw, certPEM(foreign)); err == nil {
		t.Fatal("foreign issuer accepted")
	}
	if _, err := verifier.CertificateIssuer(ctx, leaf.Raw, "bad"); err == nil {
		t.Fatal("absent issuer accepted")
	}
	if _, err := verifier.CertificateIssuer(ctx, []byte("bad"), certPEM(issuer)); err == nil {
		t.Fatal("malformed leaf accepted")
	}
}

type cancelCompletionKey struct {
	crypto.Signer
	cancel context.CancelFunc
}

func (s cancelCompletionKey) Sign(random io.Reader, body []byte, options crypto.SignerOpts) ([]byte, error) {
	sig, err := s.Signer.Sign(random, body, options)
	s.cancel()
	return sig, err
}

func TestEnrollmentHostsHonorCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	verifier := wendy.GoReceiptVerifier{}
	if _, err := verifier.ParseProofCertificate(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := verifier.VerifyMLDSA(ctx, nil, nil, nil, "ML-DSA-65", false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := verifier.CertificateIssuer(ctx, nil, ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := verifier.VerifyCompletionSignature(ctx, nil, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := verifier.RevocationEvidence(ctx, nil, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	key := proofKey(t, "P256")
	signer, err := wendy.NewCompletionSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	if sig, err := signer.SignCompletion(ctx, []byte("body")); !errors.Is(err, context.Canceled) || sig != nil {
		t.Fatal("canceled completion returned output")
	}
	after, stop := context.WithCancel(context.Background())
	defer stop()
	signer, err = wendy.NewCompletionSigner(cancelCompletionKey{key, stop})
	if err != nil {
		t.Fatal(err)
	}
	if sig, err := signer.SignCompletion(after, []byte("body")); !errors.Is(err, context.Canceled) || sig != nil {
		t.Fatal("late cancellation leaked a signature")
	}
}

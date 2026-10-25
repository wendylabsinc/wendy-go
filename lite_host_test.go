package wendy_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	wendy "github.com/wendylabsinc/wendy-go"
	liteenroll "github.com/wendylabsinc/wendy-go/lite/enrollment"
	"github.com/wendylabsinc/wendy-go/lite/pb"
)

func liteCA(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Lite test CA"}, NotBefore: time.Now().Add(-time.Hour).Truncate(time.Second), NotAfter: time.Now().Add(time.Hour).Truncate(time.Second), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestLiteCertificateInspection(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pq, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, algorithm, oid string
		key                  crypto.Signer
		p256                 bool
	}{
		{"P256", "ECDSA", "1.2.840.10045.4.3.2", ec, true},
		{"RSA", "RSA", "1.2.840.113549.1.1.11", rsaKey, false},
		{"MLDSA65", "ML-DSA", "2.16.840.1.101.3.4.3.18", pq, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der := liteCA(t, tc.key)
			original := bytes.Clone(der)
			c, err := (wendy.GoLiteCertificateInspector{}).InspectCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			parsed, _ := x509.ParseCertificate(original)
			if c.PublicKeyAlgorithm != tc.algorithm || c.SignatureOID != tc.oid || c.P256 != tc.p256 || !c.SelfSignatureValid || !c.IsCA || !c.BasicConstraintsValid || !c.NotBefore.Equal(parsed.NotBefore) || !c.NotAfter.Equal(parsed.NotAfter) || !bytes.Equal(c.RawIssuer, parsed.RawIssuer) || !bytes.Equal(c.RawSubject, parsed.RawSubject) {
				t.Fatalf("certificate facts differ: %+v", c)
			}
			clear(der)
			if !bytes.Equal(c.Raw, original) {
				t.Fatal("certificate borrows input bytes")
			}
			original[len(original)-1] ^= 1
			bad, err := (wendy.GoLiteCertificateInspector{}).InspectCertificate(original)
			if err != nil || bad.SelfSignatureValid {
				t.Fatalf("tampered signature: %v, %v", bad, err)
			}
		})
	}
	if _, err := (wendy.GoLiteCertificateInspector{}).InspectCertificate([]byte("bad DER")); err == nil {
		t.Fatal("accepted invalid DER")
	}
}

func TestLiteHTTPVerifiedChainsAndDiscovery(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: liteCA(t, key)})
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == http.MethodGet {
			if r.URL.Query().Get("chain_algorithm") != "ECDSA_P256" {
				t.Error("missing selected chain algorithm")
			}
			w.Header().Set("X-Wendy-Chain-Algorithm", "ECDSA_P256")
			_, _ = w.Write(roots)
		}
	}))
	defer server.Close()
	transport, err := wendy.NewLiteHTTPTransport(server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.DoLite(context.Background(), wendy.HTTPRequest{Method: "HEAD", URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(response.VerifiedChains) != 1 || len(response.VerifiedChains[0]) != 1 || !bytes.Equal(response.VerifiedChains[0][0].Raw, server.Certificate().Raw) {
		t.Fatalf("verified chains lost: %+v", response.VerifiedChains)
	}
	cfg := &pb.WendyConfEnrollment{CsrUrl: server.URL, TimeUrl: "roughtime"}
	profile := liteenroll.TrustProfileFromChallenge(&pb.WendyComEnrollmentChallenge{}, wendy.GoLiteCertificateInspector{})
	if err := liteenroll.DiscoverTrustForProfile(context.Background(), transport, cfg, server.URL, profile); err != nil {
		t.Fatal(err)
	}
	if !cfg.ProvisionTrust || !bytes.Equal(cfg.DeviceRoots, roots) || len(cfg.HttpsRoots) == 0 || calls.Load() != 3 {
		t.Fatalf("trust discovery did not preserve evidence: %+v, calls %d", cfg, calls.Load())
	}
	// Peer certificates from an unverified connection must not be promoted.
	insecureClient := server.Client()
	insecureRT := insecureClient.Transport.(*http.Transport).Clone()
	insecureRT.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Exercise rejected trust evidence.
	insecureClient.Transport = insecureRT
	defer insecureRT.CloseIdleConnections()
	insecure, err := wendy.NewLiteHTTPTransport(insecureClient)
	if err != nil {
		t.Fatal(err)
	}
	response, err = insecure.DoLite(context.Background(), wendy.HTTPRequest{Method: "HEAD", URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(response.VerifiedChains) != 0 {
		t.Fatal("unverified peers became trust evidence")
	}
	refused := &pb.WendyConfEnrollment{CsrUrl: server.URL, TimeUrl: "roughtime"}
	if err := liteenroll.DiscoverTrustForProfile(context.Background(), insecure, refused, server.URL, profile); err == nil || refused.ProvisionTrust || len(refused.DeviceRoots)+len(refused.HttpsRoots) != 0 {
		t.Fatalf("unverified discovery changed trust: %+v, %v", refused, err)
	}
}

func TestLiteHTTPRedirectAndCancellation(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	releaseBody := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/body" {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			// Keep EOF out of the race with client cancellation.
			<-releaseBody
			return
		}
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	defer close(releaseBody)
	client := server.Client()
	client.Timeout = 2 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { t.Error("caller's redirect policy ran"); return nil }
	transport, err := wendy.NewLiteHTTPTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.DoLite(context.Background(), wendy.HTTPRequest{Method: "POST", URL: server.URL, Headers: wendy.HTTPHeaders{"Authorization": {"token"}, "DPoP": {"proof"}}, Body: []byte("secret")})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect || redirected.Load() != 0 {
		t.Fatal("redirect followed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	response, err = transport.DoLite(ctx, wendy.HTTPRequest{Method: "GET", URL: server.URL + "/body"})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	cancel()
	if _, err = io.ReadAll(response.Body); !errors.Is(err, context.Canceled) {
		t.Fatalf("body cancellation: %v", err)
	}
	if _, err = transport.DoLite(ctx, wendy.HTTPRequest{URL: server.URL}); !errors.Is(err, context.Canceled) {
		t.Fatalf("request cancellation: %v", err)
	}
	for _, raw := range []string{"http://localhost/", "https://user:pass@localhost/", "https://localhost/#fragment"} {
		if _, err = transport.DoLite(context.Background(), wendy.HTTPRequest{URL: raw}); err == nil {
			t.Errorf("accepted unsafe URL %s", raw)
		}
	}
	if _, err = wendy.NewLiteHTTPTransport(nil); err == nil {
		t.Fatal("accepted nil HTTP client")
	}
}

func TestLiteTimeSourcePinsAndCancellation(t *testing.T) {
	source := wendy.GoLiteTimeSource{}
	servers := source.Servers()
	if len(servers) != 4 || servers[0].Address != "roughtime.cloudflare.com:2003" {
		t.Fatalf("server list differs: %+v", servers)
	}
	first := servers[0]
	servers[0].Address = "attacker:2002"
	if source.Servers()[0] != first {
		t.Fatal("server list aliases host state")
	}
	if _, err := source.Query(context.Background(), servers[0], make([]byte, 32)); err == nil {
		t.Fatal("accepted unpinned server")
	}
	if _, err := source.Query(context.Background(), first, []byte("bad nonce")); err == nil {
		t.Fatal("accepted invalid nonce")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Query(ctx, first, make([]byte, 32)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestLiteSignedTimestampThroughGoHost(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xa5}, 32)
	proof := []byte("opaque timestamp evidence verified by firmware")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Version int
			Imprint struct {
				Algorithm pkix.AlgorithmIdentifier
				Digest    []byte
			}
			Nonce   *big.Int
			CertReq bool
		}
		der, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		rest, err := asn1.Unmarshal(der, &request)
		digest := sha256.Sum256(nonce)
		if err != nil || len(rest) != 0 || r.Method != "POST" || r.Header.Get("Content-Type") != "application/timestamp-query" || request.Version != 1 || !request.CertReq || request.Nonce == nil || !bytes.Equal(request.Nonce.Bytes(), nonce) || !bytes.Equal(request.Imprint.Digest, digest[:]) {
			t.Errorf("device nonce/request changed: %+v, %v", request, err)
		}
		_, _ = w.Write(proof)
	}))
	defer server.Close()
	transport, err := wendy.NewLiteHTTPTransport(server.Client())
	if err != nil {
		t.Fatal(err)
	}
	got, err := liteenroll.SignedTime(context.Background(), transport, server.URL, hex.EncodeToString(nonce))
	if err != nil || !bytes.Equal(got, proof) {
		t.Fatalf("timestamp evidence changed: %q, %v", got, err)
	}
}

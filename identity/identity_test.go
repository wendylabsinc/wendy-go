package identity_test

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	wendy "github.com/wendylabsinc/wendy-go"
	"github.com/wendylabsinc/wendy-go/identity"
)

// Exercise the portable protocol with real TLS, cryptography, PKCS#10 and
// certificate parsing, importing only the public SDK like a CLI consumer.
func TestSignInAndRefreshWithGoHosts(t *testing.T) {
	ctx := context.Background()
	operatorKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	operator, err := wendy.NewMLDSA65Signer(operatorKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	issuerSigner, err := wendy.NewMLDSA65Signer(issuerKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	issuerJWK, _, err := identity.OperatorPublicJWK(ctx, issuerSigner)
	if err != nil {
		t.Fatal(err)
	}
	issuerJWK["kid"] = "issuer-signing-key"
	thumbprint, err := identity.OperatorJWKThumbprint(ctx, operator)
	if err != nil {
		t.Fatal(err)
	}
	const tenant = "11111111-2222-4333-8444-555555555555"
	const subject = "operator-subject"
	principal, _ := url.Parse("spiffe://wendy.sh/tenant/" + tenant + "/operator/" + subject)
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{principal}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, operatorKey.PublicKey(), operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	var mu sync.Mutex
	var nonce, challenge string
	var exchanges, issuances int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		base := "https://" + r.Host
		issuer := base + "/realms/test"
		writeJSON := func(value any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(value)
		}
		switch r.URL.Path {
		case "/realms/test/.well-known/openid-configuration":
			writeJSON(identity.ProviderMetadata{Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/jwks", CodeChallengeMethods: []string{"S256"}})
		case "/realms/test/jwks":
			writeJSON(map[string]any{"keys": []map[string]string{issuerJWK}})
		case "/realms/test/token":
			if !verifyProof(t, r, operatorKey, "") {
				http.Error(w, "bad proof", 400)
				return
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				http.Error(w, "bad form", 400)
				return
			}
			if r.Form.Get("grant_type") == "authorization_code" {
				digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if r.Form.Get("code") != "authorization-code" || base64.RawURLEncoding.EncodeToString(digest[:]) != challenge {
					t.Error("code exchange lost PKCE binding")
				}
			} else if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh-"+strconv.Itoa(exchanges) {
				t.Error("refresh token family was not rotated")
			}
			exchanges++
			claims := map[string]any{"iss": issuer, "sub": subject, "tenant_uuid": tenant, "aud": r.Form.Get("resource"), "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "cnf": map[string]string{"jkt": thumbprint}}
			access, err := identity.SignJWS(ctx, issuerSigner, map[string]any{"alg": "ML-DSA-65", "kid": "issuer-signing-key"}, claims)
			if err != nil {
				t.Error(err)
			}
			claims["aud"], claims["nonce"] = "public-client", nonce
			idToken, err := identity.SignJWS(ctx, issuerSigner, map[string]any{"alg": "ML-DSA-65", "kid": "issuer-signing-key"}, claims)
			if err != nil {
				t.Error(err)
			}
			writeJSON(identity.TokenResponse{AccessToken: access, IDToken: idToken, TokenType: "DPoP", ExpiresIn: 3600, RefreshToken: "refresh-" + strconv.Itoa(exchanges)})
		case "/v1/identity/certificate":
			access := strings.TrimPrefix(r.Header.Get("Authorization"), "DPoP ")
			if access == "" || !verifyProof(t, r, operatorKey, access) {
				http.Error(w, "bad proof", 400)
				return
			}
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			block, _ := pem.Decode(data)
			if block == nil {
				t.Error("missing PKCS#10 request")
				http.Error(w, "missing CSR", 400)
				return
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil || csr.CheckSignature() != nil || !operatorKey.PublicKey().Equal(csr.PublicKey) || csr.Subject.CommonName != subject {
				t.Error("CSR is not bound to the operator")
				http.Error(w, "bad CSR", 400)
				return
			}
			issuances++
			_, _ = w.Write(certificatePEM)
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	httpTransport, err := wendy.NewHTTPTransport(server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client := identity.Client{HTTP: httpTransport, Verifier: wendy.GoSignatureVerifier{}, Entropy: wendy.CryptoEntropy{}}
	login, err := client.PrepareLogin(ctx, identity.LoginOptions{Issuer: server.URL + "/realms/test", ClientID: "public-client", CloudResource: server.URL + "/api", IdentityResource: identity.DefaultIdentityResource, IdentityEndpoint: server.URL + "/v1/identity/certificate", CloudGRPC: "api.example.test:443"})
	if err != nil {
		t.Fatal(err)
	}
	authorize, err := login.BeginAuthorization(ctx, "http://127.0.0.1:12345/callback")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authorize)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	nonce, challenge = u.Query().Get("nonce"), u.Query().Get("code_challenge")
	mu.Unlock()
	var observed bool
	session, err := client.CompleteLogin(ctx, login, identity.Callback{Code: "authorization-code", State: login.State(), Iss: server.URL + "/realms/test"}, operator, func(progress identity.LoginProgress) { observed = progress.Claims["sub"] == subject })
	if err != nil {
		t.Fatal(err)
	}
	if !observed || session.RefreshToken != "refresh-2" || len(session.Certificates) != 1 || session.Certificates[0].TenantUUID() != tenant || session.Certificates[0].PrincipalURI != principal.String() {
		t.Fatal("sign-in did not establish the expected session")
	}
	session.OAuthExpiresAt = time.Now().Add(-time.Minute).Format(time.RFC3339)
	if err := client.RefreshAccessToken(ctx, session, operator); err != nil {
		t.Fatal(err)
	}
	if session.RefreshToken != "refresh-3" || !identity.AccessTokenFreshFor(session, time.Minute) {
		t.Fatal("access-token refresh did not update session")
	}
	if err := client.RefreshCertificate(ctx, session, operator, operator, false); err != nil {
		t.Fatal(err)
	}
	if session.RefreshToken != "refresh-5" {
		t.Fatal("certificate refresh did not restore rotated Cloud session")
	}
	mu.Lock()
	gotExchanges, gotIssuances := exchanges, issuances
	mu.Unlock()
	if gotExchanges != 5 || gotIssuances != 2 {
		t.Fatal("unexpected number of exchanges or certificate issuances")
	}
	set := &identity.SessionSet{Auth: []identity.Session{*session}}
	set.EnsureContexts()
	resolved, err := identity.ResolveSession(set, "", nil)
	if err != nil || resolved.RefreshToken != session.RefreshToken {
		t.Fatalf("SDK session selection failed: %v", err)
	}
	if _, err := identity.ResolveSession(&identity.SessionSet{}, "", nil); !errors.Is(err, identity.ErrNotLoggedIn) {
		t.Fatalf("SDK sentinel identity lost: %v", err)
	}
}

func verifyProof(t *testing.T, request *http.Request, operatorKey *mldsa.PrivateKey, accessToken string) bool {
	t.Helper()
	parts := strings.Split(request.Header.Get("DPoP"), ".")
	if len(parts) != 3 {
		t.Error("missing compact DPoP proof")
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || mldsa.Verify(operatorKey.PublicKey(), []byte(parts[0]+"."+parts[1]), signature, nil) != nil {
		t.Error("DPoP proof signature not bound to operator")
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Error(err)
		return false
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Error(err)
		return false
	}
	if claims["htm"] != request.Method || claims["htu"] != "https://"+request.Host+request.URL.Path || claims["jti"] == "" {
		t.Error("DPoP proof lost method, target or nonce")
		return false
	}
	if accessToken != "" {
		digest := sha256.Sum256([]byte(accessToken))
		if claims["ath"] != base64.RawURLEncoding.EncodeToString(digest[:]) {
			t.Error("DPoP proof lost access-token binding")
			return false
		}
	}
	return true
}

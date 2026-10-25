package wendy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net/http"
	"net/url"

	"github.com/wendylabsinc/wendy-go/internal/roughtime"
)

// GoLiteCertificateInspector uses Go's X.509 implementation. Its zero value is
// ready for concurrent use. Inspection reports public facts, not chain trust.
type GoLiteCertificateInspector struct{}

var _ LiteCertificateInspector = GoLiteCertificateInspector{}

// InspectCertificate parses DER into owned public facts, preserving signature
// OIDs even when Go reports an unknown signature enum (for example SHA-224).
// SelfSignatureValid uses CheckSignatureFrom, matching the CLI's CA check.
func (GoLiteCertificateInspector) InspectCertificate(der []byte) (*LiteCertificate, error) {
	c, err := x509.ParseCertificate(bytes.Clone(der))
	if err != nil {
		return nil, err
	}
	var outer struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if rest, err := asn1.Unmarshal(c.Raw, &outer); err != nil || len(rest) != 0 {
		return nil, errors.New("invalid certificate signature algorithm")
	}
	key, ok := c.PublicKey.(*ecdsa.PublicKey)
	return &LiteCertificate{
		Raw: c.Raw, RawIssuer: c.RawIssuer, RawSubject: c.RawSubject,
		BasicConstraintsValid: c.BasicConstraintsValid, IsCA: c.IsCA,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(), SignatureAlgorithm: c.SignatureAlgorithm.String(),
		SignatureOID: outer.Algorithm.Algorithm.String(),
		P256:         ok && key.Curve == elliptic.P256(), SelfSignatureValid: c.CheckSignatureFrom(c) == nil,
	}, nil
}

// NetLiteHTTPTransport supplies Lite HTTPS and verified TLS chains over a
// caller-configured http.Client. The caller owns trust anchors, proxy and cookie
// policy and must not configure retries or credential logging. It is safe for
// concurrent use; response bodies must be closed by their recipient.
type NetLiteHTTPTransport struct{ http *NetHTTPTransport }

var _ LiteHTTPTransport = (*NetLiteHTTPTransport)(nil)

// NewLiteHTTPTransport copies the client, sharing its Transport and Jar. It
// retains the timeout, disables redirects and refuses nil, like NewHTTPTransport.
// Configure trust anchors before construction; discovery uses the host trust
// store and subsequent enrollment uses the discovered HTTPS roots.
func NewLiteHTTPTransport(client *http.Client) (*NetLiteHTTPTransport, error) {
	h, err := NewHTTPTransport(client)
	if err != nil {
		return nil, err
	}
	return &NetLiteHTTPTransport{http: h}, nil
}

// DoLite sends one HTTPS exchange without redirects. Only TLS VerifiedChains
// become trust evidence; unverified PeerCertificates never become roots.
// Cancellation remains attached through response-body reads.
func (t *NetLiteHTTPTransport) DoLite(ctx context.Context, request HTTPRequest) (*LiteHTTPResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	u, err := url.Parse(request.URL)
	if err != nil || u.Scheme != "https" {
		return nil, errors.New("Lite HTTP request requires HTTPS")
	}
	resp, err := t.http.doResponse(ctx, request)
	if err != nil {
		return nil, err
	}
	out := &LiteHTTPResponse{HTTPResponse: HTTPResponse{StatusCode: resp.StatusCode, Headers: HTTPHeaders(resp.Header.Clone()), Body: resp.Body}}
	if resp.TLS != nil {
		for _, chain := range resp.TLS.VerifiedChains {
			certs := make([]*LiteCertificate, 0, len(chain))
			for _, c := range chain {
				cert, err := (GoLiteCertificateInspector{}).InspectCertificate(c.Raw)
				if err != nil {
					resp.Body.Close()
					return nil, err
				}
				certs = append(certs, cert)
			}
			out.VerifiedChains = append(out.VerifiedChains, certs)
		}
	}
	return out, nil
}

// GoLiteTimeSource queries the CLI's pinned Roughtime servers. The zero value
// is ready for concurrent use. It verifies signatures and nonce inclusion before
// returning the exact response bytes; firmware independently verifies consensus.
type GoLiteTimeSource struct{}

var _ LiteTimeSource = GoLiteTimeSource{}

// Servers returns an owned list of the firmware-supported servers.
func (GoLiteTimeSource) Servers() []LiteTimeServer {
	out := make([]LiteTimeServer, 0, len(roughtime.Servers))
	for _, s := range roughtime.Servers {
		out = append(out, LiteTimeServer{Name: s.Name, Address: s.Address})
	}
	return out
}

// Query obtains evidence for a 32-byte device nonce from exactly a pinned server.
// The context bounds DNS, dialing and reads; absent a deadline the exchange is
// bounded to three seconds. No local-clock value is substituted on failure.
func (GoLiteTimeSource) Query(ctx context.Context, server LiteTimeServer, nonce []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, s := range roughtime.Servers {
		if s.Name == server.Name && s.Address == server.Address {
			result, err := roughtime.QueryServerWithNonce(ctx, s, nonce)
			if err != nil {
				return nil, err
			}
			return result.RawResponse, nil
		}
	}
	return nil, errors.New("unknown Lite Roughtime server")
}

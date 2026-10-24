package wendy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	certs "github.com/wendylabsinc/wendy-go/internal/devicecerts"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// DeviceCertificateIdentity is an identity parsed from a peer certificate.
// Observed identities are untrusted until the TLS verifier accepts the peer.
type DeviceCertificateIdentity = certs.WendyIdentity

// DeviceIdentityMismatchError reports a peer differing from the required device.
type DeviceIdentityMismatchError = certs.IdentityMismatchError

// DeviceOrgMismatchError reports a peer in a different legacy organization.
type DeviceOrgMismatchError = certs.OrgMismatchError

// DevicePinChecker checks a verified leaf against caller-owned SPKI pins.
// Only errors with BlockingPinRejection() reject the peer; persistence errors
// remain best effort, preserving the CLI policy. Implementations must be safe
// for concurrent handshakes and retain their original typed errors.
type DevicePinChecker = certs.PinChecker

// DeviceTLSCredential holds the host-owned operator certificate and trust chain.
// Certificate must remain immutable while any connection uses it. ChainPEM is
// the caller's trusted issuer material, never a chain learned from the peer.
// Private keys and credential lookup remain entirely with the host.
type DeviceTLSCredential struct {
	Certificate    tls.Certificate
	ChainPEM       string
	OrganizationID int32
}

// LoadDeviceTLSCredential normalizes a PEM operator chain for TLS, including
// PKI issuer trailing bytes, and omits proven self-signed presentation roots.
func LoadDeviceTLSCredential(certPEM, chainPEM, keyPEM string, orgID int32) (DeviceTLSCredential, error) {
	cert, err := certs.TLSKeyPair(certPEM, chainPEM, keyPEM)
	if err != nil {
		return DeviceTLSCredential{}, fmt.Errorf("loading TLS cert: %w", err)
	}
	return DeviceTLSCredential{Certificate: cert, ChainPEM: chainPEM, OrganizationID: orgID}, nil
}

// DeviceSessionCache is the CLI's resumption-aware TLS cache. SetResumed runs
// before processing session tickets on every handshake, including full ones.
// A cache must be scoped to the endpoint and selected operator certificate.
type DeviceSessionCache interface {
	tls.ClientSessionCache
	SetResumed(bool)
}

// GRPCDeviceConnector supplies one lazy grpc-go connection per Core request.
// Configure it before use; callbacks must honor cancellation where applicable
// and be safe for concurrent attempts. Core owns retries and endpoint selection.
// The zero value can connect to plaintext endpoints. TLS requires Credential.
type GRPCDeviceConnector struct {
	// Credential resolves Core's opaque reference without selecting alternatives.
	Credential func(context.Context, string) (DeviceTLSCredential, error)
	Pins       DevicePinChecker
	// SessionCache returns nil to disable caching. A typed nil is not valid.
	SessionCache func(address string, operatorLeafDER []byte) DeviceSessionCache
	// DialContext supplies host routing, including CLI link-local interface binds.
	// When nil, net.Dialer is used. Proxied non-link-local targets retain grpc-go's
	// proxy path; TCP evidence is unavailable for those connections.
	DialContext func(context.Context, string) (net.Conn, error)
	// Debugf receives handshake resumption diagnostics, never certificate/key data.
	Debugf func(format string, args ...any)
}

var _ DeviceConnector = (*GRPCDeviceConnector)(nil)

// GRPCDeviceConnection owns its grpc-go connection and implements Core's RPC
// transport. Evidence and VerifiedIdentity can be read concurrently with RPCs.
// Conn supports CLI services not yet moved into Core. Close releases it.
type GRPCDeviceConnection struct {
	*GRPCTransport
	conn         *grpc.ClientConn
	mu           sync.Mutex
	evidence     DeviceConnectionEvidence
	identity     *DeviceCertificateIdentity
	tcpConnected bool
}

var _ DeviceConnection = (*GRPCDeviceConnection)(nil)

// Conn returns the same connection used by the serialized Core transport.
// Its TLS, routing and lifetime must remain owned by this connection.
func (c *GRPCDeviceConnection) Conn() *grpc.ClientConn { return c.conn }

// Evidence returns a synchronized snapshot; observed org is an untrusted hint.
func (c *GRPCDeviceConnection) Evidence() DeviceConnectionEvidence {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evidence
}

// VerifiedIdentity returns only an identity accepted by the TLS verifier.
func (c *GRPCDeviceConnection) VerifiedIdentity() (DeviceCertificateIdentity, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.identity == nil {
		return DeviceCertificateIdentity{}, false
	}
	return *c.identity, true
}

// Close releases the connection. grpc-go makes closure safe during RPCs.
func (c *GRPCDeviceConnection) Close() error { return c.conn.Close() }

// ConnectDevice creates a lazy channel to exactly request.Address. Its lifetime
// outlasts ctx; cancellation of later RPCs is controlled by their own contexts.
// As in the CLI, TLS refusal evidence is captured when the first probe runs.
func (d *GRPCDeviceConnector) ConnectDevice(ctx context.Context, request DeviceConnectRequest) (DeviceConnection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(request.Address)
	if err != nil {
		return nil, fmt.Errorf("invalid device address %q: %w", request.Address, err)
	}
	if !request.TLS && request.Expected != nil {
		return nil, errors.New("expected device identity requires TLS")
	}
	if host == "" || strings.ContainsAny(host, "/?#@") {
		return nil, fmt.Errorf("invalid device address %q", request.Address)
	}
	c := new(GRPCDeviceConnection)
	transportCreds := insecure.NewCredentials()
	if request.TLS {
		cfg, err := d.tlsConfig(ctx, request, c)
		if err != nil {
			return nil, err
		}
		transportCreds = credentials.NewTLS(cfg)
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithInitialWindowSize(256 * 1024), grpc.WithInitialConnWindowSize(512 * 1024),
		grpc.WithReadBufferSize(256 * 1024), grpc.WithWriteBufferSize(256 * 1024),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 15 * time.Minute, Timeout: 10 * time.Second}),
	}
	ip := net.ParseIP(host)
	linkLocal := ip != nil && ip.To4() != nil && ip.IsLinkLocalUnicast()
	// Match the CLI: bound initial TLS TCP dialing unless gRPC handles a proxy.
	// Plaintext uses gRPC defaults except for host-supplied link-local routing.
	if request.TLS || linkLocal {
		proxy, proxyErr := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: request.Address}})
		if linkLocal || proxy == nil && proxyErr == nil {
			dial := d.DialContext
			if dial == nil {
				dial = func(ctx context.Context, address string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", address)
				}
			}
			opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
				if !request.TLS {
					return dial(ctx, address)
				}
				c.mu.Lock()
				connected := c.tcpConnected
				c.mu.Unlock()
				if !connected {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
					defer cancel()
				}
				conn, err := dial(ctx, address)
				c.mu.Lock()
				if err == nil {
					c.tcpConnected = true
					c.evidence.TCPDialError = nil
				} else if !c.tcpConnected {
					c.evidence.TCPDialError = err
				}
				c.mu.Unlock()
				return conn, err
			}))
		}
	}
	conn, err := grpc.NewClient(deviceGRPCTarget(request.Address), opts...)
	if err != nil {
		if request.TLS {
			return nil, fmt.Errorf("connecting to agent at %s with TLS: %w", request.Address, err)
		}
		return nil, fmt.Errorf("connecting to agent at %s: %w", request.Address, err)
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	c.conn = conn
	c.GRPCTransport, _ = NewGRPCTransport(conn)
	return c, nil
}

func (d *GRPCDeviceConnector) tlsConfig(ctx context.Context, request DeviceConnectRequest, c *GRPCDeviceConnection) (*tls.Config, error) {
	if d.Credential == nil {
		return nil, errors.New("TLS device connection requires a credential resolver")
	}
	credential, err := d.Credential(ctx, request.Credential)
	if err != nil {
		return nil, err
	}
	cert := credential.Certificate
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return nil, errors.New("TLS device connection requires an operator certificate and key")
	}
	var expected *certs.WendyIdentity
	if request.Expected != nil {
		id := request.Expected
		expected = &certs.WendyIdentity{OrgID: id.OrgID, TenantUUID: id.TenantUUID, EntityType: id.EntityType, EntityID: id.EntityID}
	}
	verify, err := certs.BuildServerVerifyConnection(certs.ServerVerifyOpts{
		ChainPEM: credential.ChainPEM, ExpectedOrgID: credential.OrganizationID, PinStore: d.Pins, ExpectedIdentity: expected,
		OnServerIdentity: func(id certs.WendyIdentity) {
			if id.OrgID > 0 {
				c.mu.Lock()
				c.evidence.ObservedOrg = id.OrgID
				c.mu.Unlock()
			}
		},
		OnVerifiedServerIdentity: func(id certs.WendyIdentity) {
			if id.OrgID < 0 {
				return
			}
			if id.Principal != "" || id.TenantUUID != "" {
				parsed, err := certs.ParsePrincipal(id.Principal)
				if err != nil || parsed.TenantUUID != id.TenantUUID || parsed.EntityType != id.EntityType || parsed.EntityID != id.EntityID {
					return
				}
			} else if id.OrgID == 0 {
				return
			}
			c.mu.Lock()
			c.identity = &id
			c.mu.Unlock()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("building TLS verifier: %w", err)
	}
	var cache DeviceSessionCache
	if d.SessionCache != nil {
		cache = d.SessionCache(request.Address, cert.Certificate[0])
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true, // VerifyConnection performs Wendy chain and identity verification.
		MinVersion: tls.VersionTLS12,
		GetClientCertificate: func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			supported := *request
			supported.AcceptableCAs = nil
			if err := supported.SupportsCertificate(&cert); err != nil {
				return nil, fmt.Errorf("device cannot use the operator certificate: %w", err)
			}
			return &cert, nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cache != nil {
				cache.SetResumed(cs.DidResume)
			}
			if d.Debugf != nil {
				d.Debugf("[tls-debug] %s resumed=%v\n", request.Address, cs.DidResume)
			}
			err := verify(cs)
			c.mu.Lock()
			defer c.mu.Unlock()
			var identityMismatch *DeviceIdentityMismatchError
			if errors.As(err, &identityMismatch) {
				c.evidence.IdentityMismatch = identityMismatch
			}
			var pinMismatch certs.BlockingPinError
			if errors.As(err, &pinMismatch) {
				c.evidence.PinMismatch = err
			}
			return err
		},
	}
	if cache != nil {
		cfg.ClientSessionCache = cache
	}
	return cfg, nil
}

// Scoped IPv6 literals need URL escaping before grpc-go parses the target.
func deviceGRPCTarget(address string) string {
	if !strings.Contains(address, "%") {
		return address
	}
	return (&url.URL{Scheme: "passthrough", Path: "/" + address}).String()
}

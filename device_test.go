package wendy_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wendy "github.com/wendylabsinc/wendy-go"
	"github.com/wendylabsinc/wendy-go/devices"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

const deviceVersionMethod = "/wendy.agent.services.v1.WendyAgentService/GetAgentVersion"

type deviceTLSFixture struct {
	ca         *x509.Certificate
	caKey      crypto.Signer
	chainPEM   string
	credential wendy.DeviceTLSCredential
}

func newDeviceTLSFixture(t *testing.T) deviceTLSFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newDeviceTLSFixtureWithCA(t, key)
}

func newDeviceTLSFixtureWithCA(t *testing.T, key crypto.Signer) deviceTLSFixture {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "device test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := deviceTLSFixture{ca: ca, caKey: key, chainPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	certPEM, keyPEM := f.leaf(t, "urn:wendy:org:7:user:operator", x509.ExtKeyUsageClientAuth)
	f.credential, err = wendy.LoadDeviceTLSCredential(certPEM, f.chainPEM, keyPEM, 7)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f deviceTLSFixture) leaf(t *testing.T, principal string, eku x509.ExtKeyUsage) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return f.leafWithKey(t, principal, eku, key)
}

func (f deviceTLSFixture) leafWithKey(t *testing.T, principal string, eku x509.ExtKeyUsage, key crypto.Signer) (string, string) {
	t.Helper()
	uri, err := url.Parse(principal)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "test device"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca, key.Public(), f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func (f deviceTLSFixture) serve(t *testing.T, principal string) (string, *atomic.Int32) {
	t.Helper()
	certPEM, keyPEM := f.leaf(t, principal, x509.ExtKeyUsageServerAuth)
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.ca)
	calls := new(atomic.Int32)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
	})), grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		method, _ := grpc.MethodFromServerStream(stream)
		if method != deviceVersionMethod {
			t.Errorf("unexpected method %q", method)
		}
		p, ok := peer.FromContext(stream.Context())
		if !ok {
			t.Error("missing TLS peer")
		} else if info, ok := p.AuthInfo.(credentials.TLSInfo); !ok || len(info.State.PeerCertificates) == 0 {
			t.Error("missing operator certificate")
		}
		if err := stream.RecvMsg(new(emptypb.Empty)); err != nil {
			return err
		}
		calls.Add(1)
		return stream.SendMsg(new(emptypb.Empty)) // Empty is a valid AgentVersion protobuf.
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { srv.Stop(); _ = listener.Close() })
	return listener.Addr().String(), calls
}

func (f deviceTLSFixture) connector(t *testing.T) *wendy.GRPCDeviceConnector {
	t.Helper()
	return &wendy.GRPCDeviceConnector{Credential: func(ctx context.Context, reference string) (wendy.DeviceTLSCredential, error) {
		if reference != "operator" {
			t.Errorf("credential = %q", reference)
		}
		return f.credential, ctx.Err()
	}}
}

func openDevice(t *testing.T, connector *wendy.GRPCDeviceConnector, address string, expected *wendy.DeviceIdentity) *wendy.GRPCDeviceConnection {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	connection, err := connector.ConnectDevice(ctx, wendy.DeviceConnectRequest{Address: address, TLS: true, Credential: "operator", Expected: expected})
	cancel() // Opening context must not own the later transport lifetime.
	if err != nil {
		t.Fatal(err)
	}
	c, ok := connection.(*wendy.GRPCDeviceConnection)
	if !ok {
		t.Fatalf("connection type %T", connection)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func probeDevice(c wendy.DeviceConnection) (*devices.AgentVersion, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	return devices.GetAgentVersion(ctx, c)
}

func TestDeviceConnectorTLS(t *testing.T) {
	f := newDeviceTLSFixture(t)
	for _, tc := range []struct {
		name, principal string
		expected        *wendy.DeviceIdentity
		wantOrg         int32
		mismatch        bool
	}{
		{"legacy success", "urn:wendy:org:7:asset:42", &wendy.DeviceIdentity{OrgID: 7, EntityType: "asset", EntityID: "42"}, 7, false},
		{"wrong asset", "urn:wendy:org:7:asset:43", &wendy.DeviceIdentity{OrgID: 7, EntityType: "asset", EntityID: "42"}, 7, true},
		{"tenant success", "spiffe://wendy.sh/tenant/3c0e434d-d082-4c11-a39a-c959d20afbd7/device/board", &wendy.DeviceIdentity{TenantUUID: "3c0e434d-d082-4c11-a39a-c959d20afbd7", EntityType: "asset", EntityID: "board"}, 0, false},
		{"wrong tenant", "spiffe://wendy.sh/tenant/3c0e434d-d082-4c11-a39a-c959d20afbd7/device/board", &wendy.DeviceIdentity{TenantUUID: "1aa26cb6-7712-4ea7-a80e-2a4ac15bf949", EntityType: "asset", EntityID: "board"}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, calls := f.serve(t, tc.principal)
			c := openDevice(t, f.connector(t), address, tc.expected)
			done := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-done:
						return
					default:
						_ = c.Evidence()
						_, _ = c.VerifiedIdentity()
					}
				}
			}()
			_, err := probeDevice(c)
			close(done)
			wg.Wait()
			evidence := c.Evidence()
			if evidence.ObservedOrg != tc.wantOrg || evidence.TCPDialError != nil {
				t.Fatalf("evidence %+v", evidence)
			}
			id, verified := c.VerifiedIdentity()
			if tc.mismatch {
				var mismatch *wendy.DeviceIdentityMismatchError
				if err == nil || !errors.As(evidence.IdentityMismatch, &mismatch) || calls.Load() != 0 || verified {
					t.Fatalf("refusal err=%v evidence=%+v verified=%v calls=%d", err, evidence, verified, calls.Load())
				}
			} else if err != nil || !verified || id.EntityID != tc.expected.EntityID || calls.Load() != 1 || c.Conn() == nil {
				t.Fatalf("success err=%v id=%+v verified=%v calls=%d", err, id, verified, calls.Load())
			}
		})
	}
}

func TestDeviceConnectorCallerDialOptions(t *testing.T) {
	f := newDeviceTLSFixture(t)
	address, calls := f.serve(t, "urn:wendy:org:7:asset:42")
	connector := f.connector(t)
	connector.DialContext = func(context.Context, string) (net.Conn, error) {
		t.Error("caller dial option did not override connector routing")
		return nil, errors.New("default route unavailable")
	}
	var dials, intercepts atomic.Int32
	connector.DialOptions = []grpc.DialOption{
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			t.Error("earlier caller dial option took precedence")
			return nil, errors.New("earlier route unavailable")
		}),
		grpc.WithContextDialer(func(ctx context.Context, target string) (net.Conn, error) {
			if target != "127.0.0.1:1" {
				t.Errorf("caller target = %q", target)
			}
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}),
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			intercepts.Add(1)
			return invoke(ctx, method, req, reply, cc, opts...)
		}),
	}
	c := openDevice(t, connector, "127.0.0.1:1", &wendy.DeviceIdentity{OrgID: 7, EntityType: "asset", EntityID: "42"})
	if _, err := probeDevice(c); err != nil {
		t.Fatal(err)
	}
	if dials.Load() == 0 || intercepts.Load() != 1 || calls.Load() != 1 {
		t.Fatalf("caller options not applied: dials=%d intercepts=%d calls=%d", dials.Load(), intercepts.Load(), calls.Load())
	}
	if _, ok := c.VerifiedIdentity(); !ok {
		t.Fatal("caller routing bypassed TLS verification")
	}
}

func TestDeviceConnectorCallerCredentialsCannotReplaceTLS(t *testing.T) {
	f := newDeviceTLSFixture(t)
	var callerVerifications atomic.Int32
	callerTLS := credentials.NewTLS(&tls.Config{
		Certificates:       []tls.Certificate{f.credential.Certificate},
		InsecureSkipVerify: true, // A caller must not be able to install this verifier.
		VerifyConnection: func(tls.ConnectionState) error {
			callerVerifications.Add(1)
			return nil
		},
	})
	for _, option := range []struct {
		name string
		dial grpc.DialOption
	}{
		{"insecure", grpc.WithTransportCredentials(insecure.NewCredentials())},
		{"legacy insecure", grpc.WithInsecure()},
		{"nil credentials", grpc.WithTransportCredentials(nil)},
		{"caller verifier", grpc.WithTransportCredentials(callerTLS)},
	} {
		for _, outcome := range []string{"success", "identity mismatch", "pin mismatch"} {
			t.Run(option.name+"/"+outcome, func(t *testing.T) {
				address, calls := f.serve(t, "urn:wendy:org:7:asset:42")
				connector := f.connector(t)
				connector.DialOptions = []grpc.DialOption{option.dial}
				expected := &wendy.DeviceIdentity{OrgID: 7, EntityType: "asset", EntityID: "42"}
				pinError := &devices.PinMismatchError{Key: "urn:wendy:org:7:asset:42", Want: "old", Got: "new"}
				switch outcome {
				case "identity mismatch":
					expected.EntityID = "other"
				case "pin mismatch":
					connector.Pins = devicePinFunc(func(*x509.Certificate, string) error { return pinError })
				}
				c := openDevice(t, connector, address, expected)
				_, err := probeDevice(c)
				if outcome == "success" {
					if _, ok := c.VerifiedIdentity(); err != nil || !ok || calls.Load() != 1 {
						t.Fatalf("TLS failed: err=%v verified=%v calls=%d", err, ok, calls.Load())
					}
					return
				}
				if err == nil || calls.Load() != 0 {
					t.Fatalf("caller credentials bypassed %s: err=%v calls=%d", outcome, err, calls.Load())
				}
				if _, ok := c.VerifiedIdentity(); ok {
					t.Fatal("rejected peer exposed as verified")
				}
				if outcome == "identity mismatch" {
					var mismatch *wendy.DeviceIdentityMismatchError
					if !errors.As(c.Evidence().IdentityMismatch, &mismatch) {
						t.Fatalf("lost identity verifier: %+v", c.Evidence())
					}
				} else if !errors.Is(c.Evidence().PinMismatch, pinError) {
					t.Fatalf("lost pin verifier: %+v", c.Evidence())
				}
			})
		}
	}
	if callerVerifications.Load() != 0 {
		t.Fatal("caller TLS verifier replaced connector verification")
	}
}

func TestDeviceConnectorCallerOptionsOnPlaintext(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		if err := stream.RecvMsg(new(emptypb.Empty)); err != nil {
			return err
		}
		return stream.SendMsg(new(emptypb.Empty))
	}))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	connector := &wendy.GRPCDeviceConnector{DialOptions: []grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		// The request controls transport security even when a caller asks for TLS.
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})),
	}}
	c, err := connector.ConnectDevice(context.Background(), wendy.DeviceConnectRequest{Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := probeDevice(c); err != nil {
		t.Fatal(err)
	}
}

type deviceTestCredentialsBundle struct{}

func (b deviceTestCredentialsBundle) TransportCredentials() credentials.TransportCredentials {
	return insecure.NewCredentials()
}

func (deviceTestCredentialsBundle) PerRPCCredentials() credentials.PerRPCCredentials { return nil }

func (b deviceTestCredentialsBundle) NewWithMode(string) (credentials.Bundle, error) { return b, nil }

func TestDeviceConnectorRejectsCallerCredentialsBundle(t *testing.T) {
	f := newDeviceTLSFixture(t)
	for _, useTLS := range []bool{true, false} {
		connector := f.connector(t)
		connector.DialOptions = []grpc.DialOption{grpc.WithCredentialsBundle(deviceTestCredentialsBundle{})}
		connection, err := connector.ConnectDevice(context.Background(), wendy.DeviceConnectRequest{
			Address: "127.0.0.1:1", TLS: useTLS, Credential: "operator",
		})
		if connection != nil {
			_ = connection.Close()
		}
		if err == nil || connection != nil {
			t.Fatalf("accepted caller credentials bundle (TLS=%v): connection=%v err=%v", useTLS, connection, err)
		}
	}
}

type devicePinFunc func(*x509.Certificate, string) error

func (f devicePinFunc) CheckAndUpdate(c *x509.Certificate, name string) error { return f(c, name) }

func TestDeviceConnectorPinEvidence(t *testing.T) {
	f := newDeviceTLSFixture(t)
	address, calls := f.serve(t, "urn:wendy:org:7:asset:42")
	for _, blocking := range []bool{true, false} {
		connector := f.connector(t)
		var cause error = errors.New("read-only pin storage")
		if blocking {
			cause = &devices.PinMismatchError{Key: "urn:wendy:org:7:asset:42", DisplayName: "test device", Want: "old", Got: "new"}
		}
		connector.Pins = devicePinFunc(func(cert *x509.Certificate, name string) error {
			if len(cert.RawSubjectPublicKeyInfo) == 0 || name != "test device" {
				t.Error("missing verified pin input")
			}
			return cause
		})
		c := openDevice(t, connector, address, nil)
		_, err := probeDevice(c)
		if blocking {
			if err == nil || !errors.Is(c.Evidence().PinMismatch, cause) || calls.Load() != 0 {
				t.Fatalf("pin refusal %v %+v", err, c.Evidence())
			}
		} else if err != nil || c.Evidence().PinMismatch != nil {
			t.Fatalf("persistence error rejected peer: %v", err)
		}
	}
}

func TestDeviceConnectorTCPFailureAndTLSFailureEvidence(t *testing.T) {
	f := newDeviceTLSFixture(t)
	t.Run("TCP failure", func(t *testing.T) {
		sentinel := errors.New("TCP dial refused")
		connector := f.connector(t)
		connector.DialContext = func(context.Context, string) (net.Conn, error) { return nil, sentinel }
		c := openDevice(t, connector, "127.0.0.1:1", nil)
		if _, err := probeDevice(c); err == nil || !errors.Is(c.Evidence().TCPDialError, sentinel) {
			t.Fatalf("err=%v evidence=%+v", err, c.Evidence())
		}
	})
	t.Run("TLS failure after TCP success", func(t *testing.T) {
		other := newDeviceTLSFixture(t)
		address, _ := other.serve(t, "urn:wendy:org:7:asset:42")
		c := openDevice(t, f.connector(t), address, nil)
		if _, err := probeDevice(c); err == nil || c.Evidence().TCPDialError != nil {
			t.Fatalf("err=%v evidence=%+v", err, c.Evidence())
		}
	})
}

func TestDeviceConnectorCancellation(t *testing.T) {
	f := newDeviceTLSFixture(t)
	connector := f.connector(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := connector.ConnectDevice(ctx, wendy.DeviceConnectRequest{Address: "127.0.0.1:1", TLS: true, Credential: "operator"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	started := make(chan struct{})
	stopped := make(chan struct{})
	connector.DialContext = func(ctx context.Context, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	}
	c := openDevice(t, connector, "127.0.0.1:1", nil)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := devices.GetAgentVersion(ctx, c); done <- err }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("dial never started")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled RPC succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RPC did not cancel")
	}
	// gRPC's channel outlives the RPC, and Close must stop its in-progress dial.
	_ = c.Close()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not stop dialing")
	}
}

// The same host cache is selected again for a fresh channel, never by Core.
type deviceTestSessionCache struct {
	tls.ClientSessionCache
	mu      sync.Mutex
	resumed []bool
}

func (c *deviceTestSessionCache) SetResumed(resumed bool) {
	c.mu.Lock()
	c.resumed = append(c.resumed, resumed)
	c.mu.Unlock()
}

func TestDeviceConnectorSessionCache(t *testing.T) {
	f := newDeviceTLSFixture(t)
	address, _ := f.serve(t, "urn:wendy:org:7:asset:42")
	cache := &deviceTestSessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
	connector := f.connector(t)
	var selected atomic.Int32
	connector.SessionCache = func(gotAddress string, leaf []byte) wendy.DeviceSessionCache {
		selected.Add(1)
		if gotAddress != address || string(leaf) != string(f.credential.Certificate.Certificate[0]) {
			t.Error("cache selected without endpoint/operator identity")
		}
		return cache
	}
	for range 2 {
		c := openDevice(t, connector, address, nil)
		if _, err := probeDevice(c); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if selected.Load() != 2 || len(cache.resumed) != 2 || cache.resumed[0] || !cache.resumed[1] {
		t.Fatalf("cache selected=%d resumed=%v", selected.Load(), cache.resumed)
	}
}

func TestDeviceConnectorRequiresExactHostEndpoint(t *testing.T) {
	connector := new(wendy.GRPCDeviceConnector)
	for _, address := range []string{"", ":123", "unix:///tmp/agent:123", "dns:///device:123", "device"} {
		if c, err := connector.ConnectDevice(context.Background(), wendy.DeviceConnectRequest{Address: address}); err == nil {
			_ = c.Close()
			t.Errorf("accepted endpoint %q", address)
		}
	}
	if c, err := connector.ConnectDevice(context.Background(), wendy.DeviceConnectRequest{Address: "127.0.0.1:1", Expected: &wendy.DeviceIdentity{OrgID: 7}}); err == nil {
		_ = c.Close()
		t.Fatal("plaintext accepted an identity expectation")
	}
}

func TestDeviceDialThroughFacade(t *testing.T) {
	f := newDeviceTLSFixture(t)
	address, calls := f.serve(t, "urn:wendy:org:7:asset:42")
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	base := net.JoinHostPort(host, strconv.Itoa(port-1))
	for _, mismatch := range []bool{false, true} {
		before := calls.Load()
		expected := &wendy.DeviceIdentity{OrgID: 7, EntityType: "asset", EntityID: "42"}
		if mismatch {
			expected.EntityID = "impostor"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		result := devices.Dial(ctx, f.connector(t), devices.Target{Addr: base, PinnedKey: "board.local", Expected: expected}, []devices.Credential{{Reference: "operator", OrganizationID: 7}}, devices.DialOptions{})
		cancel()
		if mismatch {
			var cause *wendy.DeviceIdentityMismatchError
			if !errors.Is(result.Err, devices.ErrIdentityRefused) || !errors.As(result.Err, &cause) || result.Connection != nil || calls.Load() != before {
				t.Fatalf("refusal result=%+v calls=%d", result, calls.Load())
			}
		} else {
			if result.Err != nil || result.Connection == nil {
				t.Fatalf("dial result %+v", result)
			}
			// Core cancels its candidate contexts before returning. The winning channel
			// must still be usable by a later host RPC.
			if _, err := probeDevice(result.Connection); err != nil {
				t.Fatal(err)
			}
			_ = result.Connection.Close()
			// Two successful probes: Core's liveness check and the host's next call.
			if calls.Load() != before+2 {
				t.Fatalf("successful probes=%d", calls.Load())
			}
		}
	}
}

func TestDeviceConnectorRealTCPFailure(t *testing.T) {
	f := newDeviceTLSFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	c := openDevice(t, f.connector(t), address, nil)
	if _, err := probeDevice(c); err == nil {
		t.Fatal("closed TCP endpoint accepted an RPC")
	}
	var networkError *net.OpError
	if !errors.As(c.Evidence().TCPDialError, &networkError) {
		t.Fatalf("missing original TCP error: %+v", c.Evidence())
	}
}

func TestDeviceConnectorMLDSAOperatorAndChain(t *testing.T) {
	caKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	f := newDeviceTLSFixtureWithCA(t, caKey)
	operatorKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := f.leafWithKey(t, "spiffe://wendy.sh/tenant/3c0e434d-d082-4c11-a39a-c959d20afbd7/operator/person", x509.ExtKeyUsageClientAuth, operatorKey)
	f.credential, err = wendy.LoadDeviceTLSCredential(certPEM, f.chainPEM, keyPEM, 7)
	if err != nil {
		t.Fatal(err)
	}
	address, _ := f.serve(t, "urn:wendy:org:7:asset:42")
	c := openDevice(t, f.connector(t), address, &wendy.DeviceIdentity{OrgID: 7, EntityType: "asset", EntityID: "42"})
	if _, err := probeDevice(c); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceConnectorScopedAndLinkLocalRouting(t *testing.T) {
	f := newDeviceTLSFixture(t)
	address, _ := f.serve(t, "urn:wendy:org:7:asset:42")
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"169.254.1.2", "fe80::1%wendy-test"} {
		t.Run(host, func(t *testing.T) {
			target := net.JoinHostPort(host, port)
			connector := f.connector(t)
			connector.DialContext = func(ctx context.Context, got string) (net.Conn, error) {
				if got != target {
					t.Errorf("dial target=%q want=%q", got, target)
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", address)
			}
			c := openDevice(t, connector, target, nil)
			if _, err := probeDevice(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeviceConnectorPrincipalPin(t *testing.T) {
	const prefix = "spiffe://wendy.sh/tenant/3c0e434d-d082-4c11-a39a-c959d20afbd7/"
	f := newDeviceTLSFixture(t)
	for _, tc := range []struct{ peer, other string }{
		{"device/42", "service/asset-42"},
		{"service/asset-42", "device/42"},
	} {
		t.Run(tc.peer, func(t *testing.T) {
			address, calls := f.serve(t, prefix+tc.peer)
			cache := &deviceTestSessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
			connector := f.connector(t)
			connector.SessionCache = func(string, []byte) wendy.DeviceSessionCache { return cache }
			expected := devices.ExpectedIdentityForPin(devices.DevicePin{Principal: prefix + tc.peer})
			if expected == nil || expected.EntityID != "42" {
				t.Fatal("Core lost the principal pin")
			}
			c := openDevice(t, connector, address, expected)
			if _, err := probeDevice(c); err != nil {
				t.Fatal(err)
			}
			_ = c.Close()
			expected.Principal = prefix + tc.other // Same tenant, type and ID; different principal.
			c = openDevice(t, connector, address, expected)
			if _, err := probeDevice(c); err == nil {
				t.Fatal("accepted another SPIFFE principal")
			}
			var mismatch *wendy.DeviceIdentityMismatchError
			if !errors.As(c.Evidence().IdentityMismatch, &mismatch) || mismatch.WantPrincipal != prefix+tc.other || mismatch.GotPrincipal != prefix+tc.peer || calls.Load() != 1 {
				t.Fatalf("lost principal rejection: evidence=%+v calls=%d", c.Evidence(), calls.Load())
			}
			if _, ok := c.VerifiedIdentity(); ok {
				t.Fatal("rejected principal exposed as verified")
			}
			cache.mu.Lock()
			defer cache.mu.Unlock()
			if len(cache.resumed) != 2 || !cache.resumed[1] {
				t.Fatalf("principal pin was not checked on resumption: %v", cache.resumed)
			}
		})
	}
}

func TestDeviceConnectorPrincipalCannotDowngradeToLegacy(t *testing.T) {
	f := newDeviceTLSFixture(t)
	address, calls := f.serve(t, "urn:wendy:org:7:asset:42")
	expected := &wendy.DeviceIdentity{OrgID: 7, EntityType: "asset", EntityID: "42", Principal: "spiffe://wendy.sh/tenant/3c0e434d-d082-4c11-a39a-c959d20afbd7/device/42"}
	c := openDevice(t, f.connector(t), address, expected)
	if _, err := probeDevice(c); err == nil {
		t.Fatal("explicit principal was reduced to a legacy tuple")
	}
	var mismatch *wendy.DeviceIdentityMismatchError
	if !errors.As(c.Evidence().IdentityMismatch, &mismatch) || mismatch.WantPrincipal != expected.Principal || mismatch.GotPrincipal != "" || calls.Load() != 0 {
		t.Fatalf("lost absent-principal rejection: evidence=%+v calls=%d", c.Evidence(), calls.Load())
	}
}

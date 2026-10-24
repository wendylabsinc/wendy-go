package wendy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/emptypb"
)

const deviceVersionMethod = "/wendy.agent.services.v1.WendyAgentService/GetAgentVersion"

type deviceTLSFixture struct {
	ca         *x509.Certificate
	caKey      *ecdsa.PrivateKey
	chainPEM   string
	credential wendy.DeviceTLSCredential
}

func newDeviceTLSFixture(t *testing.T) deviceTLSFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "device test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
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
	uri, err := url.Parse(principal)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "test device"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca, &key.PublicKey, f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
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

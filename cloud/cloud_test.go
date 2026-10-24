package cloud_test

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	wendy "github.com/wendylabsinc/wendy-go"
	"github.com/wendylabsinc/wendy-go/cloud"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const tenant = "11111111-2222-4333-8444-555555555555"
const assetID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
const deleteMethod = "/wendycloud.v2.AssetService/DeleteAsset"

// Test the consumer boundary with real Go signing and grpc-go hosts, without
// importing Core or its private generated protobuf messages.
func TestSignedDeletionWithGoHosts(t *testing.T) {
	ctx := context.Background()
	key, host := operator(t)
	now := time.Now().Truncate(time.Second)
	signer, err := cloud.NewSigner(ctx, host, tenant, wendy.CryptoEntropy{}, cloud.SignerOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request := &cloud.DeleteAssetRequest{Id: assetID, ExpectedDeviceId: proto.String(assetID)}
	request.ProtoReflect().SetUnknown([]byte{0xc0, 0x0c, 0x01})
	transport := rpcTransport(t, func(stream grpc.ServerStream, method string, wire []byte) error {
		if method == "/wendycloud.v2.OperatorSessionService/RegisterOperatorLeaf" {
			return status.Error(codes.Unimplemented, "older Cloud")
		}
		if method != deleteMethod {
			return status.Error(codes.Unimplemented, "unexpected method")
		}
		var envelope cloud.SignedRequest
		if err := proto.Unmarshal(wire, &envelope); err != nil {
			return err
		}
		var decoded cloud.DeleteAssetRequest
		if err := proto.Unmarshal(envelope.Payload, &decoded); err != nil {
			return err
		}
		if !proto.Equal(&decoded, request) || envelope.PayloadType != "wendycloud.v2.DeleteAssetRequest" {
			return fmt.Errorf("exact request body was lost")
		}
		header, claims := verifyJWS(t, key, envelope.Signature)
		digest := sha256.Sum256(envelope.Payload)
		target, _ := claims["target"].(map[string]any)
		if header["alg"] != "ML-DSA-65" || header["x5c"] == nil || header["kid"] != nil ||
			claims["body_sha256"] != base64.RawURLEncoding.EncodeToString(digest[:]) ||
			claims["operation"] != strings.TrimPrefix(method, "/") || claims["aud"] != cloud.BrokerAudience ||
			claims["iat"] != float64(now.Unix()) || claims["expiry"] != float64(now.Add(30*time.Second).Unix()) ||
			claims["correlation_id"] != "sdk-flow" || target["tenant"] != tenant || target["resource"] != "asset/"+assetID {
			return fmt.Errorf("request signature lost its body, target, time or flow binding")
		}
		_, authority := verifyJWS(t, key, envelope.PkiManagementRequest)
		if authority["op"] != "revoke_principal" || authority["tenant"] != tenant || authority["principal"] != "spiffe://wendy.sh/tenant/"+tenant+"/device/"+assetID {
			return fmt.Errorf("missing same-key revocation authority")
		}
		stream.SetTrailer(metadata.Pairs("x-correlation-id", "sdk-flow"))
		return sendMessage(stream, &cloud.DeleteAssetResponse{ResetAuthorization: []byte("reset-proof")})
	})
	client := cloud.Client{Transport: transport}
	options := cloud.InvokeOptions{Metadata: wendy.Metadata{{Name: "x-correlation-id", Value: []byte("sdk-flow")}}}
	response, rpc, err := client.DeleteAsset(ctx, signer, request, options)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.ResetAuthorization) != "reset-proof" || len(rpc.TrailingMetadata) != 1 || string(rpc.TrailingMetadata[0].Value) != "sdk-flow" {
		t.Fatal("deletion lost reset authorization or RPC trailers")
	}
}

func TestDeviceInventoryAndRPCFailures(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprint("failure=", failure), func(t *testing.T) {
			calls := 0
			transport := rpcTransport(t, func(stream grpc.ServerStream, method string, wire []byte) error {
				if method != "/wendycloud.v2.AssetService/ListAssets" {
					return status.Error(codes.Unimplemented, "unexpected method")
				}
				calls++
				if err := checkDeviceQuery(wire, calls-1); err != nil {
					return err
				}
				// ListAssetsResponse: asset = 1, total = 2. Encode the public wire
				// contract because Core's generated streaming messages are private.
				asset, err := proto.Marshal(&cloud.Asset{Id: fmt.Sprint(calls), OrganizationId: tenant, Name: "robot"})
				if err != nil {
					return err
				}
				wire = protowire.AppendTag(nil, 1, protowire.BytesType)
				wire = protowire.AppendBytes(wire, asset)
				wire = protowire.AppendTag(wire, 2, protowire.VarintType)
				wire = protowire.AppendVarint(wire, 2)
				if err := stream.SendMsg(wire); err != nil {
					return err
				}
				if failure {
					stream.SetTrailer(metadata.Pairs(cloud.CollidingFieldMetadataKey, "name"))
					return status.Error(codes.Unavailable, "inventory unavailable")
				}
				return nil
			})
			assets, err := (&cloud.Client{Transport: transport}).ListDevices(context.Background(), tenant, "robot", true)
			if failure {
				var rpc *wendy.RPCStatusError
				if assets != nil || !errors.As(err, &rpc) || rpc.Code != wendy.RPCUnavailable || len(rpc.TrailingMetadata) != 1 || string(rpc.TrailingMetadata[0].Value) != "name" {
					t.Fatalf("partial inventory or lost RPC status/trailers: %v, %v", assets, err)
				}
				return
			}
			if err != nil || len(assets) != 2 || assets[0].Id != "1" || assets[1].Id != "2" || assets[1].OrganizationId != tenant {
				t.Fatalf("incomplete inventory: %v, %v", assets, err)
			}
		})
	}
}

func TestDeviceInventoryCancellation(t *testing.T) {
	started := make(chan struct{})
	transport := rpcTransport(t, func(stream grpc.ServerStream, _ string, _ []byte) error {
		close(started)
		<-stream.Context().Done()
		return stream.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-started:
			cancel()
		case <-ctx.Done():
		}
	}()
	assets, err := (&cloud.Client{Transport: transport}).ListDevices(ctx, tenant, "", false)
	var rpc *wendy.RPCStatusError
	if assets != nil || !errors.As(err, &rpc) || rpc.Code != wendy.RPCCanceled {
		t.Fatalf("canceled inventory lost its status: %v, %v", assets, err)
	}
}

func TestAuthenticationMetadataWithGoSigner(t *testing.T) {
	key, host := operator(t)
	ctx := context.Background()
	input := wendy.Metadata{
		{Name: "authorization", Value: []byte("old")},
		{Name: "dpop", Value: []byte("old-proof")},
		{Name: "x-correlation-id", Value: []byte("sdk-flow")},
	}
	want := wendy.Metadata{
		{Name: "authorization", Value: []byte("old")},
		{Name: "dpop", Value: []byte("old-proof")},
		{Name: "x-correlation-id", Value: []byte("sdk-flow")},
	}
	var priorJTI any
	for range 2 {
		md, err := cloud.AuthenticationMetadata(ctx, wendy.CryptoEntropy{}, "api.example.test:443", deleteMethod, "access-token", host, input)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(input, want) || len(md) != 3 || string(md[1].Value) != "DPoP access-token" || md[2].Name != "dpop" {
			t.Fatal("metadata was mutated or stale authentication survived")
		}
		_, claims := verifyJWS(t, key, md[2].Value)
		digest := sha256.Sum256([]byte("access-token"))
		if claims["htm"] != "POST" || claims["htu"] != "https://api.example.test:443"+deleteMethod ||
			claims["ath"] != base64.RawURLEncoding.EncodeToString(digest[:]) || claims["jti"] == nil || claims["jti"] == priorJTI {
			t.Fatal("DPoP lost method, URI, token binding or fresh nonce")
		}
		priorJTI = claims["jti"]
	}
	if id, err := cloud.CorrelationID(ctx, input, wendy.CryptoEntropy{}); err != nil || id != "sdk-flow" {
		t.Fatalf("flow ID was lost: %q, %v", id, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := cloud.AuthenticationMetadata(canceled, wendy.CryptoEntropy{}, "api.example.test:443", deleteMethod, "access-token", host, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

// Check the wire schema independently of Core's private generated types.
func checkDeviceQuery(wire []byte, offset int) error {
	fields := make(map[protowire.Number]any)
	for len(wire) > 0 {
		number, kind, n := protowire.ConsumeTag(wire)
		if n < 0 {
			return protowire.ParseError(n)
		}
		wire = wire[n:]
		switch kind {
		case protowire.BytesType:
			var value []byte
			value, n = protowire.ConsumeBytes(wire)
			fields[number] = string(value)
		case protowire.VarintType:
			var value uint64
			value, n = protowire.ConsumeVarint(wire)
			fields[number] = value
		default:
			return fmt.Errorf("unexpected inventory query field %d", number)
		}
		if n < 0 {
			return protowire.ParseError(n)
		}
		wire = wire[n:]
	}
	if fields[1] != tenant || fields[2] != uint64(1) || fields[3] != uint64(offset) || fields[4] != uint64(200) || fields[5] != "robot" || fields[6] != uint64(1) {
		return fmt.Errorf("inventory query lost tenant, filters or continuation: %v", fields)
	}
	return nil
}

func operator(t *testing.T) (*mldsa.PrivateKey, *wendy.MLDSA65Signer) {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	principal, err := url.Parse("spiffe://wendy.sh/tenant/" + tenant + "/operator/test")
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{principal}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.PublicKey(), key)
	if err != nil {
		t.Fatal(err)
	}
	host, err := wendy.NewMLDSA65Signer(key, [][]byte{der})
	if err != nil {
		t.Fatal(err)
	}
	return key, host
}

func verifyJWS(t *testing.T, key *mldsa.PrivateKey, compact []byte) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(string(compact), ".")
	if len(parts) != 3 {
		t.Error("missing compact JWS")
		return nil, nil
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || mldsa.Verify(key.PublicKey(), []byte(parts[0]+"."+parts[1]), signature, nil) != nil {
		t.Error("JWS signature does not match the host key")
		return nil, nil
	}
	decode := func(part string) map[string]any {
		data, err := base64.RawURLEncoding.DecodeString(part)
		var value map[string]any
		if err != nil || json.Unmarshal(data, &value) != nil {
			t.Error("invalid JWS JSON")
		}
		return value
	}
	return decode(parts[0]), decode(parts[1])
}

// rawCodec lets the fake service inspect the exact serialized wire contract.
type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }
func (rawCodec) Marshal(value any) ([]byte, error) {
	wire, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("expected wire bytes, got %T", value)
	}
	return wire, nil
}
func (rawCodec) Unmarshal(wire []byte, value any) error {
	target, ok := value.(*[]byte)
	if !ok {
		return fmt.Errorf("expected wire target, got %T", value)
	}
	*target = bytes.Clone(wire)
	return nil
}

func rpcTransport(t *testing.T, handle func(grpc.ServerStream, string, []byte) error) *wendy.GRPCTransport {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}), grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		method, _ := grpc.MethodFromServerStream(stream)
		var wire []byte
		if err := stream.RecvMsg(&wire); err != nil {
			return err
		}
		return handle(stream, method, wire)
	}))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	conn, err := grpc.NewClient("passthrough:///cloud-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	transport, err := wendy.NewGRPCTransport(conn)
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

func sendMessage(stream grpc.ServerStream, message proto.Message) error {
	wire, err := proto.Marshal(message)
	if err != nil {
		return err
	}
	return stream.SendMsg(wire)
}

package wendy_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wendylabsinc/wendy-go"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	pb "google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

const unaryMethod = "/grpc.testing.TestService/UnaryCall"
const streamMethod = "/grpc.testing.TestService/StreamingOutputCall"

type testServer struct {
	pb.UnimplementedTestServiceServer
	unary  func(context.Context, *pb.SimpleRequest) (*pb.SimpleResponse, error)
	stream func(*pb.StreamingOutputCallRequest, grpc.ServerStreamingServer[pb.StreamingOutputCallResponse]) error
}

func (s *testServer) UnaryCall(ctx context.Context, r *pb.SimpleRequest) (*pb.SimpleResponse, error) {
	return s.unary(ctx, r)
}
func (*testServer) EmptyCall(context.Context, *pb.Empty) (*pb.Empty, error) { return &pb.Empty{}, nil }
func (s *testServer) StreamingOutputCall(r *pb.StreamingOutputCallRequest, stream grpc.ServerStreamingServer[pb.StreamingOutputCallResponse]) error {
	return s.stream(r, stream)
}

func transport(t *testing.T, server *testServer, opts ...grpc.DialOption) (*wendy.GRPCTransport, *grpc.ClientConn) {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	pb.RegisterTestServiceServer(srv, server)
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { srv.Stop(); _ = listener.Close() })
	options := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() })}
	options = append(options, opts...)
	conn, err := grpc.NewClient("passthrough:///bufnet", options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	tr, err := wendy.NewGRPCTransport(conn)
	if err != nil {
		t.Fatal(err)
	}
	return tr, conn
}
func marshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, e := proto.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func values(md wendy.Metadata, name string) [][]byte {
	var result [][]byte
	for _, v := range md {
		if v.Name == name {
			result = append(result, v.Value)
		}
	}
	return result
}
func checkStatus(t *testing.T, err error, code wendy.RPCStatusCode) *wendy.RPCStatusError {
	t.Helper()
	var rpc *wendy.RPCStatusError
	if !errors.As(err, &rpc) || rpc.Code != code {
		t.Fatalf("status = %v, want %d", err, code)
	}
	return rpc
}

func TestGRPCUnary(t *testing.T) {
	payload := []byte("opaque\x00payload\xff")
	response := &pb.SimpleResponse{Payload: &pb.Payload{Body: payload}}
	response.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x07})
	tr, conn := transport(t, &testServer{unary: func(ctx context.Context, r *pb.SimpleRequest) (*pb.SimpleResponse, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		if !reflect.DeepEqual(md.Get("x-repeat"), []string{"inherited", "one", "two"}) || !reflect.DeepEqual(md.Get("x-data-bin"), []string{"\x00\xff"}) {
			t.Errorf("metadata lost: %v", md)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Error("deadline missing")
		}
		if !bytes.Equal(r.GetPayload().GetBody(), payload) {
			t.Error("request corrupted")
		}
		_ = grpc.SetHeader(ctx, metadata.Pairs("x-head", "first", "x-head", "second", "x-data-bin", "\x00\xff"))
		grpc.SetTrailer(ctx, metadata.Pairs("x-tail", "last"))
		return response, nil
	}})
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-repeat", "inherited")), 5*time.Second)
	defer cancel()
	request := wendy.RPCRequest{Method: unaryMethod, Message: marshal(t, &pb.SimpleRequest{Payload: &pb.Payload{Body: payload}}), Metadata: wendy.Metadata{{Name: "x-repeat", Value: []byte("one")}, {Name: "x-data-bin", Value: []byte{0, 255}}, {Name: "x-repeat", Value: []byte("two")}}}
	result, err := tr.Unary(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Message, marshal(t, response)) {
		t.Fatal("serialized response or unknown fields changed")
	}
	if !reflect.DeepEqual(values(result.InitialMetadata, "x-head"), [][]byte{[]byte("first"), []byte("second")}) || !reflect.DeepEqual(values(result.InitialMetadata, "x-data-bin"), [][]byte{{0, 255}}) || !reflect.DeepEqual(values(result.TrailingMetadata, "x-tail"), [][]byte{[]byte("last")}) {
		t.Fatal("response metadata lost")
	}
	// Empty protobufs are valid, and the adapter does not replace the global codec
	// or take ownership of the connection used by generated clients.
	empty, err := tr.Unary(ctx, wendy.RPCRequest{Method: "/grpc.testing.TestService/EmptyCall"})
	if err != nil || len(empty.Message) != 0 {
		t.Fatalf("empty: %v", err)
	}
	if _, err := pb.NewTestServiceClient(conn).EmptyCall(ctx, &pb.Empty{}); err != nil {
		t.Fatal(err)
	}
}

func TestGRPCUnaryStatusAndNoRetry(t *testing.T) {
	var attempts atomic.Int32
	remote, _ := status.New(codes.Unavailable, "sensitive diagnostic").WithDetails(&errdetails.ErrorInfo{Reason: "test"})
	tr, _ := transport(t, &testServer{unary: func(ctx context.Context, _ *pb.SimpleRequest) (*pb.SimpleResponse, error) {
		attempts.Add(1)
		// No initial headers: grpc-go's configured retry policy would retry this.
		grpc.SetTrailer(ctx, metadata.Pairs("x-tail-bin", "\x00\xff"))
		return nil, remote.Err()
	}}, grpc.WithDefaultServiceConfig(`{"methodConfig":[{"name":[{"service":"grpc.testing.TestService"}],"retryPolicy":{"MaxAttempts":4,"InitialBackoff":"0.001s","MaxBackoff":"0.001s","BackoffMultiplier":1,"RetryableStatusCodes":["UNAVAILABLE"]}}]}`))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := tr.Unary(ctx, wendy.RPCRequest{Method: unaryMethod})
	rpc := checkStatus(t, err, wendy.RPCUnavailable)
	if attempts.Load() != 1 {
		t.Fatalf("application request retried %d times", attempts.Load())
	}
	if rpc.Message != "sensitive diagnostic" || strings.Contains(err.Error(), "sensitive") || status.Code(errors.Unwrap(rpc)) != codes.Unavailable {
		t.Fatal("status/cause/redaction lost")
	}
	if len(values(rpc.TrailingMetadata, "grpc-status-details-bin")) != 1 || !reflect.DeepEqual(values(rpc.TrailingMetadata, "x-tail-bin"), [][]byte{{0, 255}}) || !reflect.DeepEqual(rpc.TrailingMetadata, response.TrailingMetadata) {
		t.Fatal("status trailers lost")
	}
}

func TestGRPCUnaryFailureHeaders(t *testing.T) {
	tr, _ := transport(t, &testServer{unary: func(ctx context.Context, _ *pb.SimpleRequest) (*pb.SimpleResponse, error) {
		_ = grpc.SendHeader(ctx, metadata.Pairs("x-head", "first"))
		grpc.SetTrailer(ctx, metadata.Pairs("x-tail", "last"))
		return nil, status.Error(codes.PermissionDenied, "denied")
	}})
	response, err := tr.Unary(context.Background(), wendy.RPCRequest{Method: unaryMethod})
	rpc := checkStatus(t, err, wendy.RPCPermissionDenied)
	if len(values(rpc.InitialMetadata, "x-head")) != 1 || len(values(rpc.TrailingMetadata, "x-tail")) != 1 || !reflect.DeepEqual(response.InitialMetadata, rpc.InitialMetadata) {
		t.Fatal("failure metadata lost")
	}
	response.InitialMetadata[0].Value[0] ^= 1
	if reflect.DeepEqual(response.InitialMetadata, rpc.InitialMetadata) {
		t.Fatal("metadata aliases error data")
	}
}

func TestGRPCStreams(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "EOF", true: "status"}[fail], func(t *testing.T) {
			tr, conn := transport(t, &testServer{stream: func(r *pb.StreamingOutputCallRequest, s grpc.ServerStreamingServer[pb.StreamingOutputCallResponse]) error {
				if string(r.GetPayload().GetBody()) != "request" {
					t.Error("stream request corrupted")
				}
				md, _ := metadata.FromIncomingContext(s.Context())
				if !reflect.DeepEqual(md.Get("x-data-bin"), []string{"\x00\xff"}) {
					t.Error("stream metadata lost")
				}
				if err := s.SendHeader(metadata.Pairs("x-head", "first", "x-head", "second")); err != nil {
					return err
				}
				s.SetTrailer(metadata.Pairs("x-tail-bin", "\x00\xff"))
				for _, body := range [][]byte{nil, []byte("one"), []byte("two")} {
					if err := s.Send(&pb.StreamingOutputCallResponse{Payload: &pb.Payload{Body: body}}); err != nil {
						return err
					}
				}
				if fail {
					return status.Error(codes.DataLoss, "stream diagnostic")
				}
				return nil
			}})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream, err := tr.ServerStream(ctx, wendy.RPCRequest{Method: streamMethod, Message: marshal(t, &pb.StreamingOutputCallRequest{Payload: &pb.Payload{Body: []byte("request")}}), Metadata: wendy.Metadata{{Name: "x-data-bin", Value: []byte{0, 255}}}})
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if stream.Trailer() != nil {
				t.Fatal("trailers available before completion")
			}
			header, err := stream.Header()
			if err != nil {
				t.Fatal(err)
			}
			header[0].Value[0] ^= 1
			again, err := stream.Header()
			if err != nil || reflect.DeepEqual(header, again) {
				t.Fatal("headers not caller-owned")
			}
			var retained []byte
			for i, want := range [][]byte{nil, []byte("one"), []byte("two")} {
				message, err := stream.Recv()
				if err != nil {
					t.Fatal(err)
				}
				var decoded pb.StreamingOutputCallResponse
				if err := proto.Unmarshal(message, &decoded); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(decoded.GetPayload().GetBody(), want) {
					t.Fatal("stream message corrupted")
				}
				if i == 0 {
					retained = message
				} else if !bytes.Equal(retained, marshal(t, &pb.StreamingOutputCallResponse{Payload: &pb.Payload{}})) {
					t.Fatal("message buffer reused")
				}
			}
			_, terminal := stream.Recv()
			if fail {
				rpc := checkStatus(t, terminal, wendy.RPCDataLoss)
				if len(values(rpc.InitialMetadata, "x-head")) != 2 || len(values(rpc.TrailingMetadata, "x-tail-bin")) != 1 {
					t.Fatal("stream status metadata lost")
				}
			} else if terminal != io.EOF {
				t.Fatalf("terminal: %v", terminal)
			}
			if !reflect.DeepEqual(values(stream.Trailer(), "x-tail-bin"), [][]byte{{0, 255}}) {
				t.Fatal("stream trailers lost")
			}
			trailer := stream.Trailer()
			trailer[0].Value[0] ^= 1
			if reflect.DeepEqual(trailer, stream.Trailer()) {
				t.Fatal("trailer ownership")
			}
			_ = stream.Close()
			_ = stream.Close()
			if _, err := stream.Recv(); err != terminal {
				t.Fatal("terminal result changed after close")
			}
			if _, err := pb.NewTestServiceClient(conn).EmptyCall(ctx, &pb.Empty{}); err != nil {
				t.Fatal("stream closed shared connection", err)
			}
		})
	}
}

func TestGRPCCancellation(t *testing.T) {
	for _, operation := range []string{"unary", "header", "recv"} {
		for _, deadline := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "/close", true: "/deadline"}[deadline], func(t *testing.T) {
				started := make(chan struct{})
				tr, _ := transport(t, &testServer{
					unary: func(ctx context.Context, _ *pb.SimpleRequest) (*pb.SimpleResponse, error) {
						close(started)
						<-ctx.Done()
						return nil, status.FromContextError(ctx.Err()).Err()
					},
					stream: func(_ *pb.StreamingOutputCallRequest, s grpc.ServerStreamingServer[pb.StreamingOutputCallResponse]) error {
						if operation == "recv" {
							if err := s.SendHeader(metadata.Pairs("x-head", "ready")); err != nil {
								return err
							}
						}
						close(started)
						<-s.Context().Done()
						return status.FromContextError(s.Context().Err()).Err()
					},
				})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if deadline {
					ctx, cancel = context.WithTimeout(ctx, time.Second)
					defer cancel()
				}
				result := make(chan error, 1)
				var stream wendy.ServerStream
				if operation == "unary" {
					go func() { _, err := tr.Unary(ctx, wendy.RPCRequest{Method: unaryMethod}); result <- err }()
				} else {
					var err error
					stream, err = tr.ServerStream(ctx, wendy.RPCRequest{Method: streamMethod})
					if err != nil {
						t.Fatal(err)
					}
					defer stream.Close()
					go func() {
						if operation == "header" {
							_, err := stream.Header()
							result <- err
						} else {
							_, err := stream.Recv()
							result <- err
						}
					}()
				}
				select {
				case <-started:
				case <-time.After(3 * time.Second):
					t.Fatal("server did not start")
				}
				if !deadline {
					if stream != nil {
						_ = stream.Close()
						_ = stream.Close()
					} else {
						cancel()
					}
				}
				want := error(context.Canceled)
				if deadline {
					want = context.DeadlineExceeded
				}
				select {
				case err := <-result:
					if !errors.Is(err, want) {
						t.Fatalf("cancellation = %v, want %v", err, want)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("cancellation did not unblock call")
				}
			})
		}
	}
}

func TestGRPCValidation(t *testing.T) {
	if _, err := wendy.NewGRPCTransport(nil); err == nil {
		t.Fatal("accepted nil connection")
	}
	var calls atomic.Int32
	tr, _ := transport(t, &testServer{unary: func(context.Context, *pb.SimpleRequest) (*pb.SimpleResponse, error) {
		calls.Add(1)
		return &pb.SimpleResponse{}, nil
	}})
	for _, request := range []wendy.RPCRequest{
		{Method: "bad"}, {Method: "/svc/"}, {Method: "/svc/method/extra"}, {Method: "/svc/secret\nvalue"},
		{Method: unaryMethod, Metadata: wendy.Metadata{{Name: "UPPER", Value: []byte("secret")}}},
		{Method: unaryMethod, Metadata: wendy.Metadata{{Name: "x-text", Value: []byte("secret\nvalue")}}},
		{Method: unaryMethod, Metadata: wendy.Metadata{{Name: "", Value: []byte("secret")}}},
		{Method: unaryMethod, Metadata: wendy.Metadata{{Name: "grpc-timeout", Value: []byte("1S")}}},
		{Method: unaryMethod, Metadata: wendy.Metadata{{Name: "content-type", Value: []byte("secret")}}},
	} {
		if _, err := tr.Unary(context.Background(), request); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("validation: %v", err)
		}
		if _, err := tr.ServerStream(context.Background(), request); err == nil {
			t.Fatal("stream accepted invalid request")
		}
	}
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-text", "secret\nvalue"))
	if _, err := tr.Unary(ctx, wendy.RPCRequest{Method: unaryMethod}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("inherited metadata validation: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tr.Unary(ctx, wendy.RPCRequest{Method: unaryMethod}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := tr.ServerStream(ctx, wendy.RPCRequest{Method: streamMethod}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached server")
	}
}

func TestGRPCTrailersOnlyStream(t *testing.T) {
	for _, fail := range []bool{false, true} {
		for _, headerFirst := range []bool{false, true} {
			t.Run(map[bool]string{false: "success", true: "failure"}[fail]+map[bool]string{false: "/recv", true: "/header"}[headerFirst], func(t *testing.T) {
				var attempts atomic.Int32
				tr, _ := transport(t, &testServer{stream: func(_ *pb.StreamingOutputCallRequest, s grpc.ServerStreamingServer[pb.StreamingOutputCallResponse]) error {
					attempts.Add(1)
					s.SetTrailer(metadata.Pairs("x-tail", "last"))
					if fail {
						return status.Error(codes.Unavailable, "stream refused")
					}
					return nil
				}}, grpc.WithDefaultServiceConfig(`{"methodConfig":[{"name":[{"service":"grpc.testing.TestService"}],"retryPolicy":{"MaxAttempts":4,"InitialBackoff":"0.001s","MaxBackoff":"0.001s","BackoffMultiplier":1,"RetryableStatusCodes":["UNAVAILABLE"]}}]}`))
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				stream, err := tr.ServerStream(ctx, wendy.RPCRequest{Method: streamMethod})
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				if headerFirst {
					_, err := stream.Header()
					if fail {
						checkStatus(t, err, wendy.RPCUnavailable)
					} else if err != nil {
						t.Fatal(err)
					}
					_, again := stream.Header()
					if again != err {
						t.Fatal("header result changed")
					}
					if stream.Trailer() != nil {
						t.Fatal("trailers exposed before terminal Recv")
					}
				}
				_, err = stream.Recv()
				if fail {
					rpc := checkStatus(t, err, wendy.RPCUnavailable)
					if len(values(rpc.TrailingMetadata, "x-tail")) != 1 {
						t.Fatal("trailers missing")
					}
				} else if err != io.EOF {
					t.Fatalf("expected EOF, got %v", err)
				}
				if _, again := stream.Recv(); again != err {
					t.Fatal("terminal result changed")
				}
				if attempts.Load() != 1 {
					t.Fatalf("stream application request retried %d times", attempts.Load())
				}
				if len(values(stream.Trailer(), "x-tail")) != 1 {
					t.Fatal("trailers missing")
				}
			})
		}
	}
}

func TestGRPCEmptyStreamMessage(t *testing.T) {
	tr, _ := transport(t, &testServer{stream: func(_ *pb.StreamingOutputCallRequest, s grpc.ServerStreamingServer[pb.StreamingOutputCallResponse]) error {
		return s.Send(&pb.StreamingOutputCallResponse{})
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := tr.ServerStream(ctx, wendy.RPCRequest{Method: streamMethod})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	message, err := stream.Recv()
	if err != nil || len(message) != 0 {
		t.Fatalf("empty message = %x, %v", message, err)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("completion = %v", err)
	}
}

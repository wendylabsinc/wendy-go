package wendy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GRPCTransport implements Core's Transport over a caller-owned connection.
// The caller configures TLS, credentials and interceptors, and closes the
// connection. Interceptors must accept serialized []byte messages and must not
// retry application requests or log their contents. GRPCTransport is safe for
// concurrent use and does not open connections or add authentication itself.
// Metadata values retain their order within a name. grpc-go groups names in a
// map, so response names are sorted and cross-name wire order is not retained.
type GRPCTransport struct{ conn *grpc.ClientConn }

var _ Transport = (*GRPCTransport)(nil)

// NewGRPCTransport wraps conn without taking ownership of it.
func NewGRPCTransport(conn *grpc.ClientConn) (*GRPCTransport, error) {
	if conn == nil {
		return nil, errors.New("RPC transport requires a connection")
	}
	return &GRPCTransport{conn: conn}, nil
}

// Unary sends an already-serialized protobuf, preserving response metadata on
// both success and failure. ctx controls the call deadline and cancellation.
func (t *GRPCTransport) Unary(ctx context.Context, request RPCRequest) (RPCResponse, error) {
	ctx, err := rpcContext(ctx, request)
	if err != nil {
		return RPCResponse{}, err
	}
	var message []byte
	var headers, trailers metadata.MD
	err = t.conn.Invoke(ctx, request.Method, request.Message, &message,
		grpc.ForceCodec(protobufBytesCodec{}), grpc.MaxRetryRPCBufferSize(0),
		grpc.Header(&headers), grpc.Trailer(&trailers))
	response := RPCResponse{
		Message: message, InitialMetadata: coreMetadata(headers), TrailingMetadata: coreMetadata(trailers),
	}
	if err != nil {
		response.Message = nil
		return response, rpcError(err, headers, trailers)
	}
	return response, nil
}

// ServerStream sends one serialized request and closes the sending side. The
// returned stream owns a child context; Close cancels it without closing conn.
func (t *GRPCTransport) ServerStream(ctx context.Context, request RPCRequest) (ServerStream, error) {
	ctx, err := rpcContext(ctx, request)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	stream, err := t.conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, request.Method,
		grpc.ForceCodec(protobufBytesCodec{}), grpc.MaxRetryRPCBufferSize(0))
	if err != nil {
		cancel()
		return nil, rpcError(err, nil, nil)
	}
	// SendMsg may report EOF before exposing the real server status. RecvMsg
	// retrieves that status; it remains the caller's next pull operation.
	if err = stream.SendMsg(request.Message); err != nil && !errors.Is(err, io.EOF) {
		cancel()
		return nil, rpcError(err, nil, stream.Trailer())
	}
	if err = stream.CloseSend(); err != nil && !errors.Is(err, io.EOF) {
		cancel()
		return nil, rpcError(err, nil, stream.Trailer())
	}
	return &grpcServerStream{stream: stream, cancel: cancel}, nil
}

type grpcServerStream struct {
	stream    grpc.ClientStream
	cancel    context.CancelFunc
	headerSet bool
	headers   metadata.MD
	headerErr error
	terminal  error
	trailers  metadata.MD
}

func (s *grpcServerStream) Header() (Metadata, error) {
	if !s.headerSet {
		s.headers, s.headerErr = s.stream.Header()
		s.headerSet = true
		// grpc-go returns (nil, nil) for trailers-only termination, even on
		// cancellation. RecvMsg is required to obtain the actual status.
		if s.headers == nil && s.headerErr == nil {
			var message []byte
			s.headerErr = s.stream.RecvMsg(&message)
			if errors.Is(s.headerErr, io.EOF) {
				s.terminal = io.EOF
				s.headerErr = nil
			}
			s.cancel()
		}
		if s.headerErr != nil {
			s.headerErr = rpcError(s.headerErr, s.headers, s.stream.Trailer())
			s.terminal = s.headerErr
		}
	}
	return coreMetadata(s.headers), s.headerErr
}

func (s *grpcServerStream) Recv() ([]byte, error) {
	if s.terminal != nil {
		s.trailers = s.stream.Trailer()
		return nil, s.terminal
	}
	var message []byte
	err := s.stream.RecvMsg(&message)
	if err == nil {
		return message, nil
	}
	s.trailers = s.stream.Trailer()
	// Headers are now available without blocking, including if the caller
	// never called Header. Capture them before releasing the child context.
	_, _ = s.Header()
	if errors.Is(err, io.EOF) {
		s.terminal = io.EOF
	} else {
		s.terminal = rpcError(err, s.headers, s.trailers)
	}
	s.cancel()
	return nil, s.terminal
}

func (s *grpcServerStream) Trailer() Metadata { return coreMetadata(s.trailers) }

func (s *grpcServerStream) Close() error {
	s.cancel()
	return nil
}

// A per-call codec avoids decoding/re-encoding protobufs (and preserves unknown
// fields) without registering or replacing grpc-go's global protobuf codec.
type protobufBytesCodec struct{}

func (protobufBytesCodec) Name() string { return "proto" }
func (protobufBytesCodec) Marshal(value any) ([]byte, error) {
	message, ok := value.([]byte)
	if !ok {
		return nil, errors.New("RPC codec requires serialized protobuf bytes")
	}
	return bytes.Clone(message), nil
}
func (protobufBytesCodec) Unmarshal(data []byte, value any) error {
	message, ok := value.(*[]byte)
	if !ok {
		return errors.New("RPC codec requires a serialized protobuf destination")
	}
	*message = bytes.Clone(data)
	return nil
}

func rpcContext(ctx context.Context, request RPCRequest) (context.Context, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parts := strings.Split(request.Method, "/")
	if len(parts) != 3 || parts[0] != "" || parts[1] == "" || parts[2] == "" {
		return nil, errors.New("RPC method must be /package.Service/Method")
	}
	for _, c := range request.Method {
		if c <= ' ' || c > '~' {
			return nil, errors.New("invalid RPC method")
		}
	}
	md, _ := metadata.FromOutgoingContext(ctx) // Returns an owned copy.
	if md == nil {
		md = metadata.MD{}
	}
	for _, entry := range request.Metadata {
		if !validMetadata(entry.Name, entry.Value) {
			return nil, errors.New("invalid outgoing RPC metadata")
		}
		md[entry.Name] = append(md[entry.Name], string(entry.Value))
	}
	// Validate inherited metadata too, without exposing its value in an error.
	for name, values := range md {
		for _, value := range values {
			if !validMetadata(name, []byte(value)) {
				return nil, errors.New("invalid outgoing RPC metadata")
			}
		}
	}
	return metadata.NewOutgoingContext(ctx, md), nil
}

func validMetadata(name string, value []byte) bool {
	// Protocol-owned fields are not application metadata. grpc-go may silently
	// discard these or use them for transport behavior instead of passing them.
	if name == "" || strings.HasPrefix(name, "grpc-") {
		return false
	}
	switch name {
	case "content-type", "user-agent", "te":
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	if !strings.HasSuffix(name, "-bin") {
		for _, c := range value {
			if c < ' ' || c > '~' {
				return false
			}
		}
	}
	return true
}

func coreMetadata(md metadata.MD) Metadata {
	// grpc-go groups metadata by key, losing order between distinct names.
	// Sort names for deterministic output; preserve value order within a name.
	keys := make([]string, 0, len(md))
	for key := range md {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var result Metadata
	for _, key := range keys {
		for _, value := range md[key] {
			result = append(result, MetadataEntry{Name: key, Value: []byte(value)})
		}
	}
	return result
}

func rpcError(err error, headers, trailers metadata.MD) error {
	s := status.Convert(err)
	return &RPCStatusError{
		Code: RPCStatusCode(s.Code()), Message: s.Message(), Cause: err,
		InitialMetadata: coreMetadata(headers), TrailingMetadata: coreMetadata(trailers),
	}
}

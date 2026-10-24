package wendy

import "github.com/wendylabsinc/WendyOS/go/wendy-core/platform"

// Signer is Core's host-owned signing capability.
type Signer = platform.Signer

// SignatureAlgorithm identifies a signature scheme by its protocol name.
type SignatureAlgorithm = platform.SignatureAlgorithm

// MLDSA65 identifies pure ML-DSA-65, without pre-hashing.
const MLDSA65 = platform.MLDSA65

// Transport is Core's host-owned RPC capability.
type Transport = platform.Transport

// ServerStream is a pull-based serialized RPC response stream.
type ServerStream = platform.ServerStream

// MetadataEntry holds a lowercase name and an unencoded metadata value.
// GRPCTransport rejects outgoing protocol-owned names (grpc-*, content-type,
// user-agent and te); configure protocol fields on the connection instead.
type MetadataEntry = platform.MetadataEntry

// Metadata preserves repeated metadata values, including raw binary values.
type Metadata = platform.Metadata

// RPCRequest holds a method path, serialized protobuf and outgoing metadata.
type RPCRequest = platform.RPCRequest

// RPCResponse holds a serialized protobuf and response headers and trailers.
type RPCResponse = platform.RPCResponse

// RPCStatusError retains the wire status, metadata and underlying RPC error.
// Its Error method excludes remote diagnostics; redact its fields before logging.
type RPCStatusError = platform.RPCStatusError

// RPCStatusCode is a numeric gRPC wire status.
type RPCStatusCode = platform.RPCStatusCode

// RPC status codes match the gRPC wire values.
const (
	RPCOK                 = platform.RPCOK
	RPCCanceled           = platform.RPCCanceled
	RPCUnknown            = platform.RPCUnknown
	RPCInvalidArgument    = platform.RPCInvalidArgument
	RPCDeadlineExceeded   = platform.RPCDeadlineExceeded
	RPCNotFound           = platform.RPCNotFound
	RPCAlreadyExists      = platform.RPCAlreadyExists
	RPCPermissionDenied   = platform.RPCPermissionDenied
	RPCResourceExhausted  = platform.RPCResourceExhausted
	RPCFailedPrecondition = platform.RPCFailedPrecondition
	RPCAborted            = platform.RPCAborted
	RPCOutOfRange         = platform.RPCOutOfRange
	RPCUnimplemented      = platform.RPCUnimplemented
	RPCInternal           = platform.RPCInternal
	RPCUnavailable        = platform.RPCUnavailable
	RPCDataLoss           = platform.RPCDataLoss
	RPCUnauthenticated    = platform.RPCUnauthenticated
)

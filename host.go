package wendy

import "github.com/wendylabsinc/WendyOS/go/wendy-core/platform"

// Signer is Core's host-owned signing capability.
type Signer = platform.Signer

// IdentityKey adds PKCS#10 creation and certificate key-binding checks to Signer.
type IdentityKey = platform.IdentityKey

// CertificateIdentity contains host-checked public certificate material.
type CertificateIdentity = platform.CertificateIdentity

// HTTPTransport sends HTTP data through host networking and TLS.
type HTTPTransport = platform.HTTPTransport

// HTTPRequest holds an HTTP method, URL, headers and body bytes.
type HTTPRequest = platform.HTTPRequest

// HTTPResponse transfers ownership of its headers and closeable body to Core.
type HTTPResponse = platform.HTTPResponse

// HTTPHeaders preserves repeated HTTP header values.
type HTTPHeaders = platform.HTTPHeaders

// SignatureVerifier verifies exact JWS signing bytes against a public JWK.
type SignatureVerifier = platform.SignatureVerifier

// Entropy supplies caller-owned bytes from a host's secure random generator.
type Entropy = platform.Entropy

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

// DeviceIdentity is the peer identity the TLS verifier must require.
// A nonempty Principal is an exact SPIFFE URI constraint, never a legacy tuple.
type DeviceIdentity = platform.DeviceIdentity

// DeviceConnectRequest selects exactly one endpoint and host credential reference.
type DeviceConnectRequest = platform.DeviceConnectRequest

// DeviceConnectionEvidence retains typed verifier rejections and TCP failure evidence.
type DeviceConnectionEvidence = platform.DeviceConnectionEvidence

// DeviceConnection is a host-owned RPC connection with concurrent evidence.
type DeviceConnection = platform.DeviceConnection

// DeviceConnector opens the endpoint and credential selected by Core.
type DeviceConnector = platform.DeviceConnector

// DevicePeerRejectedError preserves an eager verifier rejection without allowing fallback.
type DevicePeerRejectedError = platform.DevicePeerRejectedError

// LegacyProofSigner signs SHA-256 legacy Cloud ingress proofs as ASN.1 ECDSA.
type LegacyProofSigner = platform.LegacyProofSigner

// ProofCertificate contains host-parsed public certificate facts, never trust.
type ProofCertificate = platform.ProofCertificate

// ProofVerifier parses certificates and verifies exact pure ML-DSA-65/87 bytes.
type ProofVerifier = platform.ProofVerifier

// CompletionSigner signs canonical device reset receipts with the existing key.
type CompletionSigner = platform.CompletionSigner

// RevocationEvidence contains issuer-authenticated OCSP facts for an exact leaf.
type RevocationEvidence = platform.RevocationEvidence

// ReceiptVerifier authenticates receipt signatures and OCSP issuer/leaf binding.
// It does not establish remote root or Cloud-key trust.
type ReceiptVerifier = platform.ReceiptVerifier

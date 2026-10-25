// Package cloud exposes Wendy Core's shared Cloud request signing,
// authentication, inventory and basic inbox behavior. Hosts supply authenticated
// transports, signing keys and entropy; they retain TLS, key storage and session
// refresh.
package cloud

import (
	"context"

	core "github.com/wendylabsinc/WendyOS/go/wendy-core/core/cloud"
	wendy "github.com/wendylabsinc/wendy-go"
)

// Client sends Cloud RPCs through a host-supplied, authenticated transport.
// ListDevices returns the complete bounded inventory or an error, with no
// partial success. The upstream API does not guarantee a consistent snapshot
// while devices change; no pagination offsets are exposed by this client.
// Inbox methods use typed requests, without SignedRequest envelopes. Their
// transport must resolve the current Cloud token and bound key and obtain fresh
// exact-method AuthenticationMetadata for every RPC, batch and continuation.
type Client = core.Client

// Asset preserves Cloud v2 asset UUIDs, device metadata and unknown fields.
type Asset = core.Asset

// Organization is the Cloud v2 organization contract.
type Organization = core.Organization

// GetAssetRequest selects an exact asset, retaining optional tenant/device IDs.
// An untyped NOT_FOUND is never evidence of device deletion.
type GetAssetRequest = core.GetAssetRequest

// DeleteAssetRequest carries Cloud's compare-and-delete and reset-proof guards.
type DeleteAssetRequest = core.DeleteAssetRequest

// DeleteAssetResponse retains Cloud's reset authorization after deletion.
type DeleteAssetResponse = core.DeleteAssetResponse

// DeviceLimitError refuses a truncated inventory rather than returning success.
type DeviceLimitError = core.DeviceLimitError

// Signer encodes Cloud's exact-body request envelopes using a host-owned key.
// It supports concurrent calls when its host capabilities do.
type Signer = core.Signer

// SignerOptions fixes the caller's channel and optional concurrent-safe clock.
type SignerOptions = core.SignerOptions

// Channel marks a caller's MCP origin outside the request signature.
type Channel = core.Channel

// SignedRequest is Cloud's exact-body signed request envelope.
type SignedRequest = core.SignedRequest

// InvokeOptions preserves caller metadata and optional revocation authority.
type InvokeOptions = core.InvokeOptions

// BrokerAudience is the Cloud request-signature audience.
const BrokerAudience = core.BrokerAudience

// CollidingFieldMetadataKey identifies Cloud's collision-detail trailer.
const CollidingFieldMetadataKey = core.CollidingFieldMetadataKey

// DefaultBrokerPort is the existing local/on-prem broker port.
const DefaultBrokerPort = core.DefaultBrokerPort

// EnrollmentChainP256 selects the constrained-device P-256 enrollment chain.
const EnrollmentChainP256 = core.EnrollmentChainP256

// NewSigner binds an ML-DSA-65 host signer to a canonical operator tenant UUID.
// Hosts must validate certificate identity, chain order and key ownership first.
func NewSigner(ctx context.Context, key wendy.Signer, tenant string, entropy wendy.Entropy, options SignerOptions) (*Signer, error) {
	return core.NewSigner(ctx, key, tenant, entropy, options)
}

// AuthenticationMetadata replaces existing authorization/proof entries with a
// fresh per-RPC DPoP proof without mutating the supplied metadata. The host must
// resolve or refresh the access token and its bound key before calling.
func AuthenticationMetadata(ctx context.Context, entropy wendy.Entropy, authority, method, token string, key wendy.Signer, metadata wendy.Metadata) (wendy.Metadata, error) {
	return core.AuthenticationMetadata(ctx, entropy, authority, method, token, key, metadata)
}

// CorrelationID adopts a safe caller flow ID or creates a host-random UUID.
func CorrelationID(ctx context.Context, metadata wendy.Metadata, entropy wendy.Entropy) (string, error) {
	return core.CorrelationID(ctx, metadata, entropy)
}

// BrokerURL resolves the broker address, preferring an explicit override.
// Public-CA endpoints share the Cloud address; local endpoints use brokerPort.
func BrokerURL(cloudGRPC, brokerURL, brokerPort string) string {
	return core.BrokerURL(cloudGRPC, brokerURL, brokerPort)
}

// UsesPublicCA selects the broker root set/address, never whether TLS applies.
func UsesPublicCA(address string) bool { return core.UsesPublicCA(address) }

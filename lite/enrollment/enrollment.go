// Package liteenroll exposes Core's Lite enrollment and authenticated trust
// discovery. The host supplies networking, keys, certificate inspection and files.
package liteenroll

import (
	"context"

	core "github.com/wendylabsinc/WendyOS/go/wendy-core/core/lite/enrollment"
	wendy "github.com/wendylabsinc/wendy-go"
	"github.com/wendylabsinc/wendy-go/cloud"
	"github.com/wendylabsinc/wendy-go/lite/pb"
)

// Session supplies selected PKI/Cloud endpoints and the operator principal.
type Session = core.Session

// TrustProfile contains firmware-advertised verifier capabilities and an inspector.
type TrustProfile = core.TrustProfile

// DeviceHardware is public enrollment hardware metadata.
type DeviceHardware = core.DeviceHardware

// DefaultTimeURL is Core's default signed timestamp endpoint.
const DefaultTimeURL = core.DefaultTimeURL

// ErrDeviceUUIDTaken identifies the device-UUID collision retry class.
var ErrDeviceUUIDTaken = core.ErrDeviceUUIDTaken

// Config creates enrollment configuration for the selected identity/endpoints.
func Config(auth *Session, deviceID, csrURL, timeURL, brokerHost string, brokerPort uint32) (*pb.WendyConfEnrollment, error) {
	return core.Config(auth, deviceID, csrURL, timeURL, brokerHost, brokerPort)
}

// Mint reserves the Lite asset using the host signer, with bounded UUID retries.
func Mint(ctx context.Context, transport wendy.Transport, signer *cloud.Signer, entropy wendy.Entropy, cfg *pb.WendyConfEnrollment, name string, hardware *DeviceHardware, profile TrustProfile) (string, error) {
	return core.Mint(ctx, transport, signer, entropy, cfg, name, hardware, profile)
}

// SignedTime obtains a timestamp bound to the device's nonce.
func SignedTime(ctx context.Context, client wendy.LiteHTTPTransport, endpoint, nonceHex string) ([]byte, error) {
	return core.SignedTime(ctx, client, endpoint, nonceHex)
}

// DeviceUUIDTaken preserves the existing collision classification and trailers.
func DeviceUUIDTaken(err error, trailer wendy.Metadata) bool {
	return core.DeviceUUIDTaken(err, trailer)
}

// RetryTakenDeviceUUID regenerates a conflicting UUID within Core's retry bound.
func RetryTakenDeviceUUID(ctx context.Context, entropy wendy.Entropy, id string, enroll func(string) error) error {
	return core.RetryTakenDeviceUUID(ctx, entropy, id, enroll)
}

// PKISiblingHost selects a PKI sibling service hostname.
func PKISiblingHost(endpoint, label string) string { return core.PKISiblingHost(endpoint, label) }

// TrustProfileFromChallenge requires explicit firmware advertisement of ML-DSA.
func TrustProfileFromChallenge(challenge *pb.WendyComEnrollmentChallenge, inspector wendy.LiteCertificateInspector) TrustProfile {
	return core.TrustProfileFromChallenge(challenge, inspector)
}

// ValidateTrustBundle checks public CA material against firmware compatibility.
func ValidateTrustBundle(data []byte, profile TrustProfile) error {
	return core.ValidateTrustBundle(data, profile)
}

// CheckTrustSupport validates trust provisioning against the firmware challenge.
func CheckTrustSupport(cfg *pb.WendyConfEnrollment, challenge *pb.WendyComEnrollmentChallenge, inspector wendy.LiteCertificateInspector) error {
	return core.CheckTrustSupport(cfg, challenge, inspector)
}

// DefaultTSARoots returns an owned copy of the default timestamp trust anchor.
func DefaultTSARoots() []byte { return core.DefaultTSARoots() }

// ProvisionTrustBundles validates all bundles before updating the configuration.
func ProvisionTrustBundles(cfg *pb.WendyConfEnrollment, device, tsa, https []byte, profile TrustProfile) error {
	return core.ProvisionTrustBundles(cfg, device, tsa, https, profile)
}

// DiscoverTrustForProfile discovers roots only through host-verified HTTPS.
func DiscoverTrustForProfile(ctx context.Context, client wendy.LiteHTTPTransport, cfg *pb.WendyConfEnrollment, endpoint string, profile TrustProfile) error {
	return core.DiscoverTrustForProfile(ctx, client, cfg, endpoint, profile)
}

// DiscoverLiteDeviceCAChain fetches untrusted intermediates for subsequent
// verification against the operator session's existing roots, never new anchors.
func DiscoverLiteDeviceCAChain(ctx context.Context, client wendy.LiteHTTPTransport, inspector wendy.LiteCertificateInspector, endpoint string) (string, error) {
	return core.DiscoverLiteDeviceCAChain(ctx, client, inspector, endpoint)
}

// DeviceCAEndpoint returns the tenant-scoped Lite CA-discovery endpoint.
func DeviceCAEndpoint(pkiEndpoint, tenantID string) (string, error) {
	return core.DeviceCAEndpoint(pkiEndpoint, tenantID)
}

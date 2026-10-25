// Package enrollment exposes Wendy Core's device enrollment, Cloud removal and
// reset-evidence policy. Hosts retain keys, storage, networking and trust anchors.
package enrollment

import (
	"context"
	"time"

	core "github.com/wendylabsinc/WendyOS/go/wendy-core/core/enrollment"
	wendy "github.com/wendylabsinc/wendy-go"
)

// Session identifies the selected host-managed operator session.
type Session = core.Session

// Config preserves the device's on-disk ACME enrollment material.
type Config = core.Config

// Client sends signed enrollment and removal requests over authenticated Cloud
// transport. Keys and session refresh belong to the host.
type Client = core.Client

// DeviceHardware preserves optional hardware fields reported by the Agent.
type DeviceHardware = core.DeviceHardware

// Asset is a Cloud device with its immutable tenant/device binding.
type Asset = core.Asset

// Result records acknowledged removal steps; an error may accompany partial progress.
type Result = core.Result

// Claims is decoded enrollment-token data; parsing never authenticates a token.
type Claims = core.Claims

// Principal is a tenant-scoped identity parsed from its SPIFFE URI.
type Principal = core.Principal

// Progress records acknowledged unenrollment steps, never durable authority.
type Progress = core.Progress

// AssetState retains an active asset or authenticated deletion evidence.
type AssetState = core.AssetState

// DeletedAsset is retained Cloud deletion evidence, never an absent active row.
type DeletedAsset = core.DeletedAsset

// AuthorizedReset carries exact Cloud-authenticated bytes, verified again by the Agent.
type AuthorizedReset = core.AuthorizedReset

// UnenrollOps supplies authenticated Cloud actions and host proof/reset calls.
type UnenrollOps = core.UnenrollOps

// Completion is public device-signed reset evidence, never a credential.
type Completion = core.Completion

// Entity kinds and legacy proof headers retain Core's existing protocol values.
const (
	EntityUser              = core.EntityUser
	EntityAsset             = core.EntityAsset
	EntitySigner            = core.EntitySigner
	IdentityHeader          = core.IdentityHeader
	CertificateSerialHeader = core.CertificateSerialHeader
	TimestampHeader         = core.TimestampHeader
	NonceHeader             = core.NonceHeader
	SignatureHeader         = core.SignatureHeader
	MaxProofBytes           = core.MaxProofBytes
)

// ErrDeviceUUIDTaken retains Core's collision sentinel for errors.Is.
var ErrDeviceUUIDTaken = core.ErrDeviceUUIDTaken

// EnrollmentConfig validates the session, permanent device ID and ACME endpoint.
func EnrollmentConfig(session Session, deviceID, directoryURL string) (Config, error) {
	return core.EnrollmentConfig(session, deviceID, directoryURL)
}

// NewDeviceID creates a permanent device UUID using host entropy.
func NewDeviceID(ctx context.Context, entropy wendy.Entropy) (string, error) {
	return core.NewDeviceID(ctx, entropy)
}

// DeviceUUIDTaken distinguishes a device/mesh collision from a duplicate name.
func DeviceUUIDTaken(err error, trailer wendy.Metadata) bool {
	return core.DeviceUUIDTaken(err, trailer)
}

// RetryTakenDeviceUUID regenerates the identity only for Core's collision sentinel.
func RetryTakenDeviceUUID(ctx context.Context, entropy wendy.Entropy, deviceID string, enroll func(string) error) error {
	return core.RetryTakenDeviceUUID(ctx, entropy, deviceID, enroll)
}

// PKISiblingHost derives an enrollment endpoint in the same PKI deployment.
func PKISiblingHost(identityEndpoint, label string) string {
	return core.PKISiblingHost(identityEndpoint, label)
}

// CheckAgentEnrollment checks the Agent's enrollment readiness contract.
func CheckAgentEnrollment(ctx context.Context, transport wendy.Transport) error {
	return core.CheckAgentEnrollment(ctx, transport)
}

// ReadHardware reads the Agent's enrollment hardware report.
func ReadHardware(ctx context.Context, transport wendy.Transport) (*DeviceHardware, error) {
	return core.ReadHardware(ctx, transport)
}

// StartACMEProvisioning stages enrollment on the Agent after exact identity checks.
func StartACMEProvisioning(ctx context.Context, transport wendy.Transport, cloudHost string, cfg Config, assetID string) (string, error) {
	return core.StartACMEProvisioning(ctx, transport, cloudHost, cfg, assetID)
}

// DeviceID returns the asset's certificate identity, including older bindings.
func DeviceID(asset *Asset) string { return core.DeviceID(asset) }

// Parse decodes an enrollment token without authenticating its claims.
func Parse(token string) (Claims, error) { return core.Parse(token) }

// ParseAsset reads legacy asset identifiers without authenticating the token.
func ParseAsset(token string) (orgID, assetID int32, err error) { return core.ParseAsset(token) }

// TenantSPIFFEURIFromToken reads the unverified token's canonical tenant identity.
func TenantSPIFFEURIFromToken(token string) (string, bool) {
	return core.TenantSPIFFEURIFromToken(token)
}

// ParsePrincipal parses operator, service, device and signer identities.
func ParsePrincipal(principal string) (Principal, error) { return core.ParsePrincipal(principal) }

// LegacyMetadata creates method-bound replay proofs using a host-checked P-256 pair.
func LegacyMetadata(ctx context.Context, identityURI, serial, fullMethod string, entropy wendy.Entropy, signer wendy.LegacyProofSigner, now time.Time) (wendy.Metadata, error) {
	return core.LegacyMetadata(ctx, identityURI, serial, fullMethod, entropy, signer, now)
}

// UnenrollPreflight checks exact Cloud binding before any deletion or reset.
func UnenrollPreflight(reply *AssetState, err error, progress *Progress) error {
	return core.UnenrollPreflight(reply, err, progress)
}

// AuthorizedDeletion validates the signed deletion's exact asset/tenant/device binding.
func AuthorizedDeletion(authorization *AuthorizedReset, progress *Progress) (*DeletedAsset, error) {
	return core.AuthorizedDeletion(authorization, progress)
}

// CheckUnenrollBinding compares the authenticated asset, tenant and device.
func CheckUnenrollBinding(asset *Asset, progress Progress) error {
	return core.CheckUnenrollBinding(asset, progress)
}

// UnenrollLifecycle adopts an asset ID only after its exact identity matches.
func UnenrollLifecycle(reply *AssetState, progress *Progress) (bool, error) {
	return core.UnenrollLifecycle(reply, progress)
}

// PerformUnenroll retains acknowledged partial progress and refreshes reset authority.
func PerformUnenroll(ctx context.Context, progress *Progress, ops UnenrollOps) error {
	return core.PerformUnenroll(ctx, progress, ops)
}

// ResetIssuer resolves the existing reset-authority issuer for the Cloud endpoint.
func ResetIssuer(cloud string) (string, error) { return core.ResetIssuer(cloud) }

// ResetDeletion extracts bounded untrusted bytes; it never establishes authority.
func ResetDeletion(token []byte) ([]byte, error) { return core.ResetDeletion(token) }

// VerifySavedCloudReset checks Cloud and operator proofs with exact identity/time
// binding. The caller must authenticate the raw Cloud key separately.
func VerifySavedCloudReset(ctx context.Context, verifier wendy.ProofVerifier, token, key []byte, cloud, principal, fingerprint string, deletion, operatorDER []byte, earliest, latest time.Time) error {
	return core.VerifySavedCloudReset(ctx, verifier, token, key, cloud, principal, fingerprint, deletion, operatorDER, earliest, latest)
}

// VerifyOperatorReset checks the operator's exact-body reset request and freshness.
func VerifyOperatorReset(ctx context.Context, verifier wendy.ProofVerifier, compact string, request []byte, asset, tenant, correlation string, leafDER []byte, earliest, latest time.Time) error {
	return core.VerifyOperatorReset(ctx, verifier, compact, request, asset, tenant, correlation, leafDER, earliest, latest)
}

// SignCompletion encodes the canonical reset receipt using the device's host key.
func SignCompletion(ctx context.Context, record Completion, signer wendy.CompletionSigner) ([]byte, error) {
	return core.SignCompletion(ctx, record, signer)
}

// VerifyRevocation requires issuer-authenticated revoked evidence for the exact leaf.
func VerifyRevocation(ctx context.Context, verifier wendy.ReceiptVerifier, raw, leaf, issuer []byte, now time.Time) error {
	return core.VerifyRevocation(ctx, verifier, raw, leaf, issuer, now)
}

// ReadCompletion verifies canonical encoding, signatures, identity and revocation.
// Remote callers must independently anchor device roots and reauthenticate Cloud keys.
func ReadCompletion(ctx context.Context, verifier wendy.ReceiptVerifier, raw []byte) (*Completion, error) {
	return core.ReadCompletion(ctx, verifier, raw)
}

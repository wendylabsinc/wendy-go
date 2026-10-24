// Package devices exposes Wendy Core's device addressing, pinning, connection
// ordering and recovery. Hosts retain discovery, storage, keys and networking.
package devices

import (
	"context"
	core "github.com/wendylabsinc/WendyOS/go/wendy-core/core/devices"
	wendy "github.com/wendylabsinc/wendy-go"
	"time"
)

// HostPort brackets IPv6 literals, including scoped link-local addresses.
func HostPort(host string, port int) string {
	return core.HostPort(host, port)
}

// StripZone removes an IPv6 zone for address-family classification only.
func StripZone(host string) string {
	return core.StripZone(host)
}

// OrderDialCandidates de-duplicates literal addresses, prefers IPv4 over IPv6,
// retains scoped addresses, and applies Core’s connection candidate cap.
func OrderDialCandidates(ips []string) []string {
	return core.OrderDialCandidates(ips)
}

// OrderDialCandidatesUnbounded de-duplicates literal addresses, preferring IPv4,
// then global IPv6, then private/link-local IPv6; zones remain intact.
func OrderDialCandidatesUnbounded(ips []string) []string {
	return core.OrderDialCandidatesUnbounded(ips)
}

// LANDevice is host discovery evidence used to select addresses, never identity.
type LANDevice = core.LANDevice

// LANAgentPort returns the plaintext base port, accounting for mTLS advertisements.
func LANAgentPort(device LANDevice) int {
	return core.LANAgentPort(device)
}

// LANAgentAddresses returns discovered endpoints in Core's preferred order,
// preserving USB hostname priority and scoped IPv6 literals. Discovery supplies
// addresses only; the connector must still authenticate the selected device.
func LANAgentAddresses(device LANDevice) []string {
	return core.LANAgentAddresses(device)
}

// AgentVersion is the Agent's existing version/capability response. The wire
// descriptor is private so hosts can link their own generated Agent messages.
type AgentVersion = core.AgentVersion

// GetAgentVersion probes a device over its host-owned transport. A successful
// RPC proves liveness after the host verifier accepts the peer, including on
// lazy connections. Authentication and remote status errors retain their cause.
func GetAgentVersion(ctx context.Context, transport wendy.Transport) (*AgentVersion, error) {
	return core.GetAgentVersion(ctx, transport)
}

// Target is a snapshot of the user's selected device and its governing pin.
// Resolve aliases and pin storage once before dialing. Candidates are already
// resolved by the host; their order is preserved. Addr is the primary endpoint
// and the only one eligible for the existing CLI's plaintext fallback.
type Target = core.Target

// IdentityRefusalError preserves the host verifier's typed identity or SPKI error.
type IdentityRefusalError = core.IdentityRefusalError

// DialOptions contains host cache and diagnostic sinks. They are called from
// concurrent candidate attempts and must be safe for concurrent use. Cache hints
// only reorder credentials; they never establish authority or filter credentials.
type DialOptions = core.DialOptions

// DialFailure identifies the presentation/recovery decision after a failed walk.
type DialFailure = core.DialFailure

// DialAttempt records a failed endpoint probe in route and credential order.
type DialAttempt = core.DialAttempt

// DialResult transfers the winning connection to the caller. Failed and late
// connections are closed before Dial returns. Err and LastMTLSError retain the
// original cause; Attempts and AnyCertRejection support accurate CLI diagnostics.
type DialResult = core.DialResult

// Dial runs the CLI's two-port, every-credential connection ladder. Identity
// refusals stop new candidates and forbid plaintext; an already-started candidate
// may still authenticate the requested device. Only primary failures decide
// plaintext eligibility, and a governing pin always forbids plaintext.
// credentials includes expired certificates for diagnostics. Core filters them
// only for transport when valid alternatives exist, preserving stored order.
func Dial(ctx context.Context, connector wendy.DeviceConnector, target Target, credentials []Credential, options DialOptions) DialResult {
	return core.Dial(ctx, connector, target, credentials, options)
}

// Credential describes a host-owned client certificate, without key material.
// A zero NotAfter means the host could not parse its leaf and it is still tried.
type Credential = core.Credential

// PreferValidCerts skips expired certificates only when usable alternatives exist.
func PreferValidCerts(all []Credential, now time.Time) []Credential {
	return core.PreferValidCerts(all, now)
}

// PromoteOrgNext stably moves an untried credential for the observed org next.
func PromoteOrgNext(order []int, pos int, certs []Credential, org int32) bool {
	return core.PromoteOrgNext(order, pos, certs, org)
}

// OrderCertsByOrg stably promotes cached org credentials without filtering any.
func OrderCertsByOrg(certs []Credential, org int, have bool) []Credential {
	return core.OrderCertsByOrg(certs, org, have)
}

// RotateCertsForOrg stably promotes a discovered org while retaining all credentials.
func RotateCertsForOrg(certs []Credential, orgID int32) []Credential {
	return core.RotateCertsForOrg(certs, orgID)
}

// CertificateRefreshReason only identifies a specific clientAuth capability
// failure. Generic peer expiry alerts alone do not justify replacing credentials.
// Local expiry evidence is supplied separately by ExpiredClientCertificateReason.
func CertificateRefreshReason(err error) string {
	return core.CertificateRefreshReason(err)
}

// IsTLSCertificateError distinguishes certificate failures from non-TLS peers.
func IsTLSCertificateError(err error) bool {
	return core.IsTLSCertificateError(err)
}

// IsReachabilityTimeoutError reports the CLI's bounded handshake retry class.
func IsReachabilityTimeoutError(err error) bool {
	return core.IsReachabilityTimeoutError(err)
}

// StopRecovery prevents a retry after cancellation or a host identity refusal.
// HostRefusal is evidence from the host verifier or an explicit user refusal.
func StopRecovery(ctx context.Context, err error, hostRefusal bool) bool {
	return core.StopRecovery(ctx, err, hostRefusal)
}

// HostPins holds a snapshot of hostname identity pins; hosts own persistence.
type HostPins = core.HostPins

// DevicePin binds a hostname to its organization, Cloud endpoint and device
// identity. Hosts own persistence; Core compares observed values.
type DevicePin = core.DevicePin

// ExpectedIdentityForPin retains a complete SPIFFE principal when known,
// falling back to the legacy organization/asset constraint for older pins.
func ExpectedIdentityForPin(pin DevicePin) *wendy.DeviceIdentity {
	return core.ExpectedIdentityForPin(pin)
}

// PinVerdict is the result of comparing an observed device identity against the
// stored pin for its hostname.
type PinVerdict = core.PinVerdict

// PinnedDevice is the CLI's persisted known-device entry. Storage and locking
// stay with the host; this shape preserves its existing JSON representation.
type PinnedDevice = core.PinnedDevice

// PinMismatchError reports a new SPKI inside the existing pin's validity window.
type PinMismatchError = core.PinMismatchError

// SPKIFingerprint hashes the DER SubjectPublicKeyInfo supplied by the host.
func SPKIFingerprint(spki []byte) string {
	return core.SPKIFingerprint(spki)
}

// ComparePin applies the CLI's TOFU/rotation policy to a verified asset peer.
// The host parses and verifies the certificate and supplies its identity key,
// SPKI and expiry. User/non-asset certificates must be excluded by the host.
// A differing key is rejected only while the recorded leaf is still valid.
// Missing or unparseable historical expiry retains the existing renewal rule.
// persist is false when only LastSeen changes; the host may refresh that value
// in memory and include it in the next meaningful write. It must keep the old
// pin on rejection and treat storage errors separately from peer rejections.
func ComparePin(key, displayName string, spki []byte, notAfter time.Time, previous *PinnedDevice, now time.Time) (next PinnedDevice, persist bool, err error) {
	return core.ComparePin(key, displayName, spki, notAfter, previous, now)
}

// ExpiredClientCertificateReason captures local expiry evidence at dial failure.
// Unrelated org sessions cannot establish or disprove the selected org's expiry.
func ExpiredClientCertificateReason(org int32, credentials []Credential, now time.Time) string {
	return core.ExpiredClientCertificateReason(org, credentials, now)
}

// RecoveryEvidence contains host evidence captured for the failed target.
// Refused includes user cancellation and verified identity/org/SPKI mismatch.
// ClockSuspect includes the CLI's dial-ladder TLS-handshake rejection sentinel.
// RefreshReason includes locally observed expiry or a missing clientAuth EKU;
// a generic peer TLS expiry alert is insufficient. SwitchStep means the failing
// credential belongs to a different/unknown context, which must not be refreshed.
type RecoveryEvidence = core.RecoveryEvidence

// RecoveryDecision selects bounded recovery without changing endpoint or pins.
type RecoveryDecision = core.RecoveryDecision

// DecideRecovery preserves the CLI's recovery order: terminal refusals stop;
// clock recovery precedes a credential prompt unless local expiry/clientAuth
// evidence already warrants refresh. Hosts retain prompting and all side effects.
func DecideRecovery(ctx context.Context, cause error, evidence RecoveryEvidence) RecoveryDecision {
	return core.DecideRecovery(ctx, cause, evidence)
}

// RetryHandshakeTimeout is the CLI's bounded timeout retry predicate. Explicit
// TLS rejections, cancellation and identity failures must never be retried here.
func RetryHandshakeTimeout(ctx context.Context, cause error, refused, explicitTLSRejection bool) bool {
	return core.RetryHandshakeTimeout(ctx, cause, refused, explicitTLSRejection)
}

// Connection defaults and pin verdicts retain Core’s values.
const (
	MaxDialCandidates         = core.MaxDialCandidates
	DefaultAgentPort          = core.DefaultAgentPort
	AgentMTLSPortOffset       = core.AgentMTLSPortOffset
	MTLSProbeTimeout          = core.MTLSProbeTimeout
	DialFailed                = core.DialFailed
	CertificateRejected       = core.CertificateRejected
	PinnedEndpointUnavailable = core.PinnedEndpointUnavailable
	PinSourceLAN              = core.PinSourceLAN
	PinSourceCloud            = core.PinSourceCloud
	PinFirstUse               = core.PinFirstUse
	PinMatch                  = core.PinMatch
	PinMismatch               = core.PinMismatch
	PinAdoptAsset             = core.PinAdoptAsset
)

// ErrIdentityRefused retains Core’s sentinel for errors.Is.
var ErrIdentityRefused = core.ErrIdentityRefused

// ErrNoAuthenticatedEndpoint retains Core’s sentinel for errors.Is.
var ErrNoAuthenticatedEndpoint = core.ErrNoAuthenticatedEndpoint

// Package identity exposes Wendy Core's shared sign-in, session, organization
// and service-account protocols. Hosts retain networking, keys, secret storage,
// browser callbacks, UI and refresh locks. Callers must serialize changes to a
// session and persist rotated refresh tokens even when a later step fails.
package identity

import (
	"context"
	"time"

	core "github.com/wendylabsinc/WendyOS/go/wendy-core/core/identity"
	wendy "github.com/wendylabsinc/wendy-go"
)

// Client uses host-supplied HTTP, signature-verification and entropy capabilities.
type Client = core.Client

// LoginOptions selects the sign-in authority, client and resource audiences.
type LoginOptions = core.LoginOptions

// Login holds one authorization attempt, including its private state and nonce.
type Login = core.Login

// Callback carries the authorization response received by the host's listener.
type Callback = core.Callback

// LoginProgress reports verified claims before certificate issuance.
// Its token is secret and must not be logged.
type LoginProgress = core.LoginProgress

// Session is portable auth state. APIKey and RefreshToken are secrets; hosts
// persist them in secret storage and keep them out of errors and logs.
type Session = core.Session

// SessionSet holds named sessions and the current context selection.
type SessionSet = core.SessionSet

// SessionPicker is the host's interactive choice between several sessions.
type SessionPicker = core.SessionPicker

// Certificate holds public issued certificate material and its tenant principal.
type Certificate = core.Certificate

// Organization is a Cloud organization returned through a host RPC transport.
type Organization = core.Organization

// OrganizationCollection combines organization membership across sessions.
type OrganizationCollection = core.OrganizationCollection

// ProviderMetadata contains OIDC discovery endpoints and issuer information.
type ProviderMetadata = core.ProviderMetadata

// TokenResponse contains secret OIDC credentials and must not be logged.
type TokenResponse = core.TokenResponse

// JWK is a public JSON Web Key.
type JWK = core.JWK

// TokenVerifier verifies token signatures and claims through a host verifier.
type TokenVerifier = core.TokenVerifier

// VerifiedJWT holds claims whose signature and standard claims were checked.
type VerifiedJWT = core.VerifiedJWT

// BrowserSession holds browser sign-in state; the host serializes its use and
// supplies persistence. Its key is host-owned and must never be serialized.
type BrowserSession = core.BrowserSession

// BrowserSettings pins browser identity, PKI and Cloud service authorities.
type BrowserSettings = core.BrowserSettings

// BrowserMetadata contains the pinned browser OIDC endpoints.
type BrowserMetadata = core.BrowserMetadata

// BrowserToken contains secret browser credentials and must not be logged.
type BrowserToken = core.BrowserToken

// BrowserProfile contains verified signed-in identity and display claims.
type BrowserProfile = core.BrowserProfile

// Core's existing client settings are exposed unchanged.
const (
	Scopes                  = core.Scopes
	DefaultIdentityResource = core.DefaultIdentityResource
	DefaultIdentityEndpoint = core.DefaultIdentityEndpoint
	AuthBase                = core.AuthBase
	IdentityResource        = core.IdentityResource
	IdentityEndpoint        = core.IdentityEndpoint
	CloudResource           = core.CloudResource
	ClientID                = core.ClientID
)

// ErrNotLoggedIn reports that no session is available.
var ErrNotLoggedIn = core.ErrNotLoggedIn

// ErrMultipleSessions reports that a host must ask the user to select a session.
var ErrMultipleSessions = core.ErrMultipleSessions

// ResolveSession applies Core's context, endpoint and picker selection rules.
func ResolveSession(sessions *SessionSet, cloudGRPC string, pick SessionPicker) (*Session, error) {
	return core.ResolveSession(sessions, cloudGRPC, pick)
}

// AccessTokenFreshFor reports whether a session outlasts the requested margin.
func AccessTokenFreshFor(session *Session, margin time.Duration) bool {
	return core.AccessTokenFreshFor(session, margin)
}

// ListOrganizations uses the existing bounded, paged server-streaming RPC.
func ListOrganizations(ctx context.Context, transport wendy.Transport) ([]Organization, error) {
	return core.ListOrganizations(ctx, transport)
}

// CollectOrganizations merges membership while retaining failures and picker state.
func CollectOrganizations(ctx context.Context, sessions []Session, list func(context.Context, *Session) ([]Organization, error), label func(*Session) string, report func(error)) OrganizationCollection {
	return core.CollectOrganizations(ctx, sessions, list, label, report)
}

// ParseTokenResponse decodes an HTTP token response; the caller closes its body.
func ParseTokenResponse(response *wendy.HTTPResponse) (*TokenResponse, error) {
	return core.ParseTokenResponse(response)
}

// OperatorPublicJWK returns a signer's public JWK and protocol algorithm.
func OperatorPublicJWK(ctx context.Context, key wendy.Signer) (map[string]string, string, error) {
	return core.OperatorPublicJWK(ctx, key)
}

// OperatorJWKThumbprint computes the operator key's RFC 7638 thumbprint.
func OperatorJWKThumbprint(ctx context.Context, key wendy.Signer) (string, error) {
	return core.OperatorJWKThumbprint(ctx, key)
}

// SignJWS encodes and signs a compact JWS through the host's signing capability.
func SignJWS(ctx context.Context, key wendy.Signer, header, payload map[string]any) (string, error) {
	return core.SignJWS(ctx, key, header, payload)
}

// CanonicalHTU returns the DPoP HTTP target without query or fragment.
func CanonicalHTU(raw string) (string, error) { return core.CanonicalHTU(raw) }

// CheckServiceAccountToken preserves Core's issuer, audience and key checks.
// It inspects claims; it does not verify the token's signature.
func CheckServiceAccountToken(token *TokenResponse, kid, issuer, resource string) error {
	return core.CheckServiceAccountToken(token, kid, issuer, resource)
}

// TokenExpiry formats a token lifetime as the existing RFC3339 session expiry.
func TokenExpiry(token *TokenResponse) string { return core.TokenExpiry(token) }

// VerifyIDToken checks the signature, claims, nonce and access-token binding.
func VerifyIDToken(ctx context.Context, verifier *TokenVerifier, token *TokenResponse, clientID, nonce string) (string, error) {
	return core.VerifyIDToken(ctx, verifier, token, clientID, nonce)
}

// VerifyAccessToken checks the signature, claims, audience and DPoP key binding.
func VerifyAccessToken(ctx context.Context, verifier *TokenVerifier, raw, audience, thumbprint string) (map[string]any, error) {
	return core.VerifyAccessToken(ctx, verifier, raw, audience, thumbprint)
}

// IssuerRealm returns the human-facing realm slug of an issuer URL.
func IssuerRealm(issuer string) string { return core.IssuerRealm(issuer) }

// EffectiveLoginIssuer binds a callback issuer to the selected authority.
func EffectiveLoginIssuer(requested, authorizationBase, callbackIssuer string) (string, error) {
	return core.EffectiveLoginIssuer(requested, authorizationBase, callbackIssuer)
}

// ValidateRealmIssuer requires a canonical non-system realm on authority's origin.
func ValidateRealmIssuer(authority, issuer string) (string, error) {
	return core.ValidateRealmIssuer(authority, issuer)
}

// SameIssuerOrigin compares issuer scheme and authority.
func SameIssuerOrigin(a, b string) bool { return core.SameIssuerOrigin(a, b) }

// CanonicalAuthorizationBase validates and normalizes a realm-less authority.
func CanonicalAuthorizationBase(raw string) (string, error) {
	return core.CanonicalAuthorizationBase(raw)
}

// DecodeJWTClaims decodes unverified claims; never use it to establish identity.
func DecodeJWTClaims(token string) (map[string]any, error) { return core.DecodeJWTClaims(token) }

// ConfirmationThumbprint reads a decoded token's cnf.jkt claim.
func ConfirmationThumbprint(claims map[string]any) string {
	return core.ConfirmationThumbprint(claims)
}

// BuildAuthorizeURL encodes Core's public-client PKCE authorization request.
func BuildAuthorizeURL(meta *ProviderMetadata, clientID, redirectURI, challenge, state, nonce, resource, loginHint string) (string, error) {
	return core.BuildAuthorizeURL(meta, clientID, redirectURI, challenge, state, nonce, resource, loginHint)
}

// AudienceContains accepts a JWT audience as either a string or string array.
func AudienceContains(audience any, want string) bool { return core.AudienceContains(audience, want) }

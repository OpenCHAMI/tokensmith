package oidc

import (
	"context"
	"net/http"
)

// Provider defines the interface for OIDC token validation and introspection.
// This interface abstracts the interaction with different OIDC providers (e.g., Hydra, Keycloak, Authelia)
// by providing a common set of methods for token introspection and provider metadata retrieval.
type Provider interface {
	// IntrospectToken validates and introspects an OIDC token by making a request to the provider's introspection endpoint.
	// It returns a TokenIntrospection object containing the token's claims and metadata.
	//
	// Parameters:
	//   - ctx: Context for the request, which can be used for cancellation and timeouts
	//   - token: The OIDC token to introspect
	//
	// Returns:
	//   - *TokenIntrospection: Contains the token's claims and metadata if successful
	//   - error: Any error that occurred during introspection
	IntrospectToken(ctx context.Context, token string) (*IntrospectionResponse, error)

	// GetProviderMetadata fetches the OIDC provider's configuration and capabilities.
	// This method retrieves information about the provider's supported features,
	// endpoints, and other configuration details.
	//
	// Parameters:
	//   - ctx: Context for the request, which can be used for cancellation and timeouts
	//
	// Returns:
	//   - *ProviderMetadata: Contains the provider's configuration and capabilities
	//   - error: Any error that occurred while fetching the metadata
	GetProviderMetadata(ctx context.Context) (*ProviderMetadata, error)

	// SupportsLocalIntrospection returns true if the provider supports local token introspection
	SupportsLocalIntrospection() bool

	// GetJWKS returns the JWKS for local token validation
	GetJWKS(ctx context.Context) (interface{}, error)
}

// TokenIntrospection represents a standardized token introspection response
// that follows the OAuth 2.0 Token Introspection specification (RFC 7662)
// and includes additional OIDC-specific claims.
type TokenIntrospection struct {
	// Standard OAuth2 introspection fields
	Active    bool   `json:"active"`               // Whether the token is currently active
	Scope     string `json:"scope,omitempty"`      // Space-separated list of scopes associated with the token
	ClientID  string `json:"client_id,omitempty"`  // ID of the client that requested the token
	Username  string `json:"username,omitempty"`   // Username associated with the token
	TokenType string `json:"token_type,omitempty"` // Type of the token (e.g., "Bearer")

	// Standard OIDC claims
	Subject   string   `json:"sub,omitempty"` // Subject identifier (usually the user ID)
	Issuer    string   `json:"iss,omitempty"` // Token issuer (provider's URL)
	Audience  []string `json:"aud,omitempty"` // Intended recipients of the token
	ExpiresAt int64    `json:"exp,omitempty"` // Token expiration timestamp
	IssuedAt  int64    `json:"iat,omitempty"` // Token issuance timestamp
	NotBefore int64    `json:"nbf,omitempty"` // Token validity start timestamp

	// Additional claims as a map
	// This field can contain provider-specific claims that don't fit into the standard fields
	Claims map[string]interface{} `json:"claims,omitempty"`
}

// ProviderMetadata represents the OIDC provider's configuration and capabilities
// as defined in the OpenID Connect Discovery specification.
type ProviderMetadata struct {
	// Issuer is the URL of the OIDC provider
	Issuer string `json:"issuer"`

	// IntrospectionEndpoint is the URL of the provider's token introspection endpoint
	IntrospectionEndpoint string `json:"introspection_endpoint"`

	// JWKSURI is the URL of the provider's JSON Web Key Set (JWKS) endpoint
	// This endpoint provides the public keys used to verify tokens
	JWKSURI string `json:"jwks_uri"`

	// ScopesSupported is a list of OAuth 2.0 scopes supported by the provider
	ScopesSupported []string `json:"scopes_supported"`
}

func OIDCMiddleware(provider Provider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			provider.IntrospectToken(r.Context(), r.Header.Get("Authorization"))
		})
	}
}

// IntrospectionResponse represents the response from token introspection
type IntrospectionResponse struct {
	Active    bool                   `json:"active"`
	Username  string                 `json:"username"`
	ExpiresAt int64                  `json:"exp"`
	IssuedAt  int64                  `json:"iat"`
	Claims    map[string]interface{} `json:"claims"`
	TokenType string                 `json:"token_type"`
	Scope     string                 `json:"scope"`
	ClientID  string                 `json:"client_id"`
	TokenUse  string                 `json:"token_use"`
}

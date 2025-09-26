package mock

import (
	"context"

	"github.com/openchami/tokensmith/pkg/oidc"
)

// Provider is a mock implementation of the oidc.Provider interface
type Provider struct {
	GetJWKSFunc             func(ctx context.Context) (interface{}, error)
	IntrospectTokenFunc     func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error)
	SupportsLocalFunc       func() bool
	GetProviderMetadataFunc func(ctx context.Context) (*oidc.ProviderMetadata, error)
}

// IntrospectToken calls the mock function
func (m *Provider) IntrospectToken(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
	return m.IntrospectTokenFunc(ctx, token)
}

// GetProviderMetadata calls the mock function
func (m *Provider) GetProviderMetadata(ctx context.Context) (*oidc.ProviderMetadata, error) {
	return m.GetProviderMetadataFunc(ctx)
}

// SupportsLocalIntrospection calls the mock function
func (m *Provider) SupportsLocalIntrospection() bool {
	return m.SupportsLocalFunc()
}

// GetJWKS calls the mock function
func (m *Provider) GetJWKS(ctx context.Context) (interface{}, error) {
	return m.GetJWKSFunc(ctx)
}

// NewProvider creates a new mock provider with default implementations
func NewProvider() *Provider {
	return &Provider{
		IntrospectTokenFunc: func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
			return &oidc.IntrospectionResponse{
				Active:    true,
				Username:  "mockuser",
				ExpiresAt: 0,
				IssuedAt:  0,
				Claims:    make(map[string]interface{}),
				TokenType: "Bearer",
			}, nil
		},
		GetProviderMetadataFunc: func(ctx context.Context) (*oidc.ProviderMetadata, error) {
			return &oidc.ProviderMetadata{
				Issuer:                "mock-issuer",
				IntrospectionEndpoint: "http://mock/introspect",
				JWKSURI:               "http://mock/jwks",
				ScopesSupported:       []string{},
			}, nil
		},
		SupportsLocalFunc: func() bool {
			return false
		},
		GetJWKSFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{
				"keys": []interface{}{},
			}, nil
		},
	}
}

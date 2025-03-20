package mock

import (
	"context"
	"errors"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openchami/tokensmith/pkg/jwt/oidc"
)

// Provider implements oidc.Provider for testing
type Provider struct {
	IntrospectFunc          func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error)
	MetadataFunc            func(ctx context.Context) (*oidc.ProviderMetadata, error)
	SupportsLocalFunc       func() bool
	GetJWKSFunc             func(ctx context.Context) (interface{}, error)
	SupportsLocalIntrospect bool
	JWKS                    interface{}
}

// IntrospectToken implements the oidc.Provider interface
func (m *Provider) IntrospectToken(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
	if m.IntrospectFunc != nil {
		return m.IntrospectFunc(ctx, token)
	}
	return nil, errors.New("IntrospectToken not implemented")
}

// GetProviderMetadata implements the oidc.Provider interface
func (m *Provider) GetProviderMetadata(ctx context.Context) (*oidc.ProviderMetadata, error) {
	if m.MetadataFunc != nil {
		return m.MetadataFunc(ctx)
	}
	return nil, errors.New("GetProviderMetadata not implemented")
}

// SupportsLocalIntrospection implements the oidc.Provider interface
func (m *Provider) SupportsLocalIntrospection() bool {
	if m.SupportsLocalFunc != nil {
		return m.SupportsLocalFunc()
	}
	return m.SupportsLocalIntrospect
}

// GetJWKS implements the oidc.Provider interface
func (m *Provider) GetJWKS(ctx context.Context) (interface{}, error) {
	if m.GetJWKSFunc != nil {
		return m.GetJWKSFunc(ctx)
	}
	if m.JWKS != nil {
		return m.JWKS, nil
	}
	return nil, errors.New("GetJWKS not implemented")
}

// NewProvider creates a new mock provider with default implementations
func NewProvider() *Provider {
	return &Provider{
		SupportsLocalIntrospect: true,
		JWKS:                    jwk.NewSet(),
	}
}

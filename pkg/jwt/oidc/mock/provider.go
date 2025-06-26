package mock

import (
	"context"
	"errors"
)

// Provider implements oidc.Provider for testing
type Provider struct {
	GetJWKSFunc             func(ctx context.Context) (interface{}, error)
	IntrospectTokenFunc     func(ctx context.Context, token string) (interface{}, error)
	SupportsLocalFunc       func() bool
	GetProviderMetadataFunc func(ctx context.Context) (interface{}, error)
	JWKS                    interface{}
}

// IntrospectToken implements the oidc.Provider interface
func (m *Provider) IntrospectToken(ctx context.Context, token string) (interface{}, error) {
	if m.IntrospectTokenFunc != nil {
		return m.IntrospectTokenFunc(ctx, token)
	}
	return nil, errors.New("IntrospectToken not implemented")
}

// GetProviderMetadata implements the oidc.Provider interface
func (m *Provider) GetProviderMetadata(ctx context.Context) (interface{}, error) {
	if m.GetProviderMetadataFunc != nil {
		return m.GetProviderMetadataFunc(ctx)
	}
	return nil, errors.New("GetProviderMetadata not implemented")
}

// SupportsLocalIntrospection implements the oidc.Provider interface
func (m *Provider) SupportsLocalIntrospection() bool {
	if m.SupportsLocalFunc != nil {
		return m.SupportsLocalFunc()
	}
	return false
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
	return &Provider{}
}

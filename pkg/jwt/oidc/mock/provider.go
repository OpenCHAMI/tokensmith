package mock

import (
	"context"
	"errors"

	"github.com/openchami/tokensmith/pkg/jwt/oidc"
)

// Provider implements oidc.Provider for testing
type Provider struct {
	IntrospectFunc func(ctx context.Context, token string) (*oidc.TokenIntrospection, error)
	MetadataFunc   func(ctx context.Context) (*oidc.ProviderMetadata, error)
}

// IntrospectToken implements the oidc.Provider interface
func (m *Provider) IntrospectToken(ctx context.Context, token string) (*oidc.TokenIntrospection, error) {
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

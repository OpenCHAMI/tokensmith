// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package oidc

import (
	"context"
)

// MockProvider is a mock implementation of the Provider interface for testing
type MockProvider struct {
	IntrospectTokenFunc            func(ctx context.Context, token string) (*IntrospectionResponse, error)
	GetProviderMetadataFunc        func(ctx context.Context) (*ProviderMetadata, error)
	SupportsLocalIntrospectionFunc func() bool
	GetJWKSFunc                    func(ctx context.Context) (interface{}, error)
}

// NewMockProvider creates a new mock provider
func NewMockProvider() *MockProvider {
	return &MockProvider{}
}

// IntrospectToken calls the mock function
func (m *MockProvider) IntrospectToken(ctx context.Context, token string) (*IntrospectionResponse, error) {
	if m.IntrospectTokenFunc != nil {
		return m.IntrospectTokenFunc(ctx, token)
	}
	return &IntrospectionResponse{
		Active:    true,
		Username:  "mock-user",
		ExpiresAt: 0,
		IssuedAt:  0,
		Claims:    make(map[string]interface{}),
		TokenType: "Bearer",
	}, nil
}

// GetProviderMetadata calls the mock function
func (m *MockProvider) GetProviderMetadata(ctx context.Context) (*ProviderMetadata, error) {
	if m.GetProviderMetadataFunc != nil {
		return m.GetProviderMetadataFunc(ctx)
	}
	return &ProviderMetadata{
		Issuer:                "mock-issuer",
		IntrospectionEndpoint: "http://mock/introspect",
		JWKSURI:               "http://mock/jwks",
		ScopesSupported:       []string{"read", "write"},
	}, nil
}

// SupportsLocalIntrospection calls the mock function
func (m *MockProvider) SupportsLocalIntrospection() bool {
	if m.SupportsLocalIntrospectionFunc != nil {
		return m.SupportsLocalIntrospectionFunc()
	}
	return false
}

// GetJWKS calls the mock function
func (m *MockProvider) GetJWKS(ctx context.Context) (interface{}, error) {
	if m.GetJWKSFunc != nil {
		return m.GetJWKSFunc(ctx)
	}
	return map[string]interface{}{
		"keys": []interface{}{},
	}, nil
}

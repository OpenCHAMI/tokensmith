package authelia

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/openchami/tokensmith/pkg/jwt/oidc"
)

// Client implements the OIDC provider interface for Authelia
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Authelia OIDC client
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// IntrospectToken validates a token using Authelia's introspection endpoint
func (c *Client) IntrospectToken(ctx context.Context, token string) (*oidc.TokenIntrospection, error) {
	// Authelia's introspection endpoint is typically at /api/verify
	url := fmt.Sprintf("%s/api/verify", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add the token as a Bearer token
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token introspection failed with status: %d", resp.StatusCode)
	}

	var result struct {
		Active    bool   `json:"active"`
		Username  string `json:"username"`
		ExpiresAt int64  `json:"exp"`
		IssuedAt  int64  `json:"iat"`
		Scope     string `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &oidc.TokenIntrospection{
		Active:    result.Active,
		Username:  result.Username,
		ExpiresAt: result.ExpiresAt,
		IssuedAt:  result.IssuedAt,
		Scope:     result.Scope,
	}, nil
}

// GetProviderMetadata returns Authelia's OIDC provider metadata
func (c *Client) GetProviderMetadata(ctx context.Context) (*oidc.ProviderMetadata, error) {
	// Authelia's well-known configuration endpoint
	url := fmt.Sprintf("%s/.well-known/openid-configuration", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get provider metadata with status: %d", resp.StatusCode)
	}

	var metadata struct {
		Issuer                string   `json:"issuer"`
		IntrospectionEndpoint string   `json:"introspection_endpoint"`
		JWKSURI               string   `json:"jwks_uri"`
		ScopesSupported       []string `json:"scopes_supported"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &oidc.ProviderMetadata{
		Issuer:                metadata.Issuer,
		IntrospectionEndpoint: metadata.IntrospectionEndpoint,
		JWKSURI:               metadata.JWKSURI,
		ScopesSupported:       metadata.ScopesSupported,
	}, nil
}

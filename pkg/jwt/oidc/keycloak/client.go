package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openchami/tokensmith/pkg/jwt/oidc"
)

// Client implements the OIDC provider interface for Keycloak
type Client struct {
	baseURL      string
	realm        string
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

// NewClient creates a new Keycloak OIDC client
func NewClient(baseURL, realm, clientID, clientSecret string) *Client {
	return &Client{
		baseURL:      baseURL,
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// IntrospectToken validates a token using Keycloak's introspection endpoint
func (c *Client) IntrospectToken(ctx context.Context, token string) (*oidc.TokenIntrospection, error) {
	// Keycloak's introspection endpoint is at /realms/{realm}/protocol/openid-connect/token/introspect
	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", c.baseURL, c.realm)

	// Create form data for the request
	formData := fmt.Sprintf("token=%s&client_id=%s&client_secret=%s", token, c.clientID, c.clientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(formData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

// GetProviderMetadata returns Keycloak's OIDC provider metadata
func (c *Client) GetProviderMetadata(ctx context.Context) (*oidc.ProviderMetadata, error) {
	// Keycloak's well-known configuration endpoint
	url := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", c.baseURL, c.realm)

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

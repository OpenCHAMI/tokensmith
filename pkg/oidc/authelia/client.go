package authelia

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/openchami/tokensmith/pkg/oidc/common"
)

// Client implements the OIDC provider interface for Authelia
type Client struct {
	baseURL          string
	clientID         string
	clientSecret     string
	metadata         *oidc.ProviderMetadata
	keySet           jwk.Set
	lastJWKSUpdate   time.Time
	jwksUpdatePeriod time.Duration
}

// NewClient creates a new Authelia client
func NewClient(baseURL, clientID, clientSecret string) *Client {
	return &Client{
		baseURL:          baseURL,
		clientID:         clientID,
		clientSecret:     clientSecret,
		jwksUpdatePeriod: 24 * time.Hour,
	}
}

// SupportsLocalIntrospection returns true as Authelia supports local token validation
func (c *Client) SupportsLocalIntrospection() bool {
	return true
}

// GetJWKS returns the JWKS for local token validation
func (c *Client) GetJWKS(ctx context.Context) (interface{}, error) {
	// Check if we need to update the JWKS
	if c.keySet == nil || time.Since(c.lastJWKSUpdate) > c.jwksUpdatePeriod {
		if err := c.updateJWKS(ctx); err != nil {
			return nil, fmt.Errorf("failed to update JWKS: %w", err)
		}
	}
	return c.keySet, nil
}

// updateJWKS fetches the latest JWKS from Authelia
func (c *Client) updateJWKS(ctx context.Context) error {
	url := fmt.Sprintf("%s/.well-known/jwks.json", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	c.keySet, err = jwk.Parse(body)
	if err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}
	c.lastJWKSUpdate = time.Now()
	return nil
}

// IntrospectToken introspects a token using Authelia's introspection endpoint
func (c *Client) IntrospectToken(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
	remoteURL := fmt.Sprintf("%s/api/oauth2/introspect", c.baseURL)
	return common.IntrospectToken(ctx, c.keySet, remoteURL, c.clientID, c.clientSecret, token)

}

// GetProviderMetadata returns Authelia's OIDC provider metadata
func (c *Client) GetProviderMetadata(ctx context.Context) (*oidc.ProviderMetadata, error) {
	url := fmt.Sprintf("%s/.well-known/openid-configuration", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
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

	// Validate required fields
	if metadata.Issuer == "" {
		return nil, fmt.Errorf("missing required field: issuer")
	}
	if metadata.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("missing required field: introspection_endpoint")
	}
	if metadata.JWKSURI == "" {
		return nil, fmt.Errorf("missing required field: jwks_uri")
	}

	return &oidc.ProviderMetadata{
		Issuer:                metadata.Issuer,
		IntrospectionEndpoint: metadata.IntrospectionEndpoint,
		JWKSURI:               metadata.JWKSURI,
		ScopesSupported:       metadata.ScopesSupported,
	}, nil
}

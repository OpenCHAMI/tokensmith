package keycloak

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

// Client implements the OIDC provider interface for Keycloak
type Client struct {
	baseURL          string
	realm            string
	clientID         string
	clientSecret     string
	metadata         *oidc.ProviderMetadata
	keySet           jwk.Set
	lastJWKSUpdate   time.Time
	jwksUpdatePeriod time.Duration
}

// NewClient creates a new Keycloak client
func NewClient(baseURL, realm, clientID, clientSecret string) *Client {
	return &Client{
		baseURL:          baseURL,
		realm:            realm,
		clientID:         clientID,
		clientSecret:     clientSecret,
		jwksUpdatePeriod: 24 * time.Hour,
	}
}

// SupportsLocalIntrospection returns true as Keycloak supports local token validation
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
	// Convert KeySet to map[string]interface{}
	jwksBytes, err := json.Marshal(c.keySet)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWKS: %w", err)
	}
	var jwks map[string]interface{}
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWKS: %w", err)
	}
	return jwks, nil
}

// updateJWKS fetches the latest JWKS from Keycloak
func (c *Client) updateJWKS(ctx context.Context) error {
	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", c.baseURL, c.realm)

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

// GetProviderMetadata returns Keycloak's OIDC provider metadata
func (c *Client) GetProviderMetadata(ctx context.Context) (*oidc.ProviderMetadata, error) {
	// Keycloak's well-known configuration endpoint
	url := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", c.baseURL, c.realm)

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

// IntrospectToken introspects a token using Keycloak's introspection endpoint
func (c *Client) IntrospectToken(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
	remoteURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", c.baseURL, c.realm)
	return common.IntrospectToken(ctx, c.keySet, remoteURL, c.clientID, c.clientSecret, token)
}

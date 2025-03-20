package authelia

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/openchami/tokensmith/pkg/jwt/oidc"
)

// Client implements the OIDC provider interface for Authelia
type Client struct {
	baseURL          string
	clientID         string
	clientSecret     string
	metadata         *oidc.ProviderMetadata
	jwks             jwk.Set
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
	if c.jwks == nil || time.Since(c.lastJWKSUpdate) > c.jwksUpdatePeriod {
		if err := c.updateJWKS(ctx); err != nil {
			return nil, fmt.Errorf("failed to update JWKS: %w", err)
		}
	}
	return c.jwks, nil
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

	jwks, err := jwk.Parse(body)
	if err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	c.jwks = jwks
	c.lastJWKSUpdate = time.Now()
	return nil
}

// IntrospectToken introspects a token using Authelia's introspection endpoint
func (c *Client) IntrospectToken(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
	// If we have JWKS, try local validation first
	if c.jwks != nil {
		parsedToken, err := jwt.Parse([]byte(token), jwt.WithKeySet(c.jwks))
		if err == nil {
			return &oidc.IntrospectionResponse{
				Active:    true,
				Username:  parsedToken.Subject(),
				ExpiresAt: parsedToken.Expiration().Unix(),
				IssuedAt:  parsedToken.IssuedAt().Unix(),
				Claims:    parsedToken.PrivateClaims(),
				TokenType: "Bearer",
			}, nil
		}
	}

	// Fall back to remote introspection
	url := fmt.Sprintf("%s/api/oauth2/introspect", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add form data
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)

	q := req.URL.Query()
	q.Add("token", token)
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to introspect token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to introspect token: status %d", resp.StatusCode)
	}

	var introspection oidc.IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&introspection); err != nil {
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	return &introspection, nil
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

	return &oidc.ProviderMetadata{
		Issuer:                metadata.Issuer,
		IntrospectionEndpoint: metadata.IntrospectionEndpoint,
		JWKSURI:               metadata.JWKSURI,
		ScopesSupported:       metadata.ScopesSupported,
	}, nil
}

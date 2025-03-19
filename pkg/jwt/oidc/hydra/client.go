package hydra

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openchami/tokensmith/pkg/jwt/oidc"
)

// Client handles communication with Hydra's admin API
type Client struct {
	adminURL string
	client   *http.Client
}

// NewClient creates a new Hydra client instance
func NewClient(adminURL string) *Client {
	return &Client{
		adminURL: adminURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// IntrospectToken implements the OIDCProvider interface
func (c *Client) IntrospectToken(ctx context.Context, token string) (*oidc.TokenIntrospection, error) {
	// Prepare form data
	formData := fmt.Sprintf("token=%s", token)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", c.adminURL+"/oauth2/introspect", strings.NewReader(formData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse Hydra-specific response
	var hydraResp struct {
		Active   bool                   `json:"active"`
		Scope    string                 `json:"scope,omitempty"`
		ClientID string                 `json:"client_id,omitempty"`
		Username string                 `json:"username,omitempty"`
		Sub      string                 `json:"sub,omitempty"`
		Exp      int64                  `json:"exp,omitempty"`
		Iat      int64                  `json:"iat,omitempty"`
		Nbf      int64                  `json:"nbf,omitempty"`
		Aud      []string               `json:"aud,omitempty"`
		Iss      string                 `json:"iss,omitempty"`
		Ext      map[string]interface{} `json:"ext,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&hydraResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert to standard TokenIntrospection
	return &oidc.TokenIntrospection{
		Active:    hydraResp.Active,
		Scope:     hydraResp.Scope,
		ClientID:  hydraResp.ClientID,
		Username:  hydraResp.Username,
		Subject:   hydraResp.Sub,
		Issuer:    hydraResp.Iss,
		Audience:  hydraResp.Aud,
		ExpiresAt: hydraResp.Exp,
		IssuedAt:  hydraResp.Iat,
		NotBefore: hydraResp.Nbf,
		Claims:    hydraResp.Ext,
	}, nil
}

// GetProviderMetadata implements the OIDCProvider interface
func (c *Client) GetProviderMetadata(ctx context.Context) (*oidc.ProviderMetadata, error) {
	// Hydra doesn't have a metadata endpoint, so we return a static response
	return &oidc.ProviderMetadata{
		Issuer:                c.adminURL,
		IntrospectionEndpoint: c.adminURL + "/oauth2/introspect",
		JWKSURI:               c.adminURL + "/.well-known/jwks.json",
		ScopesSupported:       []string{"openid", "profile", "email"},
	}, nil
}

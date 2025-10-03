// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ServiceToken represents the token response from tokensmith
type ServiceToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ServiceClient handles communication with the tokensmith service
type ServiceClient struct {
	client        *http.Client
	tokensmithURL string
	serviceName   string
	serviceID     string
	token         *ServiceToken
	instanceID    string
	clusterID     string
}

// NewServiceClient creates a new service client
func NewServiceClient(tokensmithURL, serviceName, serviceID, instanceID, clusterID string) *ServiceClient {
	return &ServiceClient{
		client:        &http.Client{Timeout: 10 * time.Second},
		tokensmithURL: tokensmithURL,
		serviceName:   serviceName,
		serviceID:     serviceID,
		instanceID:    instanceID,
		clusterID:     clusterID,
	}
}

// GetServiceToken returns the service token
func (c *ServiceClient) GetServiceToken() *ServiceToken {
	return c.token
}

// GetToken obtains a new service token from tokensmith
func (c *ServiceClient) GetToken(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/v1/service/token", c.tokensmithURL), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add service authentication headers
	req.Header.Set("X-Service-Name", c.serviceName)
	req.Header.Set("X-Service-ID", c.serviceID)
	req.Header.Set("X-Instance-ID", c.instanceID)
	req.Header.Set("X-Cluster-ID", c.clusterID)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to get token: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var token ServiceToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	c.token = &token
	return nil
}

// RefreshTokenIfNeeded checks if the token needs to be refreshed and refreshes it if necessary
func (c *ServiceClient) RefreshTokenIfNeeded(ctx context.Context) error {
	if c.token == nil || time.Until(c.token.ExpiresAt) < 5*time.Minute {
		return c.GetToken(ctx)
	}
	return nil
}

// CallTargetService demonstrates using the token to call another service
func (c *ServiceClient) CallTargetService(ctx context.Context, targetURL string) error {
	if err := c.RefreshTokenIfNeeded(ctx); err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token.Token))

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call target service: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("target service returned error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	fmt.Printf("Target service response: %s\n", string(body))
	return nil
}

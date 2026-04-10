// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrMissingBootstrapToken = errors.New("missing bootstrap token")
	ErrMissingRefreshToken   = errors.New("missing refresh token")
	ErrEmptyTokenSmithURL    = errors.New("tokensmith URL is required")
	ErrEmptyTargetService    = errors.New("target service is required")
	ErrRefreshTokenExpired   = errors.New("refresh token expired")
)

// ServiceToken represents the token response from tokensmith
type ServiceToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ServiceClient handles communication with the tokensmith service
type ServiceClient struct {
	client                  *http.Client
	tokensmithURL           string
	serviceName             string
	serviceID               string
	targetService           string
	bootstrapToken          string
	refreshBefore           time.Duration
	autoInterval            time.Duration
	bootstrapMaxAttempts    int
	bootstrapInitialBackoff time.Duration
	bootstrapMaxBackoff     time.Duration
	token                   *ServiceToken
	refreshToken            string
	refreshExpiresAt        time.Time
	instanceID              string
	clusterID               string

	mu               sync.RWMutex
	lastErrorMessage atomic.Value
	refreshSuccesses uint64
	refreshFailures  uint64
	lastRefreshUnix  int64
	lastSuccessUnix  int64
}

// ServiceClientStats summarizes token refresh lifecycle behavior.
type ServiceClientStats struct {
	RefreshSuccesses uint64
	RefreshFailures  uint64
	LastError        string
	LastRefresh      time.Time
	LastSuccess      time.Time
	HasToken         bool
	ExpiresAt        time.Time
	HasRefreshToken  bool
	RefreshExpiresAt time.Time
}

// ServiceClientOption applies optional configuration to ServiceClient.
type ServiceClientOption func(*ServiceClient)

// WithHTTPClient configures a custom HTTP client.
func WithHTTPClient(httpClient *http.Client) ServiceClientOption {
	return func(c *ServiceClient) {
		if httpClient != nil {
			c.client = httpClient
		}
	}
}

// WithBootstrapToken sets a bootstrap token directly instead of reading the environment.
func WithBootstrapToken(token string) ServiceClientOption {
	return func(c *ServiceClient) {
		c.bootstrapToken = strings.TrimSpace(token)
	}
}

// WithTargetService records the intended target service for this client. This value is
// client-local metadata used for validation and logging; the server determines the actual
// authorized audience from the bootstrap token policy and ignores any client hint.
func WithTargetService(service string) ServiceClientOption {
	return func(c *ServiceClient) {
		c.targetService = strings.TrimSpace(service)
	}
}

// WithRefreshBefore sets the threshold when an existing token should be refreshed.
func WithRefreshBefore(refreshBefore time.Duration) ServiceClientOption {
	return func(c *ServiceClient) {
		if refreshBefore > 0 {
			c.refreshBefore = refreshBefore
		}
	}
}

// WithAutoRefreshInterval sets the periodic refresh check interval.
func WithAutoRefreshInterval(interval time.Duration) ServiceClientOption {
	return func(c *ServiceClient) {
		if interval > 0 {
			c.autoInterval = interval
		}
	}
}

// WithBootstrapMaxAttempts sets the maximum number of Initialize retry attempts.
func WithBootstrapMaxAttempts(maxAttempts int) ServiceClientOption {
	return func(c *ServiceClient) {
		if maxAttempts > 0 {
			c.bootstrapMaxAttempts = maxAttempts
		}
	}
}

// WithBootstrapInitialBackoff sets the initial retry backoff used by Initialize.
func WithBootstrapInitialBackoff(backoff time.Duration) ServiceClientOption {
	return func(c *ServiceClient) {
		if backoff > 0 {
			c.bootstrapInitialBackoff = backoff
		}
	}
}

// WithBootstrapMaxBackoff sets the capped retry backoff used by Initialize.
func WithBootstrapMaxBackoff(backoff time.Duration) ServiceClientOption {
	return func(c *ServiceClient) {
		if backoff > 0 {
			c.bootstrapMaxBackoff = backoff
		}
	}
}

// NewServiceClient creates a new service client
func NewServiceClient(tokensmithURL, serviceName, serviceID, instanceID, clusterID string) *ServiceClient {
	return NewServiceClientWithOptions(tokensmithURL, serviceName, serviceID, instanceID, clusterID)
}

// NewServiceClientWithOptions creates a new service client with optional lifecycle configuration.
func NewServiceClientWithOptions(tokensmithURL, serviceName, serviceID, instanceID, clusterID string, opts ...ServiceClientOption) *ServiceClient {
	client := &ServiceClient{
		client:                  &http.Client{Timeout: 10 * time.Second},
		tokensmithURL:           strings.TrimRight(strings.TrimSpace(tokensmithURL), "/"),
		serviceName:             serviceName,
		serviceID:               serviceID,
		instanceID:              instanceID,
		clusterID:               clusterID,
		refreshBefore:           5 * time.Minute,
		autoInterval:            time.Minute,
		bootstrapMaxAttempts:    5,
		bootstrapInitialBackoff: time.Second,
		bootstrapMaxBackoff:     15 * time.Second,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(client)
		}
	}
	if client.targetService == "" {
		client.targetService = strings.TrimSpace(serviceName)
	}
	return client
}

// GetServiceToken returns the service token
func (c *ServiceClient) GetServiceToken() *ServiceToken {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.token == nil {
		return nil
	}
	copy := *c.token
	return &copy
}

// Initialize performs a blocking startup token exchange.
func (c *ServiceClient) Initialize(ctx context.Context) error {
	if err := c.validateConfig(); err != nil {
		return err
	}

	var lastErr error
	backoff := c.bootstrapInitialBackoff
	if backoff <= 0 {
		backoff = time.Second
	}

	for attempt := 1; attempt <= c.bootstrapMaxAttempts; attempt++ {
		if err := c.GetToken(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}

		if attempt == c.bootstrapMaxAttempts {
			break
		}

		wait := backoff
		if c.bootstrapMaxBackoff > 0 && wait > c.bootstrapMaxBackoff {
			wait = c.bootstrapMaxBackoff
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("bootstrap token exchange canceled: %w", ctx.Err())
		case <-timer.C:
		}

		if c.bootstrapMaxBackoff > 0 && backoff < c.bootstrapMaxBackoff {
			backoff *= 2
			if backoff > c.bootstrapMaxBackoff {
				backoff = c.bootstrapMaxBackoff
			}
		}
	}

	return fmt.Errorf("bootstrap token exchange failed after %d attempts: %w", c.bootstrapMaxAttempts, lastErr)
}

// StartAutoRefresh periodically refreshes tokens until context cancellation.
func (c *ServiceClient) StartAutoRefresh(ctx context.Context) {
	ticker := time.NewTicker(c.autoInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.isRefreshTokenExpired() {
				wrapped := fmt.Errorf("%w", ErrRefreshTokenExpired)
				c.recordClientRefreshFailure(wrapped)
				return
			}

			err := c.RefreshTokenIfNeeded(ctx)
			if errors.Is(err, ErrRefreshTokenExpired) {
				return
			}
		}
	}
}

// Stats returns current refresh and token state diagnostics.
func (c *ServiceClient) Stats() ServiceClientStats {
	stats := ServiceClientStats{
		RefreshSuccesses: atomic.LoadUint64(&c.refreshSuccesses),
		RefreshFailures:  atomic.LoadUint64(&c.refreshFailures),
	}
	if msg, _ := c.lastErrorMessage.Load().(string); msg != "" {
		stats.LastError = msg
	}
	if unix := atomic.LoadInt64(&c.lastRefreshUnix); unix > 0 {
		stats.LastRefresh = time.Unix(unix, 0).UTC()
	}
	if unix := atomic.LoadInt64(&c.lastSuccessUnix); unix > 0 {
		stats.LastSuccess = time.Unix(unix, 0).UTC()
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	stats.HasToken = c.token != nil
	if c.token != nil {
		stats.ExpiresAt = c.token.ExpiresAt
	}
	stats.HasRefreshToken = strings.TrimSpace(c.refreshToken) != ""
	if !c.refreshExpiresAt.IsZero() {
		stats.RefreshExpiresAt = c.refreshExpiresAt
	}

	return stats
}

// GetToken obtains a new service token from tokensmith
func (c *ServiceClient) GetToken(ctx context.Context) error {
	if err := c.validateConfig(); err != nil {
		return err
	}

	c.mu.RLock()
	hasRefreshToken := strings.TrimSpace(c.refreshToken) != ""
	refreshExpiresAt := c.refreshExpiresAt
	c.mu.RUnlock()

	if hasRefreshToken {
		if !refreshExpiresAt.IsZero() && time.Now().After(refreshExpiresAt) {
			wrapped := fmt.Errorf("%w", ErrRefreshTokenExpired)
			c.recordClientRefreshFailure(wrapped)
			return wrapped
		}
		return c.requestServiceToken(ctx, "refresh")
	}

	return c.requestServiceToken(ctx, "bootstrap")
}

func (c *ServiceClient) requestServiceToken(ctx context.Context, grantType string) error {
	// Build RFC 8693 / RFC 6749 form-encoded request for /oauth/token
	form := url.Values{}

	switch grantType {
	case "bootstrap":
		bootstrapToken := c.currentBootstrapToken()
		if bootstrapToken == "" {
			return fmt.Errorf("%w: set %s or WithBootstrapToken", ErrMissingBootstrapToken, BootstrapTokenEnvVar)
		}
		form.Set("grant_type", GrantTypeTokenExchange)
		form.Set("subject_token", bootstrapToken)
		form.Set("subject_token_type", BootstrapTokenTypeRFC8693)
	case "refresh":
		c.mu.RLock()
		refreshToken := strings.TrimSpace(c.refreshToken)
		c.mu.RUnlock()
		if refreshToken == "" {
			return ErrMissingRefreshToken
		}
		form.Set("grant_type", GrantTypeRefreshTokenRFC8693)
		form.Set("refresh_token", refreshToken)
	default:
		return fmt.Errorf("unsupported internal grant type: %s", grantType)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/oauth/token", c.tokensmithURL), strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	now := time.Now().UTC()
	atomic.StoreInt64(&c.lastRefreshUnix, now.Unix())

	resp, err := c.client.Do(req)
	if err != nil {
		atomic.AddUint64(&c.refreshFailures, 1)
		wrapped := fmt.Errorf("failed to get token: %w", err)
		c.lastErrorMessage.Store(wrapped.Error())
		return wrapped
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		atomic.AddUint64(&c.refreshFailures, 1)
		wrapped := fmt.Errorf("failed to get token: status=%d, body=%s", resp.StatusCode, string(body))
		c.lastErrorMessage.Store(wrapped.Error())
		return wrapped
	}

	var oauthResp OAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&oauthResp); err != nil {
		atomic.AddUint64(&c.refreshFailures, 1)
		wrapped := fmt.Errorf("failed to decode token response: %w", err)
		c.lastErrorMessage.Store(wrapped.Error())
		return wrapped
	}
	if strings.TrimSpace(oauthResp.AccessToken) == "" || oauthResp.ExpiresIn <= 0 {
		atomic.AddUint64(&c.refreshFailures, 1)
		wrapped := fmt.Errorf("failed to decode token response: missing access_token or expires_in")
		c.lastErrorMessage.Store(wrapped.Error())
		return wrapped
	}
	if strings.TrimSpace(oauthResp.RefreshToken) == "" || oauthResp.RefreshExpiresIn <= 0 {
		atomic.AddUint64(&c.refreshFailures, 1)
		wrapped := fmt.Errorf("failed to decode token response: missing refresh_token or refresh_expires_in")
		c.lastErrorMessage.Store(wrapped.Error())
		return wrapped
	}

	expiresAt := now.Add(time.Duration(oauthResp.ExpiresIn) * time.Second)
	refreshExpiresAt := now.Add(time.Duration(oauthResp.RefreshExpiresIn) * time.Second)

	c.mu.Lock()
	c.token = &ServiceToken{Token: oauthResp.AccessToken, ExpiresAt: expiresAt}
	c.refreshToken = strings.TrimSpace(oauthResp.RefreshToken)
	c.refreshExpiresAt = refreshExpiresAt
	c.mu.Unlock()

	atomic.AddUint64(&c.refreshSuccesses, 1)
	atomic.StoreInt64(&c.lastSuccessUnix, now.Unix())
	c.lastErrorMessage.Store("")
	return nil
}

// RefreshTokenIfNeeded checks if the token needs to be refreshed and refreshes it if necessary
func (c *ServiceClient) RefreshTokenIfNeeded(ctx context.Context) error {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	if token == nil || time.Until(token.ExpiresAt) < c.refreshBefore {
		return c.GetToken(ctx)
	}
	return nil
}

func (c *ServiceClient) recordClientRefreshFailure(err error) {
	atomic.StoreInt64(&c.lastRefreshUnix, time.Now().UTC().Unix())
	atomic.AddUint64(&c.refreshFailures, 1)
	c.lastErrorMessage.Store(err.Error())
}

func (c *ServiceClient) isRefreshTokenExpired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if strings.TrimSpace(c.refreshToken) == "" || c.refreshExpiresAt.IsZero() {
		return false
	}

	return time.Now().After(c.refreshExpiresAt)
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

	token := c.GetServiceToken()
	if token == nil {
		return fmt.Errorf("failed to call target service: missing service token")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.Token))

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

func (c *ServiceClient) currentBootstrapToken() string {
	if c.bootstrapToken != "" {
		return c.bootstrapToken
	}
	return strings.TrimSpace(os.Getenv(BootstrapTokenEnvVar))
}

func (c *ServiceClient) validateConfig() error {
	if strings.TrimSpace(c.tokensmithURL) == "" {
		return ErrEmptyTokenSmithURL
	}
	if strings.TrimSpace(c.targetService) == "" {
		return ErrEmptyTargetService
	}
	return nil
}

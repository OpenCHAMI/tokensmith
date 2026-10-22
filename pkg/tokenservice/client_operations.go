package tokenservice

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Initialize performs a blocking startup token exchange.
func (c *ServiceClient) Initialize(ctx context.Context) error {
	if err := c.validateConfig(); err != nil {
		return c.recordGetTokenFailure(err)
	}
	if err := ctx.Err(); err != nil {
		return c.recordGetTokenFailure(err)
	}
	if c.initializeUsesSingleLifecycle() {
		return c.runTokenLifecycle(ctx)
	}
	return c.runLifecycle(ctx, c.initializeToken)
}

func (c *ServiceClient) initializeUsesSingleLifecycle() bool {
	c.mu.RLock()
	hasRefreshToken := c.refreshToken != ""
	c.mu.RUnlock()
	_, _, identityConfigured := c.serviceIdentityPaths()
	return hasRefreshToken || identityConfigured
}

func (c *ServiceClient) initializeToken(ctx context.Context) error {
	_, _, useMTLS := c.readableServiceIdentityPaths()
	backoff, lastErr := c.bootstrapInitialBackoff, error(nil)
	if backoff <= 0 {
		backoff = time.Second
	}
	for attempt := 1; attempt <= c.bootstrapMaxAttempts; attempt++ {
		if err := c.requestLifecycleToken(ctx); err == nil {
			return nil
		} else {
			lastErr = err
			if useMTLS || !isGuaranteedPreSendBootstrapError(err) || attempt == c.bootstrapMaxAttempts {
				break
			}
		}
		wait := min(backoff, c.bootstrapMaxBackoff)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("bootstrap token exchange canceled: %w", ctx.Err())
		case <-timer.C:
		}
		backoff = min(backoff*2, c.bootstrapMaxBackoff)
	}
	return fmt.Errorf("bootstrap token exchange failed after %d attempts: %w", c.bootstrapMaxAttempts, lastErr)
}

// StartAutoRefresh polls the shared refresh path until ctx is canceled.
func (c *ServiceClient) StartAutoRefresh(ctx context.Context) {
	ticker := time.NewTicker(c.autoInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := c.refreshTokenIfNeeded(ctx, true)
			if errors.Is(err, ErrRefreshTokenExpired) || (err != nil && c.isRefreshTokenExpired()) {
				return
			}
		}
	}
}

// GetToken ensures that a valid service token is available.
func (c *ServiceClient) GetToken(ctx context.Context) error {
	if err := c.validateConfig(); err != nil {
		return c.recordGetTokenFailure(err)
	}
	if err := ctx.Err(); err != nil {
		return c.recordGetTokenFailure(err)
	}
	return c.runConditionalTokenLifecycle(ctx)
}

// ForceRefresh acquires or rotates a token even while the current token is fresh.
func (c *ServiceClient) ForceRefresh(ctx context.Context) error {
	if err := c.validateConfig(); err != nil {
		return c.recordGetTokenFailure(err)
	}
	if err := ctx.Err(); err != nil {
		return c.recordGetTokenFailure(err)
	}
	return c.runTokenLifecycle(ctx)
}

// RefreshTokenIfNeeded returns nil when the cached access token is still fresh.
func (c *ServiceClient) RefreshTokenIfNeeded(ctx context.Context) error {
	return c.refreshTokenIfNeeded(ctx, false)
}

func (c *ServiceClient) refreshTokenIfNeeded(ctx context.Context, stopOnBootstrapTerminalExpiry bool) error {
	if !c.accessTokenNeedsRefresh() {
		if stopOnBootstrapTerminalExpiry && c.isRefreshTokenExpired() && c.currentServiceIdentityCertPath() == "" && c.currentServiceIdentityKeyPath() == "" {
			c.recordClientRefreshFailure(ErrRefreshTokenExpired)
			return ErrRefreshTokenExpired
		}
		return nil
	}
	return c.runConditionalTokenLifecycle(ctx)
}

func (c *ServiceClient) recordGetTokenFailure(err error) error {
	c.recordLifecycleResult(err)
	return err
}

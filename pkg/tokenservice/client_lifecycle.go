// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type lifecycleOperation struct {
	done chan struct{}
	err  error
}

func (c *ServiceClient) runTokenLifecycle(ctx context.Context) error {
	op, owner := c.joinLifecycle()
	if !owner {
		return c.waitForLifecycle(ctx, op)
	}

	if err := ctx.Err(); err != nil {
		c.finishLifecycle(op, err)
		return err
	}

	err := c.requestLifecycleToken(ctx)
	c.finishLifecycle(op, err)
	return err
}

func (c *ServiceClient) joinLifecycle() (*lifecycleOperation, bool) {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()

	if c.lifecycle != nil {
		return c.lifecycle, false
	}

	op := &lifecycleOperation{done: make(chan struct{})}
	c.lifecycle = op
	return op, true
}

func (c *ServiceClient) waitForLifecycle(ctx context.Context, op *lifecycleOperation) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-op.done:
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	if op.err != nil {
		return op.err
	}
	if !c.accessTokenNeedsRefresh() {
		return nil
	}
	return nil
}

func (c *ServiceClient) finishLifecycle(op *lifecycleOperation, err error) {
	c.lifecycleMu.Lock()
	op.err = err
	if c.lifecycle == op {
		c.lifecycle = nil
	}
	c.lifecycleMu.Unlock()
	close(op.done)
}

func (c *ServiceClient) requestLifecycleToken(ctx context.Context) error {
	if !c.accessTokenNeedsRefresh() {
		return nil
	}

	c.mu.RLock()
	hasRefreshToken := strings.TrimSpace(c.refreshToken) != ""
	refreshExpiresAt := c.refreshExpiresAt
	c.mu.RUnlock()

	if hasRefreshToken {
		if !refreshExpiresAt.IsZero() && time.Now().After(refreshExpiresAt) {
			certPath := c.currentServiceIdentityCertPath()
			keyPath := c.currentServiceIdentityKeyPath()
			if certPath != "" && keyPath != "" {
				if err := c.requestServiceIdentitySession(ctx, certPath, keyPath); err != nil {
					return fmt.Errorf("service identity reauthentication: %w", err)
				}
				return nil
			}
			c.recordClientRefreshFailure(ErrRefreshTokenExpired)
			return ErrRefreshTokenExpired
		}
		return c.requestServiceToken(ctx, "refresh")
	}

	if certPath, keyPath, ok := c.readableServiceIdentityPaths(); ok {
		return c.requestServiceIdentitySession(ctx, certPath, keyPath)
	}

	return c.requestServiceToken(ctx, "bootstrap")
}

func validateServiceIdentityURL(rawURL string) error {
	endpoint, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(endpoint.Scheme, "https") || endpoint.Host == "" {
		return fmt.Errorf("%w: service identity session requires an HTTPS TokenSmith URL", ErrTLSClientMaterial)
	}
	return nil
}

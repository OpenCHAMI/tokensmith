// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type lifecycleOperation struct {
	done chan struct{}
	err  error
}

var errLifecycleNoop = errors.New("lifecycle conditional no-op")

func (c *ServiceClient) runTokenLifecycle(ctx context.Context) error {
	return c.runLifecycle(ctx, c.requestLifecycleToken)
}

func (c *ServiceClient) runConditionalTokenLifecycle(ctx context.Context) error {
	if !c.accessTokenNeedsRefresh() {
		return nil
	}
	return c.runLifecycle(ctx, func(operationContext context.Context) error {
		if !c.accessTokenNeedsRefresh() {
			return errLifecycleNoop
		}
		return c.requestLifecycleToken(operationContext)
	})
}

func (c *ServiceClient) runLifecycle(ctx context.Context, request func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	op, owner := c.joinLifecycle()
	if owner {
		operationContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.lifecycleTimeout)
		go func() {
			defer cancel()
			c.finishLifecycle(op, request(operationContext))
		}()
	}
	return c.waitForLifecycle(ctx, op)
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
		if errors.Is(op.err, errLifecycleNoop) {
			return nil
		}
		return op.err
	}
	if !c.accessTokenNeedsRefresh() {
		return nil
	}
	return nil
}

func (c *ServiceClient) finishLifecycle(op *lifecycleOperation, err error) {
	if !errors.Is(err, errLifecycleNoop) {
		c.recordLifecycleResult(err)
	}
	c.lifecycleMu.Lock()
	op.err = err
	close(op.done)
	if c.lifecycle == op {
		c.lifecycle = nil
	}
	c.lifecycleMu.Unlock()
}

func (c *ServiceClient) requestLifecycleToken(ctx context.Context) error {
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
			return ErrRefreshTokenExpired
		}
		return c.requestServiceToken(ctx, "refresh")
	}

	if certPath, keyPath, configured := c.serviceIdentityPaths(); configured {
		if err := validateServiceIdentityMaterial(certPath, keyPath); err != nil {
			return err
		}
		return c.requestServiceIdentitySession(ctx, certPath, keyPath)
	}

	return c.requestServiceToken(ctx, "bootstrap")
}

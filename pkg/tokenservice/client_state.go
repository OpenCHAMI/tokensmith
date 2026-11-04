package tokenservice

import (
	"strings"
	"sync/atomic"
	"time"
)

// GetServiceToken returns the service token.
func (c *ServiceClient) GetServiceToken() *ServiceToken {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.token == nil {
		return nil
	}
	copy := *c.token
	return &copy
}

// Stats returns current refresh and token state diagnostics.
func (c *ServiceClient) Stats() ServiceClientStats {
	stats := ServiceClientStats{RefreshSuccesses: atomic.LoadUint64(&c.refreshSuccesses), RefreshFailures: atomic.LoadUint64(&c.refreshFailures)}
	if message, _ := c.lastErrorMessage.Load().(string); message != "" {
		stats.LastError = message
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
	stats.RefreshExpiresAt = c.refreshExpiresAt
	return stats
}

func (c *ServiceClient) accessTokenNeedsRefresh() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token == nil || time.Until(c.token.ExpiresAt) < c.refreshBefore
}

func (c *ServiceClient) isRefreshTokenExpired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return strings.TrimSpace(c.refreshToken) != "" && !c.refreshExpiresAt.IsZero() && time.Now().After(c.refreshExpiresAt)
}

func (c *ServiceClient) recordClientRefreshFailure(err error) {
	atomic.StoreInt64(&c.lastRefreshUnix, time.Now().UTC().Unix())
	atomic.AddUint64(&c.refreshFailures, 1)
	c.lastErrorMessage.Store(err.Error())
}

func (c *ServiceClient) recordLifecycleResult(err error) {
	now := time.Now().UTC()
	atomic.StoreInt64(&c.lastRefreshUnix, now.Unix())
	if err != nil {
		atomic.AddUint64(&c.refreshFailures, 1)
		c.lastErrorMessage.Store(err.Error())
		return
	}
	atomic.AddUint64(&c.refreshSuccesses, 1)
	atomic.StoreInt64(&c.lastSuccessUnix, now.Unix())
	c.lastErrorMessage.Store("")
}

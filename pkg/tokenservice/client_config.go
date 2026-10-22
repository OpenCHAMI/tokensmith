package tokenservice

import (
	"net/http"
	"strings"
	"time"
)

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
	return func(c *ServiceClient) { c.bootstrapToken = strings.TrimSpace(token) }
}

// WithServiceIdentityCertKey configures mTLS client certificate material.
func WithServiceIdentityCertKey(certPath, keyPath string) ServiceClientOption {
	return func(c *ServiceClient) {
		c.serviceIdentityCertPath = strings.TrimSpace(certPath)
		c.serviceIdentityKeyPath = strings.TrimSpace(keyPath)
	}
}

// WithTargetService records the intended target service for this client.
func WithTargetService(service string) ServiceClientOption {
	return func(c *ServiceClient) { c.targetService = strings.TrimSpace(service) }
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

// WithLifecycleTimeout limits a shared token lifecycle operation.
func WithLifecycleTimeout(timeout time.Duration) ServiceClientOption {
	return func(c *ServiceClient) {
		if timeout > 0 {
			c.lifecycleTimeout = timeout
		}
	}
}

// NewServiceClient creates a new service client with the default lifecycle settings.
func NewServiceClient(tokensmithURL, serviceName, serviceID, instanceID, clusterID string) *ServiceClient {
	return NewServiceClientWithOptions(tokensmithURL, serviceName, serviceID, instanceID, clusterID)
}

// NewServiceClientWithOptions creates a new service client with optional lifecycle configuration.
func NewServiceClientWithOptions(tokensmithURL, serviceName, serviceID, instanceID, clusterID string, opts ...ServiceClientOption) *ServiceClient {
	client := &ServiceClient{client: &http.Client{Timeout: 10 * time.Second}, tokensmithURL: strings.TrimRight(strings.TrimSpace(tokensmithURL), "/"), serviceName: serviceName, serviceID: serviceID, instanceID: instanceID, clusterID: clusterID, refreshBefore: 5 * time.Minute, autoInterval: time.Minute, bootstrapMaxAttempts: 5, bootstrapInitialBackoff: time.Second, bootstrapMaxBackoff: 15 * time.Second, lifecycleTimeout: 10 * time.Second}
	for _, option := range opts {
		if option != nil {
			option(client)
		}
	}
	if client.targetService == "" {
		client.targetService = strings.TrimSpace(serviceName)
	}
	return client
}

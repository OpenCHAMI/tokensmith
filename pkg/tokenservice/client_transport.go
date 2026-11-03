package tokenservice

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func (c *ServiceClient) currentBootstrapToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.bootstrapBurned {
		return ""
	}
	if c.bootstrapToken != "" {
		return c.bootstrapToken
	}
	return strings.TrimSpace(os.Getenv(BootstrapTokenEnvVar))
}

func (c *ServiceClient) currentServiceIdentityCertPath() string {
	if c.serviceIdentityCertPath != "" {
		return c.serviceIdentityCertPath
	}
	return strings.TrimSpace(os.Getenv(ServiceIdentityCertEnvVar))
}

func (c *ServiceClient) currentServiceIdentityKeyPath() string {
	if c.serviceIdentityKeyPath != "" {
		return c.serviceIdentityKeyPath
	}
	return strings.TrimSpace(os.Getenv(ServiceIdentityKeyEnvVar))
}

func (c *ServiceClient) readableServiceIdentityPaths() (string, string, bool) {
	certPath, keyPath, configured := c.serviceIdentityPaths()
	if !configured {
		return "", "", false
	}
	if validateServiceIdentityMaterial(certPath, keyPath) != nil {
		return "", "", false
	}
	return certPath, keyPath, true
}

func (c *ServiceClient) serviceIdentityPaths() (string, string, bool) {
	certPath, keyPath := c.currentServiceIdentityCertPath(), c.currentServiceIdentityKeyPath()
	return certPath, keyPath, certPath != "" || keyPath != ""
}

func validateServiceIdentityMaterial(certPath, keyPath string) error {
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("%w: both %s and %s must be set together", ErrTLSClientMaterial, ServiceIdentityCertEnvVar, ServiceIdentityKeyEnvVar)
	}
	if info, err := os.Stat(certPath); err != nil || info.IsDir() {
		return fmt.Errorf("%w: certificate path is unreadable", ErrTLSClientMaterial)
	}
	if info, err := os.Stat(keyPath); err != nil || info.IsDir() {
		return fmt.Errorf("%w: key path is unreadable", ErrTLSClientMaterial)
	}
	return nil
}

func (c *ServiceClient) clientWithMutualTLS(certPath, keyPath string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to load cert/key pair: %v", ErrTLSClientMaterial, err)
	}
	transport, err := cloneTransport(c.client.Transport)
	if err != nil {
		return nil, err
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.Certificates = append([]tls.Certificate(nil), cert)
	copy := *c.client
	copy.Transport = transport
	return &copy, nil
}

func cloneTransport(roundTripper http.RoundTripper) (*http.Transport, error) {
	if roundTripper == nil {
		return http.DefaultTransport.(*http.Transport).Clone(), nil
	}
	transport, ok := roundTripper.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("%w: custom transport must be *http.Transport", ErrTLSClientMaterial)
	}
	return transport.Clone(), nil
}

func (c *ServiceClient) validateConfig() error {
	if strings.TrimSpace(c.tokensmithURL) == "" {
		return ErrEmptyTokenSmithURL
	}
	if strings.TrimSpace(c.targetService) == "" {
		return ErrEmptyTargetService
	}
	if certPath, keyPath, configured := c.serviceIdentityPaths(); configured {
		if err := validateServiceIdentityMaterial(certPath, keyPath); err != nil {
			return err
		}
	}
	return nil
}

func validateServiceIdentityURL(rawURL string) error {
	endpoint, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(endpoint.Scheme, "https") || endpoint.Host == "" {
		return fmt.Errorf("%w: service identity session requires an HTTPS TokenSmith URL", ErrTLSClientMaterial)
	}
	return nil
}

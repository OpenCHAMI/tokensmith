// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTokenService_UsesOIDCCABundleForUpstreamTLS(t *testing.T) {
	server := newOIDCTLSTestServer(t)
	caPath := writeServerCABundle(t, server)
	service := newOIDCTLSService(t, Config{
		OIDCIssuerURL:    server.URL,
		OIDCClientID:     "tokensmith",
		OIDCClientSecret: "secret",
		OIDCCAPath:       caPath,
	})

	metadata, err := service.OIDCProvider.GetProviderMetadata(context.Background())

	require.NoError(t, err)
	assert.Equal(t, server.URL, metadata.Issuer)
	assert.Equal(t, server.URL+"/token/introspect", metadata.IntrospectionEndpoint)
}

func TestNewTokenService_UsesOIDCIntrospectionEndpointOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"` + r.Host + `","jwks_uri":"http://` + r.Host + `/jwks"}`))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	service := newOIDCTLSService(t, Config{
		OIDCIssuerURL:             server.URL,
		OIDCClientID:              "tokensmith",
		OIDCClientSecret:          "secret",
		OIDCIntrospectionEndpoint: server.URL + "/override/introspect",
	})

	metadata, err := service.OIDCProvider.GetProviderMetadata(context.Background())

	require.NoError(t, err)
	assert.Equal(t, server.URL+"/override/introspect", metadata.IntrospectionEndpoint)
}

func TestNewTokenService_RejectsInvalidOIDCCABundle(t *testing.T) {
	invalidCAPath := filepath.Join(t.TempDir(), "invalid-ca.pem")
	require.NoError(t, os.WriteFile(invalidCAPath, []byte("not a certificate"), 0o600))
	keyManager := keys.NewKeyManager()
	require.NoError(t, keyManager.GenerateRSAKeyPair())

	service, err := NewTokenService(keyManager, Config{
		Issuer:           "http://tokensmith.test",
		ClusterID:        "cluster-test",
		OpenCHAMIID:      "openchami-test",
		OIDCIssuerURL:    "https://keycloak.example/realms/csm",
		OIDCClientID:     "tokensmith",
		OIDCClientSecret: "secret",
		OIDCCAPath:       invalidCAPath,
	})

	require.Error(t, err)
	assert.Nil(t, service)
	assert.Contains(t, err.Error(), "upstream OIDC CA bundle")
}

func TestApplyOIDCProviderConfig_UsesOIDCCABundleForUpstreamTLS(t *testing.T) {
	server := newOIDCTLSTestServer(t)
	caPath := writeServerCABundle(t, server)
	service := newOIDCTLSService(t, Config{
		OIDCClientSecret: "secret",
		OIDCCAPath:       caPath,
	})

	status, oidcStatus, err := service.ApplyOIDCProviderConfig(context.Background(), OIDCProviderConfigUpdate{
		IssuerURL: server.URL,
		ClientID:  "tokensmith",
	})

	require.NoError(t, err)
	assert.Equal(t, "created", status)
	assert.True(t, oidcStatus.Configured)
	assert.Equal(t, server.URL, oidcStatus.IssuerURL)
}

func TestApplyOIDCProviderConfig_PreservesOIDCIntrospectionEndpointOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"` + r.Host + `","jwks_uri":"http://` + r.Host + `/jwks"}`))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	service := newOIDCTLSService(t, Config{
		OIDCClientSecret:          "secret",
		OIDCIntrospectionEndpoint: server.URL + "/override/introspect",
	})

	status, oidcStatus, err := service.ApplyOIDCProviderConfig(context.Background(), OIDCProviderConfigUpdate{
		IssuerURL: server.URL,
		ClientID:  "tokensmith",
	})

	require.NoError(t, err)
	assert.Equal(t, "created", status)
	assert.True(t, oidcStatus.Configured)
	metadata, err := service.OIDCProvider.GetProviderMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, server.URL+"/override/introspect", metadata.IntrospectionEndpoint)
}

func TestApplyOIDCProviderConfig_FailsWithoutOIDCCABundleForUpstreamTLS(t *testing.T) {
	server := newOIDCTLSTestServer(t)
	service := newOIDCTLSService(t, Config{
		OIDCClientSecret: "secret",
	})

	status, _, err := service.ApplyOIDCProviderConfig(context.Background(), OIDCProviderConfigUpdate{
		IssuerURL: server.URL,
		ClientID:  "tokensmith",
	})

	require.Error(t, err)
	assert.Empty(t, status)
	assert.Contains(t, err.Error(), "OIDC provider validation failed")
}

func TestNewTokenService_OIDCCABundleDoesNotConfigureServiceIdentityMTLS(t *testing.T) {
	server := newOIDCTLSTestServer(t)
	caPath := writeServerCABundle(t, server)
	service := newOIDCTLSService(t, Config{
		OIDCIssuerURL:    server.URL,
		OIDCClientID:     "tokensmith",
		OIDCClientSecret: "secret",
		OIDCCAPath:       caPath,
	})

	assert.Nil(t, service.serviceIdentityCAPool)
	assert.NotNil(t, service.oidcHTTPClient)
}

func TestStart_ServiceIdentityCAErrorNamesInboundMTLS(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyManager := keys.NewKeyManager()
	require.NoError(t, keyManager.SetKeyPair(privateKey, &privateKey.PublicKey))
	caPEM, _ := generateClientIdentityCertificate(t, "boot-service")
	caPath := filepath.Join(t.TempDir(), "service-identity-ca.pem")
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	service, err := NewTokenService(keyManager, Config{Issuer: "http://tokensmith.test", ClusterID: "cluster-a", OpenCHAMIID: "openchami-a", ServiceIdentityCAPath: caPath})
	require.NoError(t, err)
	err = service.Start(0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--service-identity-ca")
	assert.Contains(t, err.Error(), "TOKENSMITH_SERVICE_IDENTITY_CA")
	assert.Contains(t, err.Error(), "--oidc-ca only for outbound upstream OIDC TLS")
}

func newOIDCTLSService(t *testing.T, config Config) *TokenService {
	t.Helper()
	keyManager := keys.NewKeyManager()
	require.NoError(t, keyManager.GenerateRSAKeyPair())
	if config.Issuer == "" {
		config.Issuer = "http://tokensmith.test"
	}
	if config.ClusterID == "" {
		config.ClusterID = "cluster-test"
	}
	if config.OpenCHAMIID == "" {
		config.OpenCHAMIID = "openchami-test"
	}
	service, err := NewTokenService(keyManager, config)
	require.NoError(t, err)
	return service
}

func newOIDCTLSTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"https://` + r.Host + `","token_introspection_endpoint":"https://` + r.Host + `/token/introspect","jwks_uri":"https://` + r.Host + `/jwks"}`))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		case "/token/introspect":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"active":true,"username":"csm-admin","exp":4102444800,"iat":1700000000,"claims":{"sub":"csm-admin"},"token_type":"Bearer"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func writeServerCABundle(t *testing.T, server *httptest.Server) string {
	t.Helper()
	caPath := filepath.Join(t.TempDir(), "upstream-oidc-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	require.NotEmpty(t, certPEM)
	require.NoError(t, os.WriteFile(caPath, certPEM, 0o600))
	return caPath
}

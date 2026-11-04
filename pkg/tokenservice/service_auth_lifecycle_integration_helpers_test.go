// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"net/http"
	"net/http/httptest"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

const lifecycleBootstrapSecret = "bootstrap-lifecycle-secret"

type serviceAuthLifecycleFixture struct {
	service          *TokenService
	server           *httptest.Server
	root             string
	certPath         string
	keyPath          string
	certPEM          []byte
	keyPEM           []byte
	logs             *synchronizedLogBuffer
	bootstrapCalls   atomic.Int32
	sessionCalls     atomic.Int32
	blockSession     atomic.Bool
	transformFailure atomic.Bool
	failureBody      string
	sessionStarted   chan struct{}
	sessionRelease   chan struct{}
	sessionRequests  chan struct{}
	startOnce        sync.Once
}

func newServiceAuthLifecycleFixture(t *testing.T, withIdentityPolicy bool) *serviceAuthLifecycleFixture {
	t.Helper()
	root := t.TempDir()
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)
	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	require.NoError(t, os.Remove(certPath))
	require.NoError(t, os.Remove(keyPath))
	caPath := filepath.Join(root, "service-identity-ca.pem")
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	keyManager := keys.NewKeyManager()
	require.NoError(t, keyManager.GenerateRSAKeyPair())
	service, err := NewTokenService(keyManager, Config{
		Issuer:                         "https://tokensmith.integration.test",
		ClusterID:                      "cluster-integration",
		OpenCHAMIID:                    "openchami-integration",
		RFC8693BootstrapStorePath:      filepath.Join(root, "bootstrap"),
		RFC8693RefreshStorePath:        filepath.Join(root, "refresh"),
		ServiceIdentityCAPath:          caPath,
		ServiceIdentityPolicyStorePath: filepath.Join(root, "identities"),
	})
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, service.bootstrapTokenStore.SavePolicy(&BootstrapTokenPolicy{
		ID:         "bootstrap-lifecycle-policy",
		Subject:    "metadata-service",
		Audience:   "smd",
		Scopes:     []string{"read"},
		TTL:        time.Hour,
		RefreshTTL: time.Second,
		TokenHash:  HashBootstrapToken(lifecycleBootstrapSecret),
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
	}))
	if withIdentityPolicy {
		require.NoError(t, service.serviceIdentityPolicyStore.Create(serviceAuthIdentityPolicy(now)))
	}
	logs := useSynchronizedTestLogger(t)
	fixture := &serviceAuthLifecycleFixture{
		service:         service,
		root:            root,
		certPath:        certPath,
		keyPath:         keyPath,
		certPEM:         certPEM,
		keyPEM:          keyPEM,
		logs:            logs,
		sessionStarted:  make(chan struct{}),
		sessionRelease:  make(chan struct{}),
		sessionRequests: make(chan struct{}, 8),
	}
	router := service.newRouter(zerolog.New(logs))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/token":
			fixture.bootstrapCalls.Add(1)
		case "/service-identity/session":
			fixture.sessionCalls.Add(1)
			fixture.sessionRequests <- struct{}{}
			if fixture.blockSession.Load() {
				fixture.startOnce.Do(func() { close(fixture.sessionStarted) })
				<-fixture.sessionRelease
			}
			if fixture.transformFailure.Load() {
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, request)
				if recorder.Code != http.StatusOK {
					writer.Header().Set("Content-Type", "application/json")
					writer.WriteHeader(recorder.Code)
					_, _ = writer.Write([]byte(`{"error":"invalid_client","error_description":"` + fixture.failureBody + `"}`))
					return
				}
				result := recorder.Result()
				maps.Copy(writer.Header(), result.Header)
				writer.WriteHeader(result.StatusCode)
				if _, err := io.Copy(writer, result.Body); err != nil {
					return
				}
				if err := result.Body.Close(); err != nil {
					return
				}
				return
			}
		}
		router.ServeHTTP(writer, request)
	}))
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))
	server.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	fixture.server = server
	return fixture
}

func (f *serviceAuthLifecycleFixture) writeIdentityFiles(t *testing.T) {
	t.Helper()
	require.NoError(t, os.WriteFile(f.certPath, f.certPEM, 0o600))
	require.NoError(t, os.WriteFile(f.keyPath, f.keyPEM, 0o600))
}

func (f *serviceAuthLifecycleFixture) client(options ...ServiceClientOption) *ServiceClient {
	base := []ServiceClientOption{
		WithHTTPClient(f.server.Client()),
		WithBootstrapToken(lifecycleBootstrapSecret),
		WithServiceIdentityCertKey(f.certPath, f.keyPath),
		WithTargetService("smd"),
		WithLifecycleTimeout(time.Second),
	}
	base = append(base, options...)
	return NewServiceClientWithOptions(f.server.URL, "metadata-service", "metadata-id", "instance-1", "cluster-integration", base...)
}

func (f *serviceAuthLifecycleFixture) onlyRefreshFamily(t *testing.T) *RefreshTokenFamily {
	t.Helper()
	entries := f.refreshFamilyEntries(t)
	require.Len(t, entries, 1)
	data, err := os.ReadFile(filepath.Join(f.root, "refresh", entries[0].Name()))
	require.NoError(t, err)
	family, err := decodeRefreshFamily(data)
	require.NoError(t, err)
	return family
}

func (f *serviceAuthLifecycleFixture) refreshFamilyEntries(t *testing.T) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(f.root, "refresh"))
	require.NoError(t, err)
	jsonEntries := make([]os.DirEntry, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			jsonEntries = append(jsonEntries, entry)
		}
	}
	return jsonEntries
}

func (f *serviceAuthLifecycleFixture) persistedText(t *testing.T) string {
	t.Helper()
	var contents strings.Builder
	for _, directory := range []string{"bootstrap", "refresh", "identities"} {
		entries, err := os.ReadDir(filepath.Join(f.root, directory))
		require.NoError(t, err)
		for _, entry := range entries {
			data, readErr := os.ReadFile(filepath.Join(f.root, directory, entry.Name()))
			require.NoError(t, readErr)
			contents.Write(data)
		}
	}
	contents.WriteString(f.logs.String())
	return contents.String()
}

func serviceAuthIdentityPolicy(now time.Time) *ServiceIdentityPolicy {
	return &ServiceIdentityPolicy{
		Version:    ServiceIdentityPolicyVersion,
		ID:         "service-lifecycle-policy",
		Subject:    "metadata-service",
		Audience:   "smd",
		Scopes:     []string{"read"},
		RefreshTTL: 30 * time.Minute,
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
	}
}

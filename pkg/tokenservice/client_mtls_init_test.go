package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceClientInitialize_UsesServiceIdentitySessionWhenCertConfigured(t *testing.T) {
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM))
	var serviceIdentityCalls atomic.Int32
	var bootstrapCalls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-identity/session":
			serviceIdentityCalls.Add(1)
			require.NotNil(t, r.TLS)
			require.NotEmpty(t, r.TLS.PeerCertificates)
			_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "mtls-access-token", TokenType: "Bearer", ExpiresIn: 1800, RefreshToken: "mtls-refresh-token", RefreshExpiresIn: 86400, IssuedTokenType: AccessTokenTypeRFC8693})
		case "/oauth/token":
			bootstrapCalls.Add(1)
			http.Error(w, "bootstrap flow should not be used when mTLS identity is configured", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: caPool}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "metadata-service", "metadata-service-id", "instance-1", "cluster-1", WithHTTPClient(server.Client()), WithServiceIdentityCertKey(certPath, keyPath), WithTargetService("smd"))
	require.NoError(t, client.Initialize(context.Background()))
	assert.Equal(t, int32(1), serviceIdentityCalls.Load())
	assert.Equal(t, int32(0), bootstrapCalls.Load())
}

func TestServiceClientInitialize_FailsClosedWhenServiceIdentityFilesUnreadable(t *testing.T) {
	var bootstrapCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth/token", r.URL.Path)
		bootstrapCalls.Add(1)
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "bootstrap-access-token", TokenType: "Bearer", ExpiresIn: 1800, RefreshToken: "bootstrap-refresh-token", RefreshExpiresIn: 86400, IssuedTokenType: AccessTokenTypeRFC8693})
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "metadata-service", "metadata-service-id", "instance-2", "cluster-1", WithBootstrapToken("bootstrap-token"), WithServiceIdentityCertKey("/does/not/exist.crt", "/does/not/exist.key"), WithTargetService("smd"))
	err := client.Initialize(context.Background())
	require.ErrorIs(t, err, ErrTLSClientMaterial)
	assert.Equal(t, int32(0), bootstrapCalls.Load())
}

func TestServiceClientInitialize_FailsWhenOnlyOneServiceIdentityPathProvided(t *testing.T) {
	client := NewServiceClientWithOptions("http://tokensmith.local", "metadata-service", "metadata-service-id", "instance-3", "cluster-1", WithServiceIdentityCertKey("/tmp/service.crt", ""), WithTargetService("smd"))
	err := client.Initialize(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTLSClientMaterial)
}

func writeServiceIdentityCertFiles(t *testing.T, subjectCN string) ([]byte, string, string) {
	t.Helper()
	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "tokensmith-test-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: subjectCN, Organization: []string{"openchami"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)
	tempDir := t.TempDir()
	certPath, keyPath := filepath.Join(tempDir, "service.crt"), filepath.Join(tempDir, "service.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), certPath, keyPath
}

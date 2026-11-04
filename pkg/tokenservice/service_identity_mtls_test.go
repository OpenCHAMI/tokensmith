// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceIdentitySessionHandler_RequiresClientCertificate(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyManager := keys.NewKeyManager()
	require.NoError(t, keyManager.SetKeyPair(privateKey, &privateKey.PublicKey))

	caPEM, _ := generateClientIdentityCertificate(t, "boot-service")
	caPath := filepath.Join(t.TempDir(), "service-identity-ca.pem")
	require.NoError(t, os.WriteFile(caPath, caPEM, 0600))

	service, err := NewTokenService(keyManager, Config{
		Issuer:                "http://tokensmith.test",
		ClusterID:             "cluster-a",
		OpenCHAMIID:           "openchami-a",
		ServiceIdentityCAPath: caPath,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/service-identity/session", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	service.ServiceIdentitySessionHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}

func generateClientIdentityCertificate(t *testing.T, subjectCN string) ([]byte, *x509.Certificate) {
	t.Helper()

	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tokensmith-service-identity-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	serviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serviceTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   subjectCN,
			Organization: []string{"openchami"},
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	serviceDER, err := x509.CreateCertificate(rand.Reader, serviceTemplate, caCert, &serviceKey.PublicKey, caKey)
	require.NoError(t, err)
	serviceCert, err := x509.ParseCertificate(serviceDER)
	require.NoError(t, err)

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caDER,
	})
	return caPEM, serviceCert
}

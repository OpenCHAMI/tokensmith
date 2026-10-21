// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

type synchronizedLogBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *synchronizedLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *synchronizedLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func (b *synchronizedLogBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buffer.Reset()
}

func useSynchronizedTestLogger(t *testing.T) *synchronizedLogBuffer {
	t.Helper()
	logs := &synchronizedLogBuffer{}
	previousLogger := log.Logger
	log.Logger = zerolog.New(logs)
	t.Cleanup(func() { log.Logger = previousLogger })
	return logs
}

func bootstrapExchangeRequest(bootstrapToken string) *http.Request {
	form := url.Values{
		"grant_type":         {GrantTypeTokenExchange},
		"subject_token":      {bootstrapToken},
		"subject_token_type": {BootstrapTokenTypeRFC8693},
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func newRFC8693HandlerTestService(t *testing.T) (*TokenService, string) {
	t.Helper()
	storePath := t.TempDir()
	svc := newTestTokenService(t, Config{
		Issuer:                         "http://tokensmith.test",
		ClusterID:                      "cluster-test",
		OpenCHAMIID:                    "openchami-test",
		RFC8693BootstrapStorePath:      filepath.Join(storePath, "bootstrap"),
		RFC8693RefreshStorePath:        filepath.Join(storePath, "refresh"),
		ServiceIdentityPolicyStorePath: filepath.Join(storePath, "identities"),
	})
	bootstrapToken := "bootstrap-token-for-handler-test"
	now := time.Now().UTC()
	require.NoError(t, svc.bootstrapTokenStore.SavePolicy(&BootstrapTokenPolicy{
		ID:         "bootstrap-policy",
		Subject:    "boot-service",
		Audience:   "metadata-service",
		Scopes:     []string{"read"},
		TTL:        time.Minute,
		RefreshTTL: time.Hour,
		TokenHash:  HashBootstrapToken(bootstrapToken),
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Minute),
	}))
	return svc, bootstrapToken
}

// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceClientForceRefresh_InvalidGrantReplacementSurvivesOwnerCancellation(t *testing.T) {
	// Given: a refresh family whose terminal OAuth rejection leads to a blocked mTLS replacement.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	sessionStarted := make(chan struct{})
	releaseSession := make(chan struct{})
	var refreshCalls atomic.Int32
	var serviceIdentityCalls atomic.Int32
	var bootstrapCalls atomic.Int32
	server := newServiceIdentityTLSServer(t, caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			refreshCalls.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"}))
		case "/service-identity/session":
			serviceIdentityCalls.Add(1)
			assert.NotEmpty(t, r.TLS.PeerCertificates)
			close(sessionStarted)
			if !waitForLifecycleSignal(t, releaseSession, "invalid grant session release") {
				return
			}
			assert.NoError(t, writeLifecycleToken(w, "reacquired-access", "reacquired-refresh"))
		default:
			bootstrapCalls.Add(1)
			http.Error(w, "bootstrap must not be replayed", http.StatusBadRequest)
		}
	}))
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath, WithHTTPClient(&http.Client{Transport: transport}))
	client.mu.Lock()
	client.refreshExpiresAt = time.Now().Add(time.Hour)
	client.mu.Unlock()
	ownerContext, cancelOwner := context.WithCancel(context.Background())
	ownerResult := make(chan error, 1)
	go func() { ownerResult <- client.ForceRefresh(ownerContext) }()
	waitForLifecycle(t, sessionStarted, "invalid grant mTLS session")

	// When: the owner cancels while a healthy waiter joins the shared replacement.
	cancelOwner()
	require.ErrorIs(t, waitForLifecycle(t, ownerResult, "canceled owner result"), context.Canceled)
	waiterObserved := make(chan struct{})
	waiterResult := make(chan error, 1)
	go func() {
		waiterResult <- client.ForceRefresh(&observingContext{Context: context.Background(), observedDone: waiterObserved})
	}()
	waitForLifecycle(t, waiterObserved, "invalid grant waiter")
	close(releaseSession)

	// Then: the shared lifecycle completes one replacement without bootstrap replay.
	require.NoError(t, waitForLifecycle(t, waiterResult, "healthy waiter result"))
	assert.Equal(t, int32(1), refreshCalls.Load())
	assert.Equal(t, int32(1), serviceIdentityCalls.Load())
	assert.Equal(t, int32(0), bootstrapCalls.Load())
}

// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const lifecycleTestTimeout = time.Second

func TestServiceClientRefreshTokenIfNeeded_CoalescesTerminalExpiryReacquisition(t *testing.T) {
	// Given: concurrent callers sharing an expired refresh family.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	started := make(chan struct{})
	release := make(chan struct{})
	var serviceIdentityCalls atomic.Int32
	server := newServiceIdentityTLSServer(t, caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/service-identity/session", r.URL.Path)
		assert.NotEmpty(t, r.TLS.PeerCertificates)
		if serviceIdentityCalls.Add(1) == 1 {
			close(started)
		}
		if !waitForLifecycleSignal(t, release, "session release") {
			return
		}
		assert.NoError(t, writeLifecycleToken(w, "reacquired-access", "reacquired-refresh"))
	}))

	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath, WithHTTPClient(server.Client()))
	errCh := make(chan error, 2)
	go func() { errCh <- client.RefreshTokenIfNeeded(context.Background()) }()
	waitForLifecycle(t, started, "owner request")
	go func() { errCh <- client.RefreshTokenIfNeeded(context.Background()) }()

	// When: the in-flight mTLS session request completes.
	close(release)

	// Then: both callers succeed from the one replacement request.
	require.NoError(t, waitForLifecycle(t, errCh, "owner result"))
	require.NoError(t, waitForLifecycle(t, errCh, "waiter result"))
	assert.Equal(t, int32(1), serviceIdentityCalls.Load())
	assert.Equal(t, uint64(1), client.Stats().RefreshSuccesses)
}

func TestServiceClientGetToken_CoalescesFailedMTLSReacquisition(t *testing.T) {
	// Given: concurrent callers sharing an mTLS session request that fails.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	started := make(chan struct{})
	release := make(chan struct{})
	var serviceIdentityCalls atomic.Int32
	server := newServiceIdentityTLSServer(t, caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(t, r.TLS.PeerCertificates)
		if serviceIdentityCalls.Add(1) == 1 {
			close(started)
		}
		if !waitForLifecycleSignal(t, release, "failed session release") {
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))

	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath, WithHTTPClient(server.Client()))
	errCh := make(chan error, 1)
	go func() { errCh <- client.GetToken(context.Background()) }()
	waitForLifecycle(t, started, "owner request")
	op, owner := client.joinLifecycle()
	require.False(t, owner)

	// When: the shared request fails.
	close(release)
	ownerErr := waitForLifecycle(t, errCh, "owner failure")
	waiterErr := client.waitForLifecycle(context.Background(), op)

	// Then: both callers receive the same failure class from one network attempt.
	require.Error(t, ownerErr)
	require.Error(t, waiterErr)
	assert.ErrorContains(t, ownerErr, "service identity reauthentication:")
	assert.ErrorContains(t, waiterErr, "service identity reauthentication:")
	assert.Equal(t, int32(1), serviceIdentityCalls.Load())
	assert.Equal(t, uint64(1), client.Stats().RefreshFailures)
}

func TestServiceClientGetToken_CanceledWaiterDoesNotStartAnotherLifecycleRequest(t *testing.T) {
	// Given: one mTLS reacquisition is in flight.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	started := make(chan struct{})
	release := make(chan struct{})
	var serviceIdentityCalls atomic.Int32
	server := newServiceIdentityTLSServer(t, caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(t, r.TLS.PeerCertificates)
		serviceIdentityCalls.Add(1)
		close(started)
		if !waitForLifecycleSignal(t, release, "canceled waiter release") {
			return
		}
		assert.NoError(t, writeLifecycleToken(w, "reacquired-access", "reacquired-refresh"))
	}))

	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath, WithHTTPClient(server.Client()))
	ownerErr := make(chan error, 1)
	go func() { ownerErr <- client.GetToken(context.Background()) }()
	waitForLifecycle(t, started, "owner request")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancel()

	// When: a waiter is canceled while the owner completes its lifecycle operation.
	waiterErr := client.GetToken(ctx)
	close(release)

	// Then: cancellation wins at gate release and only the owner made a request.
	require.ErrorIs(t, waiterErr, context.Canceled)
	require.NoError(t, waitForLifecycle(t, ownerErr, "owner result"))
	assert.Equal(t, int32(1), serviceIdentityCalls.Load())
}

func TestServiceClientGetToken_CancellationDuringRequestReleasesLifecycleGate(t *testing.T) {
	// Given: a session request that is canceled by its caller.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	requestStarted := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	server := newServiceIdentityTLSServer(t, caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(t, r.TLS.PeerCertificates)
		if calls.Add(1) == 1 {
			close(requestStarted)
			if !waitForLifecycleSignal(t, release, "canceled request release") {
				return
			}
			return
		}
		assert.NoError(t, writeLifecycleToken(w, "reacquired-access", "reacquired-refresh"))
	}))

	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath, WithHTTPClient(server.Client()))
	ctx, cancel := context.WithCancel(context.Background())
	firstErrCh := make(chan error, 1)
	go func() { firstErrCh <- client.GetToken(ctx) }()
	waitForLifecycle(t, requestStarted, "first request")

	// When: the canceled request returns and a new caller retries.
	cancel()
	firstErr := waitForLifecycle(t, firstErrCh, "canceled result")
	close(release)
	secondErr := client.GetToken(context.Background())

	// Then: cancellation remains in the error chain and the retry owns a later operation.
	require.ErrorIs(t, firstErr, context.Canceled)
	require.NoError(t, secondErr)
	assert.Equal(t, int32(2), calls.Load())
}

func TestServiceClientWaitForLifecycle_CancellationAtGateRelease(t *testing.T) {
	// Given: a completed lifecycle operation and a context canceled at its release boundary.
	op := &lifecycleOperation{done: make(chan struct{})}
	close(op.done)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// When: a waiter observes both completion and cancellation.
	err := (&ServiceClient{}).waitForLifecycle(ctx, op)

	// Then: cancellation wins regardless of which ready channel select chooses.
	require.ErrorIs(t, err, context.Canceled)
}

func TestServiceClientStartAutoRefresh_ReacquiresMTLSSessionAfterTerminalExpiry(t *testing.T) {
	// Given: auto-refresh starts with terminal refresh-family expiry and mTLS configured.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	serviceIdentityCalled := make(chan struct{})
	server := newServiceIdentityTLSServer(t, caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/service-identity/session", r.URL.Path)
		assert.NotEmpty(t, r.TLS.PeerCertificates)
		close(serviceIdentityCalled)
		assert.NoError(t, writeLifecycleToken(w, "reacquired-access", "reacquired-refresh"))
	}))

	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath, WithHTTPClient(server.Client()), WithAutoRefreshInterval(time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.StartAutoRefresh(ctx)
	}()

	// When: auto-refresh reaches its first tick.
	waitForLifecycle(t, serviceIdentityCalled, "service identity request")
	cancel()

	// Then: it continued through mTLS reacquisition and stops only on cancellation.
	waitForLifecycle(t, done, "auto-refresh shutdown")
}

func waitForLifecycle[T any](t *testing.T, ch <-chan T, name string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(lifecycleTestTimeout):
		t.Fatalf("timed out waiting for %s", name)
	}
	var zero T
	return zero
}

func waitForLifecycleSignal(t *testing.T, ch <-chan struct{}, name string) bool {
	t.Helper()
	select {
	case <-ch:
		return true
	case <-time.After(lifecycleTestTimeout):
		assert.Failf(t, "lifecycle signal timeout", "timed out waiting for %s", name)
		return false
	}
}

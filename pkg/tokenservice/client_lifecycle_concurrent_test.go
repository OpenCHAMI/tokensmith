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
	errCh := make(chan error, 2)
	go func() { errCh <- client.ForceRefresh(context.Background()) }()
	waitForLifecycle(t, started, "owner request")
	observedDone := make(chan struct{})
	go func() {
		errCh <- client.ForceRefresh(&observingContext{Context: context.Background(), observedDone: observedDone})
	}()
	<-observedDone

	// When: the shared request fails.
	close(release)
	ownerErr := waitForLifecycle(t, errCh, "owner failure")
	waiterErr := waitForLifecycle(t, errCh, "waiter failure")

	// Then: both callers receive the same failure class from one network attempt.
	require.Error(t, ownerErr)
	require.Error(t, waiterErr)
	require.EqualError(t, waiterErr, ownerErr.Error())
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
	go func() { ownerErr <- client.ForceRefresh(context.Background()) }()
	waitForLifecycle(t, started, "owner request")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancel()

	// When: a waiter is canceled while the owner completes its lifecycle operation.
	waiterErr := client.ForceRefresh(ctx)
	close(release)

	// Then: cancellation wins at gate release and only the owner made a request.
	require.ErrorIs(t, waiterErr, context.Canceled)
	require.NoError(t, waitForLifecycle(t, ownerErr, "owner result"))
	assert.Equal(t, int32(1), serviceIdentityCalls.Load())
}

func TestServiceClientGetToken_OwnerCancellationDoesNotPoisonHealthyWaiter(t *testing.T) {
	// Given: a session request that outlives its canceled creator.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	requestStarted := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	server := newServiceIdentityTLSServer(t, caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(t, r.TLS.PeerCertificates)
		calls.Add(1)
		close(requestStarted)
		if !waitForLifecycleSignal(t, release, "owner cancellation release") {
			return
		}
		assert.NoError(t, writeLifecycleToken(w, "reacquired-access", "reacquired-refresh"))
	}))

	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath, WithHTTPClient(server.Client()))
	ctx, cancel := context.WithCancel(context.Background())
	firstErrCh := make(chan error, 1)
	go func() { firstErrCh <- client.ForceRefresh(ctx) }()
	waitForLifecycle(t, requestStarted, "first request")

	// When: the creator cancels and a healthy caller joins the same operation.
	cancel()
	firstErr := waitForLifecycle(t, firstErrCh, "canceled result")
	secondErr := make(chan error, 1)
	go func() { secondErr <- client.ForceRefresh(context.Background()) }()
	close(release)

	// Then: cancellation remains local and the healthy waiter receives the shared result.
	require.ErrorIs(t, firstErr, context.Canceled)
	require.NoError(t, waitForLifecycle(t, secondErr, "healthy waiter result"))
	assert.Equal(t, int32(1), calls.Load())
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

func TestServiceClientStartAutoRefresh_StopsAfterTerminalMTLSFailure(t *testing.T) {
	// Given: terminal expiry with a replacement endpoint that fails once.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	called := make(chan struct{})
	var calls atomic.Int32
	server := newServiceIdentityTLSServer(t, caPEM, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if calls.Add(1) == 1 {
			close(called)
		}
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
	}))
	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath, WithHTTPClient(server.Client()), WithAutoRefreshInterval(time.Millisecond))
	done := make(chan struct{})

	// When: automatic refresh reaches the terminal mTLS transition.
	go func() {
		defer close(done)
		client.StartAutoRefresh(context.Background())
	}()
	waitForLifecycle(t, called, "terminal mTLS request")

	// Then: the worker records one failed transition and exits without replaying it.
	waitForLifecycle(t, done, "auto-refresh terminal stop")
	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, uint64(1), client.Stats().RefreshFailures)
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

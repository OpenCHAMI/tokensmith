// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrMissingBootstrapToken = errors.New("missing bootstrap token")
	ErrMissingRefreshToken   = errors.New("missing refresh token")
	ErrTLSClientMaterial     = errors.New("invalid service identity client certificate configuration")
	ErrEmptyTokenSmithURL    = errors.New("tokensmith URL is required")
	ErrEmptyTargetService    = errors.New("target service is required")
	ErrRefreshTokenExpired   = errors.New("refresh token expired")
)

// ServiceToken represents the token response from tokensmith.
type ServiceToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ServiceClient handles token acquisition and refresh against tokensmith.
type ServiceClient struct {
	client                  *http.Client
	tokensmithURL           string
	serviceName             string
	serviceID               string
	targetService           string
	bootstrapToken          string
	serviceIdentityCertPath string
	serviceIdentityKeyPath  string
	refreshBefore           time.Duration
	autoInterval            time.Duration
	bootstrapMaxAttempts    int
	bootstrapInitialBackoff time.Duration
	bootstrapMaxBackoff     time.Duration
	lifecycleTimeout        time.Duration
	token                   *ServiceToken
	refreshToken            string
	refreshExpiresAt        time.Time
	instanceID              string
	clusterID               string
	bootstrapBurned         bool

	lifecycleMu      sync.Mutex
	lifecycle        *lifecycleOperation
	mu               sync.RWMutex
	lastErrorMessage atomic.Value
	refreshSuccesses uint64
	refreshFailures  uint64
	lastRefreshUnix  int64
	lastSuccessUnix  int64
}

// ServiceClientStats summarizes token refresh lifecycle state.
type ServiceClientStats struct {
	RefreshSuccesses uint64
	RefreshFailures  uint64
	LastError        string
	LastRefresh      time.Time
	LastSuccess      time.Time
	HasToken         bool
	ExpiresAt        time.Time
	HasRefreshToken  bool
	RefreshExpiresAt time.Time
}

// ServiceClientOption applies optional configuration to ServiceClient.
type ServiceClientOption func(*ServiceClient)

// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package oidc

import (
	"errors"
	"fmt"
)

var (
	ErrProviderMetadata    = errors.New("provider metadata failure")
	ErrUpstreamUnavailable = errors.New("upstream unavailable")
	ErrUpstreamRejected    = errors.New("upstream rejected token introspection")
	ErrInvalidResponse     = errors.New("invalid upstream response")
	ErrInvalidToken        = errors.New("invalid token")
)

type ProviderError struct {
	Operation  string
	Kind       error
	StatusCode int
	Cause      error
}

func (err *ProviderError) Error() string {
	if err == nil {
		return "provider error"
	}
	if err.StatusCode != 0 {
		return fmt.Sprintf("%s: %v: status %d", err.Operation, err.Kind, err.StatusCode)
	}
	return fmt.Sprintf("%s: %v", err.Operation, err.Kind)
}

func (err *ProviderError) Unwrap() []error {
	if err == nil {
		return nil
	}
	if err.Cause == nil {
		return []error{err.Kind}
	}
	return []error{err.Kind, err.Cause}
}

func providerError(operation string, kind error, cause error) error {
	return &ProviderError{Operation: operation, Kind: kind, Cause: cause}
}

func providerStatusError(operation string, kind error, statusCode int) error {
	return &ProviderError{Operation: operation, Kind: kind, StatusCode: statusCode}
}

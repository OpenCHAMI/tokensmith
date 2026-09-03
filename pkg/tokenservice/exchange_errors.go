// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrExchangeMissingClaims            = errors.New("exchange missing required claims")
	ErrExchangeInvalidClaim             = errors.New("exchange invalid claim")
	ErrExchangeGeneratedClaimValidation = errors.New("exchange generated claim validation failed")
	ErrExchangeScopeNotGranted          = errors.New("exchange requested scope not granted")
	ErrExchangeInactiveToken            = errors.New("token is not active")
)

type ExchangeClaimsError struct {
	Kind          error
	Claims        []string
	Allowed       []string
	RejectedScope string
}

func (err *ExchangeClaimsError) Error() string {
	if err == nil {
		return "exchange claims error"
	}
	if errors.Is(err.Kind, ErrExchangeScopeNotGranted) {
		return fmt.Sprintf("%v: scope", ErrExchangeInvalidClaim)
	}
	return fmt.Sprintf("%v: %s", err.Kind, strings.Join(err.Claims, ","))
}

func (err *ExchangeClaimsError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Kind
}

func missingExchangeClaims(claims ...string) error {
	return &ExchangeClaimsError{Kind: ErrExchangeMissingClaims, Claims: claims}
}

func invalidExchangeClaim(claim string) error {
	return &ExchangeClaimsError{Kind: ErrExchangeInvalidClaim, Claims: []string{claim}}
}

func scopeNotGranted(scope string, allowed []string) error {
	return &ExchangeClaimsError{Kind: ErrExchangeScopeNotGranted, Claims: []string{"scope"}, Allowed: append([]string(nil), allowed...), RejectedScope: scope}
}

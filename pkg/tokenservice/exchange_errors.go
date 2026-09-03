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

	// ErrExchangeNoAuthorizedGroups is returned when an upstream-authenticated
	// caller belongs to no group present in the configured groupScopes. The
	// caller is a valid user of the identity provider but has no standing in
	// this cluster, so no token is issued.
	ErrExchangeNoAuthorizedGroups = errors.New(
		"not authorized: user is not a member of any group configured for this cluster")
)

type ExchangeClaimsError struct {
	Kind   error
	Claims []string
}

func (err *ExchangeClaimsError) Error() string {
	if err == nil {
		return "exchange claims error"
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

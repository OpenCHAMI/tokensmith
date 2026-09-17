// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"time"

	"github.com/openchami/tokensmith/pkg/oidc"
)

const defaultVaultUserInfoFallbackTTL = oidc.DefaultVaultUserInfoFallbackTTL

type oidcProviderSettings struct {
	mode                     oidc.ProviderMode
	vaultUserInfoFallbackTTL time.Duration
}

func resolveOIDCProviderSettings(flagMode, flagTTL, envMode, envTTL string) (oidcProviderSettings, error) {
	modeValue := flagMode
	if modeValue == "" {
		modeValue = envMode
	}
	mode, err := oidc.ParseProviderMode(modeValue)
	if err != nil {
		return oidcProviderSettings{}, err
	}
	var ttl time.Duration
	ttlValue := flagTTL
	if ttlValue == "" {
		ttlValue = envTTL
	}
	if ttlValue != "" {
		var err error
		ttl, err = time.ParseDuration(ttlValue)
		if err != nil {
			return oidcProviderSettings{}, fmt.Errorf("parse OIDC_VAULT_USERINFO_FALLBACK_TTL: %w", err)
		}
	}
	if ttl == 0 {
		ttl = defaultVaultUserInfoFallbackTTL
	}
	if err := oidc.ValidateVaultUserInfoFallbackTTL(ttl); err != nil {
		return oidcProviderSettings{}, err
	}
	return oidcProviderSettings{mode: mode, vaultUserInfoFallbackTTL: ttl}, nil
}

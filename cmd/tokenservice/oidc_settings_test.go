// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveOIDCProviderSettings(t *testing.T) {
	tests := []struct {
		name      string
		flagMode  string
		flagTTL   string
		envMode   string
		envTTL    string
		wantMode  oidc.ProviderMode
		wantTTL   time.Duration
		wantError bool
	}{
		{name: "defaults to generic", wantMode: oidc.ProviderModeGeneric, wantTTL: 5 * time.Minute},
		{name: "reads vault environment", envMode: "vault", envTTL: "2m", wantMode: oidc.ProviderModeVault, wantTTL: 2 * time.Minute},
		{name: "flags override environment", flagMode: "generic", flagTTL: "1m", envMode: "vault", envTTL: "2m", wantMode: oidc.ProviderModeGeneric, wantTTL: time.Minute},
		{name: "rejects invalid mode", flagMode: "invalid", wantError: true},
		{name: "rejects invalid environment ttl", envTTL: "later", wantError: true},
		{name: "rejects unsafe long ttl", flagTTL: "16m", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings, err := resolveOIDCProviderSettings(tt.flagMode, tt.flagTTL, tt.envMode, tt.envTTL)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantMode, settings.mode)
			assert.Equal(t, tt.wantTTL, settings.vaultUserInfoFallbackTTL)
		})
	}
}

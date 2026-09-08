// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServeCommandRegisteredOnce(t *testing.T) {
	count := 0
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == serveCmd.Name() {
			count++
		}
	}

	assert.Equal(t, 1, count, "serve command should only be registered once")
}

func TestServeCommandHasOIDCCAFlag(t *testing.T) {
	flag := serveCmd.Flags().Lookup("oidc-ca")

	if assert.NotNil(t, flag) {
		assert.Contains(t, flag.Usage, "TOKENSMITH_OIDC_CA")
	}
}

func TestServeCommandHasOIDCIntrospectionEndpointFlag(t *testing.T) {
	flag := serveCmd.Flags().Lookup("oidc-introspection-endpoint")

	if assert.NotNil(t, flag) {
		assert.Contains(t, flag.Usage, "TOKENSMITH_OIDC_INTROSPECTION_ENDPOINT")
	}
}

func TestServeCommandHasMaxExchangeSessionLifetimeFlag(t *testing.T) {
	flag := serveCmd.Flags().Lookup("max-exchange-session-lifetime")

	if assert.NotNil(t, flag) {
		assert.Contains(t, flag.Usage, "TOKENSMITH_MAX_EXCHANGE_SESSION_LIFETIME")
	}
}

func TestEnvFallbackAppliesWhenFlagUnset(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	target := "flag-default"
	cmd.Flags().StringVar(&target, "issuer", "flag-default", "")

	t.Setenv("TOKENSMITH_TEST_ISSUER", "from-env")
	envFallback(cmd, "issuer", "TOKENSMITH_TEST_ISSUER", &target)

	assert.Equal(t, "from-env", target)
}

func TestEnvFallbackKeepsExplicitFlagValue(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	target := "flag-default"
	cmd.Flags().StringVar(&target, "issuer", "flag-default", "")
	require.NoError(t, cmd.Flags().Set("issuer", "from-flag"))

	t.Setenv("TOKENSMITH_TEST_ISSUER", "from-env")
	envFallback(cmd, "issuer", "TOKENSMITH_TEST_ISSUER", &target)

	assert.Equal(t, "from-flag", target)
}

func TestEnvFallbackKeepsDefaultWhenEnvEmpty(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	target := "flag-default"
	cmd.Flags().StringVar(&target, "issuer", "flag-default", "")

	t.Setenv("TOKENSMITH_TEST_ISSUER", "   ")
	envFallback(cmd, "issuer", "TOKENSMITH_TEST_ISSUER", &target)

	assert.Equal(t, "flag-default", target)
}

// resetServeGlobals isolates tests that invoke serveCmd.RunE, which mutates
// package-level flag targets. Other tests execute rootCmd, which can also leave
// flags marked as changed and suppress the environment fallbacks under test.
func resetServeGlobals(t *testing.T) {
	t.Helper()

	prevIssuer, prevOIDC, prevIntrospection, prevPort := issuer, oidcIssuerURL, oidcIntrospectionEndpoint, port
	issuer, oidcIssuerURL, oidcIntrospectionEndpoint = "", "", ""

	changed := map[string]bool{}
	for _, name := range []string{"issuer", "oidc-issuer", "oidc-introspection-endpoint", "port"} {
		if f := serveCmd.Flags().Lookup(name); f != nil {
			changed[name] = f.Changed
			f.Changed = false
		}
	}

	t.Cleanup(func() {
		issuer, oidcIssuerURL, oidcIntrospectionEndpoint, port = prevIssuer, prevOIDC, prevIntrospection, prevPort
		for name, was := range changed {
			if f := serveCmd.Flags().Lookup(name); f != nil {
				f.Changed = was
			}
		}
	})
}

func TestServeCommandRejectsInvalidPortEnv(t *testing.T) {
	resetServeGlobals(t)
	t.Setenv("TOKENSMITH_PORT", "not-a-port")

	err := serveCmd.RunE(serveCmd, nil)

	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid TOKENSMITH_PORT")
	}
}

func TestServeCommandRequiresIssuer(t *testing.T) {
	resetServeGlobals(t)
	t.Setenv("TOKENSMITH_ISSUER", "")
	t.Setenv("TOKENSMITH_OIDC_PROVIDER", "http://hydra:4444")

	err := serveCmd.RunE(serveCmd, nil)

	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "issuer is required")
	}
}

func TestServeCommandRequiresOIDCIssuer(t *testing.T) {
	resetServeGlobals(t)
	t.Setenv("TOKENSMITH_ISSUER", "http://tokensmith:8080")
	t.Setenv("TOKENSMITH_OIDC_PROVIDER", "")

	err := serveCmd.RunE(serveCmd, nil)

	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "OIDC issuer is required")
	}
}

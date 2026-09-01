// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestServeCommandHasMaxExchangeSessionLifetimeFlag(t *testing.T) {
	flag := serveCmd.Flags().Lookup("max-exchange-session-lifetime")

	if assert.NotNil(t, flag) {
		assert.Contains(t, flag.Usage, "TOKENSMITH_MAX_EXCHANGE_SESSION_LIFETIME")
	}
}

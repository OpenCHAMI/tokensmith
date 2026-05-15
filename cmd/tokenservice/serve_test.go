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

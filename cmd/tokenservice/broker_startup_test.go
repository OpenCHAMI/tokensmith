// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/deviceauth"
)

// Exercise Cobra startup in a subprocess to isolate its global flag state.
// An invalid port stops valid configuration before opening a listener.
func TestBrokerOnlyServeCommand(t *testing.T) {
	const argsEnv = "TOKENSMITH_TEST_BROKER_ARGS"
	if raw := os.Getenv(argsEnv); raw != "" {
		var args []string
		if json.Unmarshal([]byte(raw), &args) != nil {
			os.Exit(3)
		}
		rootCmd.SetArgs(args)
		if err := rootCmd.Execute(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(0)
	}

	for _, name := range []string{"valid", "invalid policy", "missing verifier"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			verifier := filepath.Join(dir, "verifier")
			if err := os.WriteFile(verifier, []byte("synthetic-verifier"), 0600); err != nil {
				t.Fatal(err)
			}
			policy := deviceauth.Config{
				Issuer: "https://gitlab.example", ClientID: "app", ProjectID: 701,
				ClusterIssuer: "http://tokensmith:8080", Audience: "openchami:human:zs",
				VerifierFile: verifier, CacheSeconds: 90, TokenSeconds: 180,
				SkewSeconds: 30, AbsoluteSeconds: 36000,
			}
			want := "invalid port"
			switch name {
			case "invalid policy":
				policy.ProjectID = 0
				want = "invalid device authorization configuration"
			case "missing verifier":
				policy.VerifierFile = filepath.Join(dir, "missing")
				want = "invalid device authorization configuration"
			}
			raw, err := json.Marshal(map[string]any{"device_auth": policy})
			if err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(dir, "config.json")
			if err := os.WriteFile(config, raw, 0600); err != nil {
				t.Fatal(err)
			}
			args, err := json.Marshal([]string{"serve", "--config", config, "--issuer", policy.ClusterIssuer, "--oidc-issuer=", "--port=-1", "--key-dir", dir, "--rfc8693-bootstrap-store", filepath.Join(dir, "bootstrap"), "--rfc8693-refresh-store", filepath.Join(dir, "refresh")})
			if err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestBrokerOnlyServeCommand$")
			for _, env := range os.Environ() {
				if !strings.HasPrefix(env, "TOKENSMITH_") && !strings.HasPrefix(env, "OIDC_") {
					cmd.Env = append(cmd.Env, env)
				}
			}
			cmd.Env = append(cmd.Env, argsEnv+"="+string(args))
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil || err == nil || !strings.Contains(string(output), want) {
				t.Fatalf("broker-only CLI: want %q, error %v, context %v; output:\n%s", want, err, ctx.Err(), output)
			}
		})
	}
}

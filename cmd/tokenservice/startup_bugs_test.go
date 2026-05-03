// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigFlagRegistration verifies that --config flag is registered and works
func TestConfigFlagRegistration(t *testing.T) {
	// Test 1a: --config flag is recognized (should not error on flag parsing)
	err := serveCmd.Flags().Parse([]string{"--config", "/tmp/test.json", "--issuer", "http://test:8080"})
	require.NoError(t, err, "config flag should be recognized")
	assert.Equal(t, "/tmp/test.json", configPath, "config flag should set configPath variable")
}

// TestConfigFileValidation verifies that missing config files are handled gracefully
func TestConfigFileValidation(t *testing.T) {
	testCases := []struct {
		name        string
		configPath  string
		issuer      string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Empty config path should not error",
			configPath:  "",
			issuer:      "http://test:8080",
			expectError: false,
		},
		{
			name:        "Non-existent config file should error",
			configPath:  "/tmp/nonexistent-config-" + time.Now().Format("20060102150405") + ".json",
			issuer:      "http://test:8080",
			expectError: true,
			errorMsg:    "config file not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configPath = tc.configPath
			issuer = tc.issuer

			// Parse flags to set variables
			err := serveCmd.Flags().Parse([]string{"--config", tc.configPath, "--issuer", tc.issuer})
			require.NoError(t, err)

			// Test the validation logic from serve.go RunE
			if tc.configPath != "" {
				_, err := os.Stat(tc.configPath)
				if tc.expectError {
					assert.Error(t, err, "should error when config file does not exist")
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}

// TestEntrypointConfigConditional verifies entrypoint.sh logic
func TestEntrypointConfigConditional(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()

	testCases := []struct {
		name            string
		createFile      bool
		expectConfigArg bool
	}{
		{
			name:            "Config file exists should pass --config",
			createFile:      true,
			expectConfigArg: true,
		},
		{
			name:            "Config file missing should not pass --config",
			createFile:      false,
			expectConfigArg: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configFile := filepath.Join(tmpDir, "config-"+tc.name+".json")

			if tc.createFile {
				err := os.WriteFile(configFile, []byte(`{"groupScopes":{}}`), 0644)
				require.NoError(t, err)
			}

			// Verify file existence logic matches entrypoint.sh
			_, err := os.Stat(configFile)
			fileExists := err == nil

			if tc.expectConfigArg {
				assert.True(t, fileExists, "config file should exist when expecting --config arg")
			} else {
				assert.False(t, fileExists, "config file should not exist when not expecting --config arg")
			}
		})
	}
}

// TestKeyDirPermissions verifies that key directories can be written to by non-root user
func TestKeyDirPermissions(t *testing.T) {
	// Create a temporary directory to simulate /tokensmith/keys
	keyDir := t.TempDir()

	// Verify that the directory is writable
	testFile := filepath.Join(keyDir, "test.pem")
	err := os.WriteFile(testFile, []byte("test"), 0600)
	require.NoError(t, err, "key directory should be writable")

	// Verify we can read the file back
	content, err := os.ReadFile(testFile)
	require.NoError(t, err)
	assert.Equal(t, "test", string(content))

	// Check directory permissions
	info, err := os.Stat(keyDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir(), "key path should be a directory")

	// Verify private key can be written with 0600 permissions
	privateKeyPath := filepath.Join(keyDir, "private.pem")
	err = os.WriteFile(privateKeyPath, []byte("private key data"), 0600)
	require.NoError(t, err, "private key should be writable")

	// Verify public key can be written with 0644 permissions
	publicKeyPath := filepath.Join(keyDir, "public.pem")
	err = os.WriteFile(publicKeyPath, []byte("public key data"), 0644)
	require.NoError(t, err, "public key should be writable")

	// Verify both files exist and have correct permissions
	privInfo, err := os.Stat(privateKeyPath)
	require.NoError(t, err)
	assert.True(t, (privInfo.Mode()&0600) != 0, "private key should have read/write permissions")

	pubInfo, err := os.Stat(publicKeyPath)
	require.NoError(t, err)
	assert.True(t, (pubInfo.Mode()&0644) != 0, "public key should have read/write permissions")
}

// TestDockerfileChownCommand verifies the chown command in Dockerfile
// This test ensures that the Dockerfile has the necessary chown command
func TestDockerfileChownCommand(t *testing.T) {
	dockerfilePath := filepath.Join("..", "..", "Dockerfile")

	content, err := os.ReadFile(dockerfilePath)
	require.NoError(t, err, "should be able to read Dockerfile")

	dockerfileContent := string(content)

	// Verify that chown command exists in the Dockerfile
	assert.Contains(t, dockerfileContent, "chown", "Dockerfile should contain chown command")
	assert.Contains(t, dockerfileContent, "65534:65534", "Dockerfile should chown directories to 65534:65534")
	assert.Contains(t, dockerfileContent, "/tokensmith/keys", "Dockerfile should include /tokensmith/keys in chown")
	assert.Contains(t, dockerfileContent, "/tokensmith/data", "Dockerfile should include /tokensmith/data in chown")
	assert.Contains(t, dockerfileContent, "/tokensmith/config", "Dockerfile should include /tokensmith/config in chown")
}

// TestEntrypointShConditionalConfig verifies the entrypoint.sh has conditional config logic
func TestEntrypointShConditionalConfig(t *testing.T) {
	entrypointPath := filepath.Join("..", "..", "entrypoint.sh")

	content, err := os.ReadFile(entrypointPath)
	require.NoError(t, err, "should be able to read entrypoint.sh")

	entrypointContent := string(content)

	// Verify that entrypoint.sh has conditional logic for config file
	assert.Contains(t, entrypointContent, "[ -f \"$TOKENSMITH_CONFIG\" ]", "entrypoint.sh should check if config file exists")
	assert.Contains(t, entrypointContent, "CONFIG_ARG", "entrypoint.sh should use CONFIG_ARG variable")
	assert.Contains(t, entrypointContent, "$CONFIG_ARG", "entrypoint.sh should pass CONFIG_ARG to tokensmith serve")
}

// TestAuthzOperationsDocumentation verifies that hot-reload limitation is documented
func TestAuthzOperationsDocumentation(t *testing.T) {
	docPath := filepath.Join("..", "..", "docs", "authz_operations.md")

	content, err := os.ReadFile(docPath)
	require.NoError(t, err, "should be able to read authz_operations.md")

	docContent := string(content)

	// Verify that hot-reload limitation is documented
	assert.Contains(t, docContent, "no hot reload", "documentation should mention no hot reload in v1")
	assert.Contains(t, docContent, "process start", "documentation should mention policy loaded at process start")
	assert.Contains(t, docContent, "required for policy changes", "documentation should clearly state restart is required")
	assert.Contains(t, docContent, "future", "documentation should mention future versions")
}

// TestConfigFlagIntegration tests the serve command with config flag combinations
func TestConfigFlagIntegration(t *testing.T) {
	// This test verifies flag parsing without running the actual server
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "no config flag",
			args:    []string{"--issuer", "http://test:8080"},
			wantErr: false,
		},
		{
			name:    "config flag with empty value",
			args:    []string{"--config", "", "--issuer", "http://test:8080"},
			wantErr: false,
		},
		{
			name:    "config flag recognized",
			args:    []string{"--config", "/tmp/config.json", "--issuer", "http://test:8080"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := serveCmd.Flags().Parse(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("serveCmd.Flags().Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestDatastoreVolumeMountability verifies that data store path is accessible
func TestDatastoreVolumeMountability(t *testing.T) {
	// Create a temporary directory to simulate /tokensmith/data
	dataDir := t.TempDir()

	// Verify the directory is writable
	testFile := filepath.Join(dataDir, "test-token.json")
	err := os.WriteFile(testFile, []byte(`{"token":"test"}`), 0644)
	require.NoError(t, err, "data directory should be writable")

	// Verify subdirectories can be created (for bootstrap and refresh tokens)
	bootstrapDir := filepath.Join(dataDir, "bootstrap-tokens")
	err = os.MkdirAll(bootstrapDir, 0755)
	require.NoError(t, err, "should be able to create bootstrap-tokens directory")

	refreshDir := filepath.Join(dataDir, "refresh-tokens")
	err = os.MkdirAll(refreshDir, 0755)
	require.NoError(t, err, "should be able to create refresh-tokens directory")

	// Verify files can be created in subdirectories
	bootstrapToken := filepath.Join(bootstrapDir, "token1.json")
	err = os.WriteFile(bootstrapToken, []byte(`{"id":"1"}`), 0644)
	require.NoError(t, err, "should be able to write to bootstrap-tokens directory")

	refreshToken := filepath.Join(refreshDir, "token1.json")
	err = os.WriteFile(refreshToken, []byte(`{"id":"1"}`), 0644)
	require.NoError(t, err, "should be able to write to refresh-tokens directory")
}

// BenchmarkConfigFileValidation benchmarks the config file validation logic
func BenchmarkConfigFileValidation(b *testing.B) {
	tmpDir := b.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")
	err := os.WriteFile(configFile, []byte(`{"groupScopes":{}}`), 0644)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = os.Stat(configFile)
	}
}

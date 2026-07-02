// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

//go:build integration

package tokenservice

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	postgresImage = "postgres:16-alpine"
	postgresPort  = "5432"
	postgresUser  = "tokensmith"
	postgresPass  = "tokensmith_test"
	postgresDB    = "tokensmith_test"
	maxRetries    = 30
	retryInterval = time.Second
)

// testPostgresContainer manages a postgres container for integration tests.
type testPostgresContainer struct {
	containerID string
	connStr     string
	db          *sql.DB
}

// startPostgresContainer starts a postgres container and waits for it to be ready.
func startPostgresContainer(t *testing.T) *testPostgresContainer {
	t.Helper()

	// Check if we're running in CI with external postgres
	if externalHost := os.Getenv("POSTGRES_HOST"); externalHost != "" {
		connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			externalHost,
			os.Getenv("POSTGRES_PORT"),
			os.Getenv("POSTGRES_USER"),
			os.Getenv("POSTGRES_PASSWORD"),
			os.Getenv("POSTGRES_DB"))

		db, err := sql.Open("postgres", connStr)
		require.NoError(t, err, "failed to connect to external postgres")

		return &testPostgresContainer{
			containerID: "",
			connStr:     connStr,
			db:          db,
		}
	}

	// Check if docker/podman is available
	dockerCmd := "docker"
	if _, err := os.Stat("/usr/bin/podman"); err == nil {
		dockerCmd = "podman"
	}

	// Start postgres container
	containerName := fmt.Sprintf("tokensmith-test-postgres-%d", time.Now().Unix())

	args := []string{
		"run", "-d", "--rm", "--name", containerName,
		"-e", fmt.Sprintf("POSTGRES_USER=%s", postgresUser),
		"-e", fmt.Sprintf("POSTGRES_PASSWORD=%s", postgresPass),
		"-e", fmt.Sprintf("POSTGRES_DB=%s", postgresDB),
		"-p", fmt.Sprintf("%s:5432", postgresPort),
		postgresImage,
	}

	t.Logf("Starting postgres container: %s", containerName)
	cmd := exec.Command(dockerCmd, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("Skipping postgres integration test: docker/podman not available or failed to start container: %v\nOutput: %s", err, string(output))
	}

	containerID := strings.TrimSpace(string(output))
	connStr := fmt.Sprintf("host=localhost port=%s user=%s password=%s dbname=%s sslmode=disable",
		postgresPort, postgresUser, postgresPass, postgresDB)

	// Wait for postgres to be ready
	var db *sql.DB
	for i := 0; i < maxRetries; i++ {
		db, err = sql.Open("postgres", connStr)
		if err == nil {
			if err = db.Ping(); err == nil {
				t.Logf("Postgres container ready after %d attempts", i+1)
				return &testPostgresContainer{
					containerID: containerID,
					connStr:     connStr,
					db:          db,
				}
			}
		}
		if db != nil {
			db.Close()
		}
		time.Sleep(retryInterval)
	}

	// Cleanup on failure
	stopCmd := exec.Command(dockerCmd, "stop", containerName)
	_ = stopCmd.Run()
	t.Fatalf("Postgres container failed to become ready after %d attempts: %v", maxRetries, err)
	return nil
}

// cleanup stops and removes the postgres container.
func (c *testPostgresContainer) cleanup(t *testing.T) {
	t.Helper()

	if c.db != nil {
		c.db.Close()
	}

	if c.containerID == "" {
		return // external postgres, no cleanup needed
	}

	dockerCmd := "docker"
	if _, err := os.Stat("/usr/bin/podman"); err == nil {
		dockerCmd = "podman"
	}

	stopCmd := exec.Command(dockerCmd, "stop", c.containerID)
	if err := stopCmd.Run(); err != nil {
		t.Logf("Warning: failed to stop postgres container: %v", err)
	}
}

// applyMigration applies the schema.sql migration to the database.
func applyMigration(t *testing.T, db *sql.DB, schemaPath string) {
	t.Helper()

	schema, err := os.ReadFile(schemaPath)
	require.NoError(t, err, "failed to read schema.sql")

	_, err = db.Exec(string(schema))
	require.NoError(t, err, "failed to apply migration")
}

// hashToken creates a SHA-256 hash of a token (matching production behavior).
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// TestPostgresIntegration_CreateDatabase verifies we can create a database and connect.
func TestPostgresIntegration_CreateDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	pg := startPostgresContainer(t)
	defer pg.cleanup(t)

	// Verify connection
	err := pg.db.Ping()
	require.NoError(t, err, "failed to ping database")

	// Verify we can create a simple table
	_, err = pg.db.Exec(`CREATE TABLE test_table (id SERIAL PRIMARY KEY, name TEXT)`)
	require.NoError(t, err, "failed to create test table")

	// Verify we can insert and retrieve data
	_, err = pg.db.Exec(`INSERT INTO test_table (name) VALUES ('test')`)
	require.NoError(t, err, "failed to insert test data")

	var count int
	err = pg.db.QueryRow(`SELECT COUNT(*) FROM test_table`).Scan(&count)
	require.NoError(t, err, "failed to query test table")
	assert.Equal(t, 1, count, "expected 1 row in test table")
}

// TestPostgresIntegration_MigrateDatabase verifies the schema.sql migration.
func TestPostgresIntegration_MigrateDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	pg := startPostgresContainer(t)
	defer pg.cleanup(t)

	// Apply migration
	schemaPath := "../../internal/storage/postgres/schema.sql"
	applyMigration(t, pg.db, schemaPath)

	// Verify bootstrap_token_policies table exists
	var exists bool
	err := pg.db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_name = 'bootstrap_token_policies'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	assert.True(t, exists, "bootstrap_token_policies table should exist")

	// Verify refresh_token_families table exists
	err = pg.db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_name = 'refresh_token_families'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	assert.True(t, exists, "refresh_token_families table should exist")

	// Verify indexes exist on bootstrap_token_policies
	var indexExists bool
	err = pg.db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM pg_indexes
			WHERE tablename = 'bootstrap_token_policies'
			AND indexname = 'idx_bootstrap_token_policies_token_hash'
		)
	`).Scan(&indexExists)
	require.NoError(t, err)
	assert.True(t, indexExists, "token_hash index should exist")

	// Verify indexes exist on refresh_token_families
	err = pg.db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM pg_indexes
			WHERE tablename = 'refresh_token_families'
			AND indexname = 'idx_refresh_token_families_current_token_hash'
		)
	`).Scan(&indexExists)
	require.NoError(t, err)
	assert.True(t, indexExists, "current_token_hash index should exist")
}

// TestPostgresIntegration_BootstrapTokenLifecycle verifies bootstrap token CRUD operations.
func TestPostgresIntegration_BootstrapTokenLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	pg := startPostgresContainer(t)
	defer pg.cleanup(t)

	// Apply migration
	schemaPath := "../../internal/storage/postgres/schema.sql"
	applyMigration(t, pg.db, schemaPath)

	ctx := context.Background()
	now := time.Now().UTC()

	// Create a bootstrap token policy
	tokenPlaintext := "bootstrap-token-12345"
	tokenHash := hashToken(tokenPlaintext)
	policyID := "policy-test-001"

	_, err := pg.db.ExecContext(ctx, `
		INSERT INTO bootstrap_token_policies (
			id, subject, audience, scopes, ttl, refresh_ttl,
			token_hash, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		policyID,
		"boot-service",
		"hsm",
		`["read", "write"]`,
		int64(time.Hour),
		int64(24*time.Hour),
		tokenHash,
		now,
		now.Add(time.Hour),
	)
	require.NoError(t, err, "failed to insert bootstrap token policy")

	// Retrieve by token_hash (O(1) lookup via index)
	var retrievedID, subject, audience string
	var consumed sql.NullTime
	err = pg.db.QueryRowContext(ctx, `
		SELECT id, subject, audience, consumed_at
		FROM bootstrap_token_policies
		WHERE token_hash = $1
	`, tokenHash).Scan(&retrievedID, &subject, &audience, &consumed)
	require.NoError(t, err, "failed to retrieve bootstrap token policy")
	assert.Equal(t, policyID, retrievedID)
	assert.Equal(t, "boot-service", subject)
	assert.Equal(t, "hsm", audience)
	assert.False(t, consumed.Valid, "token should not be consumed yet")

	// Mark as consumed
	consumedAt := now.Add(5 * time.Minute)
	consumedIP := "192.168.1.100"
	_, err = pg.db.ExecContext(ctx, `
		UPDATE bootstrap_token_policies
		SET consumed_at = $1, consumed_by_ip = $2
		WHERE token_hash = $3
	`, consumedAt, consumedIP, tokenHash)
	require.NoError(t, err, "failed to mark token as consumed")

	// Verify consumed state
	err = pg.db.QueryRowContext(ctx, `
		SELECT consumed_at
		FROM bootstrap_token_policies
		WHERE token_hash = $1
	`, tokenHash).Scan(&consumed)
	require.NoError(t, err)
	assert.True(t, consumed.Valid, "token should be consumed")
	assert.WithinDuration(t, consumedAt, consumed.Time, time.Second)

	// Verify we can't find non-existent token (negative case)
	err = pg.db.QueryRowContext(ctx, `
		SELECT id FROM bootstrap_token_policies WHERE token_hash = $1
	`, "nonexistent-hash").Scan(&retrievedID)
	assert.ErrorIs(t, err, sql.ErrNoRows, "should not find non-existent token")
}

// TestPostgresIntegration_RefreshTokenRotation verifies refresh token rotation.
func TestPostgresIntegration_RefreshTokenRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	pg := startPostgresContainer(t)
	defer pg.cleanup(t)

	// Apply migration
	schemaPath := "../../internal/storage/postgres/schema.sql"
	applyMigration(t, pg.db, schemaPath)

	ctx := context.Background()
	now := time.Now().UTC()

	// Create initial refresh token family
	familyID := "family-test-001"
	token1 := "refresh-token-v1"
	hash1 := hashToken(token1)

	_, err := pg.db.ExecContext(ctx, `
		INSERT INTO refresh_token_families (
			family_id, current_token_hash, subject, audience, scopes,
			issued_at, expires_at, last_used_at, usage_count
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		familyID, hash1, "service-a", "service-b", `["read"]`,
		now, now.Add(7*24*time.Hour), now, 0,
	)
	require.NoError(t, err, "failed to insert refresh token family")

	// Verify initial token is valid (O(1) lookup via index)
	var retrievedFamilyID string
	var usageCount int
	err = pg.db.QueryRowContext(ctx, `
		SELECT family_id, usage_count
		FROM refresh_token_families
		WHERE current_token_hash = $1
	`, hash1).Scan(&retrievedFamilyID, &usageCount)
	require.NoError(t, err, "failed to retrieve refresh token family")
	assert.Equal(t, familyID, retrievedFamilyID)
	assert.Equal(t, 0, usageCount)

	// Rotate token (update current_token_hash)
	token2 := "refresh-token-v2"
	hash2 := hashToken(token2)
	newLastUsedAt := now.Add(10 * time.Minute)

	_, err = pg.db.ExecContext(ctx, `
		UPDATE refresh_token_families
		SET current_token_hash = $1, last_used_at = $2, usage_count = usage_count + 1
		WHERE family_id = $3 AND current_token_hash = $4
	`, hash2, newLastUsedAt, familyID, hash1)
	require.NoError(t, err, "failed to rotate refresh token")

	// Verify old token is no longer valid
	err = pg.db.QueryRowContext(ctx, `
		SELECT family_id FROM refresh_token_families WHERE current_token_hash = $1
	`, hash1).Scan(&retrievedFamilyID)
	assert.ErrorIs(t, err, sql.ErrNoRows, "old token should not be found")

	// Verify new token is valid
	err = pg.db.QueryRowContext(ctx, `
		SELECT family_id, usage_count
		FROM refresh_token_families
		WHERE current_token_hash = $1
	`, hash2).Scan(&retrievedFamilyID, &usageCount)
	require.NoError(t, err, "failed to retrieve rotated token")
	assert.Equal(t, familyID, retrievedFamilyID)
	assert.Equal(t, 1, usageCount, "usage_count should be incremented")

	// Test replay detection: attempt to use old token again
	var replayDetected sql.NullTime
	err = pg.db.QueryRowContext(ctx, `
		SELECT replay_detected_at
		FROM refresh_token_families
		WHERE family_id = $1
	`, familyID).Scan(&replayDetected)
	require.NoError(t, err)
	assert.False(t, replayDetected.Valid, "replay should not be detected yet")

	// Mark replay detected
	replayTime := now.Add(15 * time.Minute)
	_, err = pg.db.ExecContext(ctx, `
		UPDATE refresh_token_families
		SET replay_detected_at = $1
		WHERE family_id = $2
	`, replayTime, familyID)
	require.NoError(t, err)

	// Verify replay detection was recorded
	err = pg.db.QueryRowContext(ctx, `
		SELECT replay_detected_at
		FROM refresh_token_families
		WHERE family_id = $1
	`, familyID).Scan(&replayDetected)
	require.NoError(t, err)
	assert.True(t, replayDetected.Valid, "replay should be detected")
}

// TestPostgresIntegration_ExpiryCleanup verifies expiry cleanup queries.
func TestPostgresIntegration_ExpiryCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	pg := startPostgresContainer(t)
	defer pg.cleanup(t)

	// Apply migration
	schemaPath := "../../internal/storage/postgres/schema.sql"
	applyMigration(t, pg.db, schemaPath)

	ctx := context.Background()
	now := time.Now().UTC()

	// Create expired bootstrap token
	expiredToken := hashToken("expired-token")
	_, err := pg.db.ExecContext(ctx, `
		INSERT INTO bootstrap_token_policies (
			id, subject, audience, scopes, ttl, refresh_ttl,
			token_hash, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		"expired-policy",
		"service-x",
		"service-y",
		`["read"]`,
		int64(time.Hour),
		int64(24*time.Hour),
		expiredToken,
		now.Add(-2*time.Hour),
		now.Add(-1*time.Hour), // expired 1 hour ago
	)
	require.NoError(t, err)

	// Create active bootstrap token
	activeToken := hashToken("active-token")
	_, err = pg.db.ExecContext(ctx, `
		INSERT INTO bootstrap_token_policies (
			id, subject, audience, scopes, ttl, refresh_ttl,
			token_hash, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		"active-policy",
		"service-x",
		"service-y",
		`["read"]`,
		int64(time.Hour),
		int64(24*time.Hour),
		activeToken,
		now,
		now.Add(time.Hour), // expires 1 hour from now
	)
	require.NoError(t, err)

	// Create expired refresh token family
	expiredFamily := "expired-family"
	_, err = pg.db.ExecContext(ctx, `
		INSERT INTO refresh_token_families (
			family_id, current_token_hash, subject, audience, scopes,
			issued_at, expires_at, last_used_at, usage_count
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		expiredFamily, hashToken("old-refresh"), "service-a", "service-b", `["read"]`,
		now.Add(-8*24*time.Hour), now.Add(-1*24*time.Hour), now.Add(-1*24*time.Hour), 5,
	)
	require.NoError(t, err)

	// Create active refresh token family
	activeFamily := "active-family"
	_, err = pg.db.ExecContext(ctx, `
		INSERT INTO refresh_token_families (
			family_id, current_token_hash, subject, audience, scopes,
			issued_at, expires_at, last_used_at, usage_count
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		activeFamily, hashToken("new-refresh"), "service-a", "service-b", `["read"]`,
		now, now.Add(7*24*time.Hour), now, 0,
	)
	require.NoError(t, err)

	// Run cleanup query for bootstrap tokens (O(1) with index)
	result, err := pg.db.ExecContext(ctx, `
		DELETE FROM bootstrap_token_policies WHERE expires_at < $1
	`, now)
	require.NoError(t, err)
	deleted, err := result.RowsAffected()
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "should delete 1 expired bootstrap token")

	// Run cleanup query for refresh token families (O(1) with index)
	result, err = pg.db.ExecContext(ctx, `
		DELETE FROM refresh_token_families WHERE expires_at < $1
	`, now)
	require.NoError(t, err)
	deleted, err = result.RowsAffected()
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "should delete 1 expired refresh token family")

	// Verify active tokens still exist
	var count int
	err = pg.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM bootstrap_token_policies WHERE token_hash = $1
	`, activeToken).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "active bootstrap token should remain")

	err = pg.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM refresh_token_families WHERE family_id = $1
	`, activeFamily).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "active refresh token family should remain")

	// Verify expired tokens are gone
	err = pg.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM bootstrap_token_policies WHERE token_hash = $1
	`, expiredToken).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "expired bootstrap token should be deleted")

	err = pg.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM refresh_token_families WHERE family_id = $1
	`, expiredFamily).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "expired refresh token family should be deleted")
}

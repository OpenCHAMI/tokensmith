// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/openchami/tokensmith/internal/storage"
	"github.com/openchami/tokensmith/internal/storage/ent"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/tokenservice"
	"github.com/rs/zerolog/log"

	_ "github.com/lib/pq"
)

func initializeStorage(databaseURL string) error {
	client, err := ent.Open("postgres", databaseURL)
	if err != nil {
		return fmt.Errorf("failed opening connection to postgres: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.Schema.Create(ctx); err != nil {
		_ = client.Close()
		return fmt.Errorf("failed creating schema resources: %w", err)
	}

	storage.SetEntClient(client)

	log.Info().Msg("Database schema migration completed successfully")

	return nil
}

func initializeTokenService() (*tokenservice.TokenService, error) {
	configPath := os.Getenv("CONFIG")
	var fileConfig *tokenservice.FileConfig
	var err error

	if configPath != "" {
		fileConfig, err = tokenservice.LoadFileConfig(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load config from %s: %w", configPath, err)
		}
	} else {
		fileConfig = tokenservice.DefaultFileConfig()
	}

	keyManager := keys.NewKeyManager()

	keyFile := os.Getenv("KEY_FILE")
	if keyFile != "" {
		if err := keyManager.LoadPrivateKey(keyFile); err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}
	} else {
		if err := keyManager.GenerateRSAKeyPair(); err != nil {
			return nil, fmt.Errorf("failed to generate key pair: %w", err)
		}
	}

	config := tokenservice.Config{
		Issuer:                    getEnvOrDefault("ISSUER", "http://tokensmith:8080"),
		GroupScopes:               fileConfig.GroupScopes,
		ClusterID:                 getEnvOrDefault("CLUSTER_ID", "cluster-default"),
		OpenCHAMIID:               getEnvOrDefault("OPENCHAMI_ID", "openchami-default"),
		OIDCIssuerURL:             os.Getenv("OIDC_ISSUER_URL"),
		OIDCClientID:              os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret:          os.Getenv("OIDC_CLIENT_SECRET"),
		RFC8693BootstrapStorePath: getEnvOrDefault("RFC8693_BOOTSTRAP_STORE_PATH", "/data/bootstrap-tokens"),
		RFC8693RefreshStorePath:   getEnvOrDefault("RFC8693_REFRESH_STORE_PATH", "/data/refresh-families"),
		ServiceIdentityCAPath:     os.Getenv("SERVICE_IDENTITY_CA_PATH"),
	}

	tokenService, err := tokenservice.NewTokenService(keyManager, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TokenService: %w", err)
	}

	log.Info().
		Str("issuer", config.Issuer).
		Str("cluster_id", config.ClusterID).
		Msg("TokenService initialized")

	return tokenService, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

func main() {
	// Configure structured logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zlog.Logger = zlog.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Initialize Ent client if DATABASE_URL is set
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL != "" {
		if err := initializeStorage(databaseURL); err != nil {
			log.Fatalf("Failed to initialize storage: %v", err)
		}
		zlog.Info().Msg("Ent storage initialized with PostgreSQL")
	} else {
		zlog.Info().Msg("Running without PostgreSQL (file-based storage)")
	}

	// Initialize TokenService with configuration from environment
	tokenService, err := initializeTokenService()
	if err != nil {
		log.Fatalf("Failed to initialize TokenService: %v", err)
	}

	// Setup router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// RFC 8693 OAuth token endpoint
	// Per RFC 8693 Section 2: Token Exchange
	r.Post("/oauth/token", tokenService.OAuthTokenHandler)

	// JWKS endpoint for public key discovery
	r.Get("/.well-known/jwks.json", tokenService.JWKSHandler)

	// Start server
	port := getEnvOrDefault("PORT", "8080")
	addr := fmt.Sprintf(":%s", port)

	server := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		zlog.Info().Str("addr", addr).Msg("TokenSmith server starting")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	<-done
	zlog.Info().Msg("Server shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	zlog.Info().Msg("Server exited")
}

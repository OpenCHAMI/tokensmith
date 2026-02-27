// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// minisvc is a small demonstration service showing how to wire TokenSmith
// AuthN (JWT) + AuthZ (Casbin) middleware.
//
// It demonstrates:
//   - One public endpoint (/public)
//   - One protected endpoint using explicit RouteMapper style (/protected/mapper)
//   - One protected endpoint using Casbin-native path/method style + keyMatch2
//     (/protected/path/...)
//
// Run:
//
//	go run ./examples/minisvc
//
// Notes:
// - This is an example only. It is not imported by library packages.
// - Policies are loaded from ./examples/minisvc/policy.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/authn"
	"github.com/openchami/tokensmith/pkg/authz"
	"github.com/openchami/tokensmith/pkg/authz/engine"
	"github.com/openchami/tokensmith/pkg/authz/presets"
)

type principalClaims struct {
	Sub   string   `json:"sub"`
	Roles []string `json:"roles"`
}

func main() {
	var (
		addr          = flag.String("addr", ":8085", "listen address")
		issuer        = flag.String("issuer", "https://issuer.example", "expected JWT issuer")
		audience      = flag.String("aud", "minisvc", "expected JWT audience")
		jwksURL       = flag.String("jwks", "", "JWKS URL (optional; if empty, uses policy/test jwks env)")
		policyDir     = flag.String("policy", "./examples/minisvc/policy", "policy directory")
		mode          = flag.String("mode", "enforce", "authz mode: off|shadow|enforce")
		allowUnmapped = flag.Bool("allow-unmapped", false, "allow unmapped routes in enforce")
	)
	flag.Parse()

	m, err := parseMode(*mode)
	if err != nil {
		log.Fatalf("invalid mode: %v", err)
	}

	// ---- AuthZ (Casbin) wiring ----
	//
	// Use a preset model (keyMatch2 + REST-ish actions), but load policy/grouping
	// from disk so operators can edit standard Casbin files.
	preset := presets.RBACKeyMatch2REST()
	_ = preset.ModelText // matches model.conf; kept to show the preset pairing.
	requiredFuncs := preset.RequiredFunctions

	policyDirClean := strings.TrimRight(*policyDir, "/")
	modelPath := fmt.Sprintf("%s/model.conf", policyDirClean)
	policyPath := fmt.Sprintf("%s/policy.csv", policyDirClean)
	groupingPath := fmt.Sprintf("%s/grouping.csv", policyDirClean)

	authorizer, err := engine.NewBuilder().
		WithModelPath(modelPath).
		WithPolicyPath(policyPath).
		WithGroupingPath(groupingPath).
		WithRequiredFunctions(requiredFuncs...).
		Build()
	if err != nil {
		log.Fatalf("authz engine init failed: %v", err)
	}

	// Mapper style: explicit object/action mapping.
	mapper := routeMapper{}

	// Path/method style: Casbin gets obj=r.URL.Path and act derived from method.
	pathMapper := authz.PathMethodMapper{
		MethodToAction: authz.MethodToActionREST(),
	}

	// ---- AuthN (JWT) wiring ----
	//
	// For a real service you would configure issuer/audience/JWKS via env.
	// This example supports a JWKS URL flag but can also run without it.
	jwks := *jwksURL
	if jwks == "" {
		jwks = os.Getenv("TOKENSMITH_EXAMPLE_JWKS_URL")
	}

	authnMW, err := authn.Middleware(authn.Options{
		Issuers:   []string{*issuer},
		Audiences: []string{*audience},
		JWKSURLs:  nonEmpty([]string{jwks}),
		Mapper: func(ctx context.Context, _ *jwt.Token, claims jwt.MapClaims) (authz.Principal, error) {
			// Keep it intentionally simple: {"sub":"user1","roles":["viewer"]}
			b, _ := json.Marshal(map[string]any(claims))
			var pc principalClaims
			_ = json.Unmarshal(b, &pc)
			return authz.Principal{ID: pc.Sub, Roles: append([]string(nil), pc.Roles...)}, nil
		},
	})
	if err != nil {
		log.Fatalf("authn init failed: %v", err)
	}

	// ---- Routes ----
	mux := http.NewServeMux()

	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "public": true})
	})

	mux.HandleFunc("/protected/mapper", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "route": "mapper"})
	})

	mux.HandleFunc("/protected/path/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "route": "path"})
	})

	// Compose middleware:
	// - AuthN is global (sets principal when present)
	// - AuthZ is applied twice to show both mapping styles:
	//   * mapper applies to /protected/mapper
	//   * pathMapper applies to /protected/path/*
	// - public bypass is configured so /public does not trigger evaluation.
	base := authnMW(mux)

	authzMapperMW := authz.NewMiddleware(
		authorizer,
		mapper,
		authz.WithMode(m),
		authz.WithRequireAuthn(true),
		authz.WithAllowUnmapped(*allowUnmapped),
		authz.WithPublicPrefixes([]string{"/public"}),
	)

	authzPathMW := authz.NewMiddleware(
		authorizer,
		pathMapper,
		authz.WithMode(m),
		authz.WithRequireAuthn(true),
		authz.WithAllowUnmapped(true), // pathMapper only maps /protected/path/*; allow others
		authz.WithPublicPrefixes([]string{"/public"}),
	)

	h := authzMapperMW.Handler(authzPathMW.Handler(base))

	log.Printf("minisvc listening on %s (mode=%s, policy_dir=%s)", *addr, m, *policyDir)
	log.Printf("endpoints: /public, /protected/mapper, /protected/path/<anything>")
	log.Fatal(http.ListenAndServe(*addr, h))
}

func parseMode(s string) (authz.Mode, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "off":
		return authz.ModeOff, nil
	case "shadow":
		return authz.ModeShadow, nil
	case "enforce", "":
		return authz.ModeEnforce, nil
	default:
		return authz.ModeEnforce, fmt.Errorf("unknown mode %q", s)
	}
}

func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

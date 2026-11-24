// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
// SPDX-License-Identifier: MIT

package authn

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/authz"
	"github.com/openchami/tokensmith/pkg/keys"
	tstoken "github.com/openchami/tokensmith/pkg/token"
)

type Mode int

const (
	AuthNEnforce Mode = iota
	AuthNOff
)

type nowFunc func() time.Time

// PrincipalMapper maps verified legacy claims only; human roles come from signed claims.
type PrincipalMapper func(context.Context, *jwt.Token, jwt.MapClaims) (authz.Principal, error)

// RevocationChecker is consulted after verification and before context installation.
type RevocationChecker interface{ IsRevoked(jti string) bool }

type Options struct {
	Mode                      Mode
	ValidateIssuer            bool
	DisableIssuerValidation   bool
	Issuers                   []string
	ValidateAudience          bool
	DisableAudienceValidation bool
	Audiences                 []string
	// ClockSkew defaults to 2m (maximum 10m) for legacy tokens only.
	ClockSkew         time.Duration
	StaticKeys        []crypto.PublicKey
	JWKSURLs          []string
	JWKSCacheSoftTTL  time.Duration
	JWKSCacheHardTTL  time.Duration
	HTTPClient        *http.Client
	Mapper            PrincipalMapper
	RevocationChecker RevocationChecker
	// Profiles defaults to legacy-v1; a policy alone never enables human tokens.
	Profiles           []tstoken.Profile
	HumanSessionPolicy *tstoken.HumanSessionPolicy
	// HumanSessionKeyLookup is an authoritative human-only alternative to static/JWKS
	// keys, for compatibility with named device keys. Failures never fall back.
	// It must resolve keys provisioned for HumanSessionPolicy.ClusterIssuer only.
	HumanSessionKeyLookup func(context.Context, string) (*rsa.PublicKey, error)
	staticKeysByKID       map[string]crypto.PublicKey
	now                   nowFunc
}

func (o Options) withDefaults() (Options, error) {
	out := o
	out.ValidateIssuer = !out.DisableIssuerValidation
	out.ValidateAudience = !out.DisableAudienceValidation
	if out.ClockSkew == 0 {
		out.ClockSkew = 2 * time.Minute
	}
	if out.ClockSkew > 10*time.Minute {
		return Options{}, errors.New("clock skew too large (max 10m)")
	}
	if out.HTTPClient == nil {
		out.HTTPClient = http.DefaultClient
	}
	if out.JWKSCacheSoftTTL == 0 {
		out.JWKSCacheSoftTTL = 10 * time.Minute
	}
	if out.JWKSCacheHardTTL == 0 {
		out.JWKSCacheHardTTL = time.Hour
	}
	if out.now == nil {
		out.now = time.Now
	}
	if out.Mapper == nil {
		out.Mapper = func(_ context.Context, _ *jwt.Token, c jwt.MapClaims) (authz.Principal, error) {
			sub, _ := c["sub"].(string)
			return authz.Principal{ID: sub}, nil
		}
	}
	out.Issuers = slices.Clone(out.Issuers)
	out.Audiences = slices.Clone(out.Audiences)
	out.JWKSURLs = slices.Clone(out.JWKSURLs)
	out.Profiles = slices.Clone(out.Profiles)
	if len(out.Profiles) == 0 {
		out.Profiles = []tstoken.Profile{tstoken.ProfileLegacyV1}
	}
	if out.HumanSessionPolicy != nil {
		p := *out.HumanSessionPolicy
		out.HumanSessionPolicy = &p
	}
	seen := make(map[tstoken.Profile]bool)
	for _, profile := range out.Profiles {
		if seen[profile] {
			return Options{}, errors.New("duplicate token profile")
		}
		seen[profile] = true
		switch profile {
		case tstoken.ProfileLegacyV1:
		case tstoken.ProfileHumanSessionV1:
			p := out.HumanSessionPolicy
			if p == nil || p.Validate() != nil || !out.ValidateIssuer || !out.ValidateAudience || len(out.Issuers) != 1 || len(out.Audiences) != 1 || out.Issuers[0] != p.ClusterIssuer || out.Audiences[0] != p.Audience {
				return Options{}, errors.New("human profile requires matching single issuer, audience and bounded policy")
			}
		default:
			return Options{}, errors.New("unknown token profile")
		}
	}
	if len(out.StaticKeys) > 0 {
		out.staticKeysByKID = make(map[string]crypto.PublicKey, len(out.StaticKeys))
		for _, key := range out.StaticKeys {
			kid, err := keys.RFC7638Thumbprint(key)
			if err != nil {
				return Options{}, fmt.Errorf("invalid static key for RFC 7638 kid derivation: %w", err)
			}
			out.staticKeysByKID[kid] = key
		}
	}
	if out.ValidateIssuer && len(out.Issuers) == 0 {
		return Options{}, errors.New("issuer validation enabled but no issuers configured")
	}
	if out.ValidateAudience && len(out.Audiences) == 0 {
		return Options{}, errors.New("audience validation enabled but no audiences configured")
	}
	if len(out.StaticKeys) == 0 && len(out.JWKSURLs) == 0 && (out.HumanSessionKeyLookup == nil || seen[tstoken.ProfileLegacyV1]) {
		return Options{}, errors.New("no JWT verification keys configured")
	}
	return out, nil
}

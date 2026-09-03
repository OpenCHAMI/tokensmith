// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SimpleProvider is a simplified OIDC provider that uses discovery endpoint
// ValidationMode selects how upstream tokens are validated.
type ValidationMode string

const (
	// ValidationModeOffline verifies a JWT against the provider's published JWKS
	// and falls back to introspection when that does not succeed. This is the
	// default: it removes a network round-trip per exchange and keeps working
	// while the provider is unreachable.
	ValidationModeOffline ValidationMode = "offline"

	// ValidationModeOnline calls the provider's introspection endpoint first and
	// falls back to local JWKS validation only when the endpoint cannot be
	// reached. Introspection observes revocation immediately, which local
	// validation cannot do, at the cost of a round-trip per exchange.
	ValidationModeOnline ValidationMode = "online"
)

// ParseValidationMode converts a configured string into a ValidationMode.
// An empty value selects the default (offline).
func ParseValidationMode(value string) (ValidationMode, error) {
	switch ValidationMode(strings.ToLower(strings.TrimSpace(value))) {
	case "", ValidationModeOffline:
		return ValidationModeOffline, nil
	case ValidationModeOnline:
		return ValidationModeOnline, nil
	default:
		return "", fmt.Errorf("unsupported OIDC validation mode %q (want %q or %q)",
			value, ValidationModeOffline, ValidationModeOnline)
	}
}

type SimpleProvider struct {
	issuerURL        string
	clientID         string
	clientSecret     string
	discoveryURL     string
	httpClient       *http.Client
	jwksUpdatePeriod time.Duration
	validationMode   ValidationMode

	// mu guards the cached discovery metadata and JWKS, which are read and
	// written concurrently by HTTP handlers.
	metadataTTL time.Duration

	mu               sync.RWMutex
	metadata         *ProviderMetadata
	lastMetadataLoad time.Time
	jwks             map[string]interface{}
	lastJWKSUpdate   time.Time
}

type SimpleProviderOption func(*SimpleProvider)

func WithHTTPClient(client *http.Client) SimpleProviderOption {
	return func(provider *SimpleProvider) {
		if client != nil {
			provider.httpClient = client
		}
	}
}

// WithValidationMode selects offline (JWKS) or online (introspection) as the
// primary validation path. Both remain available as fallbacks either way.
func WithValidationMode(mode ValidationMode) SimpleProviderOption {
	return func(provider *SimpleProvider) {
		if mode != "" {
			provider.validationMode = mode
		}
	}
}

// NewSimpleProvider creates a new simplified OIDC provider
func NewSimpleProvider(issuerURL, clientID, clientSecret string, options ...SimpleProviderOption) *SimpleProvider {
	provider := &SimpleProvider{
		issuerURL:        issuerURL,
		clientID:         clientID,
		clientSecret:     clientSecret,
		discoveryURL:     fmt.Sprintf("%s/.well-known/openid-configuration", issuerURL),
		httpClient:       &http.Client{},
		jwksUpdatePeriod: 24 * time.Hour,
		metadataTTL:      24 * time.Hour,
		validationMode:   ValidationModeOffline,
	}
	for _, option := range options {
		option(provider)
	}
	return provider
}

// IntrospectToken introspects a token using the OIDC provider
// IntrospectToken validates a token against the configured provider.
//
// Both validation paths are always available. The configured ValidationMode
// selects which is tried first:
//
//   - offline (default): verify the JWT signature against the provider's cached
//     JWKS, falling back to introspection if that does not succeed.
//   - online: call the introspection endpoint, falling back to local JWKS
//     validation only when the endpoint cannot be reached.
//
// Opaque (non-JWT) tokens can only be introspected, so they always take the
// remote path regardless of mode.
func (p *SimpleProvider) IntrospectToken(ctx context.Context, token string) (*IntrospectionResponse, error) {
	if !looksLikeJWT(token) {
		return p.introspectTokenRemotely(ctx, token)
	}

	if p.ValidationMode() == ValidationModeOnline {
		response, err := p.introspectTokenRemotely(ctx, token)
		if err == nil {
			return response, nil
		}
		// Only an unreachable endpoint justifies falling back. A provider that
		// answered and rejected the token is authoritative, and retrying locally
		// would override its revocation decision -- the whole reason for
		// choosing online mode.
		if !errors.Is(err, ErrUpstreamUnavailable) && !errors.Is(err, ErrProviderMetadata) {
			return nil, err
		}
		local, localErr := p.validateTokenOffline(ctx, token)
		if localErr != nil {
			return nil, err
		}
		return local, nil
	}

	// Offline mode. A JWKS that cannot be fetched is an infrastructure failure
	// and falls back to introspection; a token that fails validation against a
	// JWKS we did fetch is simply invalid and is rejected here.
	//
	// Falling back on invalid tokens would let anyone holding a forged token
	// drive an outbound introspection call per attempt, and would give a token
	// the local check already rejected a second chance at acceptance.
	response, err := p.validateTokenOffline(ctx, token)
	if err == nil {
		return response, nil
	}
	if errors.Is(err, ErrProviderMetadata) {
		return p.introspectTokenRemotely(ctx, token)
	}
	return nil, err
}

// validateTokenOffline verifies a JWT against the cached JWKS, refreshing the
// key set once if the token's `kid` is unknown so that upstream key rotation is
// picked up without waiting for the cache to expire.
func (p *SimpleProvider) validateTokenOffline(ctx context.Context, token string) (*IntrospectionResponse, error) {
	// A fetch failure is wrapped as ErrProviderMetadata, which callers use to
	// distinguish "we could not get the keys" from "the token is invalid".
	if _, err := p.GetJWKS(ctx); err != nil {
		return nil, err
	}

	response, err := p.validateTokenLocally(token)
	if err == nil {
		return response, nil
	}
	if !errors.Is(err, errUnknownKeyID) {
		return nil, providerError("validate local token", ErrInvalidToken, err)
	}

	if refreshErr := p.refreshJWKS(ctx); refreshErr != nil {
		return nil, providerError("refresh JWKS", ErrProviderMetadata, refreshErr)
	}
	response, err = p.validateTokenLocally(token)
	if err != nil {
		return nil, providerError("validate local token", ErrInvalidToken, err)
	}
	return response, nil
}

// refreshJWKS forces a key-set refetch, bypassing the cache TTL.
func (p *SimpleProvider) refreshJWKS(ctx context.Context) error {
	return p.updateJWKS(ctx)
}

// ValidationMode reports the configured primary validation path.
func (p *SimpleProvider) ValidationMode() ValidationMode {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.validationMode == "" {
		return ValidationModeOffline
	}
	return p.validationMode
}

func looksLikeJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

// GetProviderMetadata returns the OIDC provider metadata
func (p *SimpleProvider) GetProviderMetadata(ctx context.Context) (*ProviderMetadata, error) {
	// Discovery is cached, but not forever: a provider that moves its
	// introspection or JWKS endpoint would otherwise require a restart to be
	// picked up.
	p.mu.RLock()
	cached := p.metadata
	fresh := cached != nil && time.Since(p.lastMetadataLoad) <= p.metadataTTL
	p.mu.RUnlock()
	if fresh {
		return cached, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", p.discoveryURL, nil)
	if err != nil {
		return nil, providerError("create provider metadata request", ErrProviderMetadata, err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, providerError("get provider metadata", ErrProviderMetadata, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, providerStatusError("get provider metadata", ErrProviderMetadata, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, providerError("read provider metadata response", ErrProviderMetadata, err)
	}

	var metadata ProviderMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, providerError("parse provider metadata", ErrProviderMetadata, err)
	}
	normalizeProviderMetadata(&metadata)

	if metadata.Issuer == "" {
		return nil, providerError("validate provider metadata", ErrProviderMetadata, fmt.Errorf("missing required field: issuer"))
	}
	if metadata.IntrospectionEndpoint == "" {
		return nil, providerError("validate provider metadata", ErrProviderMetadata, fmt.Errorf("missing required field: introspection_endpoint or token_introspection_endpoint"))
	}
	if metadata.JWKSURI == "" {
		return nil, providerError("validate provider metadata", ErrProviderMetadata, fmt.Errorf("missing required field: jwks_uri"))
	}

	p.mu.Lock()
	p.metadata = &metadata
	p.lastMetadataLoad = time.Now()
	p.mu.Unlock()

	return &metadata, nil
}

func normalizeProviderMetadata(metadata *ProviderMetadata) {
	if metadata.IntrospectionEndpoint == "" {
		metadata.IntrospectionEndpoint = metadata.TokenIntrospectionEndpoint
	}
}

// SupportsLocalIntrospection returns true if local introspection is supported
func (p *SimpleProvider) SupportsLocalIntrospection() bool {
	return true
}

// GetJWKS returns the JWKS for local token validation
func (p *SimpleProvider) GetJWKS(ctx context.Context) (interface{}, error) {
	p.mu.RLock()
	fresh := p.jwks != nil && time.Since(p.lastJWKSUpdate) <= p.jwksUpdatePeriod
	cached := p.jwks
	p.mu.RUnlock()

	if fresh {
		return cached, nil
	}
	if err := p.updateJWKS(ctx); err != nil {
		return nil, providerError("update JWKS", ErrProviderMetadata, err)
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.jwks, nil
}

// updateJWKS fetches the latest JWKS from the provider
func (p *SimpleProvider) updateJWKS(ctx context.Context) error {
	// Get metadata first to get JWKS URI
	metadata, err := p.GetProviderMetadata(ctx)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", metadata.JWKSURI, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var keySet map[string]interface{}
	if err := json.Unmarshal(body, &keySet); err != nil {
		return providerError("parse JWKS", ErrInvalidResponse, err)
	}

	p.mu.Lock()
	p.jwks = keySet
	p.lastJWKSUpdate = time.Now()
	p.mu.Unlock()

	return nil
}

// validateTokenLocally validates a token using local JWKS
func (p *SimpleProvider) validateTokenLocally(token string) (*IntrospectionResponse, error) {
	// Parse the token without verification first to get the key ID
	parser := jwt.Parser{}
	unverifiedToken, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Get the key ID from the token header
	kid, ok := unverifiedToken.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("token missing key ID")
	}

	// Find the matching key in JWKS
	key, err := p.findKeyByID(kid)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	parser = *jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	parsedToken, err := parser.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	if err := p.validateCoreClaims(claims); err != nil {
		return nil, err
	}

	// Convert claims to map[string]interface{}
	claimsMap := make(map[string]interface{})
	for k, v := range claims {
		claimsMap[k] = v
	}

	// Check if token is expired
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("token missing expiration")
	}

	active := time.Unix(int64(exp), 0).After(time.Now())

	return &IntrospectionResponse{
		Active: active,
		Username: firstNonEmptyString(
			getStringFromClaims(claims, "preferred_username"),
			getStringFromClaims(claims, "username"),
			getStringFromClaims(claims, "sub"),
		),
		ExpiresAt: int64(exp),
		IssuedAt:  int64(getFloat64FromClaims(claims, "iat")),
		Claims:    claimsMap,
		TokenType: "Bearer",
		ClientID:  getStringFromClaims(claims, "aud"),
		Scope:     getStringFromClaims(claims, "scope"),
	}, nil
}

func (p *SimpleProvider) validateCoreClaims(claims jwt.MapClaims) error {
	issuer, ok := claims["iss"].(string)
	if !ok || !p.issuerMatches(issuer) {
		return fmt.Errorf("invalid token issuer")
	}
	if !claimMatchesClient(claims, p.clientID) {
		return fmt.Errorf("invalid token audience")
	}
	return nil
}

func claimMatchesClient(claims map[string]interface{}, expected string) bool {
	if claimHasAudience(claims["aud"], expected) {
		return true
	}
	if azp, ok := claims["azp"].(string); ok && azp == expected {
		return true
	}
	if clientID, ok := claims["client_id"].(string); ok && clientID == expected {
		return true
	}
	return false
}

func claimHasAudience(value interface{}, expected string) bool {
	if expected == "" {
		return false
	}
	switch audience := value.(type) {
	case string:
		return audience == expected
	case []string:
		for _, item := range audience {
			if item == expected {
				return true
			}
		}
	case []interface{}:
		for _, item := range audience {
			if item == expected {
				return true
			}
		}
	}
	return false
}

// introspectTokenRemotely introspects a token using the provider's introspection endpoint
func (p *SimpleProvider) introspectTokenRemotely(ctx context.Context, token string) (*IntrospectionResponse, error) {
	metadata, err := p.GetProviderMetadata(ctx)
	if err != nil {
		return nil, err
	}

	formData := url.Values{"token": []string{token}}.Encode()

	req, err := http.NewRequestWithContext(ctx, "POST", metadata.IntrospectionEndpoint, strings.NewReader(formData))
	if err != nil {
		return nil, providerError("create token introspection request", ErrUpstreamUnavailable, err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.clientID, p.clientSecret)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, providerError("introspect token", ErrUpstreamUnavailable, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		// A 5xx means the provider could not answer, which is an availability
		// problem and may be worth falling back on. A 4xx means it answered and
		// refused -- that is authoritative and must not be retried elsewhere.
		kind := ErrUpstreamRejected
		if resp.StatusCode >= 500 {
			kind = ErrUpstreamUnavailable
		}
		return nil, providerStatusError("introspect token", kind, resp.StatusCode)
	}

	introspection, err := decodeIntrospectionResponse(resp.Body)
	if err != nil {
		return nil, providerError("decode token introspection response", ErrInvalidResponse, err)
	}
	if err := p.validateRemoteIntrospection(token, introspection); err != nil {
		return nil, err
	}

	return introspection, nil
}

func decodeIntrospectionResponse(reader io.Reader) (*IntrospectionResponse, error) {
	var raw map[string]interface{}
	if err := json.NewDecoder(reader).Decode(&raw); err != nil {
		return nil, err
	}

	claims := map[string]interface{}{}
	if nestedClaims, ok := raw["claims"].(map[string]interface{}); ok {
		for key, value := range nestedClaims {
			claims[key] = value
		}
	}
	for key, value := range raw {
		switch key {
		case "active", "claims":
			continue
		default:
			claims[key] = value
		}
	}

	return &IntrospectionResponse{
		Active:    boolFromRaw(raw["active"]),
		Username:  firstNonEmptyString(stringFromRaw(raw["username"]), stringFromRaw(raw["preferred_username"]), stringFromRaw(raw["sub"])),
		ExpiresAt: int64FromRaw(raw["exp"]),
		IssuedAt:  int64FromRaw(raw["iat"]),
		Claims:    claims,
		TokenType: stringFromRaw(raw["token_type"]),
		Scope:     stringFromRaw(raw["scope"]),
		ClientID:  firstNonEmptyString(stringFromRaw(raw["client_id"]), audienceString(raw["aud"])),
	}, nil
}

func (p *SimpleProvider) validateRemoteIntrospection(token string, introspection *IntrospectionResponse) error {
	if introspection == nil || !introspection.Active {
		return nil
	}
	issuerValue, _ := introspection.Claims["iss"].(string)
	if !p.issuerMatches(issuerValue) {
		return providerError("validate introspection issuer", ErrInvalidToken, fmt.Errorf("invalid token issuer"))
	}
	if !claimMatchesClient(introspection.Claims, p.clientID) {
		return providerError("validate introspection audience", ErrInvalidToken, fmt.Errorf("invalid token audience"))
	}
	return nil
}

// issuerMatches compares a token issuer to the configured one, tolerating a
// trailing-slash difference. Operators routinely configure
// "https://host/realms/x/" while the provider issues "https://host/realms/x";
// rejecting that is surprising rather than safer, since the signature already
// binds the token to this provider's keys.
func (p *SimpleProvider) issuerMatches(issuer string) bool {
	return strings.TrimRight(issuer, "/") == strings.TrimRight(p.issuerURL, "/")
}

func boolFromRaw(value interface{}) bool {
	result, _ := value.(bool)
	return result
}

func int64FromRaw(value interface{}) int64 {
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case int64:
		return typed
	case int:
		return int64(typed)
	default:
		return 0
	}
}

func stringFromRaw(value interface{}) string {
	result, _ := value.(string)
	return result
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func audienceString(value interface{}) string {
	switch audience := value.(type) {
	case string:
		return audience
	case []interface{}:
		if len(audience) == 1 {
			return stringFromRaw(audience[0])
		}
	case []string:
		if len(audience) == 1 {
			return audience[0]
		}
	}
	return ""
}

// findKeyByID finds a key by ID in the JWKS
// errUnknownKeyID signals that the token's `kid` is absent from the cached JWKS,
// which usually means the provider rotated keys and warrants one refresh.
var errUnknownKeyID = errors.New("key ID not found in JWKS")

func (p *SimpleProvider) findKeyByID(kid string) (interface{}, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	keys, ok := p.jwks["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid JWKS format")
	}

	for _, keyInterface := range keys {
		keyMap, ok := keyInterface.(map[string]interface{})
		if !ok {
			continue
		}

		if keyID, ok := keyMap["kid"].(string); !ok || keyID != kid {
			continue
		}

		// Providers publish encryption keys alongside signing keys; only the
		// latter may verify a token.
		if use, ok := keyMap["use"].(string); ok && use != "" && use != "sig" {
			continue
		}

		return publicKeyFromJWK(keyMap)
	}

	return nil, fmt.Errorf("%w: %s", errUnknownKeyID, kid)
}

// publicKeyFromJWK converts a JWK into a Go public key, supporting the RSA and
// EC key types providers use for RS*/PS* and ES* signatures respectively.
func publicKeyFromJWK(keyMap map[string]interface{}) (interface{}, error) {
	switch kty, _ := keyMap["kty"].(string); kty {
	case "RSA":
		return rsaPublicKeyFromJWK(keyMap)
	case "EC":
		return ecPublicKeyFromJWK(keyMap)
	default:
		return nil, fmt.Errorf("unsupported key type %q (RSA and EC are supported)", kty)
	}
}

// ecPublicKeyFromJWK builds an ECDSA public key from a JWK (RFC 7518 §6.2).
func ecPublicKeyFromJWK(keyMap map[string]interface{}) (interface{}, error) {
	crv, _ := keyMap["crv"].(string)
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", crv)
	}

	xRaw, ok := keyMap["x"].(string)
	if !ok || xRaw == "" {
		return nil, errors.New("EC JWK is missing the x coordinate")
	}
	yRaw, ok := keyMap["y"].(string)
	if !ok || yRaw == "" {
		return nil, errors.New("EC JWK is missing the y coordinate")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(xRaw, "="))
	if err != nil {
		return nil, fmt.Errorf("invalid EC x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(yRaw, "="))
	if err != nil {
		return nil, fmt.Errorf("invalid EC y coordinate: %w", err)
	}

	key := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	// Reject a point that is not on the curve rather than letting verification
	// proceed with undefined behaviour.
	if !curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("EC JWK coordinates are not on the named curve")
	}
	return key, nil
}

func rsaPublicKeyFromJWK(keyMap map[string]interface{}) (*rsa.PublicKey, error) {
	kty, _ := keyMap["kty"].(string)
	if kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type %q", kty)
	}

	nValue, ok := keyMap["n"].(string)
	if !ok || nValue == "" {
		return nil, fmt.Errorf("missing RSA modulus")
	}
	eValue, ok := keyMap["e"].(string)
	if !ok || eValue == "" {
		return nil, fmt.Errorf("missing RSA exponent")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(nValue)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eValue)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA exponent: %w", err)
	}

	exponent := new(big.Int).SetBytes(eBytes)
	if !exponent.IsInt64() || exponent.Sign() <= 0 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}

	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(exponent.Int64())}, nil
}

// Helper functions
func getStringFromClaims(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func getFloat64FromClaims(claims jwt.MapClaims, key string) float64 {
	if val, ok := claims[key].(float64); ok {
		return val
	}
	return 0
}

// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SimpleProvider is a simplified OIDC provider that uses discovery endpoint
type SimpleProvider struct {
	issuerURL                     string
	clientID                      string
	clientSecret                  string
	discoveryURL                  string
	introspectionEndpointOverride string
	httpClient                    *http.Client
	metadata                      *ProviderMetadata
	jwks                          map[string]interface{}
	lastJWKSUpdate                time.Time
	jwksUpdatePeriod              time.Duration
}

type SimpleProviderOption func(*SimpleProvider)

func WithHTTPClient(client *http.Client) SimpleProviderOption {
	return func(provider *SimpleProvider) {
		if client != nil {
			provider.httpClient = client
		}
	}
}

// WithIntrospectionEndpoint overrides the provider discovery metadata endpoint
// used for remote OAuth token introspection.
func WithIntrospectionEndpoint(endpoint string) SimpleProviderOption {
	return func(provider *SimpleProvider) {
		provider.introspectionEndpointOverride = strings.TrimSpace(endpoint)
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
	}
	for _, option := range options {
		option(provider)
	}
	return provider
}

// IntrospectToken introspects a token using the OIDC provider
func (p *SimpleProvider) IntrospectToken(ctx context.Context, token string) (*IntrospectionResponse, error) {
	if looksLikeJWT(token) {
		if _, err := p.GetJWKS(ctx); err != nil {
			return p.introspectTokenRemotely(ctx, token)
		}
		if response, err := p.validateTokenLocally(token); err == nil {
			return response, nil
		} else {
			return nil, providerError("validate local token", ErrInvalidToken, err)
		}
	}

	return p.introspectTokenRemotely(ctx, token)
}

func looksLikeJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

// GetProviderMetadata returns the OIDC provider metadata
func (p *SimpleProvider) GetProviderMetadata(ctx context.Context) (*ProviderMetadata, error) {
	if p.metadata != nil {
		return p.metadata, nil
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
	p.normalizeProviderMetadata(&metadata)

	if metadata.Issuer == "" {
		return nil, providerError("validate provider metadata", ErrProviderMetadata, fmt.Errorf("missing required field: issuer"))
	}
	if metadata.IntrospectionEndpoint == "" {
		return nil, providerError("validate provider metadata", ErrProviderMetadata, fmt.Errorf("missing required field: oidc introspection endpoint override, token_introspection_endpoint, or introspection_endpoint"))
	}
	if metadata.JWKSURI == "" {
		return nil, providerError("validate provider metadata", ErrProviderMetadata, fmt.Errorf("missing required field: jwks_uri"))
	}

	p.metadata = &metadata
	return &metadata, nil
}

func (p *SimpleProvider) normalizeProviderMetadata(metadata *ProviderMetadata) {
	if p.introspectionEndpointOverride != "" {
		metadata.IntrospectionEndpoint = p.introspectionEndpointOverride
		return
	}
	if metadata.TokenIntrospectionEndpoint != "" {
		metadata.IntrospectionEndpoint = metadata.TokenIntrospectionEndpoint
	}
}

// SupportsLocalIntrospection returns true if local introspection is supported
func (p *SimpleProvider) SupportsLocalIntrospection() bool {
	return true
}

// GetJWKS returns the JWKS for local token validation
func (p *SimpleProvider) GetJWKS(ctx context.Context) (interface{}, error) {
	// Check if we need to update the JWKS
	if p.jwks == nil || time.Since(p.lastJWKSUpdate) > p.jwksUpdatePeriod {
		if err := p.updateJWKS(ctx); err != nil {
			return nil, providerError("update JWKS", ErrProviderMetadata, err)
		}
	}
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

	if err := json.Unmarshal(body, &p.jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	p.lastJWKSUpdate = time.Now()
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
		Active:    active,
		Username:  getStringFromClaims(claims, "sub"),
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
	if !ok || issuer != p.issuerURL {
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
		return nil, providerStatusError("introspect token", ErrUpstreamRejected, resp.StatusCode)
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
	if issuerValue != p.issuerURL {
		return providerError("validate introspection issuer", ErrInvalidToken, fmt.Errorf("invalid token issuer"))
	}
	if !claimMatchesClient(introspection.Claims, p.clientID) {
		return providerError("validate introspection audience", ErrInvalidToken, fmt.Errorf("invalid token audience"))
	}
	return nil
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
func (p *SimpleProvider) findKeyByID(kid string) (interface{}, error) {
	keys, ok := p.jwks["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid JWKS format")
	}

	for _, keyInterface := range keys {
		keyMap, ok := keyInterface.(map[string]interface{})
		if !ok {
			continue
		}

		if keyID, ok := keyMap["kid"].(string); ok && keyID == kid {
			return rsaPublicKeyFromJWK(keyMap)
		}
	}

	return nil, fmt.Errorf("key with ID %s not found", kid)
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

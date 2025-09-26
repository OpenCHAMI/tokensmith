package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/errors"
	"github.com/openchami/tokensmith/pkg/logging"
)

// SimpleProvider is a simplified OIDC provider that uses discovery endpoint
type SimpleProvider struct {
	issuerURL        string
	clientID         string
	clientSecret     string
	discoveryURL     string
	metadata         *ProviderMetadata
	jwks             map[string]interface{}
	lastJWKSUpdate   time.Time
	jwksUpdatePeriod time.Duration
	logger           *logging.StructuredLogger
}

// NewSimpleProvider creates a new simplified OIDC provider
func NewSimpleProvider(issuerURL, clientID, clientSecret string) *SimpleProvider {
	return &SimpleProvider{
		issuerURL:        issuerURL,
		clientID:         clientID,
		clientSecret:     clientSecret,
		discoveryURL:     fmt.Sprintf("%s/.well-known/openid-configuration", issuerURL),
		jwksUpdatePeriod: 24 * time.Hour,
		logger:           logging.NewStructuredLogger("oidc-simple-provider"),
	}
}

// IntrospectToken introspects a token using the OIDC provider
func (p *SimpleProvider) IntrospectToken(ctx context.Context, token string) (*IntrospectionResponse, error) {
	logger := logging.NewStructuredLoggerFromContext(ctx, "oidc-introspect")

	result, err := logger.LogOperationWithResult("introspect_token", func() (interface{}, error) {
		// Try local validation first if we have JWKS
		if p.jwks != nil {
			logger.Debug("attempting local token validation")
			if response, err := p.validateTokenLocally(ctx, token); err == nil {
				logger.Info("token validated locally")
				return response, nil
			}
			logger.Warn("local token validation failed, falling back to remote")
		}

		// Fall back to remote introspection
		logger.Debug("attempting remote token introspection")
		response, err := p.introspectTokenRemotely(ctx, token)
		if err != nil {
			logger.WithError(err).Error("remote token introspection failed")
			return nil, errors.Wrap(err, errors.ErrCodeIntrospectionFailed, "failed to introspect token remotely")
		}

		logger.Info("token introspected remotely")
		return response, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*IntrospectionResponse), nil
}

// GetProviderMetadata returns the OIDC provider metadata
func (p *SimpleProvider) GetProviderMetadata(ctx context.Context) (*ProviderMetadata, error) {
	if p.metadata != nil {
		return p.metadata, nil
	}

	logger := logging.NewStructuredLoggerFromContext(ctx, "oidc-metadata")
	logger.WithField("discovery_url", p.discoveryURL).Debug("fetching provider metadata")

	req, err := http.NewRequestWithContext(ctx, "GET", p.discoveryURL, nil)
	if err != nil {
		logger.WithError(err).Error("failed to create metadata request")
		return nil, errors.Wrap(err, errors.ErrCodeProviderError, "failed to create metadata request")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.WithError(err).Error("failed to get provider metadata")
		return nil, errors.Wrap(err, errors.ErrCodeProviderTimeout, "failed to get provider metadata")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.WithField("status_code", resp.StatusCode).Error("metadata request failed")
		return nil, errors.New(errors.ErrCodeProviderError, "metadata request failed").
			WithDetails("status_code", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.WithError(err).Error("failed to read metadata response")
		return nil, errors.Wrap(err, errors.ErrCodeProviderError, "failed to read metadata response")
	}

	var metadata ProviderMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		logger.WithError(err).Error("failed to parse metadata")
		return nil, errors.Wrap(err, errors.ErrCodeProviderError, "failed to parse metadata")
	}

	// Validate required fields
	if metadata.Issuer == "" {
		logger.Error("metadata missing required field: issuer")
		return nil, errors.New(errors.ErrCodeInvalidConfig, "metadata missing required field: issuer")
	}
	if metadata.IntrospectionEndpoint == "" {
		logger.Error("metadata missing required field: introspection_endpoint")
		return nil, errors.New(errors.ErrCodeInvalidConfig, "metadata missing required field: introspection_endpoint")
	}
	if metadata.JWKSURI == "" {
		logger.Error("metadata missing required field: jwks_uri")
		return nil, errors.New(errors.ErrCodeInvalidConfig, "metadata missing required field: jwks_uri")
	}

	logger.WithFields(map[string]interface{}{
		"issuer":                 metadata.Issuer,
		"introspection_endpoint": metadata.IntrospectionEndpoint,
		"jwks_uri":               metadata.JWKSURI,
	}).Info("successfully fetched provider metadata")

	p.metadata = &metadata
	return &metadata, nil
}

// SupportsLocalIntrospection returns true if local introspection is supported
func (p *SimpleProvider) SupportsLocalIntrospection() bool {
	return true
}

// GetJWKS returns the JWKS for local token validation
func (p *SimpleProvider) GetJWKS(ctx context.Context) (interface{}, error) {
	logger := logging.NewStructuredLoggerFromContext(ctx, "oidc-jwks")

	// Check if we need to update the JWKS
	if p.jwks == nil || time.Since(p.lastJWKSUpdate) > p.jwksUpdatePeriod {
		logger.Debug("updating JWKS")
		if err := p.updateJWKS(ctx); err != nil {
			logger.WithError(err).Error("failed to update JWKS")
			return nil, errors.Wrap(err, errors.ErrCodeJWKSUnavailable, "failed to update JWKS")
		}
		logger.Info("JWKS updated successfully")
	} else {
		logger.Debug("using cached JWKS")
	}

	return p.jwks, nil
}

// updateJWKS fetches the latest JWKS from the provider
func (p *SimpleProvider) updateJWKS(ctx context.Context) error {
	logger := logging.NewStructuredLoggerFromContext(ctx, "oidc-jwks-update")

	// Get metadata first to get JWKS URI
	metadata, err := p.GetProviderMetadata(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to get metadata for JWKS update")
		return errors.Wrap(err, errors.ErrCodeProviderError, "failed to get metadata for JWKS update")
	}

	logger.WithField("jwks_uri", metadata.JWKSURI).Debug("fetching JWKS")

	req, err := http.NewRequestWithContext(ctx, "GET", metadata.JWKSURI, nil)
	if err != nil {
		logger.WithError(err).Error("failed to create JWKS request")
		return errors.Wrap(err, errors.ErrCodeProviderError, "failed to create JWKS request")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.WithError(err).Error("failed to fetch JWKS")
		return errors.Wrap(err, errors.ErrCodeProviderTimeout, "failed to fetch JWKS")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.WithField("status_code", resp.StatusCode).Error("JWKS request failed")
		return errors.New(errors.ErrCodeJWKSUnavailable, "JWKS request failed").
			WithDetails("status_code", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.WithError(err).Error("failed to read JWKS response")
		return errors.Wrap(err, errors.ErrCodeProviderError, "failed to read JWKS response")
	}

	if err := json.Unmarshal(body, &p.jwks); err != nil {
		logger.WithError(err).Error("failed to parse JWKS")
		return errors.Wrap(err, errors.ErrCodeJWKSUnavailable, "failed to parse JWKS")
	}

	p.lastJWKSUpdate = time.Now()
	logger.Info("JWKS updated successfully")
	return nil
}

// validateTokenLocally validates a token using local JWKS
func (p *SimpleProvider) validateTokenLocally(ctx context.Context, token string) (*IntrospectionResponse, error) {
	logger := logging.NewStructuredLoggerFromContext(ctx, "oidc-local-validation")

	// Parse the token without verification first to get the key ID
	parser := jwt.Parser{}
	unverifiedToken, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		logger.WithError(err).Error("failed to parse token for key ID extraction")
		return nil, errors.Wrap(err, errors.ErrCodeTokenMalformed, "failed to parse token")
	}

	// Get the key ID from the token header
	kid, ok := unverifiedToken.Header["kid"].(string)
	if !ok {
		logger.Error("token missing key ID")
		return nil, errors.New(errors.ErrCodeTokenMalformed, "token missing key ID")
	}

	logger.WithField("kid", kid).Debug("extracted key ID from token")

	// Find the matching key in JWKS
	key, err := p.findKeyByID(kid)
	if err != nil {
		logger.WithError(err).WithField("kid", kid).Error("key not found in JWKS")
		return nil, errors.Wrap(err, errors.ErrCodeJWKSUnavailable, "key not found in JWKS")
	}

	logger.WithField("kid", kid).Debug("found matching key in JWKS")

	// Parse and verify the token with the public key
	parsedToken, err := parser.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		logger.WithError(err).Error("token validation failed")
		return nil, errors.Wrap(err, errors.ErrCodeInvalidToken, "token validation failed")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		logger.Error("invalid token claims format")
		return nil, errors.New(errors.ErrCodeInvalidToken, "invalid token claims")
	}

	// Convert claims to map[string]interface{}
	claimsMap := make(map[string]interface{})
	for k, v := range claims {
		claimsMap[k] = v
	}

	// Check if token is expired
	exp, ok := claims["exp"].(float64)
	if !ok {
		logger.Error("token missing expiration claim")
		return nil, errors.New(errors.ErrCodeTokenMalformed, "token missing expiration")
	}

	active := time.Unix(int64(exp), 0).After(time.Now())
	if !active {
		logger.Warn("token has expired")
		return nil, errors.New(errors.ErrCodeTokenExpired, "token has expired")
	}

	logger.Debug("token validated successfully locally")

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

// introspectTokenRemotely introspects a token using the provider's introspection endpoint
func (p *SimpleProvider) introspectTokenRemotely(ctx context.Context, token string) (*IntrospectionResponse, error) {
	logger := logging.NewStructuredLoggerFromContext(ctx, "oidc-remote-introspect")

	metadata, err := p.GetProviderMetadata(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to get provider metadata")
		return nil, errors.Wrap(err, errors.ErrCodeProviderError, "failed to get provider metadata")
	}

	logger.WithField("introspection_endpoint", metadata.IntrospectionEndpoint).Debug("using introspection endpoint")

	// Create form data
	formData := fmt.Sprintf("token=%s", token)

	req, err := http.NewRequestWithContext(ctx, "POST", metadata.IntrospectionEndpoint, strings.NewReader(formData))
	if err != nil {
		logger.WithError(err).Error("failed to create introspection request")
		return nil, errors.Wrap(err, errors.ErrCodeProviderError, "failed to create introspection request")
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.clientID, p.clientSecret)

	logger.Debug("sending introspection request")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.WithError(err).Error("failed to send introspection request")
		return nil, errors.Wrap(err, errors.ErrCodeProviderTimeout, "failed to send introspection request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.WithField("status_code", resp.StatusCode).Error("introspection request failed")
		return nil, errors.New(errors.ErrCodeIntrospectionFailed, "introspection request failed").
			WithDetails("status_code", resp.StatusCode)
	}

	var introspection IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&introspection); err != nil {
		logger.WithError(err).Error("failed to decode introspection response")
		return nil, errors.Wrap(err, errors.ErrCodeIntrospectionFailed, "failed to decode introspection response")
	}

	logger.WithField("active", introspection.Active).Debug("received introspection response")
	return &introspection, nil
}

// findKeyByID finds a key by ID in the JWKS
func (p *SimpleProvider) findKeyByID(kid string) (interface{}, error) {
	logger := p.logger.WithField("kid", kid)

	keys, ok := p.jwks["keys"].([]interface{})
	if !ok {
		logger.Error("invalid JWKS format")
		return nil, errors.New(errors.ErrCodeJWKSUnavailable, "invalid JWKS format")
	}

	logger.WithField("key_count", len(keys)).Debug("searching for key in JWKS")

	for _, keyInterface := range keys {
		keyMap, ok := keyInterface.(map[string]interface{})
		if !ok {
			continue
		}

		if keyID, ok := keyMap["kid"].(string); ok && keyID == kid {
			logger.Debug("found matching key in JWKS")
			// This is a simplified key extraction - in production you'd want to properly
			// parse the JWK and convert it to a Go crypto key
			return keyMap, nil
		}
	}

	logger.Error("key not found in JWKS")
	return nil, errors.New(errors.ErrCodeJWKSUnavailable, "key not found").
		WithDetails("kid", kid)
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

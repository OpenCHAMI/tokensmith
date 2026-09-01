// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExchangeToken_EnrichedPolicyStillRequiresTokenSmithClaims(t *testing.T) {
	service := newExchangePolicyService(t, OIDCClaimPolicyEnriched, map[string]interface{}{
		"sub":    "admin-user",
		"groups": []interface{}{"admin"},
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.Error(t, err)
	assert.Empty(t, tokenValue)
	assert.True(t, errors.Is(err, ErrExchangeMissingClaims), "error %v should be missing-claims", err)
	var claimsErr *ExchangeClaimsError
	require.True(t, errors.As(err, &claimsErr))
	assert.ElementsMatch(t, []string{"auth_level", "auth_factors", "auth_methods", "session_id", "session_exp", "auth_events"}, claimsErr.Claims)
}

func TestExchangeToken_CSMKeycloakPolicyMapsStandardClaims(t *testing.T) {
	now := time.Now()
	service := newExchangePolicyService(t, OIDCClaimPolicyCSMKeycloak, map[string]interface{}{
		"sub":         "admin-user",
		"aud":         []interface{}{"tokensmith"},
		"groups":      []interface{}{"admin"},
		"acr":         "IAL2",
		"amr":         []interface{}{"pwd", "otp"},
		"sid":         "keycloak-session-1",
		"exp":         float64(now.Add(time.Hour).Unix()),
		"auth_events": []interface{}{"login"},
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.NoError(t, err)
	claims, _, err := service.TokenManager.ParseToken(tokenValue)
	require.NoError(t, err)
	assert.Equal(t, "admin-user", claims.Subject)
	assert.Equal(t, "IAL2", claims.AuthLevel)
	assert.Equal(t, 2, claims.AuthFactors)
	assert.ElementsMatch(t, []string{"password", "otp"}, claims.AuthMethods)
	assert.Equal(t, "keycloak-session-1", claims.SessionID)
	assert.Equal(t, now.Add(time.Hour).Unix(), claims.SessionExp)
	assert.ElementsMatch(t, []string{"login"}, claims.AuthEvents)
	assert.Contains(t, claims.Scope, "admin")
}

func TestExchangeToken_CSMKeycloakPolicyAcceptsObservedServiceAccountShape(t *testing.T) {
	now := time.Now()
	service := newExchangePolicyService(t, OIDCClaimPolicyCSMKeycloak, map[string]interface{}{
		"exp":                float64(now.Add(5 * time.Minute).Unix()),
		"iat":                float64(now.Unix()),
		"jti":                "7836e8d0-6928-4db8-90ee-dea5a7888dc7",
		"iss":                "https://api.cmn.prealps.cscs.ch/keycloak/realms/shasta",
		"aud":                "account",
		"sub":                "5eca73ee-c3f3-4a0c-a5ef-e1f25ed764a4",
		"typ":                "Bearer",
		"azp":                "openchami-tokensmith",
		"acr":                "1",
		"scope":              "email offline_access openid profile",
		"preferred_username": "service-account-openchami-tokensmith",
		"client_id":          "openchami-tokensmith",
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.NoError(t, err)
	claims, _, err := service.TokenManager.ParseToken(tokenValue)
	require.NoError(t, err)
	assert.Equal(t, "admin-user", claims.Subject)
	assert.Equal(t, []string{"account"}, []string(claims.Audience))
	assert.Equal(t, "1", claims.AuthLevel)
	assert.Equal(t, 2, claims.AuthFactors)
	assert.Equal(t, []string{"keycloak", "client_credentials"}, claims.AuthMethods)
	assert.Equal(t, "7836e8d0-6928-4db8-90ee-dea5a7888dc7", claims.SessionID)
	assert.Equal(t, now.Add(5*time.Minute).Unix(), claims.SessionExp)
	assert.Equal(t, []string{"token_exchange"}, claims.AuthEvents)
}

func TestExchangeToken_CapsLongUpstreamSessionByDefault(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	service := newExchangePolicyServiceWithConfig(t, OIDCClaimPolicyCSMKeycloak, Config{}, map[string]interface{}{
		"exp":                float64(now.Add(365 * 24 * time.Hour).Unix()),
		"iat":                float64(now.Unix()),
		"jti":                "device-flow-session",
		"aud":                []interface{}{"openchami-tokensmith", "account"},
		"sub":                "09979c65-647e-4f64-b2da-67713a0725f1",
		"azp":                "openchami-tokensmith",
		"acr":                "0",
		"groups":             []interface{}{"admin"},
		"preferred_username": "testuser",
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.NoError(t, err)
	claims, _, err := service.TokenManager.ParseToken(tokenValue)
	require.NoError(t, err)
	wantDeadline := now.Add(DefaultMaxExchangeSessionLifetime).Unix()
	assert.Equal(t, wantDeadline, claims.ExpiresAt.Unix())
	assert.Equal(t, wantDeadline, claims.SessionExp)
}

func TestExchangeToken_DoesNotExtendShortUpstreamSession(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	shortExpiry := now.Add(2 * time.Hour).Unix()
	service := newExchangePolicyServiceWithConfig(t, OIDCClaimPolicyCSMKeycloak, Config{}, map[string]interface{}{
		"exp":                float64(shortExpiry),
		"iat":                float64(now.Unix()),
		"jti":                "short-session",
		"aud":                "account",
		"azp":                "openchami-tokensmith",
		"sub":                "09979c65-647e-4f64-b2da-67713a0725f1",
		"acr":                "0",
		"groups":             []interface{}{"admin"},
		"preferred_username": "testuser",
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.NoError(t, err)
	claims, _, err := service.TokenManager.ParseToken(tokenValue)
	require.NoError(t, err)
	assert.Equal(t, shortExpiry, claims.ExpiresAt.Unix())
	assert.Equal(t, shortExpiry, claims.SessionExp)
}

func TestExchangeToken_AllowsExplicitLongerExchangeSessionLifetime(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	service := newExchangePolicyServiceWithConfig(t, OIDCClaimPolicyCSMKeycloak, Config{
		MaxExchangeSessionLifetime: 7 * 24 * time.Hour,
	}, map[string]interface{}{
		"exp":                float64(now.Add(365 * 24 * time.Hour).Unix()),
		"iat":                float64(now.Unix()),
		"jti":                "week-session",
		"aud":                []interface{}{"openchami-tokensmith", "account"},
		"sub":                "09979c65-647e-4f64-b2da-67713a0725f1",
		"azp":                "openchami-tokensmith",
		"acr":                "0",
		"groups":             []interface{}{"admin"},
		"preferred_username": "testuser",
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.NoError(t, err)
	claims, _, err := service.TokenManager.ParseToken(tokenValue)
	require.NoError(t, err)
	wantDeadline := now.Add(7 * 24 * time.Hour).Unix()
	assert.Equal(t, wantDeadline, claims.ExpiresAt.Unix())
	assert.Equal(t, wantDeadline, claims.SessionExp)
}

func TestExchangeToken_PreservesStringAudience(t *testing.T) {
	now := time.Now()
	service := newExchangePolicyService(t, OIDCClaimPolicyCSMKeycloak, map[string]interface{}{
		"sub":         "admin-user",
		"aud":         "tokensmith",
		"groups":      []interface{}{"admin"},
		"acr":         "IAL2",
		"amr":         []interface{}{"pwd", "otp"},
		"sid":         "keycloak-session-1",
		"exp":         float64(now.Add(time.Hour).Unix()),
		"auth_events": []interface{}{"login"},
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.NoError(t, err)
	claims, _, err := service.TokenManager.ParseToken(tokenValue)
	require.NoError(t, err)
	assert.Equal(t, []string{"tokensmith"}, []string(claims.Audience))
}

func TestExchangeToken_RequestedScopesCannotExceedDerivedScopes(t *testing.T) {
	now := time.Now()
	service := newExchangePolicyService(t, OIDCClaimPolicyCSMKeycloak, map[string]interface{}{
		"sub":         "admin-user",
		"aud":         []interface{}{"tokensmith"},
		"groups":      []interface{}{"admin"},
		"acr":         "IAL2",
		"amr":         []interface{}{"pwd", "otp"},
		"sid":         "keycloak-session-1",
		"exp":         float64(now.Add(time.Hour).Unix()),
		"auth_events": []interface{}{"login"},
	})
	ctx := context.WithValue(context.Background(), ScopeContextKey, []string{"read", "delete-everything"})

	tokenValue, err := service.ExchangeToken(ctx, "keycloak-token")

	require.Error(t, err)
	assert.Empty(t, tokenValue)
	assert.True(t, errors.Is(err, ErrExchangeInvalidClaim), "error %v should be invalid-claim", err)
}

func TestExchangeToken_CSMKeycloakPolicyPreservesExplicitEnrichedClaims(t *testing.T) {
	now := time.Now()
	service := newExchangePolicyService(t, OIDCClaimPolicyCSMKeycloak, map[string]interface{}{
		"sub":          "admin-user",
		"aud":          []interface{}{"tokensmith"},
		"groups":       []interface{}{"admin"},
		"acr":          "IAL1",
		"amr":          []interface{}{"pwd", "otp"},
		"sid":          "keycloak-session-1",
		"exp":          float64(now.Add(time.Hour).Unix()),
		"auth_level":   "IAL3",
		"auth_factors": float64(3),
		"auth_methods": []interface{}{"pwd", "otp", "hwk"},
		"session_id":   "explicit-session",
		"session_exp":  float64(now.Add(30 * time.Minute).Unix()),
		"auth_events":  []interface{}{"login", "step_up"},
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.NoError(t, err)
	claims, _, err := service.TokenManager.ParseToken(tokenValue)
	require.NoError(t, err)
	assert.Equal(t, "IAL3", claims.AuthLevel)
	assert.Equal(t, 3, claims.AuthFactors)
	assert.ElementsMatch(t, []string{"pwd", "otp", "hwk"}, claims.AuthMethods)
	assert.Equal(t, "explicit-session", claims.SessionID)
	assert.Equal(t, now.Add(30*time.Minute).Unix(), claims.SessionExp)
	assert.ElementsMatch(t, []string{"login", "step_up"}, claims.AuthEvents)
}

func TestExchangeToken_CSMKeycloakPolicyFallsBackWhenAuthMethodsAreMissing(t *testing.T) {
	now := time.Now()
	service := newExchangePolicyService(t, OIDCClaimPolicyCSMKeycloak, map[string]interface{}{
		"sub":    "admin-user",
		"aud":    "account",
		"groups": []interface{}{"admin"},
		"acr":    "IAL1",
		"sid":    "keycloak-session-1",
		"exp":    float64(now.Add(time.Hour).Unix()),
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.NoError(t, err)
	assert.NotEmpty(t, tokenValue)
}

func TestExchangeToken_CSMKeycloakPolicyFallsBackForSingleFactorCategory(t *testing.T) {
	now := time.Now()
	service := newExchangePolicyService(t, OIDCClaimPolicyCSMKeycloak, map[string]interface{}{
		"sub":         "admin-user",
		"aud":         "account",
		"groups":      []interface{}{"admin"},
		"acr":         "IAL2",
		"amr":         []interface{}{"otp", "webauthn"},
		"sid":         "keycloak-session-1",
		"exp":         float64(now.Add(time.Hour).Unix()),
		"auth_events": []interface{}{"login"},
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.NoError(t, err)
	claims, _, err := service.TokenManager.ParseToken(tokenValue)
	require.NoError(t, err)
	assert.Equal(t, 2, claims.AuthFactors)
}

func TestExchangeToken_CSMKeycloakPolicyFallsBackWhenAuthEventsAreMissing(t *testing.T) {
	now := time.Now()
	service := newExchangePolicyService(t, OIDCClaimPolicyCSMKeycloak, map[string]interface{}{
		"sub":    "admin-user",
		"aud":    "account",
		"groups": []interface{}{"admin"},
		"acr":    "IAL2",
		"sid":    "keycloak-session-1",
		"exp":    float64(now.Add(time.Hour).Unix()),
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.NoError(t, err)
	assert.NotEmpty(t, tokenValue)
}

func TestExchangeToken_CSMKeycloakPolicyAcceptsOpaqueACR(t *testing.T) {
	now := time.Now()
	service := newExchangePolicyService(t, OIDCClaimPolicyCSMKeycloak, map[string]interface{}{
		"sub":         "admin-user",
		"aud":         "account",
		"groups":      []interface{}{"admin"},
		"acr":         "2",
		"amr":         []interface{}{"pwd", "otp"},
		"sid":         "keycloak-session-1",
		"exp":         float64(now.Add(time.Hour).Unix()),
		"auth_events": []interface{}{"login"},
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.NoError(t, err)
	assert.NotEmpty(t, tokenValue)
}

func TestParseOIDCClaimPolicy(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    OIDCClaimPolicy
		wantErr bool
	}{
		{name: "empty defaults to enriched", value: "", want: OIDCClaimPolicyEnriched},
		{name: "enriched", value: "enriched", want: OIDCClaimPolicyEnriched},
		{name: "csm keycloak", value: "csm-keycloak", want: OIDCClaimPolicyCSMKeycloak},
		{name: "unknown", value: "loose", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseOIDCClaimPolicy(test.value)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func newExchangePolicyService(t *testing.T, policy OIDCClaimPolicy, claims map[string]interface{}) *TokenService {
	return newExchangePolicyServiceWithConfig(t, policy, Config{}, claims)
}

func newExchangePolicyServiceWithConfig(t *testing.T, policy OIDCClaimPolicy, config Config, claims map[string]interface{}) *TokenService {
	t.Helper()
	now := time.Now()
	config.Issuer = "tokensmith-test"
	config.ClusterID = "cl-test"
	config.OpenCHAMIID = "oc-test"
	config.OIDCClaimPolicy = policy
	config.GroupScopes = map[string][]string{
		"admin": {"read", "write", "admin"},
	}
	service := newTestTokenService(t, config)
	provider := oidc.NewMockProvider()
	provider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
		expiresAt := now.Add(time.Hour).Unix()
		if exp, ok := numberClaim(claims, "exp"); ok {
			expiresAt = int64(exp)
		}
		issuedAt := now.Unix()
		if iat, ok := numberClaim(claims, "iat"); ok {
			issuedAt = int64(iat)
		}
		return &oidc.IntrospectionResponse{
			Active:    true,
			Username:  "admin-user",
			ExpiresAt: expiresAt,
			IssuedAt:  issuedAt,
			Claims:    claims,
			TokenType: "Bearer",
		}, nil
	}
	service.OIDCProvider = provider
	return service
}

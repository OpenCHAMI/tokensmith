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

func TestExchangeToken_CSMKeycloakPolicyRequiresEnoughAuthMethods(t *testing.T) {
	now := time.Now()
	service := newExchangePolicyService(t, OIDCClaimPolicyCSMKeycloak, map[string]interface{}{
		"sub":         "admin-user",
		"groups":      []interface{}{"admin"},
		"acr":         "IAL1",
		"amr":         []interface{}{"pwd"},
		"sid":         "keycloak-session-1",
		"exp":         float64(now.Add(time.Hour).Unix()),
		"auth_events": []interface{}{"login"},
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.Error(t, err)
	assert.Empty(t, tokenValue)
	assert.True(t, errors.Is(err, ErrExchangeInvalidClaim), "error %v should be invalid-claim", err)
	var claimsErr *ExchangeClaimsError
	require.True(t, errors.As(err, &claimsErr))
	assert.Equal(t, []string{"auth_factors"}, claimsErr.Claims)
}

func TestExchangeToken_CSMKeycloakPolicyCountsDistinctFactorCategories(t *testing.T) {
	now := time.Now()
	service := newExchangePolicyService(t, OIDCClaimPolicyCSMKeycloak, map[string]interface{}{
		"sub":         "admin-user",
		"groups":      []interface{}{"admin"},
		"acr":         "IAL2",
		"amr":         []interface{}{"otp", "webauthn"},
		"sid":         "keycloak-session-1",
		"exp":         float64(now.Add(time.Hour).Unix()),
		"auth_events": []interface{}{"login"},
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.Error(t, err)
	assert.Empty(t, tokenValue)
	assert.True(t, errors.Is(err, ErrExchangeInvalidClaim), "error %v should be invalid-claim", err)
}

func TestExchangeToken_CSMKeycloakPolicyRequiresUpstreamAuthEvents(t *testing.T) {
	now := time.Now()
	service := newExchangePolicyService(t, OIDCClaimPolicyCSMKeycloak, map[string]interface{}{
		"sub":    "admin-user",
		"groups": []interface{}{"admin"},
		"acr":    "IAL2",
		"amr":    []interface{}{"pwd", "otp"},
		"sid":    "keycloak-session-1",
		"exp":    float64(now.Add(time.Hour).Unix()),
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.Error(t, err)
	assert.Empty(t, tokenValue)
	assert.True(t, errors.Is(err, ErrExchangeMissingClaims), "error %v should be missing-claims", err)
}

func TestExchangeToken_CSMKeycloakPolicyRejectsOpaqueNumericACR(t *testing.T) {
	now := time.Now()
	service := newExchangePolicyService(t, OIDCClaimPolicyCSMKeycloak, map[string]interface{}{
		"sub":         "admin-user",
		"groups":      []interface{}{"admin"},
		"acr":         "2",
		"amr":         []interface{}{"pwd", "otp"},
		"sid":         "keycloak-session-1",
		"exp":         float64(now.Add(time.Hour).Unix()),
		"auth_events": []interface{}{"login"},
	})

	tokenValue, err := service.ExchangeToken(context.Background(), "keycloak-token")

	require.Error(t, err)
	assert.Empty(t, tokenValue)
	assert.True(t, errors.Is(err, ErrExchangeMissingClaims), "error %v should be missing-claims", err)
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
	t.Helper()
	now := time.Now()
	service := newTestTokenService(t, Config{
		Issuer:          "tokensmith-test",
		ClusterID:       "cl-test",
		OpenCHAMIID:     "oc-test",
		OIDCClaimPolicy: policy,
		GroupScopes: map[string][]string{
			"admin": {"read", "write", "admin"},
		},
	})
	provider := oidc.NewMockProvider()
	provider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
		return &oidc.IntrospectionResponse{
			Active:    true,
			Username:  "admin-user",
			ExpiresAt: now.Add(time.Hour).Unix(),
			IssuedAt:  now.Unix(),
			Claims:    claims,
			TokenType: "Bearer",
		}, nil
	}
	service.OIDCProvider = provider
	return service
}

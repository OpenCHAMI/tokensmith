// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenService_GenerateServiceToken_HeaderAndPayloadShape(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	service := &TokenService{
		TokenManager: token.NewTokenManager(keyManager, "https://tokensmith.openchami.dev", "default-cluster", "default-openchami", true),
		Config:       Config{Issuer: "https://tokensmith.openchami.dev", ClusterID: "default-cluster", OpenCHAMIID: "default-openchami"},
		Issuer:       "https://tokensmith.openchami.dev", ClusterID: "default-cluster", OpenCHAMIID: "default-openchami",
	}

	tokenValue, err := service.MintServiceToken(context.Background(), "dev-client", "smd", nil)
	require.NoError(t, err)

	parsedToken, _, err := jwt.NewParser().ParseUnverified(tokenValue, jwt.MapClaims{})
	require.NoError(t, err)

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok)

	kid, err := keyManager.GetKid()
	require.NoError(t, err)

	assert.Equal(t, service.TokenManager.GetSigningAlgorithm(), parsedToken.Header["alg"])
	assert.Equal(t, "JWT", parsedToken.Header["typ"])
	assert.Equal(t, kid, parsedToken.Header["kid"])
	assert.Equal(t, "https://tokensmith.openchami.dev", claims["iss"])
	assert.Equal(t, "dev-client", claims["sub"])
	assert.ElementsMatch(t, []interface{}{"smd"}, claims["aud"])
	assert.NotNil(t, claims["exp"])
	assert.NotNil(t, claims["iat"])
	assert.NotNil(t, claims["nbf"])
	assert.NotEmpty(t, claims["jti"])
	assert.NotEmpty(t, claims["nonce"])
	assert.Equal(t, "IAL2", claims["auth_level"])
	assert.Equal(t, float64(2), claims["auth_factors"])
	assert.ElementsMatch(t, []interface{}{"service", "certificate"}, claims["auth_methods"])
	assert.NotEmpty(t, claims["session_id"])
	assert.NotNil(t, claims["session_exp"])
	assert.ElementsMatch(t, []interface{}{"service_auth"}, claims["auth_events"])
	assert.Equal(t, "default-cluster", claims["cluster_id"])
	assert.Equal(t, "default-openchami", claims["openchami_id"])
	_, hasScope := claims["scope"]
	assert.False(t, hasScope)

	iat, ok := claims["iat"].(float64)
	require.True(t, ok)
	nbf, ok := claims["nbf"].(float64)
	require.True(t, ok)
	exp, ok := claims["exp"].(float64)
	require.True(t, ok)
	sessionExp, ok := claims["session_exp"].(float64)
	require.True(t, ok)
	assert.LessOrEqual(t, nbf, iat)
	assert.Greater(t, exp, iat)
	assert.GreaterOrEqual(t, sessionExp, exp)
}

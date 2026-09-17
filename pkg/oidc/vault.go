// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (p *SimpleProvider) getVaultUserInfo(ctx context.Context, token string) (*IntrospectionResponse, error) {
	metadata, err := p.GetProviderMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("get Vault provider metadata: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadata.UserInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create Vault UserInfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get Vault UserInfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get Vault UserInfo: status %d", resp.StatusCode)
	}

	claims := make(map[string]any)
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&claims); err != nil {
		return nil, fmt.Errorf("decode Vault UserInfo response: %w", err)
	}
	subject := strings.TrimSpace(stringFromRaw(claims["sub"]))
	if subject == "" {
		return nil, fmt.Errorf("vault UserInfo response missing subject")
	}

	now := time.Now()
	expiresAt := numericDateClaim(claims, "exp", now.Add(p.vaultUserInfoFallbackTTL).Unix())
	issuedAt := numericDateClaim(claims, "iat", now.Unix())
	groups := stringSliceClaim(claims, "groups")
	return &IntrospectionResponse{
		Active:    expiresAt > now.Unix(),
		Username:  subject,
		ExpiresAt: expiresAt,
		IssuedAt:  issuedAt,
		Claims:    claims,
		TokenType: "Bearer",
		Scope:     strings.Join(groups, " "),
		ClientID:  p.clientID,
	}, nil
}

func numericDateClaim(claims map[string]any, key string, fallback int64) int64 {
	switch value := claims[key].(type) {
	case float64:
		return int64(value)
	case json.Number:
		parsed, err := value.Int64()
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func stringSliceClaim(claims map[string]any, key string) []string {
	switch values := claims[key].(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok && text != "" {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}

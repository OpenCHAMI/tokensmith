// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/openchami/tokensmith/pkg/token"
)

type OIDCClaimPolicy string

const (
	OIDCClaimPolicyEnriched    OIDCClaimPolicy = "enriched"
	OIDCClaimPolicyCSMKeycloak OIDCClaimPolicy = "csm-keycloak"
)

func ParseOIDCClaimPolicy(value string) (OIDCClaimPolicy, error) {
	switch OIDCClaimPolicy(strings.TrimSpace(value)) {
	case "", OIDCClaimPolicyEnriched:
		return OIDCClaimPolicyEnriched, nil
	case OIDCClaimPolicyCSMKeycloak:
		return OIDCClaimPolicyCSMKeycloak, nil
	default:
		return "", fmt.Errorf("unsupported OIDC claim policy %q", value)
	}
}

func normalizeExchangeClaims(source map[string]interface{}, dst *token.TSClaims, policy OIDCClaimPolicy) error {
	var missing []string

	authLevel, ok := stringClaim(source, "auth_level")
	if !ok && policy == OIDCClaimPolicyCSMKeycloak {
		authLevel, ok = stringClaim(source, "acr")
		if ok {
			authLevel, ok = normalizeCSMAuthLevel(authLevel)
		}
	}
	if !ok {
		missing = append(missing, "auth_level")
	}

	authMethods := stringArrayClaim(source, "auth_methods")
	if len(authMethods) == 0 && policy == OIDCClaimPolicyCSMKeycloak {
		authMethods = normalizeCSMAuthMethods(stringArrayClaim(source, "amr"))
	}
	if len(authMethods) == 0 {
		missing = append(missing, "auth_methods")
	}

	authFactors, ok := numberClaim(source, "auth_factors")
	if !ok {
		if policy == OIDCClaimPolicyCSMKeycloak && len(authMethods) > 0 {
			authFactors = countCSMAuthFactorCategories(authMethods)
		} else {
			missing = append(missing, "auth_factors")
		}
	}

	sessionID, ok := stringClaim(source, "session_id")
	if !ok && policy == OIDCClaimPolicyCSMKeycloak {
		sessionID, ok = stringClaim(source, "sid")
	}
	if !ok {
		missing = append(missing, "session_id")
	}

	sessionExp, ok := numberClaim(source, "session_exp")
	if !ok && policy == OIDCClaimPolicyCSMKeycloak {
		sessionExp, ok = numberClaim(source, "exp")
	}
	if !ok {
		missing = append(missing, "session_exp")
	}

	authEvents := stringArrayClaim(source, "auth_events")
	if len(authEvents) == 0 {
		missing = append(missing, "auth_events")
	}

	if len(missing) > 0 {
		return missingExchangeClaims(missing...)
	}
	if authFactors < 2 {
		return invalidExchangeClaim("auth_factors")
	}

	dst.AuthLevel = authLevel
	dst.AuthFactors = authFactors
	dst.AuthMethods = authMethods
	dst.SessionID = sessionID
	dst.SessionExp = int64(sessionExp)
	dst.AuthEvents = authEvents
	return nil
}

func normalizeCSMAuthLevel(value string) (string, bool) {
	switch strings.TrimSpace(value) {
	case "IAL1", "IAL2", "IAL3":
		return value, true
	default:
		return "", false
	}
}

func normalizeCSMAuthMethods(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		method, ok := csmAuthMethod(value)
		if !ok {
			continue
		}
		if _, exists := seen[method]; exists {
			continue
		}
		seen[method] = struct{}{}
		out = append(out, method)
	}
	return out
}

func csmAuthMethod(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "pwd", "password":
		return "password", true
	case "otp", "totp", "hotp", "sms":
		return "otp", true
	case "hwk", "fido", "fido2", "webauthn":
		return "hardware", true
	default:
		return "", false
	}
}

func countCSMAuthFactorCategories(methods []string) int {
	categories := map[string]struct{}{}
	for _, method := range methods {
		switch method {
		case "password":
			categories["knowledge"] = struct{}{}
		case "otp", "hardware":
			categories["possession"] = struct{}{}
		}
	}
	return len(categories)
}

func stringClaim(claims map[string]interface{}, key string) (string, bool) {
	value, ok := claims[key].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

func numberClaim(claims map[string]interface{}, key string) (int, bool) {
	switch value := claims[key].(type) {
	case int:
		return value, true
	case int64:
		return int(value), true
	case float64:
		return int(value), true
	case json.Number:
		parsed, err := strconv.ParseInt(value.String(), 10, 64)
		if err != nil {
			return 0, false
		}
		return int(parsed), true
	default:
		return 0, false
	}
}

func stringArrayClaim(claims map[string]interface{}, key string) []string {
	switch values := claims[key].(type) {
	case []string:
		return compactStrings(values)
	case []interface{}:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if item, ok := value.(string); ok && strings.TrimSpace(item) != "" {
				out = append(out, item)
			}
		}
		return out
	default:
		return nil
	}
}

func compactStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

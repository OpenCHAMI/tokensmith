// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
// SPDX-License-Identifier: MIT

package authn

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/keys"
	tstoken "github.com/openchami/tokensmith/pkg/token"
)

func (resolver keyResolver) verifyLegacy(r *http.Request, raw string, now time.Time) (*jwt.Token, jwt.MapClaims, error) {
	opt := resolver.opt
	claims := &tstoken.TSClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("missing kid header")
		}
		if !keys.IsRFC7638Thumbprint(kid) {
			return nil, errors.New("invalid kid header format")
		}
		return resolver.resolve(r.Context(), t, now)
	}, jwt.WithValidMethods(keys.GetFIPSApprovedAlgorithms()), jwt.WithLeeway(opt.ClockSkew), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		logAuthNFailure(r, "parse_or_verify_failed", err)
		return nil, nil, err
	}
	if err := claims.ValidateAt(true, now); err != nil {
		logAuthNFailure(r, "claims_validation_failed", err)
		return nil, nil, err
	}
	m, err := tsClaimsToMapClaims(claims)
	if err != nil {
		logAuthNFailure(r, "invalid_token_claims_type", nil)
		return nil, nil, err
	}
	if opt.ValidateIssuer {
		iss, _ := m["iss"].(string)
		if !stringInSlice(iss, opt.Issuers) {
			logAuthNFailureWithFields(r, "issuer_mismatch", nil, map[string]any{"token_iss": iss, "allowed_issuers": opt.Issuers})
			return nil, nil, errors.New("invalid issuer")
		}
	}
	if opt.ValidateAudience {
		ok := false
		for _, aud := range extractAudienceValues(m) {
			if stringInSlice(aud, opt.Audiences) {
				ok = true
				break
			}
		}
		if !ok {
			logAuthNFailureWithFields(r, "audience_mismatch", nil, map[string]any{"token_aud": extractAudienceValues(m), "allowed_audiences": opt.Audiences})
			return nil, nil, errors.New("invalid audience")
		}
	}
	return parsed, m, nil
}

func tsClaimsToMapClaims(claims *tstoken.TSClaims) (jwt.MapClaims, error) {
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	var out jwt.MapClaims
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

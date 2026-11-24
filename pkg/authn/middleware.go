// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authn

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/authz"
	tstoken "github.com/openchami/tokensmith/pkg/token"
)

func Middleware(opt Options) (func(http.Handler) http.Handler, error) {
	opt, err := opt.withDefaults()
	if err != nil {
		return nil, err
	}
	resolver := keyResolver{opt: opt, cache: newJWKSCache()}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if opt.Mode == AuthNOff {
				next.ServeHTTP(w, r)
				return
			}
			raw, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok || len(r.Header.Values("Authorization")) != 1 {
				logAuthNFailure(r, "missing_bearer_token", nil)
				rejectAuthentication(w)
				return
			}
			profile, err := tstoken.SelectProfile(raw)
			if err != nil || !slices.Contains(opt.Profiles, profile) {
				logAuthNFailure(r, "invalid_token_profile", nil)
				rejectAuthentication(w)
				return
			}
			now := opt.now()
			var parsed *jwt.Token
			var claims jwt.MapClaims
			var human *tstoken.HumanSessionClaims
			var id string
			switch profile {
			case tstoken.ProfileLegacyV1:
				parsed, claims, err = resolver.verifyLegacy(r, raw, now)
				if err == nil {
					id, _ = claims["jti"].(string)
				}
			case tstoken.ProfileHumanSessionV1:
				human, err = tstoken.VerifyHumanSession(r.Context(), raw, tstoken.HumanSessionVerification{
					Policy: *opt.HumanSessionPolicy, Now: now,
					Lookup: func(ctx context.Context, kid string) (*rsa.PublicKey, error) {
						if opt.HumanSessionKeyLookup != nil {
							return opt.HumanSessionKeyLookup(ctx, kid)
						}
						key, err := resolver.resolve(ctx, &jwt.Token{Header: map[string]any{"kid": kid}, Method: jwt.SigningMethodPS256}, now)
						if err != nil {
							return nil, err
						}
						rsaKey, ok := key.(*rsa.PublicKey)
						if !ok {
							return nil, tstoken.ErrHumanSessionDenied
						}
						return rsaKey, nil
					},
				})
				if err == nil {
					id = human.ID
					var data []byte
					data, err = json.Marshal(human)
					if err == nil {
						d := json.NewDecoder(bytes.NewReader(data))
						d.UseNumber()
						err = d.Decode(&claims)
					}
				}
				if err != nil {
					logAuthNFailure(r, "human_session_denied", nil)
				}
			default:
				err = errors.New("invalid token profile")
			}
			if err != nil {
				rejectAuthentication(w)
				return
			}
			if opt.RevocationChecker != nil && id != "" && opt.RevocationChecker.IsRevoked(id) {
				logAuthNFailure(r, "token_revoked", nil)
				rejectAuthentication(w)
				return
			}
			var p authz.Principal
			if human != nil {
				p = authz.Principal{ID: human.Subject, Roles: []string{human.Role}}
			} else {
				p, err = opt.Mapper(r.Context(), parsed, claims)
				if err != nil {
					logAuthNFailure(r, "principal_mapping_failed", err)
					rejectAuthentication(w)
					return
				}
			}
			ctx := ContextWithPrincipal(r.Context(), p)
			ctx = authz.SetPrincipal(ctx, &p)
			ctx = ContextWithVerifiedClaims(ctx, claims)
			if human != nil {
				ctx = context.WithValue(ctx, humanClaimsContextKey{}, *human)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, nil
}

func rejectAuthentication(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "invalid token", http.StatusUnauthorized)
}

// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authn

import (
	"encoding/json"
	"fmt"
	"net/http"

	tstoken "github.com/openchami/tokensmith/pkg/token"
)

type InsufficientACRError struct {
	Error            string   `json:"error"`
	ErrorDescription string   `json:"error_description"`
	RequiredACR      []string `json:"required_acr,omitempty"`
	CurrentACR       string   `json:"current_acr,omitempty"`
}

func RequireACR(minACR string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			verifiedClaims, ok := VerifiedClaimsFromContext(ctx)
			if !ok {
				http.Error(w, "Unauthorized: No verified claims found", http.StatusUnauthorized)
				return
			}

			acrValue, _ := verifiedClaims["acr"].(string)

			if !MeetsACRRequirement(acrValue, []string{minACR}) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)

				resp := InsufficientACRError{
					Error:            "insufficient_acr",
					ErrorDescription: fmt.Sprintf("This operation requires ACR >= %s. Current ACR: %s. Please re-authenticate with MFA.", minACR, acrValue),
					RequiredACR:      []string{minACR},
					CurrentACR:       acrValue,
				}

				_ = json.NewEncoder(w).Encode(resp)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func RequireAnyACR(requiredACRs []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			verifiedClaims, ok := VerifiedClaimsFromContext(ctx)
			if !ok {
				http.Error(w, "Unauthorized: No verified claims found", http.StatusUnauthorized)
				return
			}

			acrValue, _ := verifiedClaims["acr"].(string)

			if !MeetsACRRequirement(acrValue, requiredACRs) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)

				resp := InsufficientACRError{
					Error:            "insufficient_acr",
					ErrorDescription: fmt.Sprintf("This operation requires one of: %v. Current ACR: %s. Please re-authenticate with MFA.", requiredACRs, acrValue),
					RequiredACR:      requiredACRs,
					CurrentACR:       acrValue,
				}

				_ = json.NewEncoder(w).Encode(resp)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func ExtractACRFromClaims(claims *tstoken.TSClaims) string {
	if claims == nil {
		return ""
	}
	return claims.ACR
}

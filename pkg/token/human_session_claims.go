// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// HumanSessionClaims retains integer wire identities without MapClaims rounding.
type HumanSessionClaims struct {
	TokenProfile        Profile  `json:"token_profile"`
	Issuer              string   `json:"iss"`
	Subject             string   `json:"sub"`
	Audience            []string `json:"aud"`
	IssuedAt            int64    `json:"iat"`
	NotBefore           int64    `json:"nbf"`
	ExpiresAt           int64    `json:"exp"`
	ID                  string   `json:"jti"`
	Class               string   `json:"token_class"`
	GitLabIssuer        string   `json:"gitlab_issuer"`
	ProjectID           int64    `json:"gitlab_project_id"`
	UserID              int64    `json:"gitlab_user_id"`
	SessionID           string   `json:"session_id"`
	ApprovedAt          int64    `json:"approved_at"`
	SessionExp          int64    `json:"session_exp"`
	MembershipCheckedAt int64    `json:"membership_checked_at"`
	Role                string   `json:"role"`
}

func (c HumanSessionClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}
func (c HumanSessionClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}
func (c HumanSessionClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.NotBefore, 0)), nil
}
func (c HumanSessionClaims) GetIssuer() (string, error)             { return c.Issuer, nil }
func (c HumanSessionClaims) GetSubject() (string, error)            { return c.Subject, nil }
func (c HumanSessionClaims) GetAudience() (jwt.ClaimStrings, error) { return c.Audience, nil }

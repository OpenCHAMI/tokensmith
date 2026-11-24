// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package token

import (
	"strconv"
	"time"
)

// ValidateAt applies the human contract, not legacy assurance/session semantics.
func (c HumanSessionClaims) ValidateAt(p HumanSessionPolicy, now time.Time) error {
	if p.Validate() != nil {
		return ErrHumanSessionDenied
	}
	n := now.Unix()
	if c.TokenProfile != ProfileHumanSessionV1 || c.Issuer != p.ClusterIssuer || c.Class != "human" || c.GitLabIssuer != p.GitLabIssuer || c.ProjectID != p.ProjectID || c.UserID <= 0 || c.Subject != p.GitLabIssuer+"/user/"+strconv.FormatInt(c.UserID, 10) || len(c.Audience) != 1 || c.Audience[0] != p.Audience || c.ID == "" || c.SessionID == "" {
		return ErrHumanSessionDenied
	}
	switch c.Role {
	case "admin", "operator", "viewer":
	default:
		return ErrHumanSessionDenied
	}
	if c.IssuedAt <= 0 || c.NotBefore != c.IssuedAt || (c.IssuedAt > n && c.IssuedAt-n > p.SkewSeconds) || n >= c.ExpiresAt || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > p.TokenSeconds {
		return ErrHumanSessionDenied
	}
	// Subtraction after ordering avoids attacker-controlled int64 addition overflow.
	if c.ApprovedAt <= 0 || c.ApprovedAt > c.IssuedAt || c.SessionExp <= c.ApprovedAt || c.SessionExp-c.ApprovedAt != p.AbsoluteSeconds || n >= c.SessionExp || c.ExpiresAt > c.SessionExp || c.SessionExp-c.ExpiresAt < p.SkewSeconds {
		return ErrHumanSessionDenied
	}
	if c.MembershipCheckedAt < c.ApprovedAt || c.MembershipCheckedAt > c.IssuedAt || c.IssuedAt-c.MembershipCheckedAt > p.CacheSeconds || c.ExpiresAt-c.MembershipCheckedAt > p.CacheSeconds+p.TokenSeconds {
		return ErrHumanSessionDenied
	}
	return nil
}

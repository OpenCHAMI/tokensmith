// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package token

import (
	"encoding/json"
	"testing"
	"time"
)

func humanFixture() (HumanSessionClaims, HumanSessionPolicy, time.Time) {
	now := time.Unix(1800000000, 0)
	p := HumanSessionPolicy{ClusterIssuer: "cluster", Audience: "resource", GitLabIssuer: "https://gitlab.test", ProjectID: 9007199254740993, CacheSeconds: 90, TokenSeconds: 180, SkewSeconds: 30, AbsoluteSeconds: 36000}
	c := HumanSessionClaims{TokenProfile: ProfileHumanSessionV1, Issuer: p.ClusterIssuer, Subject: p.GitLabIssuer + "/user/9007199254740995", Audience: []string{p.Audience}, IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Unix() + 180, ID: "jti", Class: "human", GitLabIssuer: p.GitLabIssuer, ProjectID: p.ProjectID, UserID: 9007199254740995, SessionID: "session", ApprovedAt: now.Unix(), SessionExp: now.Unix() + 36000, MembershipCheckedAt: now.Unix(), Role: "viewer"}
	return c, p, now
}

func TestHumanSessionClaims(t *testing.T) {
	for name, mutate := range map[string]func(*HumanSessionClaims){
		"valid":                      func(c *HumanSessionClaims) {},
		"profile":                    func(c *HumanSessionClaims) { c.TokenProfile = "" },
		"issuer":                     func(c *HumanSessionClaims) { c.Issuer = "other" },
		"provider":                   func(c *HumanSessionClaims) { c.GitLabIssuer = "other" },
		"project":                    func(c *HumanSessionClaims) { c.ProjectID++ },
		"user":                       func(c *HumanSessionClaims) { c.UserID++ },
		"subject":                    func(c *HumanSessionClaims) { c.Subject = "other" },
		"audience":                   func(c *HumanSessionClaims) { c.Audience = []string{"resource", "extra"} },
		"class":                      func(c *HumanSessionClaims) { c.Class = "ci" },
		"role":                       func(c *HumanSessionClaims) { c.Role = "owner" },
		"jti":                        func(c *HumanSessionClaims) { c.ID = "" },
		"session":                    func(c *HumanSessionClaims) { c.SessionID = "" },
		"iat":                        func(c *HumanSessionClaims) { c.IssuedAt = 0 },
		"nbf":                        func(c *HumanSessionClaims) { c.NotBefore++ },
		"future":                     func(c *HumanSessionClaims) { c.IssuedAt += 31; c.NotBefore = c.IssuedAt },
		"expiry boundary":            func(c *HumanSessionClaims) { c.ExpiresAt = c.IssuedAt },
		"token cap":                  func(c *HumanSessionClaims) { c.ExpiresAt++ },
		"approval":                   func(c *HumanSessionClaims) { c.ApprovedAt = 0 },
		"future approval":            func(c *HumanSessionClaims) { c.ApprovedAt++ },
		"absolute cap":               func(c *HumanSessionClaims) { c.SessionExp++ },
		"session budget":             func(c *HumanSessionClaims) { c.ApprovedAt -= 35820; c.SessionExp -= 35820 },
		"membership before approval": func(c *HumanSessionClaims) { c.MembershipCheckedAt-- },
		"membership future":          func(c *HumanSessionClaims) { c.MembershipCheckedAt++ },
		"membership stale":           func(c *HumanSessionClaims) { c.ApprovedAt -= 100; c.SessionExp -= 100; c.MembershipCheckedAt -= 91 },
	} {
		t.Run(name, func(t *testing.T) {
			// Given one mutated invariant, when validated, then accept only the valid fixture.
			c, p, now := humanFixture()
			mutate(&c)
			err := c.ValidateAt(p, now)
			if (err == nil) != (name == "valid") {
				t.Fatalf("validation: %v", err)
			}
		})
	}
	// Given integer identities, when decoded directly, then preserve all 64 bits.
	c, _, _ := humanFixture()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var decoded HumanSessionClaims
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.UserID != 9007199254740995 || decoded.ProjectID != 9007199254740993 {
		t.Fatal("lossy identity")
	}
}

func TestHumanSessionPolicy(t *testing.T) {
	for name, mutate := range map[string]func(*HumanSessionPolicy){
		"valid": func(p *HumanSessionPolicy) {}, "http": func(p *HumanSessionPolicy) { p.GitLabIssuer = "http://gitlab.test" },
		"path": func(p *HumanSessionPolicy) { p.GitLabIssuer += "/path" }, "credentials": func(p *HumanSessionPolicy) { p.GitLabIssuer = "https://user:pass@gitlab.test" },
		"query": func(p *HumanSessionPolicy) { p.GitLabIssuer += "?x=1" }, "fragment": func(p *HumanSessionPolicy) { p.GitLabIssuer += "#x" },
		"project": func(p *HumanSessionPolicy) { p.ProjectID = 0 }, "issuer": func(p *HumanSessionPolicy) { p.ClusterIssuer = "" }, "audience": func(p *HumanSessionPolicy) { p.Audience = "" },
		"cache zero": func(p *HumanSessionPolicy) { p.CacheSeconds = 0 }, "cache cap": func(p *HumanSessionPolicy) { p.CacheSeconds = 91 },
		"token zero": func(p *HumanSessionPolicy) { p.TokenSeconds = 0 }, "token cap": func(p *HumanSessionPolicy) { p.TokenSeconds = 181 },
		"skew negative": func(p *HumanSessionPolicy) { p.SkewSeconds = -1 }, "skew cap": func(p *HumanSessionPolicy) { p.SkewSeconds = 31 },
		"absolute": func(p *HumanSessionPolicy) { p.AbsoluteSeconds++ },
	} {
		t.Run(name, func(t *testing.T) {
			// Given consumer-only configuration, when validated, then enforce the bounded policy.
			_, p, _ := humanFixture()
			mutate(&p)
			if (p.Validate() == nil) != (name == "valid") {
				t.Fatal("unexpected policy acceptance")
			}
		})
	}
}

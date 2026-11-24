// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/deviceauth"
	"github.com/openchami/tokensmith/pkg/token"
)

func TestProfileBrokerPublishedJWKSCasbinLifecycle(t *testing.T) {
	// Given real HTTPS GitLab, the opt-in broker, published JWKS and a protected service.
	x := newProfileE2E(t)
	var challenge deviceauth.DeviceResponse
	if err := json.Unmarshal(x.brokerCall("/device-auth/start", "", 200), &challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.Transaction == "" || challenge.URI != x.policy.Issuer+"/oauth/device" || challenge.Interval != 1 {
		t.Fatal("invalid public challenge")
	}
	// Await the advertised RFC polling interval, not an expiry or guessed scheduling delay.
	timer := time.NewTimer(time.Duration(challenge.Interval) * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-x.ctx.Done():
		t.Fatal(x.ctx.Err())
	}
	var issued deviceauth.Result
	payload, err := json.Marshal(map[string]string{"transaction": challenge.Transaction})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(x.request(x.broker.Client(), profileHTTPRequest{"POST", x.broker.URL + "/device-auth/poll", string(payload), "", 200}), &issued); err != nil {
		t.Fatal(err)
	}
	if issued.Access == "" || issued.Renewal == "" || issued.Deadline == 0 {
		t.Fatal("broker did not issue a session")
	}
	// When the actual issued token reaches AuthN/JWKS/Casbin, then enforce read/write boundaries.
	body := x.request(x.resource.Client(), profileHTTPRequest{"GET", x.resource.URL + "/nodes", "", issued.Access, 200})
	if string(body) != "nodes-ok" {
		t.Fatalf("wrong resource response %q", body)
	}
	writeDenied := x.request(x.resource.Client(), profileHTTPRequest{"POST", x.resource.URL + "/nodes", "", issued.Access, 403})
	var decision struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(writeDenied, &decision); err != nil || decision.Code != "AUTHZ_DENIED" || decision.Reason != "policy_denied" {
		t.Fatalf("unexpected policy denial: %s %v", writeDenied, err)
	}
	x.request(x.resource.Client(), profileHTTPRequest{"GET", x.resource.URL + "/nodes", "", "invalid-token", 401})
	legacy := x.protected(true)
	x.request(legacy.Client(), profileHTTPRequest{"GET", legacy.URL + "/nodes", "", issued.Access, 401})
	var renewed deviceauth.Result
	if err := json.Unmarshal(x.brokerCall("/device-auth/renew", issued.Renewal, 200), &renewed); err != nil {
		t.Fatal(err)
	}
	if renewed.Access == "" || renewed.Deadline != issued.Deadline || renewed.Renewal != "" {
		t.Fatal("renewal extended approval or changed handle contract")
	}
	pub, err := x.service.TokenManager.GetKeyManager().GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	var claims token.HumanSessionClaims
	if _, err := jwt.ParseWithClaims(renewed.Access, &claims, func(*jwt.Token) (any, error) { return pub, nil }, jwt.WithValidMethods([]string{"PS256"})); err != nil {
		t.Fatal(err)
	}
	if claims.TokenProfile != token.ProfileHumanSessionV1 || claims.SessionExp != issued.Deadline || claims.SessionExp-claims.ApprovedAt != 36000 || claims.ExpiresAt-claims.IssuedAt > x.policy.TokenSeconds {
		t.Fatal("signed deadline/lifetime contract changed")
	}
	logout := x.brokerCall("/device-auth/logout", issued.Renewal, 200)
	var result struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(logout, &result); err != nil || result.Status != "logged_out" {
		t.Fatalf("logout response: %s %v", logout, err)
	}
	denied := x.brokerCall("/device-auth/renew", issued.Renewal, 401)
	var failure struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(denied, &failure); err != nil || failure.Error != "authorization_failed" {
		t.Fatalf("renewal denial: %s %v", denied, err)
	}
	if x.revokes.Load() != 1 || x.memberCalls.Load() != 1 {
		t.Fatal("real provider lifecycle was not exercised")
	}
	x.request(x.resource.Client(), profileHTTPRequest{"GET", x.resource.URL + "/nodes", "", renewed.Access, 200})
	// Given the same trusted signer but an already expired issuance, then HTTP must reject it without waiting.
	claims.IssuedAt -= 1000
	claims.NotBefore -= 1000
	claims.ExpiresAt -= 1000
	claims.ApprovedAt -= 1000
	claims.SessionExp -= 1000
	claims.MembershipCheckedAt -= 1000
	j := jwt.NewWithClaims(jwt.SigningMethodPS256, claims)
	kid, err := x.service.TokenManager.GetKeyManager().GetKid()
	if err != nil {
		t.Fatal(err)
	}
	j.Header["kid"] = kid
	key, err := x.service.TokenManager.GetKeyManager().GetPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	expired, err := j.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	body = x.request(x.resource.Client(), profileHTTPRequest{"GET", x.resource.URL + "/nodes", "", expired, 401})
	if strings.TrimSpace(string(body)) != "invalid token" {
		t.Fatalf("unsafe expiry denial %q", body)
	}
}

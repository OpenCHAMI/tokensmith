// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package token

import (
	"encoding/base64"
	"strings"
	"testing"
)

func profileJWT(payload string) string {
	return "eyJhbGciOiJQUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}

func TestTokenProfileRouting(t *testing.T) {
	for _, tc := range []struct {
		payload string
		want    Profile
	}{
		{`{}`, ProfileLegacyV1},
		{`{"extra":true}`, ProfileLegacyV1},
		{`{"token_profile":"legacy-v1"}`, ProfileLegacyV1},
		{`{"token_profile":"human-session-v1","token_class":"human"}`, ProfileHumanSessionV1},
		{`{"token_profile":null}`, ""}, {`{"token_profile":1}`, ""},
		{`{"token_profile":"unknown"}`, ""}, {`{"token_profile":""}`, ""},
		{`{"token_profile":"legacy-v1","token_profile":"legacy-v1"}`, ""},
		{`{"token_profile":"human-session-v1","TOKEN_PROFILE":"legacy-v1"}`, ""},
		{`{"GITLAB_USER_ID":2}`, ""},
		{`{"TOKEN_CLASS":"human"}`, ""},
		{`{"gitlab_i\u017f\u017fuer":"https://gitlab.test"}`, ""},
		{`{"token_profile":"human-session-v1","\u017fcope":null}`, ""},
		{`{"token_class":"human"}`, ""},
		{`{"token_profile":"legacy-v1","gitlab_user_id":null}`, ""},
		{`{"gitlab_issuer":"https://gitlab.test"}`, ""},
		{`{"gitlab_project_id":2}`, ""}, {`{"approved_at":1}`, ""},
		{`{"membership_checked_at":1}`, ""},
		{`{"token_profile":"human-session-v1","scope":null}`, ""},
		{`{"token_profile":"human-session-v1","auth_factors":2}`, ""},
		{`{} {}`, ""}, {`null`, ""}, {`[]`, ""},
	} {
		t.Run(tc.payload, func(t *testing.T) {
			// Given untrusted routing metadata, when selected, then return only a profile or denial.
			got, err := SelectProfile(profileJWT(tc.payload))
			if tc.want == "" {
				if err == nil {
					t.Fatal("accepted invalid routing metadata")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	if _, err := SelectProfile(strings.Repeat("x", 8193)); err == nil {
		t.Fatal("accepted oversized token")
	}
}

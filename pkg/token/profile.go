// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

type Profile string

const (
	ProfileLegacyV1       Profile = "legacy-v1"
	ProfileHumanSessionV1 Profile = "human-session-v1"
)

var ErrInvalidProfile = errors.New("invalid token profile")

// SelectProfile inspects UNVERIFIED routing metadata, never identity.
// Callers must allow the result before key lookup, verify the signature, and
// apply exactly that profile's validator without fallback. Input size is bounded
// by the caller; this selector does not impose a new legacy token size policy.
func SelectProfile(raw string) (Profile, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", ErrInvalidProfile
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrInvalidProfile
	}
	return selectPayload(payload)
}

func selectPayload(payload []byte) (Profile, error) {
	d := json.NewDecoder(bytes.NewReader(payload))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return "", ErrInvalidProfile
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		name, err := d.Token()
		if err != nil {
			return "", ErrInvalidProfile
		}
		key, ok := name.(string)
		if !ok {
			return "", ErrInvalidProfile
		}
		// Match encoding/json's ASCII aliases, including Unicode long s and Kelvin K.
		key = strings.ToLower(strings.ToUpper(key))
		if _, exists := fields[key]; exists {
			return "", ErrInvalidProfile
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return "", ErrInvalidProfile
		}
		fields[key] = value
	}
	if _, err := d.Token(); err != nil {
		return "", ErrInvalidProfile
	}
	if _, err := d.Token(); err != io.EOF {
		return "", ErrInvalidProfile
	}
	profile := ProfileLegacyV1
	if value, exists := fields["token_profile"]; exists {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &profile) != nil {
			return "", ErrInvalidProfile
		}
	}
	switch profile {
	case ProfileLegacyV1:
		for _, name := range []string{"gitlab_issuer", "gitlab_project_id", "gitlab_user_id", "approved_at", "membership_checked_at"} {
			if _, exists := fields[name]; exists {
				return "", ErrInvalidProfile
			}
		}
		var class string
		if value, exists := fields["token_class"]; exists {
			if json.Unmarshal(value, &class) != nil || class == "human" {
				return "", ErrInvalidProfile
			}
		}
	case ProfileHumanSessionV1:
		for _, name := range []string{"auth_time", "amr", "acr", "scope", "auth_level", "auth_factors", "auth_methods", "auth_events", "cluster_id", "openchami_id"} {
			if _, exists := fields[name]; exists {
				return "", ErrInvalidProfile
			}
		}
	default:
		return "", ErrInvalidProfile
	}
	return profile, nil
}

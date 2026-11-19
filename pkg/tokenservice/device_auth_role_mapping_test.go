// SPDX-FileCopyrightText: 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDeviceAuthRoleMappingConfigRoundTrip(t *testing.T) {
	_, original := deviceAuthServiceFixture(t)
	for _, tc := range []struct {
		name    string
		mapping map[string]string
	}{
		{"default", nil},
		{"deny all", map[string]string{}},
		{"custom", map[string]string{"maintainer": "operator", "developer": "viewer"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := *original
			c.GitLabRoleMapping = tc.mapping
			path := filepath.Join(t.TempDir(), "tokensmith.json")
			if err := SaveFileConfig(&FileConfig{DeviceAuth: &c}, path); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadFileConfig(path)
			if err != nil || !reflect.DeepEqual(loaded.DeviceAuth, &c) {
				t.Fatalf("mapping changed during save/load: %#v, %v", loaded, err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var raw struct {
				DeviceAuth map[string]json.RawMessage `json:"device_auth"`
			}
			if err := json.Unmarshal(body, &raw); err != nil {
				t.Fatal(err)
			}
			if tc.mapping != nil && len(tc.mapping) == 0 && string(raw.DeviceAuth["gitlab_role_mapping"]) != "{}" {
				t.Fatal("empty deny-all map was omitted or replaced by defaults")
			}
		})
	}
}

func TestDeviceAuthInvalidRoleMappingFailsBeforeEnabling(t *testing.T) {
	service, c := deviceAuthServiceFixture(t)
	c.GitLabRoleMapping = map[string]string{"maintainer": "root"}
	if err := service.ConfigureDeviceAuth(c); err == nil || service.deviceAuth != nil {
		t.Fatal("invalid role mapping enabled the broker")
	}
}

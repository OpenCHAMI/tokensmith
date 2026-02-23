// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package testutil

import (
	"os"
	"path/filepath"
)

// WritePolicyFragment writes a policy fragment file into dir.
func WritePolicyFragment(dir, filename, content string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, filename)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		return "", err
	}
	return p, nil
}

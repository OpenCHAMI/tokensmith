// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authz

import (
	"net/url"
	"testing"
)

func FuzzNormalizeEscapedPath(f *testing.F) {
	seeds := []string{
		"",
		"/",
		"//",
		"/a/b",
		"/a/../b",
		"/%2F",
		"/%2f",
		"/a%2Fb",
		"/a%252Fb",
		"/a%20b",
		"/%",
		"/%2",
		"/%GG",
		"/%C3%28",
		"/%00",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, rawPath string) {
		u := &url.URL{RawPath: rawPath}
		out1, err1 := NormalizeEscapedPath(u)
		out2, err2 := NormalizeEscapedPath(u)

		// Determinism: the same input should always produce the same output.
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic error: err1=%v err2=%v", err1, err2)
		}
		if err1 == nil && out1 != out2 {
			t.Fatalf("non-deterministic output: out1=%q out2=%q", out1, out2)
		}

		// Basic invariant: successful output must be absolute.
		if err1 == nil && (out1 == "" || out1[0] != '/') {
			t.Fatalf("expected absolute path, got %q", out1)
		}
	})
}

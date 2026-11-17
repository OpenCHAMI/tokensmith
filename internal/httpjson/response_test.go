// SPDX-FileCopyrightText: 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package httpjson

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestDecodeResponseContract(t *testing.T) {
	valid := `{"value":"ok"}`
	for _, tc := range []struct {
		name string
		body string
		ok   bool
	}{
		{"valid", valid, true},
		{"whitespace", "\n" + valid + " \t\r\n", true},
		{"exact limit", valid + strings.Repeat(" ", MaxResponseBytes-len(valid)), true},
		{"one byte over", valid + strings.Repeat(" ", MaxResponseBytes+1-len(valid)), false},
		{"hidden trailing document", valid + strings.Repeat(" ", MaxResponseBytes+1-len(valid)) + `{}`, false},
		{"oversized value", `{"value":"` + strings.Repeat("x", MaxResponseBytes) + `"}`, false},
		{"two documents", valid + `{}`, false},
		{"trailing garbage", valid + "private-secret", false},
		{"empty", "", false},
		{"whitespace only", " \n", false},
		{"malformed", `{"private-secret":`, false},
		{"wrong field type", `{"value":42}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out struct{ Value string }
			err := Decode(strings.NewReader(tc.body), &out)
			if tc.ok {
				if err != nil || out.Value != "ok" {
					t.Fatalf("valid response rejected: %q, %v", out.Value, err)
				}
			} else if err != ErrResponse {
				t.Fatalf("expected sanitized response error, got %v", err)
			}
		})
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("private transport credential")
}

func TestDecodeReadFailure(t *testing.T) {
	// A valid prefix must not conceal a later read failure or expose its detail.
	reader := io.MultiReader(strings.NewReader(`{"value":"ok"}`), failingReader{})
	var out any
	if err := Decode(reader, &out); err != ErrResponse {
		t.Fatalf("expected sanitized response error, got %v", err)
	}
}

func TestDecodeReadBound(t *testing.T) {
	reader := strings.NewReader(strings.Repeat(" ", MaxResponseBytes*2))
	var out any
	if err := Decode(reader, &out); err != ErrResponse {
		t.Fatalf("expected oversized response rejection, got %v", err)
	}
	if consumed := MaxResponseBytes*2 - reader.Len(); consumed != MaxResponseBytes+1 {
		t.Fatalf("read %d bytes, want %d", consumed, MaxResponseBytes+1)
	}
}

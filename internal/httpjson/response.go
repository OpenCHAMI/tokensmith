// SPDX-FileCopyrightText: 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

// Package httpjson decodes bounded upstream JSON responses. Callers own HTTP
// requests, response closure, status handling and authentication policy.
package httpjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// MaxResponseBytes bounds the entire response, including trailing whitespace.
const MaxResponseBytes = 64 * 1024

// ErrResponse excludes upstream content and underlying errors, which may contain
// credentials. Callers may map it to their own protocol or authorization error.
var ErrResponse = errors.New("invalid JSON response")

// Decode reads at most MaxResponseBytes+1 bytes and accepts exactly one JSON
// value followed by optional whitespace. It does not close the reader.
func Decode(reader io.Reader, out any) error {
	body, err := io.ReadAll(io.LimitReader(reader, MaxResponseBytes+1))
	if err != nil || len(body) > MaxResponseBytes {
		return ErrResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(out) != nil {
		return ErrResponse
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrResponse
	}
	return nil
}

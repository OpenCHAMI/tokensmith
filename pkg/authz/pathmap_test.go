// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
//
// SPDX-License-Identifier: MIT

package authz

import (
	"net/url"
	"testing"
)

func TestNormalizeEscapedPath_EmptyPathBecomesSlash(t *testing.T) {
	u := &url.URL{}
	got, err := NormalizeEscapedPath(u)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "/" {
		t.Fatalf("expected '/', got %q", got)
	}
}

func TestNormalizeEscapedPath_MalformedEscape_IsBadRequest(t *testing.T) {
	u := &url.URL{RawPath: "/x%ZZ"}
	_, err := NormalizeEscapedPath(u)
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(BadRequestError); !ok {
		t.Fatalf("expected BadRequestError, got %T: %v", err, err)
	}
}

func TestNormalizeEscapedPath_PreservesEncodedSlash(t *testing.T) {
	u := &url.URL{Path: "/a%2Fb/c"}
	got, err := NormalizeEscapedPath(u)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "/a%2Fb/c" {
		t.Fatalf("expected '/a%%2Fb/c', got %q", got)
	}
}

func TestNormalizeEscapedPath_CleansDotSegmentsWithoutDecodingSlash(t *testing.T) {
	u := &url.URL{Path: "/a/./b/../c%2Fd"}
	got, err := NormalizeEscapedPath(u)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "/a/c%2Fd" {
		t.Fatalf("expected '/a/c%%2Fd', got %q", got)
	}
}

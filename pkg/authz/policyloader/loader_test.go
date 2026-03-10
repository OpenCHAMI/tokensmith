// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
//
// SPDX-License-Identifier: MIT

package policyloader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadMaybeDirCSV_DeterministicOrder(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "20.csv"), []byte("b"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "10.csv"), []byte("a"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	b, origins, err := readMaybeDirCSV(dir)
	if err != nil {
		t.Fatalf("readMaybeDirCSV: %v", err)
	}
	if got, want := origins, []string{filepath.Join(dir, "10.csv"), filepath.Join(dir, "20.csv")}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("origins order mismatch: got %v want %v", got, want)
	}
	if got, want := string(b), "a\nb\n"; got != want {
		t.Fatalf("merged bytes mismatch: got %q want %q", got, want)
	}
}

func TestReadMaybeDirCSV_StripsUTF8BOM(t *testing.T) {
	dir := t.TempDir()
	bom := []byte{0xEF, 0xBB, 0xBF}
	content := append(append([]byte(nil), bom...), []byte("p, a, b, c\n")...)
	if err := os.WriteFile(filepath.Join(dir, "a.csv"), content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	b, _, err := readMaybeDirCSV(dir)
	if err != nil {
		t.Fatalf("readMaybeDirCSV: %v", err)
	}
	if strings.HasPrefix(string(b), string(bom)) {
		t.Fatalf("expected BOM stripped")
	}
	if got, want := string(b), "p, a, b, c\n"; got != want {
		t.Fatalf("unexpected content: got %q want %q", got, want)
	}
}

func TestReadMaybeDirCSV_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.csv"), []byte("p, a, b, c\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, "real.csv"), filepath.Join(dir, "link.csv")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, _, err := readMaybeDirCSV(dir)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "link.csv") {
		t.Fatalf("expected path in error, got: %v", err)
	}
}

func TestLoader_ErrorIncludesPathAndLine(t *testing.T) {
	dir := t.TempDir()
	bad := "p, a, b\n" // missing act
	badPath := filepath.Join(dir, "bad.csv")
	if err := os.WriteFile(badPath, []byte(bad), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	l := New()
	_, err := l.LoadSource(Source{ModelText: baselineModelText, PolicyPath: badPath})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), badPath) {
		t.Fatalf("expected path in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), ":87") {
		t.Fatalf("expected line number in error, got: %v", err)
	}
}

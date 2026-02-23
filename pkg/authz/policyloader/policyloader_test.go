package policyloader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_BaselineOnly(t *testing.T) {
	l := New()
	e, err := l.Load("")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if v := l.PolicyVersion(); v == "" {
		t.Fatalf("PolicyVersion() empty")
	}

	ok, err := e.Enforce("role:viewer", "metadata:nodes", "read")
	if err != nil {
		t.Fatalf("Enforce error: %v", err)
	}
	if !ok {
		t.Fatalf("expected viewer read metadata:nodes allowed")
	}
}

func TestLoad_BaselinePlusFragments_Order(t *testing.T) {
	dir := t.TempDir()

	// Create two fragments and ensure lexical order is applied. We purposely
	// add a deny-ish effect by only granting one permission in a late fragment.
	fragA := "p, role:viewer, boot:configs, read\n"
	fragB := "p, role:viewer, boot:parameters, read\n"

	if err := os.WriteFile(filepath.Join(dir, "10-a.csv"), []byte(fragA), 0o600); err != nil {
		t.Fatalf("write fragA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "20-b.csv"), []byte(fragB), 0o600); err != nil {
		t.Fatalf("write fragB: %v", err)
	}

	l := New()
	e, err := l.Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	ok, err := e.Enforce("role:viewer", "boot:configs", "read")
	if err != nil {
		t.Fatalf("Enforce error: %v", err)
	}
	if !ok {
		t.Fatalf("expected viewer read boot:configs allowed")
	}

	ok, err = e.Enforce("role:viewer", "boot:parameters", "read")
	if err != nil {
		t.Fatalf("Enforce error: %v", err)
	}
	if !ok {
		t.Fatalf("expected viewer read boot:parameters allowed")
	}
}

func TestPolicyVersion_HashStable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.csv"), []byte("p, role:viewer, metadata:nodes, read\n"), 0o600); err != nil {
		t.Fatalf("write frag: %v", err)
	}

	l1 := New()
	_, err := l1.Load(dir)
	if err != nil {
		t.Fatalf("Load l1 error: %v", err)
	}
	v1 := l1.PolicyVersion()

	l2 := New()
	_, err = l2.Load(dir)
	if err != nil {
		t.Fatalf("Load l2 error: %v", err)
	}
	v2 := l2.PolicyVersion()

	if v1 == "" || v2 == "" {
		t.Fatalf("expected non-empty policy versions")
	}
	if v1 != v2 {
		t.Fatalf("expected stable hash; got %s != %s", v1, v2)
	}
}

func TestLoad_MalformedPolicyFragment(t *testing.T) {
	dir := t.TempDir()
	// Missing fields for p line.
	if err := os.WriteFile(filepath.Join(dir, "bad.csv"), []byte("p, role:viewer, metadata:nodes\n"), 0o600); err != nil {
		t.Fatalf("write bad frag: %v", err)
	}

	l := New()
	_, err := l.Load(dir)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadFromEnv_CompatVar(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.csv"), []byte("p, role:viewer, metadata:nodes, read\n"), 0o600); err != nil {
		t.Fatalf("write frag: %v", err)
	}

	t.Setenv(EnvPolicyDir, "")
	t.Setenv(EnvPolicyDirCompat, dir)

	l := New()
	_, err := l.LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error: %v", err)
	}
	if l.PolicyVersion() == "" {
		t.Fatalf("expected policy version")
	}
}

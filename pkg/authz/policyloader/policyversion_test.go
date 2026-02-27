package policyloader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyVersionHashV1_OrderIndependentForFragmentDirs(t *testing.T) {
	dir1 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir1, "10.csv"), []byte("p, role:viewer, a, read\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir1, "20.csv"), []byte("p, role:viewer, b, read\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	dir2 := t.TempDir()
	// Same content, different filenames / creation order.
	if err := os.WriteFile(filepath.Join(dir2, "b.csv"), []byte("p, role:viewer, b, read\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "a.csv"), []byte("p, role:viewer, a, read\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	l1 := New()
	_, err := l1.LoadSource(Source{ModelText: baselineModelText, PolicyPath: dir1})
	if err != nil {
		t.Fatalf("LoadSource dir1: %v", err)
	}
	v1 := l1.PolicyVersion()

	l2 := New()
	_, err = l2.LoadSource(Source{ModelText: baselineModelText, PolicyPath: dir2})
	if err != nil {
		t.Fatalf("LoadSource dir2: %v", err)
	}
	v2 := l2.PolicyVersion()

	if v1 == "" || v2 == "" {
		t.Fatalf("expected non-empty versions")
	}
	if v1 != v2 {
		t.Fatalf("expected same policy_version for equivalent policy content; got %s != %s", v1, v2)
	}
}

func TestPolicyVersionHashV1_ChangesWhenEffectiveContentChanges(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.csv")
	groupPath := filepath.Join(dir, "grouping.csv")

	if err := os.WriteFile(policyPath, []byte("p, role:viewer, a, read\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := os.WriteFile(groupPath, []byte("g, user:alice, role:viewer\n"), 0o600); err != nil {
		t.Fatalf("write grouping: %v", err)
	}

	l1 := New()
	_, err := l1.LoadSource(Source{ModelText: baselineModelText, PolicyPath: policyPath, GroupingPath: groupPath})
	if err != nil {
		t.Fatalf("LoadSource: %v", err)
	}
	v1 := l1.PolicyVersion()

	// Change grouping content.
	if err := os.WriteFile(groupPath, []byte("g, user:alice, role:admin\n"), 0o600); err != nil {
		t.Fatalf("write grouping: %v", err)
	}

	l2 := New()
	_, err = l2.LoadSource(Source{ModelText: baselineModelText, PolicyPath: policyPath, GroupingPath: groupPath})
	if err != nil {
		t.Fatalf("LoadSource: %v", err)
	}
	v2 := l2.PolicyVersion()

	if v1 == v2 {
		t.Fatalf("expected policy_version to change when effective content changes")
	}
}

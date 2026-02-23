// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package policyloader loads the TokenSmith baseline Casbin model+policy and
// optional filesystem policy fragments.
package policyloader

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

const (
	// EnvPolicyDir is the preferred env var pointing to a directory containing
	// Casbin policy fragment CSV files.
	EnvPolicyDir = "TOKENS_MITH_POLICY_DIR"

	// EnvPolicyDirCompat is an alternate env var name used by some deployments.
	EnvPolicyDirCompat = "AUTHZ_POLICY_DIR"
)

//go:embed baseline_model.conf
var baselineModelText string

//go:embed baseline_policy.csv
var baselinePolicyText string

// Loader loads the effective policy set and exposes a deterministic version
// hash.
//
// It is safe for concurrent use.
type Loader struct {
	mu            sync.RWMutex
	policyVersion string
}

// New creates a new loader.
func New() *Loader { return &Loader{} }

// LoadFromEnv loads baseline model+policy plus optional fragments from the
// directory specified by TOKENS_MITH_POLICY_DIR or AUTHZ_POLICY_DIR.
func (l *Loader) LoadFromEnv() (*casbin.Enforcer, error) {
	dir := strings.TrimSpace(os.Getenv(EnvPolicyDir))
	if dir == "" {
		dir = strings.TrimSpace(os.Getenv(EnvPolicyDirCompat))
	}
	return l.Load(dir)
}

// Load loads baseline model+policy and then loads optional policy fragments
// from policyDir.
//
// Load order:
//  1. embedded baseline model+policy
//  2. fragments in lexical order
//
// If policyDir is empty, only the baseline is loaded.
func (l *Loader) Load(policyDir string) (*casbin.Enforcer, error) {
	m, err := model.NewModelFromString(baselineModelText)
	if err != nil {
		return nil, fmt.Errorf("baseline model parse: %w", err)
	}

	e, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, fmt.Errorf("create enforcer: %w", err)
	}

	// Baseline
	baseLines, err := parsePolicyLines(strings.NewReader(baselinePolicyText))
	if err != nil {
		return nil, fmt.Errorf("baseline policy parse: %w", err)
	}
	if err := addPolicies(e, baseLines); err != nil {
		return nil, fmt.Errorf("baseline policy load: %w", err)
	}

	// Fragments
	var effectiveLines []string
	effectiveLines = append(effectiveLines, baseLines...)

	if strings.TrimSpace(policyDir) != "" {
		fragFiles, err := discoverFragments(os.DirFS(policyDir))
		if err != nil {
			return nil, fmt.Errorf("discover policy fragments in %q: %w", policyDir, err)
		}
		for _, name := range fragFiles {
			b, err := os.ReadFile(filepath.Join(policyDir, name))
			if err != nil {
				return nil, fmt.Errorf("read policy fragment %q: %w", filepath.Join(policyDir, name), err)
			}
			lines, err := parsePolicyLines(bytes.NewReader(b))
			if err != nil {
				return nil, fmt.Errorf("parse policy fragment %q: %w", filepath.Join(policyDir, name), err)
			}
			if err := addPolicies(e, lines); err != nil {
				return nil, fmt.Errorf("load policy fragment %q: %w", filepath.Join(policyDir, name), err)
			}
			effectiveLines = append(effectiveLines, lines...)
		}
	}

	pv := policyHash(baselineModelText, effectiveLines)
	l.mu.Lock()
	l.policyVersion = pv
	l.mu.Unlock()

	return e, nil
}

// PolicyVersion returns the last computed deterministic policy version hash.
// It will be empty until Load/LoadFromEnv succeeds.
func (l *Loader) PolicyVersion() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.policyVersion
}

func discoverFragments(fsys fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		n := ent.Name()
		if strings.HasSuffix(n, ".csv") || strings.HasSuffix(n, ".policy.csv") {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

func parsePolicyLines(r io.Reader) ([]string, error) {
	s := bufio.NewScanner(r)
	// allow large fragments
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var out []string
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := normalizeLine(s.Text())
		if line == "" {
			continue
		}
		// Validate by attempting to parse: we only support p/g lines.
		parts := splitCSVLine(line)
		if len(parts) < 3 {
			return nil, fmt.Errorf("line %d: expected at least 3 CSV fields, got %d", lineNo, len(parts))
		}
		switch parts[0] {
		case "p":
			if len(parts) != 4 {
				return nil, fmt.Errorf("line %d: policy line must be 4 fields: p, sub, obj, act", lineNo)
			}
		case "g":
			if len(parts) != 3 {
				return nil, fmt.Errorf("line %d: grouping line must be 3 fields: g, user, role", lineNo)
			}
		default:
			return nil, fmt.Errorf("line %d: unsupported policy line prefix %q", lineNo, parts[0])
		}
		out = append(out, line)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeLine(in string) string {
	// Strip comments.
	if i := strings.Index(in, "#"); i >= 0 {
		in = in[:i]
	}
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
	// Normalize whitespace: remove spaces around commas and collapse internal
	// runs of whitespace within fields.
	parts := splitCSVLine(in)
	for i := range parts {
		parts[i] = strings.Join(strings.Fields(parts[i]), " ")
	}
	return strings.Join(parts, ",")
}

func splitCSVLine(in string) []string {
	parts := strings.Split(in, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func addPolicies(e *casbin.Enforcer, lines []string) error {
	for _, line := range lines {
		parts := splitCSVLine(line)
		switch parts[0] {
		case "p":
			ok, err := e.AddPolicy(parts[1], parts[2], parts[3])
			if err != nil {
				return err
			}
			_ = ok
		case "g":
			ok, err := e.AddGroupingPolicy(parts[1], parts[2])
			if err != nil {
				return err
			}
			_ = ok
		default:
			return errors.New("unsupported policy line")
		}
	}
	return nil
}

func policyHash(modelText string, effectiveLines []string) string {
	// Deterministically normalize model text too: trim spaces and normalize newlines.
	mt := strings.ReplaceAll(modelText, "\r\n", "\n")
	mt = strings.TrimSpace(mt) + "\n"

	var buf strings.Builder
	buf.WriteString(mt)
	for _, l := range effectiveLines {
		buf.WriteString(normalizeLine(l))
		buf.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(buf.String()))
	return hex.EncodeToString(sum[:])
}

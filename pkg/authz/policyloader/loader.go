// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package policyloader loads Casbin model and policy artifacts (policy +
// grouping fragments) deterministically.
//
// Symlink policy:
//   - When walking a directory for fragments, TokenSmith does NOT follow
//     symlinks by default.
//   - If a symlink is encountered, loading returns an error.
//
// Rationale: policy files are security-sensitive; following symlinks can allow
// unexpected policy injection via filesystem tricks.
package policyloader

import (
	"bufio"
	"bytes"
	"crypto/sha256"
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

// Source describes where to load model/policy/grouping from.
//
// Exactly one of ModelPreset, ModelText, or ModelPath should be provided.
//
// Policy and grouping sources may be a single file path or a directory.
// Directories are walked non-recursively and merged deterministically in
// lexicographic path order.
//
// Fragment file selection is intentionally simple: any file with a .csv suffix
// is considered.
//
// Note: Hot reload / watchers are intentionally not implemented here.
type Source struct {
	// ModelPreset is an optional preset model name. This is retained for forward
	// compatibility; current loader does not interpret preset names itself.
	ModelPreset string

	// ModelText is raw model.conf content.
	ModelText string

	// ModelPath points to a model.conf file.
	ModelPath string

	// PolicyPath points to a policy.csv file or directory containing policy
	// fragments.
	PolicyPath string

	// GroupingPath points to a grouping.csv file or directory containing grouping
	// fragments.
	GroupingPath string
}

// Loader loads model/policy/grouping and exposes a deterministic version hash.
//
// It is safe for concurrent use.
type Loader struct {
	mu            sync.RWMutex
	policyVersion string
}

func New() *Loader { return &Loader{} }

// Load loads Casbin artifacts from src and returns an enforcer and deterministic
// policy version.
func (l *Loader) LoadSource(src Source) (*casbin.Enforcer, error) {
	modelText, err := l.loadModelText(src)
	if err != nil {
		return nil, err
	}

	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, fmt.Errorf("model parse: %w", err)
	}

	e, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, fmt.Errorf("create enforcer: %w", err)
	}

	baselinePolicyBytes := stripUTF8BOM([]byte(baselinePolicyText))

	policyBytes, policyOrigins, err := readMaybeDirCSV(src.PolicyPath)
	if err != nil {
		return nil, err
	}
	policyBytes = append(append([]byte(nil), baselinePolicyBytes...), policyBytes...)
	if len(policyOrigins) == 0 {
		policyOrigins = []string{"<embedded baseline policy>"}
	}

	groupingBytes, groupingOrigins, err := readMaybeDirCSV(src.GroupingPath)
	if err != nil {
		return nil, err
	}

	policyLines, err := parsePolicyLines(bytes.NewReader(policyBytes), policyOrigins)
	if err != nil {
		return nil, err
	}
	groupingLines, err := parseGroupingLines(bytes.NewReader(groupingBytes), groupingOrigins)
	if err != nil {
		return nil, err
	}

	if err := addPolicies(e, policyLines); err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}
	if err := addGroupings(e, groupingLines); err != nil {
		return nil, fmt.Errorf("load grouping: %w", err)
	}

	pv := policyHash(modelText, policyBytes, groupingBytes)
	l.mu.Lock()
	l.policyVersion = pv
	l.mu.Unlock()

	return e, nil
}

func (l *Loader) PolicyVersion() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.policyVersion
}

func (l *Loader) loadModelText(src Source) (string, error) {
	switch {
	case strings.TrimSpace(src.ModelText) != "":
		return normalizeUTF8BOMString(src.ModelText), nil
	case strings.TrimSpace(src.ModelPath) != "":
		b, err := os.ReadFile(src.ModelPath)
		if err != nil {
			return "", fmt.Errorf("read model %q: %w", src.ModelPath, err)
		}
		return string(stripUTF8BOM(b)), nil
	case strings.TrimSpace(src.ModelPreset) != "":
		return "", fmt.Errorf("model preset %q: preset resolution is not supported by this loader", src.ModelPreset)
	default:
		return "", errors.New("model source not specified")
	}
}

func readMaybeDirCSV(path string) ([]byte, []string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil, nil
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("stat %q: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%q: symlink not permitted", path)
	}
	if !fi.IsDir() {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("read %q: %w", path, err)
		}
		b = stripUTF8BOM(b)
		// origins includes the single file path for error context.
		return b, []string{path}, nil
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, nil, fmt.Errorf("readdir %q: %w", path, err)
	}
	var files []string
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			return nil, nil, fmt.Errorf("stat dir entry %q: %w", filepath.Join(path, ent.Name()), err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("%q: symlink fragment not permitted", filepath.Join(path, ent.Name()))
		}
		if !strings.HasSuffix(ent.Name(), ".csv") {
			continue
		}
		files = append(files, filepath.Join(path, ent.Name()))
	}
	sort.Strings(files)

	var buf bytes.Buffer
	for _, fp := range files {
		b, err := os.ReadFile(fp)
		if err != nil {
			return nil, nil, fmt.Errorf("read fragment %q: %w", fp, err)
		}
		b = stripUTF8BOM(b)
		buf.Write(b)
		if len(b) > 0 && b[len(b)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes(), files, nil
}

func parsePolicyLines(r io.Reader, origins []string) ([]policyLine, error) {
	return parseLinesWithOrigins(r, origins, "p")
}

func parseGroupingLines(r io.Reader, origins []string) ([]policyLine, error) {
	return parseLinesWithOrigins(r, origins, "g")
}

type originRange struct {
	Origin    string
	StartLine int
	EndLine   int
}

func parseLinesWithOrigins(r io.Reader, origins []string, kind string) ([]policyLine, error) {
	if len(origins) == 0 {
		return parseLines(r, "<memory>", kind)
	}

	// Re-scan the merged stream but attribute line ranges to each origin by
	// counting newlines. This lets us return useful (path, line) errors even
	// though fragments are merged into a single byte stream.
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	start := 1
	var ranges []originRange
	for i, o := range origins {
		end := start
		if i < len(origins)-1 {
			// For all but the last origin, determine end line by counting newlines
			// in the corresponding segment. We approximate by splitting the merged
			// content evenly by concatenation order; since readMaybeDirCSV always
			// appends a trailing newline per fragment, this produces stable ranges.
			//
			// We don't have segment lengths here, so we fall back to treating each
			// origin as unknown range except the first. This is still useful for the
			// common case where a single file is provided.
			_ = end
		}
		// Default: unknown ranges (single origin is accurate).
		ranges = append(ranges, originRange{Origin: o, StartLine: start, EndLine: 1 << 30})
		_ = end
	}

	// Single origin: accurate.
	if len(origins) == 1 {
		return parseLines(bytes.NewReader(b), origins[0], kind)
	}

	// Multi-origin: best-effort. We at least surface the first origin.
	return parseLines(bytes.NewReader(b), ranges[0].Origin, kind)
}

type policyLine struct {
	Origin string
	LineNo int
	Raw    string
	Parts  []string
}

func parseLines(r io.Reader, origin string, kind string) ([]policyLine, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var out []policyLine
	lineNo := 0
	for s.Scan() {
		lineNo++
		n := normalizeLine(s.Text())
		if n == "" {
			continue
		}
		parts := splitCSVLine(n)
		if parts[0] != kind {
			// Allow mixed inputs only when kind parsing is called for entire merged
			// stream; ignore other kinds.
			continue
		}
		switch kind {
		case "p":
			if len(parts) != 4 {
				return nil, fmt.Errorf("%s:%d: policy line must be 4 fields: p, sub, obj, act", origin, lineNo)
			}
		case "g":
			if len(parts) != 3 {
				return nil, fmt.Errorf("%s:%d: grouping line must be 3 fields: g, user, role", origin, lineNo)
			}
		default:
			return nil, fmt.Errorf("%s:%d: unsupported line kind %q", origin, lineNo, kind)
		}
		out = append(out, policyLine{Origin: origin, LineNo: lineNo, Raw: n, Parts: parts})
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", origin, err)
	}
	return out, nil
}

func addPolicies(e *casbin.Enforcer, lines []policyLine) error {
	for _, l := range lines {
		parts := l.Parts
		if _, err := e.AddPolicy(parts[1], parts[2], parts[3]); err != nil {
			return fmt.Errorf("%s:%d: %w", l.Origin, l.LineNo, err)
		}
	}
	return nil
}

func addGroupings(e *casbin.Enforcer, lines []policyLine) error {
	for _, l := range lines {
		parts := l.Parts
		if _, err := e.AddGroupingPolicy(parts[1], parts[2]); err != nil {
			return fmt.Errorf("%s:%d: %w", l.Origin, l.LineNo, err)
		}
	}
	return nil
}

func normalizeLine(in string) string {
	if i := strings.Index(in, "#"); i >= 0 {
		in = in[:i]
	}
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
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

func stripUTF8BOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

func normalizeUTF8BOMString(s string) string {
	return string(stripUTF8BOM([]byte(s)))
}

func policyHash(modelText string, policyBytes, groupingBytes []byte) string {
	mt := strings.ReplaceAll(modelText, "\r\n", "\n")
	mt = strings.TrimSpace(mt) + "\n"

	h := sha256.New()
	h.Write([]byte(mt))
	h.Write([]byte("\n--policy--\n"))
	h.Write(policyBytes)
	h.Write([]byte("\n--grouping--\n"))
	h.Write(groupingBytes)
	return hex.EncodeToString(h.Sum(nil))
}

// Ensure we don't accidentally depend on os.DirFS semantics in callers.
var _ fs.FS

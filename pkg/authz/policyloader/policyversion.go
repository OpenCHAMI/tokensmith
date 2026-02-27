// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package policyloader

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// policyVersionHashV1 computes policy_version as a stable hash over the
// effective Casbin artifacts.
//
// Hash inputs (in order):
//   - normalized model text
//   - merged policy bytes
//   - merged grouping bytes
//
// Notes:
//   - policy_version is intended to represent the *authorization policy
//     configuration* only.
//   - It intentionally does not include runtime settings like enforcement mode
//     or mapping strategy; those should be logged alongside policy_version.
func policyVersionHashV1(modelText string, policyBytes, groupingBytes []byte) string {
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

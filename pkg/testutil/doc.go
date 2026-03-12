// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package testutil provides helpers for integration tests in downstream
// OpenCHAMI services.
//
// Compatibility policy:
//   - Best-effort stability within a major version of TokenSmith.
//   - No guarantees are made about internal structures or unexported behavior.
//   - Helpers may change when AuthN/AuthZ wiring evolves; prefer using these
//     helpers only in tests.
package testutil

// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

module github.com/openchami/tokensmith/example/server

go 1.24.0

toolchain go1.24.4

require (
	github.com/go-chi/chi/v5 v5.2.3
	github.com/openchami/tokensmith v0.0.0
)

require (
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/openchami/chi-middleware/log v0.0.0-20240812224658-b16b83c70700 // indirect
	github.com/rs/zerolog v1.34.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

replace github.com/openchami/tokensmith => ../../

replace github.com/openchami/tokensmith/middleware => ../../middleware

replace github.com/openchami/tokensmith/pkg/token => ../../pkg/token

replace github.com/openchami/tokensmith/pkg/oidc/hydra => ../../pkg/oidc/hydra

replace github.com/openchami/tokensmith/pkg/oidc => ../../pkg/oidc

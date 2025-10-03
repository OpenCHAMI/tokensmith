// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

module github.com/openchami/tokensmith

go 1.24.0

require (
	github.com/go-chi/chi/v5 v5.2.3
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/rs/zerolog v1.34.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/openchami/chi-middleware/log v0.0.0-20240812224658-b16b83c70700
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/openchami/tokensmith => ./

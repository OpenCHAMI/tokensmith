// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

module github.com/openchami/tokensmith/middleware

go 1.24.0

require (
	github.com/MicahParks/keyfunc v1.9.0
	github.com/casbin/casbin/v2 v2.128.0
	github.com/openchami/tokensmith v0.0.0
	github.com/rs/zerolog v1.34.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/bmatcuk/doublestar/v4 v4.6.1 // indirect
	github.com/casbin/govaluate v1.3.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.4.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/openchami/tokensmith => ../

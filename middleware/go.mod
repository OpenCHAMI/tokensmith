// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

module github.com/openchami/tokensmith/middleware

go 1.24.0

require (
	github.com/MicahParks/keyfunc v1.9.0
	github.com/casbin/casbin/v2 v2.128.0
	github.com/casbin/xorm-adapter/v2 v2.5.1
	github.com/openchami/tokensmith v0.0.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/bmatcuk/doublestar/v4 v4.6.1 // indirect
	github.com/casbin/govaluate v1.3.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.4.2 // indirect
	github.com/golang/snappy v0.0.0-20180518054509-2e65f85255db // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/lib/pq v1.8.0 // indirect
	github.com/syndtr/goleveldb v1.0.0 // indirect
	xorm.io/builder v0.3.7 // indirect
	xorm.io/xorm v1.0.3 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/openchami/tokensmith => ../

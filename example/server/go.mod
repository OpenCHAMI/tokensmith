module github.com/openchami/tokensmith/example/server

go 1.24.0

toolchain go1.24.4

require (
	github.com/go-chi/chi/v5 v5.2.3
	github.com/openchami/tokensmith v0.0.0
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.0 // indirect
	github.com/lestrrat-go/jwx/v3 v3.0.10 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/openchami/chi-middleware/log v0.0.0-20240812224658-b16b83c70700 // indirect
	github.com/rs/zerolog v1.34.0 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

replace github.com/openchami/tokensmith => ../../

replace github.com/openchami/tokensmith/middleware => ../../middleware

replace github.com/openchami/tokensmith/pkg/token => ../../pkg/token

replace github.com/openchami/tokensmith/pkg/oidc/hydra => ../../pkg/oidc/hydra

replace github.com/openchami/tokensmith/pkg/oidc => ../../pkg/oidc

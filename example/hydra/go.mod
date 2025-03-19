module github.com/openchami/tokensmith/example/hydra

go 1.23.4

require (
	github.com/go-chi/chi/v5 v5.2.1
	github.com/openchami/tokensmith v0.0.0
	github.com/openchami/tokensmith/middleware v0.0.0
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.6 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/jwx/v2 v2.1.4 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
)

replace github.com/openchami/tokensmith => ../../

replace github.com/openchami/tokensmith/middleware => ../../middleware

replace github.com/openchami/tokensmith/pkg/jwt => ../../pkg/jwt

replace github.com/openchami/tokensmith/pkg/jwt/oidc/hydra => ../../pkg/jwt/oidc/hydra

replace github.com/openchami/tokensmith/pkg/jwt/oidc => ../../pkg/jwt/oidc

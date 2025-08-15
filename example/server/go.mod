module github.com/openchami/tokensmith/example/server

go 1.23.4

require (
	github.com/go-chi/chi/v5 v5.2.2
	github.com/openchami/tokensmith v0.0.0
)

require github.com/golang-jwt/jwt/v5 v5.2.2 // indirect

replace github.com/openchami/tokensmith => ../../

replace github.com/openchami/tokensmith/middleware => ../../middleware

replace github.com/openchami/tokensmith/pkg/token => ../../pkg/token

replace github.com/openchami/tokensmith/pkg/oidc/hydra => ../../pkg/oidc/hydra

replace github.com/openchami/tokensmith/pkg/oidc => ../../pkg/oidc

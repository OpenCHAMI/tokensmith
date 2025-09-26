module github.com/openchami/tokensmith/example/hydra

go 1.24.0

toolchain go1.24.4

require (
	github.com/go-chi/chi/v5 v5.2.3
	github.com/openchami/tokensmith v0.0.0
	github.com/openchami/tokensmith/middleware v0.0.0
)

require (
	github.com/MicahParks/keyfunc v1.9.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.4.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
)

replace github.com/openchami/tokensmith => ../../

replace github.com/openchami/tokensmith/middleware => ../../middleware

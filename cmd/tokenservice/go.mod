module github.com/openchami/tokensmith/cmd/tokenservice

go 1.24.0

toolchain go1.24.4

require (
	github.com/openchami/tokensmith v0.0.0
	github.com/spf13/cobra v1.9.1
)

require (
	github.com/go-chi/chi/v5 v5.2.3 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/openchami/chi-middleware/log v0.0.0-20240812224658-b16b83c70700 // indirect
	github.com/rs/zerolog v1.34.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

replace github.com/openchami/tokensmith => ../../

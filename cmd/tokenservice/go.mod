module github.com/openchami/tokensmith/cmd/tokenservice

go 1.23.4

require (
	github.com/openchami/tokensmith v0.0.0
	github.com/spf13/cobra v1.9.1
)

require (
	github.com/go-chi/chi/v5 v5.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
)

replace github.com/openchami/tokensmith => ../../

module github.com/openchami/tokensmith

go 1.23.4

require (
	github.com/go-chi/chi/v5 v5.2.2
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/rs/zerolog v1.33.0
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	golang.org/x/sys v0.12.0 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/openchami/chi-middleware/log v0.0.0-20240812224658-b16b83c70700
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/openchami/tokensmith => ./

module github.com/openchami/tokensmith/middleware

go 1.24.0

require (
	github.com/MicahParks/keyfunc v1.9.0
	github.com/openchami/tokensmith v0.0.0
	github.com/stretchr/testify v1.11.1
)

require github.com/golang-jwt/jwt/v4 v4.4.2 // indirect

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/openchami/tokensmith => ../

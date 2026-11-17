package deviceauth

import "context"

var ctx = context.Background()

func config() Config {
	return Config{Issuer: "https://gitlab.example", ClientID: "application", ProjectID: 701, ClusterIssuer: "https://cluster.example", Audience: "openchami-device-auth", VerifierFile: "/run/secrets/verifier", CacheSeconds: 90, TokenSeconds: 180, SkewSeconds: 30, AbsoluteSeconds: 36000}
}

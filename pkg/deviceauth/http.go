package deviceauth

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// Mount under /device-auth/. All credentials travel in POST bodies or Authorization,
// never paths/query strings. Parent logging must not log bodies/headers.
func (a *Authority) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	fail := func(status int) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_failed"})
	}
	if r.Method != "POST" {
		fail(405)
		return
	}
	if r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
		fail(400)
		return
	}
	var body struct {
		Transaction string `json:"transaction,omitempty"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil {
		fail(400)
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		fail(400)
		return
	}
	var result any
	var err error
	switch r.URL.Path {
	case "/device-auth/start":
		if body.Transaction != "" || r.Header.Get("Authorization") != "" {
			fail(400)
			return
		}
		result, err = a.Start(r.Context())
	case "/device-auth/poll":
		if body.Transaction == "" || r.Header.Get("Authorization") != "" {
			fail(400)
			return
		}
		result, err = a.Poll(r.Context(), body.Transaction)
	case "/device-auth/renew", "/device-auth/logout":
		parts := strings.Split(r.Header.Get("Authorization"), " ")
		if body.Transaction != "" || len(parts) != 2 || parts[0] != "Bearer" || len(parts[1]) != 43 {
			fail(401)
			return
		}
		if r.URL.Path == "/device-auth/renew" {
			result, err = a.Renew(r.Context(), parts[1])
		} else {
			err = a.Logout(r.Context(), parts[1])
			result = map[string]string{"status": "logged_out"}
		}
	default:
		fail(404)
		return
	}
	if err != nil {
		fail(401)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}

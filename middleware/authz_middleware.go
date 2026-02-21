package middleware

import (
	"net/http"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
)

var (
	authzDeniedCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tokensmith_authz_denied_total",
			Help: "Total number of requests denied by tokensmith authorization middleware",
		},
	)
)

func init() {
	// Register metric but do not fail if already registered
	_ = prometheus.Register(authzDeniedCounter)
}

// helper: path is exempt
func pathExempt(path string, exempt []string) bool {
	for _, e := range exempt {
		if strings.HasSuffix(e, "*") {
			pref := strings.TrimSuffix(e, "*")
			if strings.HasPrefix(path, pref) {
				return true
			}
		} else if e == path {
			return true
		}
	}
	return false
}

// default subject mapping follows priority:
// 1) if claims has realm_access.roles (common Keycloak format) then map each role to 'role:<role>'
// 2) if claims has a "roles" claim (array of strings) map each to 'role:<role>'
// 3) fallback to user:<sub>
func defaultSubjectMapper(r *http.Request, claims interface{}) []string {
	// We expect the JWT middleware to populate claims as *token.TSClaims under ClaimsContextKey
	if claims == nil {
		return nil
	}

	// Attempt type assertion
	if c, ok := claims.(*token.TSClaims); ok {
		// realm_access not currently modeled on TSClaims; users can provide a SubjectMapper if they
		// embed custom fields. Fall back to Roles if present.
		// If the TSClaims had a Roles field, we'd use it. For now, use the subject.
		return []string{"user:" + c.Subject}
	}

	// Last resort: attempt to read a map[string]interface{}
	if m, ok := claims.(map[string]interface{}); ok {
		// check realm_access.roles
		if ra, ok := m["realm_access"]; ok {
			if rm, ok := ra.(map[string]interface{}); ok {
				if rolesRaw, ok := rm["roles"]; ok {
					if rolesArr, ok := rolesRaw.([]interface{}); ok {
						out := make([]string, 0, len(rolesArr))
						for _, rr := range rolesArr {
							if rs, ok := rr.(string); ok {
								out = append(out, "role:"+rs)
							}
						}
						if len(out) > 0 {
							return out
						}
					}
				}
			}
		}
		// check roles claim
		if rolesRaw, ok := m["roles"]; ok {
			if rolesArr, ok := rolesRaw.([]interface{}); ok {
				out := make([]string, 0, len(rolesArr))
				for _, rr := range rolesArr {
					if rs, ok := rr.(string); ok {
						out = append(out, "role:"+rs)
					}
				}
				if len(out) > 0 {
					return out
				}
			}
		}
		// fallback to sub
		if sub, ok := m["sub"].(string); ok {
			return []string{"user:" + sub}
		}
	}
	return nil
}

// AuthzMiddleware enforces Casbin policies using an existing enforcer.
// It expects JWT claims to be present in the request context under opts.ContextKey (or default)
// which are placed there by the JWT middleware. The middleware will call enforcer.Enforce(sub,obj,act)
// where subject(s) are derived from claims using SubjectMapper (or default), object is derived from
// ObjectMapper (or request path), and action from ActionMapper (or HTTP method lowercased).
//
// Behavior:
//   - If no claims are present -> respond 401 Unauthorized
//   - If subject/object/action are derived and enforcer.Enforce returns false -> respond 403 Forbidden
//   - If opts.FailOpen==true and enforcer.Enforce returns an error -> allow request (log at warn)
//   - ExemptPaths are skipped entirely (200 passes through to next)
func AuthzMiddleware(enforcer *casbin.Enforcer, opts *AuthzOptions) func(http.Handler) http.Handler {
	if opts == nil {
		opts = &AuthzOptions{ContextKey: string(ClaimsContextKey)}
	}
	if opts.ContextKey == "" {
		opts.ContextKey = string(ClaimsContextKey)
	}
	if opts.ObjectMapper == nil {
		opts.ObjectMapper = func(r *http.Request, claims interface{}) string { return r.URL.Path }
	}
	if opts.ActionMapper == nil {
		opts.ActionMapper = func(r *http.Request, claims interface{}) string { return strings.ToLower(r.Method) }
	}
	if opts.SubjectMapper == nil {
		opts.SubjectMapper = func(r *http.Request, claims interface{}) []string { return defaultSubjectMapper(r, claims) }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Exempt paths
			if len(opts.ExemptPaths) > 0 && pathExempt(r.URL.Path, opts.ExemptPaths) {
				next.ServeHTTP(w, r)
				return
			}

			// Retrieve claims from context
			claims := r.Context().Value(ContextKey(opts.ContextKey))
			if claims == nil {
				log.Debug().Msg("authorization: no claims in context")
				http.Error(w, "missing or invalid authentication", http.StatusUnauthorized)
				return
			}

			subs := opts.SubjectMapper(r, claims)
			if len(subs) == 0 {
				// no subject derived, deny
				log.Debug().Msg("authorization: no subject derived from claims")
				http.Error(w, "forbidden", http.StatusForbidden)
				authzDeniedCounter.Inc()
				return
			}

			obj := opts.ObjectMapper(r, claims)
			act := opts.ActionMapper(r, claims)

			var allowed bool
			var err error
			for _, s := range subs {
				allowed, err = enforcer.Enforce(s, obj, act)
				if err != nil {
					log.Warn().Err(err).Str("sub", s).Str("obj", obj).Str("act", act).Msg("authorization: enforcement error")
					if opts.FailOpen {
						next.ServeHTTP(w, r)
						return
					}
					http.Error(w, "forbidden", http.StatusForbidden)
					authzDeniedCounter.Inc()
					return
				}
				if allowed {
					log.Debug().Str("sub", s).Str("obj", obj).Str("act", act).Msg("authorization: allowed")
					next.ServeHTTP(w, r)
					return
				}
			}

			// No subject allowed
			log.Info().Strs("subjects", subs).Str("obj", obj).Str("act", act).Msg("authorization: denied")
			http.Error(w, "forbidden", http.StatusForbidden)
			authzDeniedCounter.Inc()
		})
	}
}

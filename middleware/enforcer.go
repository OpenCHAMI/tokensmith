package middleware

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/rs/zerolog/log"
)

const (
	EnvCasbinModelPath      = "TOKENSMITH_CASBIN_MODEL_PATH"
	EnvCasbinPolicyPath     = "TOKENSMITH_CASBIN_POLICY_PATH"
	EnvCasbinAutoload       = "TOKENSMITH_CASBIN_AUTOLOAD_SECONDS"
	DefaultCasbinModelPath  = "./casbin_model.conf"
	DefaultCasbinPolicyPath = "./casbin_policy.csv"
)

// EnforcerOptions controls factory behavior.
type EnforcerOptions struct {
	ModelPath       string
	PolicyPath      string
	AutoLoadSeconds int
	FailFast        bool
	Permissive      bool
}

// PolicyAdapter allows different persistence backends
type PolicyAdapter interface {
	Adapter() persist.Adapter
}

// FilePolicyAdapter implements PolicyAdapter for filesystem policies
type FilePolicyAdapter struct{ Path string }

func (f *FilePolicyAdapter) Adapter() persist.Adapter { return fileadapter.NewAdapter(f.Path) }

// CreateEnforcer builds a casbin.Enforcer based on options and env vars.
func CreateEnforcer(ctx context.Context, opts *EnforcerOptions) (*casbin.Enforcer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &EnforcerOptions{FailFast: true}
	}

	modelPath := opts.ModelPath
	if modelPath == "" {
		if v := os.Getenv(EnvCasbinModelPath); v != "" {
			modelPath = v
		} else {
			modelPath = DefaultCasbinModelPath
		}
	}

	policy := opts.PolicyPath
	if policy == "" {
		if v := os.Getenv(EnvCasbinPolicyPath); v != "" {
			policy = v
		} else {
			policy = DefaultCasbinPolicyPath
		}
	}

	autoload := opts.AutoLoadSeconds
	if v := os.Getenv(EnvCasbinAutoload); v != "" {
		if s, err := strconv.Atoi(v); err == nil {
			autoload = s
		}
	}

	adapter := (&FilePolicyAdapter{Path: policy}).Adapter()
	enf, err := casbin.NewEnforcer(modelPath, adapter)
	if err == nil {
		if err = enf.LoadPolicy(); err == nil {
			if autoload > 0 {
				d := time.Duration(autoload) * time.Second
				go func() {
					ticker := time.NewTicker(d)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							if err := enf.LoadPolicy(); err != nil {
								log.Warn().Err(err).Msg("failed to auto-load policy")
							}
						}
					}
				}()
			}
			return enf, nil
		}
	}

	if opts.FailFast {
		return nil, fmt.Errorf("failed to create casbin enforcer model=%s policy=%s: %w", modelPath, policy, err)
	}

	// fallback: permissive or deny-all
	if opts.Permissive {
		m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = true
`)
		if err != nil {
			return nil, fmt.Errorf("failed to create permissive model: %w", err)
		}
		enf, err = casbin.NewEnforcer(m)
		if err != nil {
			return nil, fmt.Errorf("failed to create permissive enforcer: %w", err)
		}
		return enf, nil
	}

	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = false
`)
	if err != nil {
		return nil, fmt.Errorf("failed to create deny-all model: %w", err)
	}
	enf, err = casbin.NewEnforcer(m)
	if err != nil {
		return nil, fmt.Errorf("failed to create deny-all enforcer: %w", err)
	}
	return enf, nil
}

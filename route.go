package godns

import (
	"fmt"
	"strings"

	"github.com/taodev/pkg/geodb"
)

type Router struct {
	Rules   []*geodb.Rule
	Default string // Default upstream to use if no rules match
}

func (r *Router) Route(domain string) (upstream string) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, rule := range r.Rules {
		if upstream, ok := rule.Match(&geodb.Context{Domain: domain}); ok {
			return upstream
		}
	}
	return r.Default
}

// 判断是否有效的路由规则
func (r *Router) Check(upstream *UpstreamManager) error {
	for i, rule := range r.Rules {
		if _, ok := upstream.Get(rule.Action); !ok {
			return fmt.Errorf("upstream %s not found for rule %v", rule.Action, i)
		}
	}
	if _, ok := upstream.Get(r.Default); !ok {
		return fmt.Errorf("default upstream %s not found", r.Default)
	}
	return nil
}

func NewRouter(opts []string, defaultUpstream string) (*Router, error) {
	r := &Router{
		Rules:   make([]*geodb.Rule, 0),
		Default: defaultUpstream,
	}
	for _, opt := range opts {
		matcher, err := geodb.LoadRule(opt)
		if err != nil {
			return nil, err
		}
		r.Rules = append(r.Rules, matcher)
		if len(r.Default) <= 0 {
			r.Default = matcher.Action
		}
	}
	return r, nil
}
